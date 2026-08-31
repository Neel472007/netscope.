// Package server provides the NetScope HTTP server.
package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptoRand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Neel472007/netscope/internal/benchmark"
	"github.com/Neel472007/netscope/internal/concurrency"
	"github.com/Neel472007/netscope/internal/diagnostics"
	"github.com/Neel472007/netscope/internal/dns"
	"github.com/Neel472007/netscope/internal/dnsrace"
	"github.com/Neel472007/netscope/internal/history"
	"github.com/Neel472007/netscope/internal/httpdiag"
	"github.com/Neel472007/netscope/internal/lbsim"
	"github.com/Neel472007/netscope/internal/multiscan"
	"github.com/Neel472007/netscope/internal/fingerprint"
	"github.com/Neel472007/netscope/internal/healthmon"
	"github.com/Neel472007/netscope/internal/overview"
	"github.com/Neel472007/netscope/internal/packetflow"
	"github.com/Neel472007/netscope/internal/report"
	"github.com/Neel472007/netscope/internal/ping"
	"github.com/Neel472007/netscope/internal/portscan"
	"github.com/Neel472007/netscope/internal/simulator"
	"github.com/Neel472007/netscope/internal/speedtest"
	"github.com/Neel472007/netscope/internal/tcp"
	"github.com/Neel472007/netscope/internal/tlsinspector"
	"github.com/Neel472007/netscope/internal/traceroute"
	"github.com/Neel472007/netscope/internal/types"
	"github.com/Neel472007/netscope/internal/validate"
	"github.com/Neel472007/netscope/internal/whois"
)

const (
	maxRequestBody      = 1024 * 4 // 4KB
	requestTimeout      = 30 * time.Second
	readTimeout         = 0 // No read timeout — long-running requests need it
	writeTimeout        = 0 // No write timeout — SSE streams and stress tests can run indefinitely
	maxStressConns      = 10000
	maxStressDuration   = 60 * time.Second
	maxConcurrentReqs   = 50 // Max simultaneous requests
	csrfTokenLength     = 32
)

// Config holds server configuration.
type Config struct {
	Addr      string
	WebDir    string
	WebFS     http.FileSystem // optional: embedded filesystem (overrides WebDir)
	SimAddr   string
	LBAddr    string
	LBPorts   []int
}

// Server is the NetScope HTTP server.
type Server struct {
	config       Config
	orchestrator *diagnostics.Orchestrator
	dnsEngine    *dns.Engine
	tcpEngine    *tcp.Engine
	httpEngine   *httpdiag.Engine
	analyzer     *diagnostics.Engine
	simulator    *simulator.Server
	lbSimulator  *lbsim.LoadBalancer
	pingEngine   *ping.Engine
	history      *history.History
	mux          *http.ServeMux
	server       *http.Server
	sseClients   map[chan types.Event]struct{}
	sseMu        sync.Mutex
	monitors     map[string]*healthmon.Monitor
	monitorsMu   sync.Mutex
	// Security
	csrfToken    string
	reqLimiter   *concurrentLimiter
	auditLog     []AuditEntry
	auditMu      sync.Mutex
}

// NewServer creates a new NetScope server.
func NewServer(config Config) *Server {	s := &Server{
		config:       config,
		orchestrator: diagnostics.NewOrchestrator(),
		dnsEngine:    dns.NewEngine(),
		tcpEngine:    tcp.NewEngine(),
		httpEngine:   httpdiag.NewEngine(),
		analyzer:     diagnostics.NewEngine(),
		simulator:    simulator.NewServer(config.SimAddr),
		pingEngine:   ping.NewEngine(),
		history:      history.New(200),
		mux:          http.NewServeMux(),
		sseClients:   make(map[chan types.Event]struct{}),
		monitors:     make(map[string]*healthmon.Monitor),
		csrfToken:    generateCSRFToken(),
		reqLimiter:   newConcurrentLimiter(maxConcurrentReqs),
		auditLog:     make([]AuditEntry, 0, 1000),
	}

	// Initialize LB simulator if configured
	if len(config.LBPorts) > 0 {
		lbCfg := lbsim.Config{
			Port:         config.LBPort(),
			BackendPorts: config.LBPorts,
		}
		lb, err := lbsim.New(lbCfg)
		if err != nil {
			log.Printf("Warning: LB simulator failed to start: %v", err)
		} else {
			s.lbSimulator = lb
		}
	}

	s.setupRoutes()
	return s
}

// setupRoutes configures API routes.
func (s *Server) setupRoutes() {
	// API endpoints
	s.mux.HandleFunc("/api/health", s.handleHealth)
	s.mux.HandleFunc("/api/diagnose", s.handleDiagnose)
	s.mux.HandleFunc("/api/stream", s.handleStream)
	s.mux.HandleFunc("/api/dns", s.handleDNS)
	s.mux.HandleFunc("/api/dns/doh", s.handleDNSDoH)
	s.mux.HandleFunc("/api/tcp", s.handleTCP)
	s.mux.HandleFunc("/api/http", s.handleHTTP)
	s.mux.HandleFunc("/api/stress", s.handleStress)
	s.mux.HandleFunc("/api/simulator", s.handleSimulator)

	// LB simulator routes
	if s.lbSimulator != nil {
		s.lbSimulator.RegisterRoutes(s.mux)
		s.mux.HandleFunc("/api/lbsim", s.handleLBSim)
		s.mux.HandleFunc("/api/lbsim/kill", s.handleLBSimKill)
		s.mux.HandleFunc("/api/lbsim/revive", s.handleLBSimRevive)
	}

	// New diagnostic endpoints
	s.mux.HandleFunc("/api/portscan", s.handlePortScan)
	s.mux.HandleFunc("/api/tls", s.handleTLS)
	s.mux.HandleFunc("/api/benchmark", s.handleBenchmark)
	s.mux.HandleFunc("/api/traceroute", s.handleTraceroute)

	// Ping monitoring endpoints
	s.mux.HandleFunc("/api/ping", s.handlePing)
	s.mux.HandleFunc("/api/ping/stream", s.handlePingStream)

	// New power features
	s.mux.HandleFunc("/api/overview", s.handleOverview)
	s.mux.HandleFunc("/api/healthmon", s.handleHealthMon)
	s.mux.HandleFunc("/api/healthmon/start", s.handleHealthMonStart)
	s.mux.HandleFunc("/api/healthmon/stop", s.handleHealthMonStop)

	// New powerful features
	s.mux.HandleFunc("/api/packetflow", s.handlePacketFlow)
	s.mux.HandleFunc("/api/fingerprint", s.handleFingerprint)
	s.mux.HandleFunc("/api/diff", s.handleDiff)
	s.mux.HandleFunc("/api/baseline", s.handleBaseline)
	s.mux.HandleFunc("/api/correlation", s.handleCorrelation)
	s.mux.HandleFunc("/api/report", s.handleReport)
	s.mux.HandleFunc("/api/whois", s.handleWhois)
	s.mux.HandleFunc("/api/speedtest", s.handleSpeedTest)
	s.mux.HandleFunc("/api/dnsrace", s.handleDNSRace)
	s.mux.HandleFunc("/api/multiscan", s.handleMultiScan)

	// History and export endpoints
	s.mux.HandleFunc("/api/history", s.handleHistory)
	s.mux.HandleFunc("/api/history/stats", s.handleHistoryStats)
	s.mux.HandleFunc("/api/history/timeline", s.handleHistoryTimeline)
	s.mux.HandleFunc("/api/history/compare", s.handleHistoryCompare)
	s.mux.HandleFunc("/api/export", s.handleExport)
	s.mux.HandleFunc("/api/audit", s.handleAudit)
	s.mux.HandleFunc("/api/csrf-token", s.handleCSRFToken)

	// Static files — serve dashboard
	var fs http.Handler
	if s.config.WebFS != nil {
		fs = http.FileServer(s.config.WebFS)
	} else {
		fs = http.FileServer(http.Dir(s.config.WebDir))
	}
	s.mux.Handle("/", fs)
}

// Start starts the server.
func (s *Server) Start() error {
	// Start simulator
	if err := s.simulator.Start(); err != nil {
		log.Printf("Warning: simulator failed to start: %v", err)
	}

	// LB simulator runs on separate port, not managed by main server

	s.server = &http.Server{
		Addr:         s.config.Addr,
		Handler:      directoryTraversalProtection(inputLengthLimiter(securityHeaders(blockPrivateIPs(rateLimitMiddleware(newRateLimiter(120, time.Minute))(concurrentLimitMiddleware(s.reqLimiter)(corsMiddleware(auditMiddleware(s)(csrfProtected{token: s.csrfToken, next: hideServerVersion(contentTypeMiddleware(recoveryMiddleware(s.mux)))})))))))),
		ReadTimeout:  readTimeout,
		WriteTimeout: writeTimeout,
	}

	log.Printf("NetScope server starting on %s", s.config.Addr)
	log.Printf("Dashboard: http://%s", s.config.Addr)
	log.Printf("Simulator: %s", s.config.SimAddr)
	if s.lbSimulator != nil {
		log.Printf("LB Simulator: http://%s/lbsim/health?token=%s", s.config.Addr, s.lbSimulator.AdminToken())
	}

	return s.server.ListenAndServe()
}

// StartTLS starts the server with HTTPS using a self-signed certificate.
func (s *Server) StartTLS() error {
	// Start simulator
	if err := s.simulator.Start(); err != nil {
		log.Printf("Warning: simulator failed to start: %v", err)
	}

	// Generate self-signed certificate
	cert, err := generateSelfSignedCert()
	if err != nil {
		return fmt.Errorf("failed to generate TLS certificate: %w", err)
	}

	s.server = &http.Server{
		Addr:         s.config.Addr,
		Handler:      directoryTraversalProtection(inputLengthLimiter(securityHeaders(blockPrivateIPs(rateLimitMiddleware(newRateLimiter(120, time.Minute))(concurrentLimitMiddleware(s.reqLimiter)(corsMiddleware(auditMiddleware(s)(csrfProtected{token: s.csrfToken, next: hideServerVersion(contentTypeMiddleware(recoveryMiddleware(s.mux)))})))))))),
		ReadTimeout:  readTimeout,
		WriteTimeout: writeTimeout,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{*cert},
			MinVersion:   tls.VersionTLS12,
		},
	}

	log.Printf("NetScope server starting on HTTPS %s", s.config.Addr)
	log.Printf("Dashboard: https://%s", s.config.Addr)
	log.Printf("Simulator: %s", s.config.SimAddr)
	if s.lbSimulator != nil {
		log.Printf("LB Simulator: https://%s/lbsim/health?token=%s", s.config.Addr, s.lbSimulator.AdminToken())
	}

	return s.server.ListenAndServeTLS("", "")
}

// Stop gracefully stops the server.
func (s *Server) Stop() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s.simulator.Stop()
	s.server.Shutdown(ctx)
}

// Middleware

func recoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("Panic recovered: %v", rec)
				http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// securityHeaders adds standard security headers.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Content-Security-Policy", "default-src 'self' 'unsafe-inline'; img-src 'self' data:; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'")
		next.ServeHTTP(w, r)
	})
}

// rateLimiter provides simple in-memory per-IP rate limiting.
type rateLimiter struct {
	mu       sync.Mutex
	requests map[string][]time.Time
	limit    int
	window   time.Duration
}

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	return &rateLimiter{
		requests: make(map[string][]time.Time),
		limit:    limit,
		window:   window,
	}
}

func (rl *rateLimiter) allow(key string) bool {
	now := time.Now()
	rl.mu.Lock()
	defer rl.mu.Unlock()

	cutoff := now.Add(-rl.window)
	reqs := rl.requests[key]

	// Remove old entries
	valid := reqs[:0]
	for _, t := range reqs {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}
	if len(valid) >= rl.limit {
		return false
	}
	rl.requests[key] = append(valid, now)
	return true
}

func rateLimitMiddleware(limiter *rateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := r.RemoteAddr
			if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
				ip = strings.Split(fwd, ",")[0]
			}
			if !limiter.allow(ip) {
				w.Header().Set("Retry-After", "10")
				http.Error(w, `{"error":"rate limit exceeded, try again later"}`, http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// isPrivateIP checks if an IP is in a private/reserved range.
func isPrivateIP(host string) bool {
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	// Block private, loopback, link-local, and multicast
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified()
}

// blockPrivateIPs blocks requests targeting private/internal networks.
func blockPrivateIPs(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.URL.Query().Get("target")
		if host == "" {
			host = r.URL.Query().Get("host")
		}
		if host != "" && isPrivateIP(host) {
			writeError(w, http.StatusForbidden, "scanning private/internal networks is not allowed")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only allow same-origin (localhost) requests — no wildcard
		origin := r.Header.Get("Origin")
		if origin == "" || strings.Contains(origin, "localhost") || strings.Contains(origin, "127.0.0.1") {
			if origin == "" {
				origin = "*"
			}
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// --- Advanced Security: CSRF Protection ---

func generateCSRFToken() string {
	b := make([]byte, csrfTokenLength)
	if _, err := cryptoRand.Read(b); err != nil {
		// Fallback — not ideal but won't crash
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

type csrfProtected struct {
	token string
	next  http.Handler
}

func (c csrfProtected) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Only protect POST/PUT/DELETE
	if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodDelete {
		// Accept token from header or query param
		token := r.Header.Get("X-CSRF-Token")
		if token == "" {
			token = r.URL.Query().Get("csrf_token")
		}
		if token != c.token {
			writeError(w, http.StatusForbidden, "invalid or missing CSRF token")
			return
		}
	}
	c.next.ServeHTTP(w, r)
}

// --- Advanced Security: Concurrent Request Limiter ---

type concurrentLimiter struct {
	sem chan struct{}
}

func newConcurrentLimiter(max int) *concurrentLimiter {
	return &concurrentLimiter{sem: make(chan struct{}, max)}
}

func (cl *concurrentLimiter) acquire() bool {
	select {
	case cl.sem <- struct{}{}:
		return true
	default:
		return false
	}
}

func (cl *concurrentLimiter) release() {
	<-cl.sem
}

func concurrentLimitMiddleware(cl *concurrentLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !cl.acquire() {
				http.Error(w, `{"error":"server overloaded, too many concurrent requests"}`, http.StatusServiceUnavailable)
				return
			}
			defer cl.release()
			next.ServeHTTP(w, r)
		})
	}
}

// --- Advanced Security: Audit Logging ---

type AuditEntry struct {
	Timestamp time.Time `json:"timestamp"`
	IP        string    `json:"ip"`
	Method    string    `json:"method"`
	Path      string    `json:"path"`
	Status    int       `json:"status"`
	Duration  string    `json:"duration"`
	RequestID string    `json:"request_id"`
}

// Request ID generation
var reqIDCounter uint64

func generateRequestID() string {
	id := atomic.AddUint64(&reqIDCounter, 1)
	return fmt.Sprintf("%x-%x", time.Now().UnixNano(), id)
}

func auditMiddleware(s *Server) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			reqID := generateRequestID()
			w.Header().Set("X-Request-ID", reqID)
			w.Header().Set("Server", "NetScope") // Remove default Go server header

			// Wrap ResponseWriter to capture status code
			rec := &statusRecorder{ResponseWriter: w, status: 200}
			next.ServeHTTP(rec, r)

			// Log the request
			ip := r.RemoteAddr
			if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
				ip = strings.Split(fwd, ",")[0]
			}
			entry := AuditEntry{
				Timestamp: start,
				IP:        ip,
				Method:    r.Method,
				Path:      r.URL.Path,
				Status:    rec.status,
				Duration:  time.Since(start).String(),
				RequestID: reqID,
			}
			s.auditMu.Lock()
			if len(s.auditLog) >= 1000 {
				s.auditLog = s.auditLog[len(s.auditLog)-500:] // Keep last 500
			}
			s.auditLog = append(s.auditLog, entry)
			s.auditMu.Unlock()

			// Log errors and slow requests
			if rec.status >= 400 || time.Since(start) > 5*time.Second {
				log.Printf("[SECURITY] %s %s %d %s [%s] IP=%s", r.Method, r.URL.Path, rec.status, time.Since(start).String(), reqID, ip)
			}
		})
	}
}

type statusRecorder struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (sr *statusRecorder) WriteHeader(code int) {
	if !sr.wrote {
		sr.status = code
		sr.wrote = true
	}
	sr.ResponseWriter.WriteHeader(code)
}

func (sr *statusRecorder) Write(b []byte) (int, error) {
	if !sr.wrote {
		sr.wrote = true
	}
	return sr.ResponseWriter.Write(b)
}

// --- Advanced Security: Content-Type Enforcement ---

func contentTypeMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.Header.Get("Content-Type") == "" {
			// Allow form submissions for compatibility
			if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
				writeError(w, http.StatusBadRequest, "Content-Type header required for POST requests")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// --- Advanced Security: Server Version Masking ---

func hideServerVersion(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Remove headers that reveal server technology
		w.Header().Del("X-Powered-By")
		w.Header().Del("Server")
		w.Header().Set("Server", "NetScope")
		next.ServeHTTP(w, r)
	})
}

// --- Final Security: Directory Traversal Protection ---

func directoryTraversalProtection(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Block path traversal attempts in URL path
		path := r.URL.Path
		if strings.Contains(path, "..") || strings.Contains(path, "%2e%2e") || strings.Contains(path, "%2E%2E") {
			http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
			return
		}
		// Block null bytes
		if strings.Contains(path, "%00") || strings.Contains(path, "\x00") {
			http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// --- Final Security: Input Length Limiter ---

func inputLengthLimiter(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Limit total query string length to 2KB
		if len(r.URL.RawQuery) > 2048 {
			writeError(w, http.StatusBadRequest, "query string too long (max 2048 bytes)")
			return
		}
		// Limit individual parameter values to 512 bytes
		for key, values := range r.URL.Query() {
			for _, v := range values {
				if len(v) > 512 {
					writeError(w, http.StatusBadRequest, fmt.Sprintf("parameter '%s' value too long (max 512 bytes)", key))
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

// --- Final Security: Self-Signed TLS Certificate ---

func generateSelfSignedCert() (*tls.Certificate, error) {
	// Generate ECDSA P-256 private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), cryptoRand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	// Create certificate template
	serialNumber, err := cryptoRand.Int(cryptoRand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"NetScope"},
			CommonName:   "NetScope Self-Signed",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Self-sign the certificate
	certDER, err := x509.CreateCertificate(cryptoRand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, _ := x509.MarshalECPrivateKey(privateKey)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to create key pair: %w", err)
	}
	return &cert, nil
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func readBody(r *http.Request) (map[string]string, error) {
	if r.Body == nil {
		return nil, fmt.Errorf("empty request body")
	}
	defer r.Body.Close()

	limited := io.LimitReader(r.Body, maxRequestBody)
	var body map[string]string
	if err := json.NewDecoder(limited).Decode(&body); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	return body, nil
}

// API Handlers

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"status":   "healthy",
		"service":  "netscope",
		"version":  "1.0.0",
		"simulator": string(s.simulator.GetState().Mode),
	})
}

func (s *Server) handleDiagnose(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("target")
	if target == "" {
		writeError(w, http.StatusBadRequest, "missing 'target' query parameter")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
	defer cancel()

	result, err := s.orchestrator.DiagnoseTarget(ctx, target)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Record to history
	s.history.Add(result)

	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleStream(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("target")
	if target == "" {
		writeError(w, http.StatusBadRequest, "missing 'target' query parameter")
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming not supported")
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
	defer cancel()

	eventCh := make(chan types.Event, 20)
	done := make(chan struct{})

	go func() {
		defer close(done)
		s.orchestrator.DiagnoseTargetStream(ctx, target, func(e types.Event) {
			// Record completed diagnoses to history
			if e.Type == "complete" {
				if result, ok := e.Value.(*types.DiagnosticResult); ok {
					s.history.Add(result)
				}
			}
			select {
			case eventCh <- e:
			default:
			}
		})
	}()

	for {
		select {
		case <-done:
			// Drain remaining events
			for {
				select {
				case e := <-eventCh:
					data, _ := json.Marshal(e)
					fmt.Fprintf(w, "data: %s\n\n", data)
					flusher.Flush()
				default:
					return
				}
			}
		case e := <-eventCh:
			data, _ := json.Marshal(e)
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

func (s *Server) handleDNS(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	if host == "" {
		writeError(w, http.StatusBadRequest, "missing 'host' query parameter")
		return
	}

	host, err := validate.Host(host)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
	defer cancel()

	result := s.dnsEngine.Resolve(ctx, host)
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleDNSDoH(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	if host == "" {
		writeError(w, http.StatusBadRequest, "missing 'host' query parameter")
		return
	}

	host, err := validate.Host(host)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	provider := r.URL.Query().Get("provider")
	if provider == "" {
		provider = "cloudflare"
	}

	ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
	defer cancel()

	result := s.dnsEngine.ResolveDoH(ctx, host, provider)
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleTCP(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	portStr := r.URL.Query().Get("port")
	if host == "" || portStr == "" {
		writeError(w, http.StatusBadRequest, "missing 'host' and/or 'port' query parameters")
		return
	}

	host, err := validate.Host(host)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	port, err := validate.PortString(portStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
	defer cancel()

	result := s.tcpEngine.Test(ctx, host, port)
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleHTTP(w http.ResponseWriter, r *http.Request) {
	rawURL := r.URL.Query().Get("url")
	if rawURL == "" {
		writeError(w, http.StatusBadRequest, "missing 'url' query parameter")
		return
	}

	u, err := validate.URL(rawURL)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
	defer cancel()

	result := s.httpEngine.Diagnose(ctx, u.String())
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleStress(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	// Require explicit confirmation to prevent accidental DoS
	confirm := r.URL.Query().Get("confirm")
	if confirm != "yes" {
		writeError(w, http.StatusForbidden, "stress test requires ?confirm=yes parameter")
		return
	}

	body, err := readBody(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	host := body["host"]
	portStr := body["port"]
	connsStr := body["connections"]
	durationStr := body["duration"]

	if host == "" {
		writeError(w, http.StatusBadRequest, "missing 'host'")
		return
	}

	host, err = validate.Host(host)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	port, err := validate.PortString(portStr)
	if err != nil {
		port = 80 // default
	}

	conns := 10
	if connsStr != "" {
		conns, err = strconv.Atoi(connsStr)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid 'connections'")
			return
		}
	}
	if conns < 1 {
		conns = 1
	}
	if conns > maxStressConns {
		conns = maxStressConns
	}

	duration := 5 * time.Second
	if durationStr != "" {
		secs, err := strconv.Atoi(durationStr)
		if err == nil {
			duration = time.Duration(secs) * time.Second
		}
	}
	if duration > maxStressDuration {
		duration = maxStressDuration
	}

	ctx, cancel := context.WithTimeout(r.Context(), duration+10*time.Second)
	defer cancel()

	runner := concurrency.NewStressRunner(concurrency.StressConfig{
		Concurrency: conns,
		Duration:    duration,
	})

	result := runner.Run(ctx, func(ctx context.Context) (time.Duration, bool, bool) {
		start := time.Now()
		tcpResult := s.tcpEngine.Test(ctx, host, port)
		elapsed := time.Since(start)
		return elapsed, tcpResult.Connected, tcpResult.IsTimeout
	})

	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleLBSim(w http.ResponseWriter, r *http.Request) {
	if s.lbSimulator == nil {
		writeError(w, http.StatusServiceUnavailable, "LB simulator not configured")
		return
	}
	// This handler only matches /api/lbsim exactly.
	// Kill and revive are handled by separate route registrations.
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.lbSimulator.GetSnapshot())
}

func (s *Server) handleLBSimKill(w http.ResponseWriter, r *http.Request) {
	if s.lbSimulator == nil {
		writeError(w, http.StatusServiceUnavailable, "LB simulator not configured")
		return
	}
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	node := r.URL.Query().Get("node")
	if node == "" {
		writeError(w, http.StatusBadRequest, "missing 'node'")
		return
	}
	s.lbSimulator.Kill(node)
	writeJSON(w, http.StatusOK, map[string]string{"status": "killed", "node": node})
}

func (s *Server) handleLBSimRevive(w http.ResponseWriter, r *http.Request) {
	if s.lbSimulator == nil {
		writeError(w, http.StatusServiceUnavailable, "LB simulator not configured")
		return
	}
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	node := r.URL.Query().Get("node")
	if node == "" {
		writeError(w, http.StatusBadRequest, "missing 'node'")
		return
	}
	s.lbSimulator.Revive(node)
	writeJSON(w, http.StatusOK, map[string]string{"status": "revived", "node": node})
}

func (s *Server) handlePortScan(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	if host == "" {
		writeError(w, http.StatusBadRequest, "missing 'host' query parameter")
		return
	}

	host, err := validate.Host(host)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	portsStr := r.URL.Query().Get("ports")
	var ports []int
	if portsStr != "" {
		for _, p := range strings.Split(portsStr, ",") {
			p = strings.TrimSpace(p)
			var port int
			if _, err := fmt.Sscanf(p, "%d", &port); err == nil {
				ports = append(ports, port)
			}
		}
	}
	if len(ports) == 0 {
		ports = portscan.CommonPorts
	}

	scanner := portscan.New()
	result := scanner.Scan(r.Context(), portscan.ScanRequest{
		Host:  host,
		Ports: ports,
	})
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleTLS(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	if host == "" {
		writeError(w, http.StatusBadRequest, "missing 'host' query parameter")
		return
	}

	host, err := validate.Host(host)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	port := 443
	if p := r.URL.Query().Get("port"); p != "" {
		if _, err := fmt.Sscanf(p, "%d", &port); err != nil {
			port = 443
		}
	}

	result := tlsinspector.Inspect(host, port)
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleBenchmark(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	if host == "" {
		writeError(w, http.StatusBadRequest, "missing 'host' query parameter")
		return
	}

	host, err := validate.Host(host)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	port := 80
	if p := r.URL.Query().Get("port"); p != "" {
		if _, err := fmt.Sscanf(p, "%d", &port); err != nil {
			port = 80
		}
	}

	rounds := 20
	if r.URL.Query().Get("rounds") != "" {
		fmt.Sscanf(r.URL.Query().Get("rounds"), "%d", &rounds)
	}

	concurrency := 5
	if r.URL.Query().Get("concurrency") != "" {
		fmt.Sscanf(r.URL.Query().Get("concurrency"), "%d", &concurrency)
	}

	result := benchmark.Benchmark(host, port, rounds, concurrency)
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleSimulator(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.simulator.GetState())

	case http.MethodPost:
		body, err := readBody(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}

		state := types.SimulatorState{
			Mode:          body["mode"],
			LatencyMs:     0,
			HTTPErrorCode: 500,
		}

		if v, ok := body["latency_ms"]; ok {
			if n, err := strconv.Atoi(v); err == nil {
				state.LatencyMs = n
			}
		}
		if v, ok := body["http_error_code"]; ok {
			if n, err := strconv.Atoi(v); err == nil {
				state.HTTPErrorCode = n
			}
		}

		// Validate mode
		validModes := map[string]bool{
			"normal": true, "break_dns": true, "break_tcp": true,
			"break_http": true, "add_latency": true, "http_errors": true, "timeout": true,
		}
		if !validModes[state.Mode] {
			writeError(w, http.StatusBadRequest, "invalid mode. Valid: normal, break_dns, break_tcp, break_http, add_latency, http_errors, timeout")
			return
		}

		s.simulator.SetState(state)
		writeJSON(w, http.StatusOK, s.simulator.GetState())

	default:
		writeError(w, http.StatusMethodNotAllowed, "GET or POST required")
	}
}

// LBPort returns the port for the LB simulator (default 8080).
func (c Config) LBPort() int {
	if c.LBAddr != "" {
		var port int
		fmt.Sscanf(c.LBAddr, ":%d", &port)
		if port > 0 {
			return port
		}
	}
	return 8080
}

// --- New Feature Handlers ---

func (s *Server) handleTraceroute(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	if host == "" {
		writeError(w, http.StatusBadRequest, "missing 'host' query parameter")
		return
	}

	host, err := validate.Host(host)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	maxHops := 30
	if v := r.URL.Query().Get("max_hops"); v != "" {
		fmt.Sscanf(v, "%d", &maxHops)
	}

	probes := 3
	if v := r.URL.Query().Get("probes"); v != "" {
		fmt.Sscanf(v, "%d", &probes)
	}

	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()

	result := traceroute.Traceroute(ctx, host, maxHops, probes)
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handlePing(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	if host == "" {
		writeError(w, http.StatusBadRequest, "missing 'host' query parameter")
		return
	}

	host, err := validate.Host(host)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	port := 80
	if p := r.URL.Query().Get("port"); p != "" {
		fmt.Sscanf(p, "%d", &port)
	}

	count := 20
	if v := r.URL.Query().Get("count"); v != "" {
		fmt.Sscanf(v, "%d", &count)
	}
	if count > 200 {
		count = 200
	}
	if count < 1 {
		count = 1
	}

	interval := 1000
	if v := r.URL.Query().Get("interval"); v != "" {
		fmt.Sscanf(v, "%d", &interval)
	}
	if interval < 100 {
		interval = 100
	}

	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(count)*time.Duration(interval)*time.Millisecond+30*time.Second)
	defer cancel()

	cfg := ping.Config{
		Host:     host,
		Port:     port,
		Interval: time.Duration(interval) * time.Millisecond,
		Count:    count,
		Timeout:  2 * time.Second,
	}

	result := s.pingEngine.Monitor(ctx, cfg, nil)
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handlePingStream(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	if host == "" {
		writeError(w, http.StatusBadRequest, "missing 'host' query parameter")
		return
	}

	host, err := validate.Host(host)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	port := 80
	if p := r.URL.Query().Get("port"); p != "" {
		fmt.Sscanf(p, "%d", &port)
	}

	count := 60
	if v := r.URL.Query().Get("count"); v != "" {
		fmt.Sscanf(v, "%d", &count)
	}
	if count > 500 {
		count = 500
	}
	if count < 1 {
		count = 1
	}

	interval := 1000
	if v := r.URL.Query().Get("interval"); v != "" {
		fmt.Sscanf(v, "%d", &interval)
	}
	if interval < 200 {
		interval = 200
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming not supported")
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(count)*time.Duration(interval)*time.Millisecond+30*time.Second)
	defer cancel()

	cfg := ping.Config{
		Host:     host,
		Port:     port,
		Interval: time.Duration(interval) * time.Millisecond,
		Count:    count,
		Timeout:  2 * time.Second,
	}

	updates := make(chan ping.PingUpdate, 50)

	go func() {
		s.pingEngine.Monitor(ctx, cfg, updates)
		close(updates)
	}()

	for update := range updates {
		data, _ := json.Marshal(update)
		fmt.Fprintf(w, "data: %s\n\n", data)
		flusher.Flush()
	}
}

func (s *Server) handleHistory(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		limit := 20
		if v := r.URL.Query().Get("limit"); v != "" {
			fmt.Sscanf(v, "%d", &limit)
		}
		writeJSON(w, http.StatusOK, s.history.List(limit))
	case http.MethodPost:
		// Manually add an entry (used after diagnosis)
		var result types.DiagnosticResult
		if err := json.NewDecoder(io.LimitReader(r.Body, maxRequestBody)).Decode(&result); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON")
			return
		}
		entry := s.history.Add(&result)
		writeJSON(w, http.StatusOK, entry)
	default:
		writeError(w, http.StatusMethodNotAllowed, "GET or POST required")
	}
}

func (s *Server) handleHistoryStats(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.history.GetStats())
}

func (s *Server) handleHistoryTimeline(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.history.GetTimeline())
}

func (s *Server) handleHistoryCompare(w http.ResponseWriter, r *http.Request) {
	targets := r.URL.Query().Get("targets")
	if targets == "" {
		writeError(w, http.StatusBadRequest, "missing 'targets' query parameter (comma-separated)")
		return
	}
	var list []string
	for _, t := range strings.Split(targets, ",") {
		t = strings.TrimSpace(t)
		if t != "" {
			list = append(list, t)
		}
	}
	writeJSON(w, http.StatusOK, s.history.CompareTargets(list))
}

func (s *Server) handleExport(w http.ResponseWriter, r *http.Request) {
	// Export the most recent diagnosis as a downloadable JSON report
	limit := 1
	if v := r.URL.Query().Get("limit"); v != "" {
		fmt.Sscanf(v, "%d", &limit)
	}
	if limit > 50 {
		limit = 50
	}

	entries := s.history.List(limit)
	if len(entries) == 0 {
		writeError(w, http.StatusNotFound, "no diagnostic history to export")
		return
	}

	report := map[string]any{
		"tool":       "NetScope",
		"version":    "1.0.0",
		"exported_at": time.Now().Format(time.RFC3339),
		"entries":     entries,
		"stats":       s.history.GetStats(),
		"timeline":    s.history.GetTimeline(),
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=netscope-report-%s.json", time.Now().Format("20060102-150405")))
	json.NewEncoder(w).Encode(report)
}

// --- Power Feature Handlers ---

func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("target")
	if target == "" {
		writeError(w, http.StatusBadRequest, "missing 'target' query parameter")
		return
	}
	target, err := validate.Host(target)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	port := 443
	if p := r.URL.Query().Get("port"); p != "" {
		fmt.Sscanf(p, "%d", &port)
	}
	benchRounds := 5
	if v := r.URL.Query().Get("bench_rounds"); v != "" {
		fmt.Sscanf(v, "%d", &benchRounds)
	}
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	engine := overview.NewEngine()
	result := engine.Scan(ctx, target, port, benchRounds)
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleWhois(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		writeError(w, http.StatusBadRequest, "missing 'domain' query parameter")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	result := whois.Lookup(ctx, whois.ExtractRootDomain(domain))
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleSpeedTest(w http.ResponseWriter, r *http.Request) {
	url := r.URL.Query().Get("url")
	rounds := 5
	if v := r.URL.Query().Get("rounds"); v != "" {
		fmt.Sscanf(v, "%d", &rounds)
	}
	concurrency := 3
	if v := r.URL.Query().Get("concurrency"); v != "" {
		fmt.Sscanf(v, "%d", &concurrency)
	}
	ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
	defer cancel()
	result := speedtest.Test(ctx, url, rounds, concurrency)
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleDNSRace(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	if host == "" {
		writeError(w, http.StatusBadRequest, "missing 'host' query parameter")
		return
	}
	host, err := validate.Host(host)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	result := dnsrace.Race(ctx, host)
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleMultiScan(w http.ResponseWriter, r *http.Request) {
	hostsStr := r.URL.Query().Get("hosts")
	if hostsStr == "" {
		writeError(w, http.StatusBadRequest, "missing 'hosts' query parameter (comma-separated)")
		return
	}
	var hosts []string
	for _, h := range strings.Split(hostsStr, ",") {
		h = strings.TrimSpace(h)
		if h != "" {
			hosts = append(hosts, h)
		}
	}
	if len(hosts) == 0 {
		writeError(w, http.StatusBadRequest, "no valid hosts provided")
		return
	}
	if len(hosts) > 20 {
		writeError(w, http.StatusBadRequest, "maximum 20 hosts per scan")
		return
	}
	port := 80
	if p := r.URL.Query().Get("port"); p != "" {
		fmt.Sscanf(p, "%d", &port)
	}
	ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
	defer cancel()
	result := multiscan.Scan(ctx, hosts, port, 5)
	writeJSON(w, http.StatusOK, result)
}

// --- Health Monitoring Handlers ---

func (s *Server) handleHealthMonStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	body, err := readBody(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	host := body["host"]
	if host == "" {
		writeError(w, http.StatusBadRequest, "missing 'host'")
		return
	}
	host, err = validate.Host(host)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	port := 80
	if v, ok := body["port"]; ok && v != "" {
		fmt.Sscanf(v, "%d", &port)
	}
	intervalMs := 1000
	if v, ok := body["interval_ms"]; ok && v != "" {
		fmt.Sscanf(v, "%d", &intervalMs)
	}
	if intervalMs < 200 {
		intervalMs = 200
	}
	spikeThresholdMs := 500.0
	if v, ok := body["spike_threshold_ms"]; ok && v != "" {
		fmt.Sscanf(v, "%f", &spikeThresholdMs)
	}

	// Stop existing monitor for this host if any
	key := fmt.Sprintf("%s:%d", host, port)
	s.monitorsMu.Lock()
	if old, ok := s.monitors[key]; ok {
		old.Stop()
	}
	mon := healthmon.NewMonitor(healthmon.MonitorConfig{
		Host:             host,
		Port:             port,
		Interval:         time.Duration(intervalMs) * time.Millisecond,
		Timeout:          2 * time.Second,
		SpikeThresholdMs: spikeThresholdMs,
		SpikePercentile:  2.5,
		WindowSize:       30,
	})
	s.monitors[key] = mon
	s.monitorsMu.Unlock()

	mon.Start()
	writeJSON(w, http.StatusOK, mon.Snapshot())
}

func (s *Server) handleHealthMonStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	body, err := readBody(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	host := body["host"]
	port := 80
	if v, ok := body["port"]; ok && v != "" {
		fmt.Sscanf(v, "%d", &port)
	}
	key := fmt.Sprintf("%s:%d", host, port)
	s.monitorsMu.Lock()
	if mon, ok := s.monitors[key]; ok {
		mon.Stop()
	}
	s.monitorsMu.Unlock()
	writeJSON(w, http.StatusOK, map[string]string{"status": "stopped"})
}

func (s *Server) handleHealthMon(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	port := 80
	if v := r.URL.Query().Get("port"); v != "" {
		fmt.Sscanf(v, "%d", &port)
	}
	if host == "" {
		// Return all monitors
		s.monitorsMu.Lock()
		all := make(map[string]*healthmon.MonitorSnapshot)
		for k, m := range s.monitors {
			snap := m.Snapshot()
			if snap != nil {
				all[k] = snap
			}
		}
		s.monitorsMu.Unlock()
		writeJSON(w, http.StatusOK, all)
		return
	}
	key := fmt.Sprintf("%s:%d", host, port)
	s.monitorsMu.Lock()
	mon, ok := s.monitors[key]
	s.monitorsMu.Unlock()
	if !ok {
		writeError(w, http.StatusNotFound, "no monitor for "+key)
		return
	}
	writeJSON(w, http.StatusOK, mon.Snapshot())
}

// --- Feature 1: Packet Flow ---

func (s *Server) handlePacketFlow(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("target")
	if target == "" {
		writeError(w, http.StatusBadRequest, "missing 'target' query parameter")
		return
	}
	target, err := validate.Host(target)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	port := 443
	if p := r.URL.Query().Get("port"); p != "" {
		fmt.Sscanf(p, "%d", &port)
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	result := packetflow.Trace(ctx, target, port)
	writeJSON(w, http.StatusOK, result)
}

// --- Feature 2: Network Fingerprint ---

func (s *Server) handleFingerprint(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("target")
	if target == "" {
		writeError(w, http.StatusBadRequest, "missing 'target' query parameter")
		return
	}
	target, err := validate.Host(target)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	result := fingerprint.Fingerprint(ctx, target)
	writeJSON(w, http.StatusOK, result)
}

// --- Feature 3: Diagnostic Diff ---

func (s *Server) handleBaseline(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	body, err := readBody(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	target := body["target"]
	if target == "" {
		writeError(w, http.StatusBadRequest, "missing 'target'")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	result, dErr := s.orchestrator.DiagnoseTarget(ctx, target)
	if dErr != nil {
		writeError(w, http.StatusBadRequest, dErr.Error())
		return
	}
	s.history.SetBaseline(target, result)
	writeJSON(w, http.StatusOK, map[string]string{"status": "baseline_set", "target": target})
}

func (s *Server) handleDiff(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("target")
	if target == "" {
		writeError(w, http.StatusBadRequest, "missing 'target' query parameter")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	result, err := s.orchestrator.DiagnoseTarget(ctx, target)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	diff := s.history.Diff(target, result)
	writeJSON(w, http.StatusOK, diff)
}

// --- Feature 4: Correlation ---

func (s *Server) handleCorrelation(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("target")
	if target == "" {
		writeError(w, http.StatusBadRequest, "missing 'target' query parameter")
		return
	}
	target, err := validate.Host(target)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	result, dErr := s.orchestrator.DiagnoseTarget(ctx, target)
	if dErr != nil {
		writeError(w, http.StatusBadRequest, dErr.Error())
		return
	}
	s.history.Add(result)
	engine := diagnostics.NewEngine()
	correlation := engine.AnalyzeCorrelation(result)
	rootCause := engine.Analyze(result)
	writeJSON(w, http.StatusOK, map[string]any{
		"correlation": correlation,
		"root_cause":  rootCause,
		"result":      result,
	})
}

// --- Feature 5: Executive Report ---

func (s *Server) handleReport(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("target")
	if target == "" {
		writeError(w, http.StatusBadRequest, "missing 'target' query parameter")
		return
	}
	target, err := validate.Host(target)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	result, dErr := s.orchestrator.DiagnoseTarget(ctx, target)
	if dErr != nil {
		writeError(w, http.StatusBadRequest, dErr.Error())
		return
	}
	s.history.Add(result)
	htmlReport := report.Generate(result)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=netscope-report-%s.html", target))
		fmt.Fprint(w, htmlReport)
}

// --- Security Endpoints ---

// handleAudit returns the last N audit log entries.
func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		fmt.Sscanf(v, "%d", &limit)
	}
	if limit > 500 {
		limit = 500
	}
	s.auditMu.Lock()
	total := len(s.auditLog)
	start := total - limit
	if start < 0 {
		start = 0
	}
	entries := make([]AuditEntry, total-start)
	copy(entries, s.auditLog[start:])
	s.auditMu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"total":   total,
		"entries": entries,
	})
}

// handleCSRFToken returns the current CSRF token (for frontend use).
func (s *Server) handleCSRFToken(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"token": s.csrfToken,
	})
}
