// Package lbsim provides a load balancer simulator for realistic NetScope diagnostics.
// It runs mock backend services, performs real health checks via TCP dial,
// and provides a reverse proxy with failover — all using the Go standard library.
package lbsim

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"sync/atomic"
	"time"
)

// --- Types ---

// Backend represents a single backend service behind the load balancer.
type Backend struct {
	URL          *url.URL
	ReverseProxy *httputil.ReverseProxy
	mux          sync.RWMutex
	healthAlive  bool
	forcedDown   bool
	RequestCount int64
}

// IsAlive returns true if the backend is healthy and not manually disabled.
func (b *Backend) IsAlive() bool {
	b.mux.RLock()
	defer b.mux.RUnlock()
	return b.healthAlive && !b.forcedDown
}

// SetHealth updates the health status of a backend.
func (b *Backend) SetHealth(alive bool) {
	b.mux.Lock()
	defer b.mux.Unlock()
	b.healthAlive = alive
}

// GetForcedDown returns the forced-down status.
func (b *Backend) GetForcedDown() bool {
	b.mux.RLock()
	defer b.mux.RUnlock()
	return b.forcedDown
}

// SetForcedDown manually sets the forced-down status.
func (b *Backend) SetForcedDown(down bool) {
	b.mux.Lock()
	defer b.mux.Unlock()
	b.forcedDown = down
}

// ServerPool manages a set of backends with round-robin selection.
type ServerPool struct {
	backends []*Backend
	current  uint64
}

// GetNext returns the next alive backend using round-robin.
func (s *ServerPool) GetNext() *Backend {
	l := len(s.backends)
	if l == 0 {
		return nil
	}
	n := atomic.AddUint64(&s.current, 1)
	for i := 0; i < l; i++ {
		b := s.backends[int(n+uint64(i))%l]
		if b.IsAlive() {
			return b
		}
	}
	return nil
}

// Snapshot is the JSON-serializable status of the entire load balancer.
type Snapshot struct {
	TotalRequests  uint64         `json:"total_requests"`
	ActiveClients  int64          `json:"active_clients"`
	FailedRequests uint64         `json:"failed_requests"`
	UptimeSeconds  float64        `json:"uptime_seconds"`
	SecurityLevel  string         `json:"security_level"`
	Notifications  []string       `json:"notifications"`
	Backends       []BackendInfo  `json:"backends"`
}

// BackendInfo is the JSON-serializable status of a single backend.
type BackendInfo struct {
	Host       string `json:"host"`
	Alive      bool   `json:"alive"`
	ForcedDown bool   `json:"forced_down"`
	Reqs       int64  `json:"reqs"`
}

// --- Load Balancer ---

// LoadBalancer is the main load balancer simulator.
type LoadBalancer struct {
	pool            *ServerPool
	startTime       time.Time
	totalRequests   uint64
	activeClients   int64
	failedRequests  uint64
	securityLevel   string
	securityMu      sync.RWMutex
	notifications   []string
	notificationsMu sync.Mutex
	adminToken      string
	port            int
}

// Config holds configuration for the load balancer.
type Config struct {
	Port         int    // HTTP port for the load balancer
	BackendPorts []int // Ports for mock backend services
}

// DefaultConfig returns a reasonable default configuration.
func DefaultConfig() Config {
	return Config{
		Port:         8080,
		BackendPorts: []int{8081, 8082, 8083},
	}
}

// New creates a new LoadBalancer with the given configuration.
func New(cfg Config) (*LoadBalancer, error) {
	// Generate admin token
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("generating admin token: %w", err)
	}
	adminToken := hex.EncodeToString(b)

	lb := &LoadBalancer{
		pool:          &ServerPool{},
		startTime:     time.Now(),
		securityLevel: "SECURE",
		adminToken:    adminToken,
		port:          cfg.Port,
	}

	lb.addNotification("System: Load Balancer Simulator Active")

	// Start mock backend services
	for _, port := range cfg.BackendPorts {
		ps := fmt.Sprintf("%d", port)
		go func() {
			mux := http.NewServeMux()
			mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/plain")
				fmt.Fprintf(w, "Node %s OK\nServed by: %s\nTime: %s",
					ps, r.Host, time.Now().Format("15:04:05.000"))
			})
			if err := http.ListenAndServe(":"+ps, mux); err != nil {
				lb.addNotification(fmt.Sprintf("Warning: Backend %s failed to start: %v", ps, err))
			}
		}()
	}

	// Create backend pool with reverse proxies
	for _, port := range cfg.BackendPorts {
		host := fmt.Sprintf("localhost:%d", port)
		rawURL := fmt.Sprintf("http://%s", host)
		u, err := url.Parse(rawURL)
		if err != nil {
			return nil, fmt.Errorf("parsing backend URL %s: %w", rawURL, err)
		}
		b := &Backend{URL: u, healthAlive: true}
		b.ReverseProxy = &httputil.ReverseProxy{
			Rewrite: func(pr *httputil.ProxyRequest) {
				pr.SetURL(u)
				pr.SetXForwarded()
				atomic.AddInt64(&b.RequestCount, 1)
				atomic.AddUint64(&lb.totalRequests, 1)
			},
		}
		lb.pool.backends = append(lb.pool.backends, b)
	}

	// Background traffic generator (simulates real load)
	go lb.trafficGenerator()

	// Health monitor (real TCP health checks)
	go lb.healthMonitor()

	return lb, nil
}

func (lb *LoadBalancer) addNotification(msg string) {
	lb.notificationsMu.Lock()
	defer lb.notificationsMu.Unlock()
	timestamp := time.Now().Format("15:04:05")
	lb.notifications = append([]string{"[" + timestamp + "] " + msg}, lb.notifications...)
	if len(lb.notifications) > 12 {
		lb.notifications = lb.notifications[:12]
	}
}

func (lb *LoadBalancer) trafficGenerator() {
	for {
		// Simulate variable traffic patterns
		atomic.AddUint64(&lb.totalRequests, uint64(time.Now().UnixNano()%3+1))
		atomic.StoreInt64(&lb.activeClients, int64(time.Now().UnixNano()%10+5))

		// Occasional random failure
		if time.Now().UnixNano()%30 == 0 {
			atomic.AddUint64(&lb.failedRequests, 1)
		}

		// Route traffic to random backend
		backends := lb.pool.backends
		if len(backends) > 0 {
			idx := time.Now().UnixNano() % int64(len(backends))
			atomic.AddInt64(&backends[idx].RequestCount, 1)
		}

		time.Sleep(500 * time.Millisecond)
	}
}

func (lb *LoadBalancer) healthMonitor() {
	for {
		allAlive := true
		for _, b := range lb.pool.backends {
			conn, err := net.DialTimeout("tcp", b.URL.Host, 2*time.Second)
			alive := err == nil
			if conn != nil {
				conn.Close()
			}
			b.SetHealth(alive)
			if !alive {
				allAlive = false
			}
		}
		lb.securityMu.Lock()
		if allAlive {
			lb.securityLevel = "SECURE"
		} else {
			lb.securityLevel = "MONITORING"
		}
		lb.securityMu.Unlock()
		time.Sleep(3 * time.Second)
	}
}

// GetSnapshot returns the current state of the load balancer.
func (lb *LoadBalancer) GetSnapshot() Snapshot {
	lb.notificationsMu.Lock()
	defer lb.notificationsMu.Unlock()

	var backends []BackendInfo
	for _, b := range lb.pool.backends {
		backends = append(backends, BackendInfo{
			Host:       b.URL.Host,
			Alive:      b.IsAlive(),
			ForcedDown: b.GetForcedDown(),
			Reqs:       atomic.LoadInt64(&b.RequestCount),
		})
	}

	lb.securityMu.RLock()
	secLevel := lb.securityLevel
	lb.securityMu.RUnlock()

	return Snapshot{
		TotalRequests:  atomic.LoadUint64(&lb.totalRequests),
		ActiveClients:  atomic.LoadInt64(&lb.activeClients),
		FailedRequests: atomic.LoadUint64(&lb.failedRequests),
		UptimeSeconds:  time.Since(lb.startTime).Seconds(),
		SecurityLevel:  secLevel,
		Notifications:  lb.notifications,
		Backends:       backends,
	}
}

// Auth checks if the request has a valid admin token.
func (lb *LoadBalancer) Auth(r *http.Request) bool {
	return r.URL.Query().Get("token") == lb.adminToken
}

// Kill forces a backend offline.
func (lb *LoadBalancer) Kill(host string) {
	for _, b := range lb.pool.backends {
		if b.URL.Host == host {
			b.SetForcedDown(true)
			lb.addNotification(fmt.Sprintf("Alert: Admin manual isolation of %s", host))
			return
		}
	}
}

// Revive restores a backend to service.
func (lb *LoadBalancer) Revive(host string) {
	for _, b := range lb.pool.backends {
		if b.URL.Host == host {
			b.SetForcedDown(false)
			lb.addNotification(fmt.Sprintf("System: Node %s restored", host))
			return
		}
	}
}

// AdminToken returns the admin token for API access.
func (lb *LoadBalancer) AdminToken() string {
	return lb.adminToken
}

// Port returns the port the load balancer listens on.
func (lb *LoadBalancer) Port() int {
	return lb.port
}

// ServeHTTP implements the load balancer's main request handler.
func (lb *LoadBalancer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	atomic.AddInt64(&lb.activeClients, 1)
	defer atomic.AddInt64(&lb.activeClients, -1)

	if peer := lb.pool.GetNext(); peer != nil {
		peer.ReverseProxy.ServeHTTP(w, r)
	} else {
		http.Error(w, "Service Unavailable: all backends are down", http.StatusServiceUnavailable)
		atomic.AddUint64(&lb.failedRequests, 1)
	}
}

// RegisterRoutes registers the load balancer's HTTP routes on the given mux.
func (lb *LoadBalancer) RegisterRoutes(mux *http.ServeMux) {
	// Health/status endpoint
	mux.HandleFunc("/lbsim/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(lb.GetSnapshot())
	})

	// Admin: kill a backend
	mux.HandleFunc("/lbsim/kill", func(w http.ResponseWriter, r *http.Request) {
		if !lb.Auth(r) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		node := r.URL.Query().Get("node")
		if node == "" {
			http.Error(w, "Missing 'node' parameter", http.StatusBadRequest)
			return
		}
		lb.Kill(node)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok", "action": "killed", "node": node})
	})

	// Admin: revive a backend
	mux.HandleFunc("/lbsim/revive", func(w http.ResponseWriter, r *http.Request) {
		if !lb.Auth(r) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		node := r.URL.Query().Get("node")
		if node == "" {
			http.Error(w, "Missing 'node' parameter", http.StatusBadRequest)
			return
		}
		lb.Revive(node)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok", "action": "revived", "node": node})
	})

	// Reverse proxy root — forwards traffic to backends
	mux.Handle("/lb/", lb)
}

// Start runs the load balancer as a standalone server (blocking).
func (lb *LoadBalancer) Start() error {
	mux := http.NewServeMux()
	lb.RegisterRoutes(mux)

	fmt.Printf("\n")
	fmt.Printf("\033[32m  ⚖️  Load Balancer Simulator: http://localhost:%d/lbsim/health?token=%s\033[0m\n", lb.port, lb.adminToken)
	fmt.Printf("\033[33m  📊 Admin token: %s\033[0m\n", lb.adminToken)
	fmt.Printf("\033[36m  🌐 Proxy endpoint: http://localhost:%d/lb/\033[0m\n", lb.port)
	fmt.Printf("\n")

	return http.ListenAndServe(fmt.Sprintf(":%d", lb.port), mux)
}
