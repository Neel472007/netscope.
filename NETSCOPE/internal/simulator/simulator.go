// Package simulator provides a local failure simulator for NetScope demos.
package simulator

import (
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/Neel472007/netscope/internal/types"
)

// Mode represents a simulator failure mode.
type Mode string

const (
	ModeNormal      Mode = "normal"
	ModeBreakDNS    Mode = "break_dns"
	ModeBreakTCP    Mode = "break_tcp"
	ModeBreakHTTP   Mode = "break_http"
	ModeAddLatency  Mode = "add_latency"
	ModeHTTPErrors  Mode = "http_errors"
	ModeTimeout     Mode = "timeout"
)

// Server is the local failure simulator HTTP server.
type Server struct {
	mu         sync.RWMutex
	mode       Mode
	latencyMs  int
	errorCode  int
	httpServer *http.Server
	addr       string
}

// NewServer creates a new simulator server.
func NewServer(addr string) *Server {
	return &Server{
		mode:      ModeNormal,
		latencyMs: 0,
		errorCode: 500,
		addr:      addr,
	}
}

// GetState returns the current simulator state.
func (s *Server) GetState() types.SimulatorState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return types.SimulatorState{
		Mode:          string(s.mode),
		LatencyMs:     s.latencyMs,
		HTTPErrorCode: s.errorCode,
	}
}

// SetMode changes the simulator mode.
func (s *Server) SetMode(mode Mode) {
	s.mu.Lock()
	s.mode = mode
	s.mu.Unlock()
}

// SetState sets the full simulator state.
func (s *Server) SetState(state types.SimulatorState) {
	s.mu.Lock()
	s.mode = Mode(state.Mode)
	s.latencyMs = state.LatencyMs
	s.errorCode = state.HTTPErrorCode
	if s.errorCode == 0 {
		s.errorCode = 500
	}
	s.mu.Unlock()
}

// ServeHTTP handles simulator requests.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	mode := s.mode
	latencyMs := s.latencyMs
	errorCode := s.errorCode
	s.mu.RUnlock()

	switch mode {
	case ModeNormal:
		s.handleNormal(w, r)

	case ModeBreakDNS:
		// Simulate DNS failure — we can't actually break DNS from a server,
		// but we can return an error indicating what would happen
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprintf(w, `{"error":"simulated DNS failure","mode":"break_dns","message":"In a real scenario, DNS resolution for this host would fail."}`)

	case ModeBreakTCP:
		// Simulate TCP failure — connection would be refused/dropped
		hj, ok := w.(http.Hijacker)
		if ok {
			conn, _, err := hj.Hijack()
			if err == nil {
				conn.Close()
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprintf(w, `{"error":"simulated TCP failure","mode":"break_tcp"}`)

	case ModeBreakHTTP:
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `{"error":"simulated HTTP failure","mode":"break_http","message":"The server is returning an internal error."}`)

	case ModeAddLatency:
		time.Sleep(time.Duration(latencyMs) * time.Millisecond)
		s.handleNormal(w, r)

	case ModeHTTPErrors:
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(errorCode)
		fmt.Fprintf(w, `{"error":"simulated error","mode":"http_errors","code":%d}`, errorCode)

	case ModeTimeout:
		// Sleep longer than any reasonable client timeout
		time.Sleep(60 * time.Second)
		s.handleNormal(w, r)

	default:
		s.handleNormal(w, r)
	}
}

func (s *Server) handleNormal(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-NetScope-Simulator", "true")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"status":"ok","message":"Simulator is healthy","mode":"normal","timestamp":"%s"}`, time.Now().Format(time.RFC3339))
}

// Start starts the simulator server.
func (s *Server) Start() error {
	s.httpServer = &http.Server{
		Addr:    s.addr,
		Handler: s,
	}
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("simulator listen: %w", err)
	}
	go s.httpServer.Serve(ln)
	return nil
}

// Stop gracefully stops the simulator server.
func (s *Server) Stop() {
	if s.httpServer != nil {
		s.httpServer.Close()
	}
}

// GetAddr returns the actual listening address.
func (s *Server) GetAddr() string {
	return s.addr
}
