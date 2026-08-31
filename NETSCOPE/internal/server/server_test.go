package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Neel472007/netscope/internal/types"
)

func newTestServer(t *testing.T) *Server {
	t.Helper()
	config := Config{
		Addr:     ":0",
		WebDir:   "../../web",
		SimAddr:  ":0",
		LBAddr:   "0",
		LBPorts:  nil,
	}
	return NewServer(config)
}

func TestHandleHealth(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest("GET", "/api/health", nil)
	w := httptest.NewRecorder()
	s.handleHealth(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp["status"] != "healthy" {
		t.Errorf("expected status=healthy, got %s", resp["status"])
	}
	if resp["service"] != "netscope" {
		t.Errorf("expected service=netscope, got %s", resp["service"])
	}
}

func TestHandleDiagnoseMissingTarget(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest("GET", "/api/diagnose", nil)
	w := httptest.NewRecorder()
	s.handleDiagnose(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestHandleDNSMissingHost(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest("GET", "/api/dns", nil)
	w := httptest.NewRecorder()
	s.handleDNS(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestHandleTCPMissingParams(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest("GET", "/api/tcp", nil)
	w := httptest.NewRecorder()
	s.handleTCP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestHandleHTTPMissingURL(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest("GET", "/api/http", nil)
	w := httptest.NewRecorder()
	s.handleHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestHandleStressMethodNotAllowed(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest("GET", "/api/stress", nil)
	w := httptest.NewRecorder()
	s.handleStress(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

func TestHandleSimulatorGet(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest("GET", "/api/simulator", nil)
	w := httptest.NewRecorder()
	s.handleSimulator(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var state types.SimulatorState
	if err := json.NewDecoder(w.Body).Decode(&state); err != nil {
		t.Fatal(err)
	}
}

func TestHandleHistoryEmpty(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest("GET", "/api/history?limit=5", nil)
	w := httptest.NewRecorder()
	s.handleHistory(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestHandleHistoryStats(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest("GET", "/api/history/stats", nil)
	w := httptest.NewRecorder()
	s.handleHistoryStats(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestHandleExportEmpty(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest("GET", "/api/export", nil)
	w := httptest.NewRecorder()
	s.handleExport(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for empty export, got %d", w.Code)
	}
}

func TestHandlePortScanMissingHost(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest("GET", "/api/portscan", nil)
	w := httptest.NewRecorder()
	s.handlePortScan(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestHandleTLSMissingHost(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest("GET", "/api/tls", nil)
	w := httptest.NewRecorder()
	s.handleTLS(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestHandleBenchmarkMissingHost(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest("GET", "/api/benchmark", nil)
	w := httptest.NewRecorder()
	s.handleBenchmark(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestHandleTracerouteMissingHost(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest("GET", "/api/traceroute", nil)
	w := httptest.NewRecorder()
	s.handleTraceroute(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestHandlePingMissingHost(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest("GET", "/api/ping", nil)
	w := httptest.NewRecorder()
	s.handlePing(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestHandlePingStreamMissingHost(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest("GET", "/api/ping/stream", nil)
	w := httptest.NewRecorder()
	s.handlePingStream(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestHandleLBSimNotConfigured(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest("GET", "/api/lbsim", nil)
	w := httptest.NewRecorder()
	s.handleLBSim(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", w.Code)
	}
}

func TestHandleHistoryCompareMissingTargets(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest("GET", "/api/history/compare", nil)
	w := httptest.NewRecorder()
	s.handleHistoryCompare(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestWriteJSON(t *testing.T) {
	w := httptest.NewRecorder()
	writeJSON(w, http.StatusOK, map[string]string{"test": "value"})

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected application/json, got %s", ct)
	}
}

func TestWriteError(t *testing.T) {
	w := httptest.NewRecorder()
	writeError(w, http.StatusBadRequest, "test error")

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}

	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp["error"] != "test error" {
		t.Errorf("expected error=test error, got %s", resp["error"])
	}
}

func TestLBPort(t *testing.T) {
	config := Config{LBAddr: ":9090"}
	if config.LBPort() != 9090 {
		t.Errorf("expected 9090, got %d", config.LBPort())
	}

	config2 := Config{}
	if config2.LBPort() != 8080 {
		t.Errorf("expected 8080, got %d", config2.LBPort())
	}
}

func TestCORSHeaders(t *testing.T) {
	handler := corsMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("OPTIONS", "/api/health", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Error("expected CORS allow-origin header")
	}
}
