package simulator

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Neel472007/netscope/internal/types"
)

func TestSimulatorNormal(t *testing.T) {
	srv := NewServer(":0")
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestSimulatorBreakHTTP(t *testing.T) {
	srv := NewServer(":0")
	srv.SetMode(ModeBreakHTTP)

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

func TestSimulatorBreakTCP(t *testing.T) {
	srv := NewServer(":0")
	srv.SetMode(ModeBreakTCP)

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)

	// Connection should be terminated — status may be 503 or 0 (connection closed)
	if w.Code == http.StatusOK {
		t.Error("expected non-OK status for TCP break mode")
	}
}

func TestSimulatorBreakDNS(t *testing.T) {
	srv := NewServer(":0")
	srv.SetMode(ModeBreakDNS)

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", w.Code)
	}
}

func TestSimulatorHTTPErrors(t *testing.T) {
	srv := NewServer(":0")
	srv.SetState(types.SimulatorState{
		Mode:          "http_errors",
		HTTPErrorCode: 418,
	})

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)

	if w.Code != 418 {
		t.Errorf("expected 418, got %d", w.Code)
	}
}

func TestSimulatorGetState(t *testing.T) {
	srv := NewServer(":0")
	state := srv.GetState()

	if state.Mode != "normal" {
		t.Errorf("expected 'normal' mode, got '%s'", state.Mode)
	}
}

func TestSimulatorSetMode(t *testing.T) {
	srv := NewServer(":0")
	srv.SetMode(ModeBreakDNS)

	state := srv.GetState()
	if state.Mode != "break_dns" {
		t.Errorf("expected 'break_dns' mode, got '%s'", state.Mode)
	}
}

func TestSimulatorSetState(t *testing.T) {
	srv := NewServer(":0")
	srv.SetState(types.SimulatorState{
		Mode:          "add_latency",
		LatencyMs:     2000,
		HTTPErrorCode: 500,
	})

	state := srv.GetState()
	if state.Mode != "add_latency" {
		t.Errorf("expected 'add_latency', got '%s'", state.Mode)
	}
	if state.LatencyMs != 2000 {
		t.Errorf("expected latency 2000ms, got %d", state.LatencyMs)
	}
}

func TestSimulatorStartStop(t *testing.T) {
	srv := NewServer(":0")
	err := srv.Start()
	if err != nil {
		t.Fatalf("failed to start simulator: %v", err)
	}
	srv.Stop()
}
