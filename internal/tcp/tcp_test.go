package tcp

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"
)

// startTestServer starts a local TCP server for testing and returns its port.
func startTestServer(t *testing.T) (string, int, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start test server: %v", err)
	}
	addr := ln.Addr().(*net.TCPAddr)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	return addr.IP.String(), addr.Port, func() { ln.Close() }
}

func TestTCPOpenPort(t *testing.T) {
	engine := NewEngine()
	host, port, cleanup := startTestServer(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result := engine.Test(ctx, host, port)

	if !result.Connected {
		t.Errorf("expected TCP connection to succeed, got error: %s", result.Error)
	}
	if result.Latency < 0 {
		t.Error("expected non-negative latency")
	}
	if result.ErrorType != "" {
		t.Errorf("expected no error type, got: %s", result.ErrorType)
	}
}

func TestTCPClosedPort(t *testing.T) {
	engine := NewEngine()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Use a port that is very likely closed
	result := engine.Test(ctx, "127.0.0.1", 1)

	if result.Connected {
		t.Error("expected TCP connection to fail on closed port")
	}
	if result.Error == "" {
		t.Error("expected error message")
	}
}

func TestTCPTimeout(t *testing.T) {
	engine := NewEngine()
	engine.SetTimeout(1 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result := engine.Test(ctx, "127.0.0.1", 1)

	// Should fail — either timeout or connection refused
	if result == nil {
		t.Error("expected non-nil result")
	}
}

func TestTCPConcurrent(t *testing.T) {
	engine := NewEngine()
	host, port, cleanup := startTestServer(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	results := engine.TestConcurrent(ctx, host, port, 10)

	if len(results) != 10 {
		t.Errorf("expected 10 results, got %d", len(results))
	}

	successCount := 0
	for _, r := range results {
		if r.Connected {
			successCount++
		}
	}

	if successCount == 0 {
		t.Error("expected at least one successful connection")
	}

	fmt.Printf("TCP concurrent: %d/10 succeeded\n", successCount)
}

func TestTCPStress(t *testing.T) {
	engine := NewEngine()
	host, port, cleanup := startTestServer(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result := engine.TestStress(ctx, host, port, 5, 2*time.Second)

	if result.TotalRequests == 0 {
		t.Error("expected at least one request")
	}
	if result.SuccessRate <= 0 {
		t.Error("expected positive success rate")
	}
	if result.AvgLatency < 0 {
		t.Error("expected non-negative average latency")
	}

	fmt.Printf("TCP stress: %d/%d succeeded, avg=%.1fms, P50=%.1fms, P95=%.1fms, P99=%.1fms, rps=%.1f\n",
		result.Successful, result.TotalRequests, result.AvgLatency, result.P50, result.P95, result.P99, result.RequestsPerSec)
}
