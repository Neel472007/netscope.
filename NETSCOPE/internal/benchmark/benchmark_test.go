package benchmark

import (
	"net"
	"testing"
	"time"
)

func TestBenchmarkLocalhost(t *testing.T) {
	// Start a simple TCP listener
	listener, err := startTestServer(t)
	if err != nil {
		t.Fatalf("failed to start test server: %v", err)
	}
	defer listener.Close()

	result := Benchmark("localhost", listener.Addr().(*net.TCPAddr).Port, 5, 1)
	if result == nil {
		t.Fatal("expected result, got nil")
	}
	if result.Successful == 0 {
		t.Error("expected at least one successful round")
	}
	if result.Grade == "" {
		t.Error("expected non-empty grade")
	}
	t.Logf("Grade: %s, Avg: %v, Jitter: %v, Consistency: %.1f%%",
		result.Grade, result.AvgRTT, result.Jitter, result.Consistency)
}

func TestBenchmarkFailure(t *testing.T) {
	result := Benchmark("nonexistent.invalid", 9999, 3, 1)
	if result == nil {
		t.Fatal("expected result, got nil")
	}
	if result.Successful != 0 {
		t.Error("expected 0 successful rounds for invalid target")
	}
	if result.Failed != 3 {
		t.Errorf("expected 3 failed rounds, got %d", result.Failed)
	}
}

func startTestServer(t *testing.T) (net.Listener, error) {
	t.Helper()
	return net.Listen("tcp", "localhost:0")
}

func TestPercentile(t *testing.T) {
	durations := []time.Duration{
		10 * time.Millisecond,
		20 * time.Millisecond,
		30 * time.Millisecond,
		40 * time.Millisecond,
		50 * time.Millisecond,
	}

	p50 := percentile(durations, 50)
	p95 := percentile(durations, 95)
	p99 := percentile(durations, 99)

	if p50 < 20*time.Millisecond || p50 > 30*time.Millisecond {
		t.Errorf("P50 should be around 25ms, got %v", p50)
	}
	if p95 != 50*time.Millisecond {
		t.Errorf("P95 should be 50ms, got %v", p95)
	}
	if p99 != 50*time.Millisecond {
		t.Errorf("P99 should be 50ms, got %v", p99)
	}
}
