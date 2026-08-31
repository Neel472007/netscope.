package diagnostics

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/Neel472007/netscope/internal/types"
)

func TestAnalyzeDNSFailure(t *testing.T) {
	engine := NewEngine()
	result := &types.DiagnosticResult{
		Target: types.DiagnosticTarget{Host: "invalid.example.test"},
		DNS: &types.DNSResult{
			Host:    "invalid.example.test",
			Success: false,
			Error:   "no such host",
		},
	}

	rc := engine.Analyze(result)

	if rc == nil {
		t.Fatal("expected non-nil root cause")
	}
	if rc.Severity != "critical" {
		t.Errorf("expected severity 'critical', got '%s'", rc.Severity)
	}
	if rc.AffectedLayer != "DNS" {
		t.Errorf("expected affected layer 'DNS', got '%s'", rc.AffectedLayer)
	}
	if rc.Confidence <= 0 {
		t.Error("expected positive confidence")
	}
	fmt.Printf("DNS failure: cause=%s, severity=%s, confidence=%.0f%%\n",
		rc.RootCause, rc.Severity, rc.Confidence*100)
}

func TestAnalyzeTCPFailure(t *testing.T) {
	engine := NewEngine()
	result := &types.DiagnosticResult{
		Target: types.DiagnosticTarget{Host: "example.com"},
		DNS: &types.DNSResult{
			Host:    "example.com",
			Success: true,
		},
		TCP: &types.TCPResult{
			Host:      "example.com",
			Port:      9999,
			Connected: false,
			Error:     "connection refused",
			ErrorType: "refused",
		},
	}

	rc := engine.Analyze(result)

	if rc == nil {
		t.Fatal("expected non-nil root cause")
	}
	if rc.AffectedLayer != "TCP" {
		t.Errorf("expected affected layer 'TCP', got '%s'", rc.AffectedLayer)
	}
	if rc.Severity != "high" {
		t.Errorf("expected severity 'high', got '%s'", rc.Severity)
	}
	fmt.Printf("TCP failure: cause=%s, severity=%s\n", rc.RootCause, rc.Severity)
}

func TestAnalyzeTCPTimeout(t *testing.T) {
	engine := NewEngine()
	result := &types.DiagnosticResult{
		Target: types.DiagnosticTarget{Host: "example.com"},
		DNS: &types.DNSResult{
			Host:    "example.com",
			Success: true,
		},
		TCP: &types.TCPResult{
			Host:      "example.com",
			Port:      443,
			Connected: false,
			Error:     "dial tcp: i/o timeout",
			ErrorType: "timeout",
			IsTimeout: true,
		},
	}

	rc := engine.Analyze(result)

	if rc == nil {
		t.Fatal("expected non-nil root cause")
	}
	if rc.Severity != "critical" {
		t.Errorf("expected severity 'critical' for TCP timeout, got '%s'", rc.Severity)
	}
}

func TestAnalyzeHTTPFailure(t *testing.T) {
	engine := NewEngine()
	result := &types.DiagnosticResult{
		Target: types.DiagnosticTarget{Host: "example.com"},
		DNS: &types.DNSResult{
			Host:    "example.com",
			Success: true,
		},
		TCP: &types.TCPResult{
			Host:      "example.com",
			Port:      443,
			Connected: true,
		},
		HTTP: &types.HTTPResult{
			URL:        "https://example.com",
			StatusCode: 500,
			StatusText: "Internal Server Error",
			Success:    false,
		},
	}

	rc := engine.Analyze(result)

	if rc == nil {
		t.Fatal("expected non-nil root cause")
	}
	if rc.AffectedLayer != "HTTP" {
		t.Errorf("expected affected layer 'HTTP', got '%s'", rc.AffectedLayer)
	}
	if rc.Severity != "high" {
		t.Errorf("expected severity 'high', got '%s'", rc.Severity)
	}
}

func TestAnalyzeSlowHTTP(t *testing.T) {
	engine := NewEngine()
	result := &types.DiagnosticResult{
		Target: types.DiagnosticTarget{Host: "example.com"},
		DNS: &types.DNSResult{
			Host:            "example.com",
			Success:         true,
			ResolutionTime:  20 * time.Millisecond,
		},
		TCP: &types.TCPResult{
			Host:      "example.com",
			Port:      443,
			Connected: true,
			Latency:   30 * time.Millisecond,
		},
		HTTP: &types.HTTPResult{
			URL:           "https://example.com",
			StatusCode:    200,
			Success:       true,
			DNSResolution: 20 * time.Millisecond,
			TCPConnection: 30 * time.Millisecond,
			TotalDuration: 3 * time.Second,
		},
	}

	rc := engine.Analyze(result)

	if rc == nil {
		t.Fatal("expected non-nil root cause")
	}
	if rc.RootCause == "No issues detected" {
		t.Error("expected issues to be detected for slow HTTP")
	}
	fmt.Printf("Slow HTTP: cause=%s, severity=%s\n", rc.RootCause, rc.Severity)
}

func TestAnalyzeHealthy(t *testing.T) {
	engine := NewEngine()
	result := &types.DiagnosticResult{
		Target: types.DiagnosticTarget{Host: "example.com"},
		DNS: &types.DNSResult{
			Host:            "example.com",
			Success:         true,
			ResolutionTime:  15 * time.Millisecond,
		},
		TCP: &types.TCPResult{
			Host:      "example.com",
			Port:      443,
			Connected: true,
			Latency:   25 * time.Millisecond,
		},
		HTTP: &types.HTTPResult{
			URL:           "https://example.com",
			StatusCode:    200,
			Success:       true,
			DNSResolution: 15 * time.Millisecond,
			TCPConnection: 25 * time.Millisecond,
			TotalDuration: 100 * time.Millisecond,
		},
	}

	rc := engine.Analyze(result)

	if rc == nil {
		t.Fatal("expected non-nil root cause")
	}
	if rc.Severity != "info" {
		t.Errorf("expected severity 'info' for healthy system, got '%s'", rc.Severity)
	}
}

func TestAnalyzeNil(t *testing.T) {
	engine := NewEngine()
	rc := engine.Analyze(nil)

	if rc == nil {
		t.Fatal("expected non-nil root cause for nil result")
	}
	if rc.Severity != "critical" {
		t.Errorf("expected severity 'critical' for nil result, got '%s'", rc.Severity)
	}
}

func TestHealthScoreDNSFailure(t *testing.T) {
	engine := NewEngine()
	result := &types.DiagnosticResult{
		Target: types.DiagnosticTarget{Host: "example.com"},
		DNS: &types.DNSResult{
			Host:    "example.com",
			Success: false,
			Error:   "no such host",
		},
	}

	health := engine.CalculateHealthScore(result)

	if health == nil {
		t.Fatal("expected non-nil health score")
	}
	if health.Score >= 50 {
		t.Errorf("expected health score < 50 for DNS failure, got %d", health.Score)
	}
	if health.Status != "UNHEALTHY" && health.Status != "CRITICAL" {
		t.Errorf("expected UNHEALTHY or CRITICAL status, got '%s'", health.Status)
	}
	if health.RootCause == nil {
		t.Error("expected root cause for DNS failure")
	}
	fmt.Printf("DNS failure health: %d/100 %s\n", health.Score, health.Status)
}

func TestHealthScoreHealthy(t *testing.T) {
	engine := NewEngine()
	result := &types.DiagnosticResult{
		Target: types.DiagnosticTarget{Host: "example.com"},
		DNS: &types.DNSResult{
			Host:            "example.com",
			Success:         true,
			ResolutionTime:  10 * time.Millisecond,
		},
		TCP: &types.TCPResult{
			Host:      "example.com",
			Port:      443,
			Connected: true,
			Latency:   20 * time.Millisecond,
		},
		HTTP: &types.HTTPResult{
			URL:           "https://example.com",
			StatusCode:    200,
			Success:       true,
			DNSResolution: 10 * time.Millisecond,
			TCPConnection: 20 * time.Millisecond,
			TotalDuration: 80 * time.Millisecond,
		},
	}

	health := engine.CalculateHealthScore(result)

	if health.Score < 80 {
		t.Errorf("expected health score >= 80 for healthy system, got %d", health.Score)
	}
	if health.Status != "HEALTHY" {
		t.Errorf("expected HEALTHY status, got '%s'", health.Status)
	}
	fmt.Printf("Healthy: %d/100 %s\n", health.Score, health.Status)
}

func TestOrchestrator(t *testing.T) {
	orch := NewOrchestrator()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := orch.DiagnoseTarget(ctx, "localhost")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.DNS == nil {
		t.Error("expected DNS result")
	}
	if result.Health == nil {
		t.Error("expected health score")
	}
	fmt.Printf("Orchestrator localhost: health=%d/100 %s\n", result.Health.Score, result.Health.Status)
}
