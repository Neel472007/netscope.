package portscan

import (
	"context"
	"testing"
)

func TestScanKnownPorts(t *testing.T) {
	scanner := New()
	result := scanner.Scan(context.Background(), ScanRequest{
		Host:  "example.com",
		Ports: []int{80, 443},
	})
	if result.Host != "example.com" {
		t.Errorf("expected host 'example.com', got '%s'", result.Host)
	}
	if len(result.Results) == 0 {
		t.Error("expected at least some port results")
	}
}

func TestScanSinglePort(t *testing.T) {
	scanner := New()
	result := scanner.Scan(context.Background(), ScanRequest{
		Host:  "1.1.1.1",
		Ports: []int{53},
	})
	if len(result.Results) != 1 {
		t.Fatalf("expected 1 port result, got %d", len(result.Results))
	}
}

func TestScanInvalidHost(t *testing.T) {
	scanner := New()
	result := scanner.Scan(context.Background(), ScanRequest{
		Host:  "this-host-does-not-exist-12345.invalid",
		Ports: []int{80},
	})
	if len(result.Results) == 0 {
		t.Error("expected at least one port result")
	}
}

func TestCommonPorts(t *testing.T) {
	if len(CommonPorts) == 0 {
		t.Error("expected common ports list to be non-empty")
	}
}
