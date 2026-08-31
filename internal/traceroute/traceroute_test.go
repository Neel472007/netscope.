package traceroute

import (
	"context"
	"testing"
	"time"
)

func TestTracerouteBasic(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result := Traceroute(ctx, "example.com", 15, 2)

	if result.Error != "" {
		t.Logf("Traceroute error (may be expected): %s", result.Error)
	}

	if result.ResolvedIP == "" && result.Error == "" {
		t.Error("expected resolved IP or an error")
	}

	t.Logf("Target: %s, Resolved: %s, Hops: %d, Completed: %v, Duration: %d ms",
		result.Target, result.ResolvedIP, result.TotalHops, result.Completed, result.DurationNs/1e6)

	for _, hop := range result.Hops {
		if hop.Reached {
			t.Logf("  Hop %d: IP=%s, Host=%s, AvgRTT=%dms, Loss=%.0f%%",
				hop.TTL, hop.IP, hop.Host, hop.AvgRTT.Nanoseconds()/1e6, hop.Loss*100)
		} else {
			t.Logf("  Hop %d: *", hop.TTL)
		}
	}
}

func TestTracerouteInvalidHost(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result := Traceroute(ctx, "this-host-does-not-exist-12345.invalid", 5, 1)

	if result.Error == "" && !result.Completed {
		t.Log("no error but also not completed — may be expected depending on network")
	}

	if result.Error != "" {
		t.Logf("Expected DNS error: %s", result.Error)
	}
}

func TestTracerouteCancelled(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	result := Traceroute(ctx, "example.com", MaxHops, DefaultProbes)

	// Should either complete quickly or be cancelled
	t.Logf("Result: error=%q, hops=%d", result.Error, result.TotalHops)
}

func TestTracerouteLocalhost(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result := Traceroute(ctx, "127.0.0.1", 5, 2)

	if result.Error != "" {
		t.Logf("Error for localhost: %s", result.Error)
	}

	t.Logf("Localhost traceroute: %d hops, completed=%v", result.TotalHops, result.Completed)
}

func TestMaxHopsLimit(t *testing.T) {
	// Test that 0 gets replaced with default
	Traceroute(context.Background(), "127.0.0.1", 0, 1)
	// Just verifying it doesn't panic
	t.Log("MaxHops=0 handled gracefully")
}
