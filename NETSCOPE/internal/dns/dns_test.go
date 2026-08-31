package dns

import (
	"context"
	"testing"
	"time"
)

func TestResolveValidHost(t *testing.T) {
	engine := NewEngine()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result := engine.Resolve(ctx, "localhost")

	if !result.Success {
		t.Errorf("expected DNS resolution to succeed for localhost, got error: %s", result.Error)
	}
	if result.ResolutionTime <= 0 {
		t.Error("expected positive resolution time")
	}
	if len(result.IPv4Addresses) == 0 && len(result.IPv6Addresses) == 0 {
		t.Error("expected at least one IP address")
	}
}

func TestResolveInvalidHost(t *testing.T) {
	engine := NewEngine()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result := engine.Resolve(ctx, "this-host-definitely-does-not-exist-12345.invalid")

	if result.Success {
		t.Error("expected DNS resolution to fail for invalid host")
	}
	if result.Error == "" {
		t.Error("expected error message")
	}
}

func TestResolveTimeout(t *testing.T) {
	engine := NewEngine()
	engine.SetTimeout(1 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result := engine.Resolve(ctx, "example.com")

	// May succeed or fail depending on system speed, but should not panic
	if result == nil {
		t.Error("expected non-nil result")
	}
}

func TestResolveEmptyHost(t *testing.T) {
	engine := NewEngine()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result := engine.Resolve(ctx, "")

	if result.Success {
		t.Error("expected DNS resolution to fail for empty host")
	}
}

func TestResolveWithResolvers(t *testing.T) {
	engine := NewEngine()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	results := engine.ResolveWithResolvers(ctx, "localhost")

	if len(results) == 0 {
		t.Error("expected at least one result")
	}

	// At least one resolver should succeed for localhost
	anySuccess := false
	for _, r := range results {
		if r != nil && r.Success {
			anySuccess = true
			break
		}
	}
	if !anySuccess {
		t.Error("expected at least one resolver to succeed for localhost")
	}
}

func TestLookupTXT(t *testing.T) {
	engine := NewEngine()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// TXT lookup may not return records, but should not panic
	_, _, err := engine.LookupTXT(ctx, "example.com")
	// We don't assert error here as TXT records may not exist
	_ = err
}
