package lbsim

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestLBSimSnapshot(t *testing.T) {
	// Create a mock LB without starting backends
	lb := &LoadBalancer{
		pool:          &ServerPool{},
		securityLevel: "SECURE",
		adminToken:    "test-token-1234",
	}

	snap := lb.GetSnapshot()
	if snap.SecurityLevel != "SECURE" {
		t.Errorf("expected SECURE, got %s", snap.SecurityLevel)
	}
	if snap.TotalRequests != 0 {
		t.Errorf("expected 0 total requests, got %d", snap.TotalRequests)
	}
}

func TestLBSimKillRevive(t *testing.T) {
	lb := &LoadBalancer{
		pool:          &ServerPool{},
		securityLevel: "SECURE",
		adminToken:    "test-token",
	}

	// Add a mock backend
	u := &url.URL{Host: "localhost:9999"}
	b := &Backend{URL: u, healthAlive: true}
	lb.pool.backends = append(lb.pool.backends, b)

	// Kill it
	lb.Kill("localhost:9999")
	if b.IsAlive() {
		t.Error("expected backend to be down after kill")
	}

	// Revive it
	lb.Revive("localhost:9999")
	if !b.IsAlive() {
		t.Error("expected backend to be alive after revive")
	}
}

func TestLBSimAuth(t *testing.T) {
	lb := &LoadBalancer{
		adminToken: "secret123",
	}

	// Valid token
	r := httptest.NewRequest("GET", "/lbsim/kill?token=secret123&node=localhost:8081", nil)
	if !lb.Auth(r) {
		t.Error("expected valid auth")
	}

	// Invalid token
	r = httptest.NewRequest("GET", "/lbsim/kill?token=wrong&node=localhost:8081", nil)
	if lb.Auth(r) {
		t.Error("expected invalid auth")
	}

	// No token
	r = httptest.NewRequest("GET", "/lbsim/kill?node=localhost:8081", nil)
	if lb.Auth(r) {
		t.Error("expected no auth")
	}
}

func TestLBSimServerPool(t *testing.T) {
	pool := &ServerPool{}

	// No backends
	if pool.GetNext() != nil {
		t.Error("expected nil with no backends")
	}

	// Add backends
	u1 := &url.URL{Host: "a:8081"}
	u2 := &url.URL{Host: "b:8082"}
	b1 := &Backend{URL: u1, healthAlive: true}
	b2 := &Backend{URL: u2, healthAlive: true}
	pool.backends = append(pool.backends, b1, b2)

	// Should get alive backends
	next := pool.GetNext()
	if next == nil {
		t.Error("expected alive backend")
	}
	if next.URL.Host != "a:8081" && next.URL.Host != "b:8082" {
		t.Errorf("unexpected backend: %s", next.URL.Host)
	}

	// Kill one, should get the other
	b1.SetHealth(false)
	next = pool.GetNext()
	if next == nil {
		t.Error("expected alive backend")
	}
	if next.URL.Host != "b:8082" {
		t.Errorf("expected b:8082, got %s", next.URL.Host)
	}

	// Kill both, should get nil
	b2.SetHealth(false)
	next = pool.GetNext()
	if next != nil {
		t.Error("expected nil when all backends dead")
	}
}

func TestLBSimHTTPHandler(t *testing.T) {
	lb := &LoadBalancer{
		pool:          &ServerPool{},
		securityLevel: "SECURE",
		adminToken:    "test-token",
	}

	mux := http.NewServeMux()
	lb.RegisterRoutes(mux)

	// Test health endpoint
	req := httptest.NewRequest("GET", "/lbsim/health", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var snap Snapshot
	if err := json.NewDecoder(w.Body).Decode(&snap); err != nil {
		t.Fatalf("failed to decode health response: %v", err)
	}
	if snap.SecurityLevel != "SECURE" {
		t.Errorf("expected SECURE, got %s", snap.SecurityLevel)
	}
}
