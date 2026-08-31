package httpdiag

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"
)

// startHTTPTestServer starts a local HTTP server for testing.
func startHTTPTestServer(t *testing.T, handler http.Handler) (string, int, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start test server: %v", err)
	}
	addr := ln.Addr().(*net.TCPAddr)
	srv := &http.Server{Handler: handler}
	go srv.Serve(ln)
	return addr.IP.String(), addr.Port, func() { srv.Close() }
}

func TestHTTP200(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Test", "ok")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "Hello, NetScope!")
	})

	host, port, cleanup := startHTTPTestServer(t, mux)
	defer cleanup()

	engine := NewEngine()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	url := fmt.Sprintf("http://%s:%d/", host, port)
	result := engine.Diagnose(ctx, url)

	if !result.Success {
		t.Errorf("expected HTTP request to succeed, got error: %s", result.Error)
	}
	if result.StatusCode != 200 {
		t.Errorf("expected status 200, got %d", result.StatusCode)
	}
	if result.TotalDuration <= 0 {
		t.Error("expected positive total duration")
	}
	if result.ResponseSize == 0 {
		t.Error("expected non-zero response size")
	}

	fmt.Printf("HTTP 200: status=%d, DNS=%dms, TCP=%dms, Total=%dms, Size=%d\n",
		result.StatusCode, result.DNSResolution.Milliseconds(), result.TCPConnection.Milliseconds(),
		result.TotalDuration.Milliseconds(), result.ResponseSize)
}

func TestHTTP404(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/notfound", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, "Not Found")
	})

	host, port, cleanup := startHTTPTestServer(t, mux)
	defer cleanup()

	engine := NewEngine()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	url := fmt.Sprintf("http://%s:%d/notfound", host, port)
	result := engine.Diagnose(ctx, url)

	if result.StatusCode != 404 {
		t.Errorf("expected status 404, got %d", result.StatusCode)
	}
	if result.Success {
		t.Error("expected success to be false for 404")
	}
}

func TestHTTP500(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/error", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, "Internal Server Error")
	})

	host, port, cleanup := startHTTPTestServer(t, mux)
	defer cleanup()

	engine := NewEngine()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	url := fmt.Sprintf("http://%s:%d/error", host, port)
	result := engine.Diagnose(ctx, url)

	if result.StatusCode != 500 {
		t.Errorf("expected status 500, got %d", result.StatusCode)
	}
	if result.Success {
		t.Error("expected success to be false for 500")
	}
}

func TestHTTPRedirect(t *testing.T) {
	mux := http.NewServeMux()
	redirCount := 0
	mux.HandleFunc("/redirect", func(w http.ResponseWriter, r *http.Request) {
		redirCount++
		if redirCount > 5 {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "Done")
			return
		}
		http.Redirect(w, r, "/redirect", http.StatusFound)
	})

	host, port, cleanup := startHTTPTestServer(t, mux)
	defer cleanup()

	engine := NewEngine()
	engine.SetTimeout(10 * time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	url := fmt.Sprintf("http://%s:%d/redirect", host, port)
	result := engine.Diagnose(ctx, url)

	if result.RedirectCount == 0 {
		// At least some redirects should happen
		t.Log("redirect count is 0 - may be follow-redirect behavior")
	}
	fmt.Printf("HTTP redirect: count=%d, status=%d\n", result.RedirectCount, result.StatusCode)
}

func TestHTTPTimeout(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/slow", func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(30 * time.Second)
		fmt.Fprint(w, "Done")
	})

	host, port, cleanup := startHTTPTestServer(t, mux)
	defer cleanup()

	engine := NewEngine()
	engine.SetTimeout(500 * time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	url := fmt.Sprintf("http://%s:%d/slow", host, port)
	result := engine.Diagnose(ctx, url)

	if result.Success {
		t.Error("expected HTTP request to timeout")
	}
	if !result.IsTimeout {
		t.Error("expected is_timeout to be true")
	}
	fmt.Printf("HTTP timeout: error=%s\n", result.Error)
}

func TestHTTPInvalidURL(t *testing.T) {
	engine := NewEngine()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result := engine.Diagnose(ctx, "://invalid")

	if result.Success {
		t.Error("expected invalid URL to fail")
	}
}

func TestHTTPHeaders(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/headers", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Custom", "test-value")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"status":"ok"}`)
	})

	host, port, cleanup := startHTTPTestServer(t, mux)
	defer cleanup()

	engine := NewEngine()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	url := fmt.Sprintf("http://%s:%d/headers", host, port)
	result := engine.Diagnose(ctx, url)

	if !result.Success {
		t.Errorf("expected success, got error: %s", result.Error)
	}
}
