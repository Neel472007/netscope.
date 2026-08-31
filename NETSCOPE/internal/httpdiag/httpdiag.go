// Package httpdiag provides HTTP diagnostic measurements.
package httpdiag

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Neel472007/netscope/internal/types"
)

const (
	maxResponseSize = 10 * 1024 * 1024 // 10MB
	maxHeaderSize   = 8 * 1024         // 8KB
)

// Engine performs HTTP diagnostics.
type Engine struct {
	timeout     time.Duration
	maxRedirect int
}

// NewEngine creates a new HTTP diagnostic engine.
func NewEngine() *Engine {
	return &Engine{
		timeout:     10 * time.Second,
		maxRedirect: 10,
	}
}

// SetTimeout sets the HTTP request timeout.
func (e *Engine) SetTimeout(d time.Duration) {
	e.timeout = d
}

// Diagnose performs a full HTTP diagnostic measurement.
func (e *Engine) Diagnose(ctx context.Context, rawURL string) *types.HTTPResult {
	result := &types.HTTPResult{
		URL: rawURL,
	}

	// Parse URL
	u, err := url.Parse(rawURL)
	if err != nil {
		result.Success = false
		result.Error = fmt.Sprintf("invalid URL: %v", err)
		return result
	}

	host := u.Hostname()
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}

	// Step 1: DNS Resolution
	dnsStart := time.Now()
	resolver := &net.Resolver{PreferGo: false}
	addrs, dnsErr := resolver.LookupHost(ctx, host)
	result.DNSResolution = time.Since(dnsStart)

	if dnsErr != nil {
		result.Success = false
		result.Error = fmt.Sprintf("DNS resolution failed: %v", dnsErr)
		result.ErrorType = "dns"
		return result
	}
	_ = addrs

	// Step 2: TCP Connection + TLS (if HTTPS)
	connStart := time.Now()
	var tlsDuration time.Duration

	targetAddr := net.JoinHostPort(host, port)
	dialer := &net.Dialer{
		Timeout: e.timeout,
	}

	conn, dialErr := dialer.DialContext(ctx, "tcp", targetAddr)
	result.TCPConnection = time.Since(connStart)

	if dialErr != nil {
		result.Success = false
		result.Error = fmt.Sprintf("TCP connection failed: %v", dialErr)
		result.ErrorType = "tcp"
		return result
	}

	// TLS handshake if HTTPS
	if u.Scheme == "https" {
		tlsStart := time.Now()
		tlsConn := tls.Client(conn, &tls.Config{
			ServerName: host,
		})
		tlsErr := tlsConn.HandshakeContext(ctx)
		tlsDuration = time.Since(tlsStart)
		result.TLSHandshake = tlsDuration

		if tlsErr != nil {
			conn.Close()
			result.Success = false
			result.Error = fmt.Sprintf("TLS handshake failed: %v", tlsErr)
			result.ErrorType = "tls"
			return result
		}
		conn.Close()
	}

	// Step 3: HTTP Request using a custom transport for timing
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, addr)
		},
		TLSClientConfig:     &tls.Config{ServerName: host},
		MaxIdleConns:        1,
		IdleConnTimeout:     e.timeout,
		TLSHandshakeTimeout: e.timeout,
		ResponseHeaderTimeout: e.timeout,
	}

	httpClient := &http.Client{
		Transport: transport,
		Timeout:   e.timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			result.RedirectCount = len(via)
			if len(via) >= e.maxRedirect {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	reqStart := time.Now()
	req, reqErr := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
	if reqErr != nil {
		result.Success = false
		result.Error = fmt.Sprintf("HTTP request creation failed: %v", reqErr)
		result.ErrorType = "http"
		return result
	}

	req.Header.Set("User-Agent", "NetScope/1.0")
	req.Header.Set("Accept", "*/*")

	resp, httpErr := httpClient.Do(req)
	if httpErr != nil {
		totalElapsed := time.Since(reqStart)
		result.TotalDuration = totalElapsed
		result.Success = false
		result.Error = fmt.Sprintf("HTTP request failed: %v", httpErr)
		if ctx.Err() == context.DeadlineExceeded {
			result.IsTimeout = true
			result.ErrorType = "timeout"
		} else if strings.Contains(httpErr.Error(), "timeout") || strings.Contains(httpErr.Error(), "deadline exceeded") {
			result.IsTimeout = true
			result.ErrorType = "timeout"
		} else {
			result.ErrorType = "http"
		}
		return result
	}

	// Measure time to first byte (approximate)
	result.TimeToFirstByte = time.Since(reqStart)

	// Read response body (limited)
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	resp.Body.Close()
	totalElapsed := time.Since(reqStart)

	result.TotalDuration = totalElapsed
	result.StatusCode = resp.StatusCode
	result.StatusText = http.StatusText(resp.StatusCode)
	result.ResponseSize = int64(len(body))
	result.Success = resp.StatusCode >= 200 && resp.StatusCode < 400

	if readErr != nil {
		result.Error = fmt.Sprintf("error reading response body: %v", readErr)
	}

	// Collect relevant headers
	importantHeaders := []string{
		"Content-Type", "Content-Length", "Server", "X-Response-Time",
		"Cache-Control", "Strict-Transport-Security", "X-Frame-Options",
	}
	for _, h := range importantHeaders {
		if v := resp.Header.Get(h); v != "" {
			result.Headers = append(result.Headers, types.HTTPHeader{
				Name:  h,
				Value: v,
			})
		}
	}

	return result
}
