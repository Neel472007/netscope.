// Package packetflow traces the complete connection journey from DNS resolution
// through TCP handshake, TLS negotiation, and HTTP request/response — producing
// a detailed timing breakdown for each layer, suitable for visual rendering.
package packetflow

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// StepType identifies the connection step.
type StepType string

const (
	StepDNSResolve  StepType = "dns_resolve"
	StepTCPConnect  StepType = "tcp_connect"
	StepTLSHandshake StepType = "tls_handshake"
	StepHTTPSend    StepType = "http_send"
	StepHTTPRecv    StepType = "http_recv"
	StepDNSCache    StepType = "dns_cache_check"
)

// Step represents one step in the connection journey.
type Step struct {
	Type        StepType  `json:"type"`
	Label       string    `json:"label"`
	Description string    `json:"description"`
	StartNs     int64     `json:"start_ns"`
	DurationNs  int64     `json:"duration_ns"`
	EndNs       int64     `json:"end_ns"`
	Success     bool      `json:"success"`
	Error       string    `json:"error,omitempty"`
	Detail      string    `json:"detail,omitempty"`
	SubSteps    []SubStep `json:"sub_steps,omitempty"`
}

// SubStep is a detail within a step (e.g., individual TLS extensions).
type SubStep struct {
	Label      string `json:"label"`
	DurationNs int64  `json:"duration_ns"`
	Detail     string `json:"detail,omitempty"`
}

// FlowResult is the complete packet flow trace.
type FlowResult struct {
	Target      string `json:"target"`
	ResolvedIP  string `json:"resolved_ip"`
	Port        int    `json:"port"`
	TotalNs     int64  `json:"total_ns"`
	TotalMs     float64 `json:"total_ms"`
	Steps       []Step `json:"steps"`
	Success     bool   `json:"success"`
	Error       string `json:"error,omitempty"`
	Summary     string `json:"summary"`
	Breakdown   map[string]float64 `json:"breakdown_ms"`
}

// Trace performs a complete packet flow trace against a target.
func Trace(ctx context.Context, target string, port int) *FlowResult {
	result := &FlowResult{
		Target:    target,
		Port:      port,
		Breakdown: make(map[string]float64),
	}

	// Ensure we have a valid target
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		host = target
	}

	if host == "" {
		result.Error = "empty target"
		return result
	}

	// Resolve the host
	var steps []Step
	totalStart := time.Now()

	// Step 1: DNS Resolution
	dnsStep := traceDNS(ctx, host)
	steps = append(steps, dnsStep)
	if !dnsStep.Success {
		result.Steps = steps
		result.Error = dnsStep.Error
		result.TotalNs = time.Since(totalStart).Nanoseconds()
		result.TotalMs = float64(result.TotalNs) / 1e6
		return result
	}

	// Extract resolved IP
	result.ResolvedIP = dnsStep.Detail

	// Step 2: TCP Connect
	tcpStep := traceTCP(ctx, result.ResolvedIP, port)
	steps = append(steps, tcpStep)
	if !tcpStep.Success {
		result.Steps = steps
		result.Error = tcpStep.Error
		result.TotalNs = time.Since(totalStart).Nanoseconds()
		result.TotalMs = float64(result.TotalNs) / 1e6
		return result
	}

	// Step 3: TLS Handshake (only for HTTPS)
	if port == 443 || port == 8443 {
		tlsStep := traceTLS(ctx, result.ResolvedIP, port, host)
		steps = append(steps, tlsStep)
	}

	// Step 4: HTTP Request
	httpStep := traceHTTP(ctx, target, port, host)
	steps = append(steps, httpStep)

	result.Steps = steps
	result.TotalNs = time.Since(totalStart).Nanoseconds()
	result.TotalMs = float64(result.TotalNs) / 1e6
	result.Success = true

	// Build breakdown
	for _, s := range steps {
		ms := float64(s.DurationNs) / 1e6
		result.Breakdown[string(s.Type)] = ms
	}

	// Build summary
	result.Summary = buildSummary(steps, result.TotalMs)

	return result
}

func traceDNS(ctx context.Context, host string) Step {
	step := Step{
		Type:        StepDNSResolve,
		Label:       "DNS Resolution",
		Description: "Resolving hostname to IP address",
		StartNs:     time.Now().UnixNano(),
	}

	resolver := &net.Resolver{}
	start := time.Now()
	ips, err := resolver.LookupHost(ctx, host)
	elapsed := time.Since(start)

	step.DurationNs = elapsed.Nanoseconds()
	step.EndNs = time.Now().UnixNano()

	if err != nil {
		step.Success = false
		step.Error = err.Error()
		return step
	}

	step.Success = true
	if len(ips) > 0 {
		step.Detail = ips[0]
	}
	step.SubSteps = append(step.SubSteps, SubStep{
		Label:      fmt.Sprintf("Found %d IP(s)", len(ips)),
		DurationNs: elapsed.Nanoseconds(),
		Detail:     strings.Join(ips, ", "),
	})

	return step
}

func traceTCP(ctx context.Context, ip string, port int) Step {
	step := Step{
		Type:        StepTCPConnect,
		Label:       "TCP Connection",
		Description: "Establishing TCP connection (3-way handshake)",
		StartNs:     time.Now().UnixNano(),
	}

	addr := net.JoinHostPort(ip, fmt.Sprintf("%d", port))
	start := time.Now()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	elapsed := time.Since(start)

	step.DurationNs = elapsed.Nanoseconds()
	step.EndNs = time.Now().UnixNano()

	if err != nil {
		step.Success = false
		step.Error = err.Error()
		return step
	}
	conn.Close()

	step.Success = true
	step.Detail = fmt.Sprintf("Connected to %s in %.1fms", addr, float64(elapsed.Microseconds())/1000)
	step.SubSteps = append(step.SubSteps, SubStep{
		Label:      "SYN → SYN-ACK → ACK",
		DurationNs: elapsed.Nanoseconds(),
		Detail:     fmt.Sprintf("RTT: %.1fms", float64(elapsed.Microseconds())/1000),
	})

	return step
}

func traceTLS(ctx context.Context, ip string, port int, sni string) Step {
	step := Step{
		Type:        StepTLSHandshake,
		Label:       "TLS Handshake",
		Description: "Negotiating secure connection",
		StartNs:     time.Now().UnixNano(),
	}

	start := time.Now()
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 5 * time.Second},
		"tcp",
		net.JoinHostPort(ip, fmt.Sprintf("%d", port)),
		&tls.Config{
			ServerName:         sni,
			InsecureSkipVerify: false,
		},
	)
	elapsed := time.Since(start)

	step.DurationNs = elapsed.Nanoseconds()
	step.EndNs = time.Now().UnixNano()

	if err != nil {
		step.Success = false
		step.Error = err.Error()
		return step
	}

	state := conn.ConnectionState()
	conn.Close()

	step.Success = true
	step.Detail = fmt.Sprintf("%s / %s", tls.VersionName(state.Version), tls.CipherSuiteName(state.CipherSuite))
	step.SubSteps = append(step.SubSteps, SubStep{
		Label:      "ClientHello → ServerHello",
		DurationNs: elapsed.Nanoseconds(),
		Detail:     step.Detail,
	})

	return step
}

func traceHTTP(ctx context.Context, target string, port int, host string) Step {
	step := Step{
		Type:        StepHTTPSend,
		Label:       "HTTP Request",
		Description: "Sending HTTP request and receiving response",
		StartNs:     time.Now().UnixNano(),
	}

	scheme := "https"
	if port == 80 || port == 8080 {
		scheme = "http"
	}
	rawURL := fmt.Sprintf("%s://%s", scheme, host)
	if port != 80 && port != 443 {
		rawURL = fmt.Sprintf("%s:%d", rawURL, port)
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		step.DurationNs = 0
		step.EndNs = time.Now().UnixNano()
		step.Success = false
		step.Error = err.Error()
		return step
	}

	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if err != nil {
		step.DurationNs = 0
		step.EndNs = time.Now().UnixNano()
		step.Success = false
		step.Error = err.Error()
		return step
	}
	req.Header.Set("User-Agent", "NetScope/1.0")

	client := &http.Client{Timeout: 10 * time.Second}
	start := time.Now()
	resp, err := client.Do(req)
	elapsed := time.Since(start)

	step.DurationNs = elapsed.Nanoseconds()
	step.EndNs = time.Now().UnixNano()

	if err != nil {
		step.Success = false
		step.Error = err.Error()
		return step
	}
	defer resp.Body.Close()

	step.Success = true
	step.Detail = fmt.Sprintf("%d %s (%.1fms)", resp.StatusCode, resp.Status, float64(elapsed.Microseconds())/1000)
	step.SubSteps = append(step.SubSteps, SubStep{
		Label:      "Request → Response",
		DurationNs: elapsed.Nanoseconds(),
		Detail:     fmt.Sprintf("Status: %d, Content-Length: %s", resp.StatusCode, resp.Header.Get("Content-Length")),
	})

	return step
}

func buildSummary(steps []Step, totalMs float64) string {
	parts := []string{}
	for _, s := range steps {
		if s.Success {
			parts = append(parts, fmt.Sprintf("%s: %.1fms", s.Label, float64(s.DurationNs)/1e6))
		} else {
			parts = append(parts, fmt.Sprintf("%s: FAILED (%s)", s.Label, s.Error))
		}
	}
	return fmt.Sprintf("Total: %.1fms — %s", totalMs, strings.Join(parts, " → "))
}
