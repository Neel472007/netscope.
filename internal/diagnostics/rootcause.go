// Package diagnostics provides root-cause analysis and diagnostic orchestration.
package diagnostics

import (
	"fmt"
	"math"
	"time"

	"github.com/Neel472007/netscope/internal/types"
)

// Engine performs root-cause analysis on diagnostic results.
type Engine struct{}

// NewEngine creates a new diagnostic engine.
func NewEngine() *Engine {
	return &Engine{}
}

// Analyze performs root-cause analysis on a complete diagnostic result.
func (e *Engine) Analyze(result *types.DiagnosticResult) *types.RootCause {
	if result == nil {
		return &types.RootCause{
			RootCause:      "No diagnostic data available",
			Evidence:       "Diagnostic run produced no results.",
			Severity:       "critical",
			Confidence:     1.0,
			AffectedLayer:  "unknown",
			Recommendation: "Ensure target is valid and reachable.",
		}
	}

	// Collect evidence
	var dnsFailed, tcpFailed, httpFailed bool
	var dnsSlow, tcpSlow, httpSlow bool
	var dnsLatency, tcpLatency, httpLatency time.Duration

	if result.DNS != nil {
		dnsFailed = !result.DNS.Success
		dnsLatency = result.DNS.ResolutionTime
		dnsSlow = dnsLatency > 500*time.Millisecond
	}

	if result.TCP != nil {
		tcpFailed = !result.TCP.Connected
		tcpLatency = result.TCP.Latency
		tcpSlow = tcpLatency > 1*time.Second
	}

	if result.HTTP != nil {
		httpFailed = !result.HTTP.Success
		httpLatency = result.HTTP.TotalDuration
		httpSlow = httpLatency > 2*time.Second
	}

	// Rule-based analysis: check in dependency order

	// Rule 1: DNS failure is the most fundamental
	if dnsFailed {
		return e.analyzeDNSFailure(result, dnsLatency)
	}

	// Rule 2: DNS is extremely slow
	if dnsSlow {
		return e.analyzeSlowDNS(result, dnsLatency)
	}

	// Rule 3: TCP failure after DNS success
	if tcpFailed {
		return e.analyzeTCPFailure(result, tcpLatency)
	}

	// Rule 4: TCP is extremely slow
	if tcpSlow {
		return e.analyzeSlowTCP(result, tcpLatency)
	}

	// Rule 5: HTTP failure after TCP success
	if httpFailed {
		return e.analyzeHTTPFailure(result)
	}

	// Rule 6: HTTP is extremely slow (likely server-side)
	if httpSlow {
		return e.analyzeSlowHTTP(result, httpLatency, tcpLatency, dnsLatency)
	}

	// Rule 7: Check for moderate issues
	if httpLatency > 500*time.Millisecond {
		return &types.RootCause{
			RootCause:      "Elevated HTTP response time",
			Evidence:       fmt.Sprintf("DNS: %d ms, TCP: %d ms, HTTP: %d ms", dnsLatency.Milliseconds(), tcpLatency.Milliseconds(), httpLatency.Milliseconds()),
			Severity:       "medium",
			Confidence:     0.7,
			AffectedLayer:  "HTTP",
			Recommendation: "Monitor server response times. Check for increased load or resource contention.",
		}
	}

	// All healthy
	return &types.RootCause{
		RootCause:      "No issues detected",
		Evidence:       fmt.Sprintf("DNS: %d ms, TCP: %d ms, HTTP: %d ms — all within normal ranges.", dnsLatency.Milliseconds(), tcpLatency.Milliseconds(), httpLatency.Milliseconds()),
		Severity:       "info",
		Confidence:     1.0,
		AffectedLayer:  "none",
		Recommendation: "Network is healthy. No action required.",
	}
}

func (e *Engine) analyzeDNSFailure(result *types.DiagnosticResult, latency time.Duration) *types.RootCause {
	evidence := ""
	recommendation := ""

	if result.DNS != nil && result.DNS.IsTimeout {
		evidence = fmt.Sprintf("DNS resolution timed out after %d ms. Host: %s.", latency.Milliseconds(), result.DNS.Host)
		recommendation = "Check DNS resolver availability. Verify the hostname is correct. Try an alternative DNS resolver."
	} else if result.DNS != nil && result.DNS.Error != "" {
		evidence = fmt.Sprintf("DNS resolution failed: %s. Host: %s.", result.DNS.Error, result.DNS.Host)
		recommendation = "Verify the hostname exists. Check DNS configuration. Ensure network connectivity to DNS servers."
	} else {
		evidence = fmt.Sprintf("DNS resolution failed for host: %s.", result.Target.Host)
		recommendation = "Investigate DNS resolver configuration and network connectivity."
	}

	return &types.RootCause{
		RootCause:      "DNS resolution failure",
		Evidence:       evidence,
		Severity:       "critical",
		Confidence:     0.95,
		AffectedLayer:  "DNS",
		Recommendation: recommendation,
	}
}

func (e *Engine) analyzeSlowDNS(result *types.DiagnosticResult, latency time.Duration) *types.RootCause {
	return &types.RootCause{
		RootCause:      "Slow DNS resolution",
		Evidence:       fmt.Sprintf("DNS resolution took %d ms (threshold: 500 ms). Host: %s.", latency.Milliseconds(), result.Target.Host),
		Severity:       "medium",
		Confidence:     0.8,
		AffectedLayer:  "DNS",
		Recommendation: "Consider using a faster DNS resolver (e.g., 1.1.1.1 or 8.8.8.8). Check for DNS cache issues.",
	}
}

func (e *Engine) analyzeTCPFailure(result *types.DiagnosticResult, latency time.Duration) *types.RootCause {
	if result.TCP != nil && result.TCP.ErrorType == "refused" {
		return &types.RootCause{
			RootCause:      "TCP connection refused",
			Evidence:       fmt.Sprintf("DNS resolved successfully, but TCP connection to %s:%d was actively refused in %d ms.", result.TCP.Host, result.TCP.Port, latency.Milliseconds()),
			Severity:       "high",
			Confidence:     0.9,
			AffectedLayer:  "TCP",
			Recommendation: "The target server is running but not accepting connections on this port. Verify the service is running and the port is correct.",
		}
	}

	if result.TCP != nil && result.TCP.ErrorType == "timeout" {
		return &types.RootCause{
			RootCause:      "TCP connection timeout",
			Evidence:       fmt.Sprintf("DNS resolved successfully, but TCP connection to %s:%d timed out after %d ms.", result.TCP.Host, result.TCP.Port, latency.Milliseconds()),
			Severity:       "critical",
			Confidence:     0.85,
			AffectedLayer:  "TCP",
			Recommendation: "A firewall or network issue may be blocking the connection. Check for firewall rules and network routing.",
		}
	}

	if result.TCP != nil && result.TCP.ErrorType == "unreachable" {
		return &types.RootCause{
			RootCause:      "Network unreachable",
			Evidence:       fmt.Sprintf("DNS resolved, but the network is unreachable to %s:%d.", result.TCP.Host, result.TCP.Port),
			Severity:       "critical",
			Confidence:     0.9,
			AffectedLayer:  "TCP",
			Recommendation: "Check network routing and connectivity. The target may be behind a firewall or on an unreachable network segment.",
		}
	}

	return &types.RootCause{
		RootCause:      "TCP connection failure",
		Evidence:       fmt.Sprintf("DNS resolved but TCP connection to %s:%d failed.", result.Target.Host, result.Target.Port),
		Severity:       "high",
		Confidence:     0.85,
		AffectedLayer:  "TCP",
		Recommendation: "Investigate network connectivity, firewall rules, and target service availability.",
	}
}

func (e *Engine) analyzeSlowTCP(result *types.DiagnosticResult, latency time.Duration) *types.RootCause {
	return &types.RootCause{
		RootCause:      "Slow TCP connection",
		Evidence:       fmt.Sprintf("TCP handshake to %s:%d took %d ms (threshold: 1000 ms).", result.TCP.Host, result.TCP.Port, latency.Milliseconds()),
		Severity:       "medium",
		Confidence:     0.75,
		AffectedLayer:  "TCP",
		Recommendation: "Check for network congestion or geographic distance. Consider connection pooling or keep-alive.",
	}
}

func (e *Engine) analyzeHTTPFailure(result *types.DiagnosticResult) *types.RootCause {
	if result.HTTP == nil {
		return &types.RootCause{
			RootCause:      "HTTP diagnostic not available",
			Evidence:       "HTTP results were not collected.",
			Severity:       "high",
			Confidence:     0.8,
			AffectedLayer:  "HTTP",
			Recommendation: "Re-run HTTP diagnostics.",
		}
	}

	if result.HTTP.IsTimeout {
		return &types.RootCause{
			RootCause:      "HTTP request timeout",
			Evidence:       fmt.Sprintf("HTTP request to %s timed out after %d ms. DNS and TCP succeeded.", result.HTTP.URL, result.HTTP.TotalDuration.Milliseconds()),
			Severity:       "critical",
			Confidence:     0.9,
			AffectedLayer:  "HTTP",
			Recommendation: "The server may be overloaded or unresponsive. Check server health and application logs.",
		}
	}

	statusCode := result.HTTP.StatusCode
	if statusCode >= 500 {
		return &types.RootCause{
			RootCause:      fmt.Sprintf("Server error (HTTP %d)", statusCode),
			Evidence:       fmt.Sprintf("Server returned HTTP %d %s. DNS and TCP connectivity are normal.", statusCode, result.HTTP.StatusText),
			Severity:       "high",
			Confidence:     0.95,
			AffectedLayer:  "HTTP",
			Recommendation: "The server is experiencing internal errors. Check application logs and server health.",
		}
	}

	if statusCode >= 400 {
		return &types.RootCause{
			RootCause:      fmt.Sprintf("Client error (HTTP %d)", statusCode),
			Evidence:       fmt.Sprintf("Server returned HTTP %d %s. The request may be malformed.", statusCode, result.HTTP.StatusText),
			Severity:       "medium",
			Confidence:     0.9,
			AffectedLayer:  "HTTP",
			Recommendation: "Verify the request URL, headers, and parameters.",
		}
	}

	if statusCode >= 300 && statusCode < 400 {
		return &types.RootCause{
			RootCause:      "HTTP redirect chain issue",
			Evidence:       fmt.Sprintf("Server returned HTTP %d with %d redirects.", statusCode, result.HTTP.RedirectCount),
			Severity:       "low",
			Confidence:     0.7,
			AffectedLayer:  "HTTP",
			Recommendation: "Check redirect configuration. Ensure redirect chains terminate properly.",
		}
	}

	return &types.RootCause{
		RootCause:      "HTTP request failed",
		Evidence:       fmt.Sprintf("HTTP request to %s failed: %s", result.HTTP.URL, result.HTTP.Error),
		Severity:       "high",
		Confidence:     0.85,
		AffectedLayer:  "HTTP",
		Recommendation: "Investigate server-side errors and network conditions.",
	}
}

func (e *Engine) analyzeSlowHTTP(result *types.DiagnosticResult, httpLatency, tcpLatency, dnsLatency time.Duration) *types.RootCause {
	// Determine if the issue is server-side or network-side
	serverTime := httpLatency - tcpLatency - dnsLatency
	if serverTime < 0 {
		serverTime = 0
	}

	if serverTime > httpLatency/2 {
		return &types.RootCause{
			RootCause:      "High HTTP response latency (server-side)",
			Evidence:       fmt.Sprintf("DNS: %d ms, TCP: %d ms, HTTP total: %d ms. Estimated server processing: %d ms.", dnsLatency.Milliseconds(), tcpLatency.Milliseconds(), httpLatency.Milliseconds(), serverTime.Milliseconds()),
			Severity:       "high",
			Confidence:     0.8,
			AffectedLayer:  "HTTP/Server",
			Recommendation: "Investigate server processing time, application performance, and database queries. The bottleneck is server-side.",
		}
	}

	return &types.RootCause{
		RootCause:      "High HTTP response latency (network-side)",
		Evidence:       fmt.Sprintf("DNS: %d ms, TCP: %d ms, HTTP total: %d ms. Significant latency in network layers.", dnsLatency.Milliseconds(), tcpLatency.Milliseconds(), httpLatency.Milliseconds()),
		Severity:       "medium",
		Confidence:     0.7,
		AffectedLayer:  "Network",
		Recommendation: "Check for network congestion, geographic distance, or intermediate proxy issues.",
	}
}

// CalculateHealthScore computes a 0-100 health score from diagnostic results.
func (e *Engine) CalculateHealthScore(result *types.DiagnosticResult) *types.HealthScore {
	health := &types.HealthScore{
		Layers: make([]types.LayerStatus, 0, 3),
	}

	var totalScore float64
	var layerCount float64

	// DNS Layer
	dnsScore := e.scoreDNS(result.DNS)
	totalScore += dnsScore
	layerCount++
	health.Layers = append(health.Layers, dnsScoreToLayerStatus(result.DNS, dnsScore))

	// TCP Layer
	tcpScore := e.scoreTCP(result.TCP)
	totalScore += tcpScore
	layerCount++
	health.Layers = append(health.Layers, tcpScoreToLayerStatus(result.TCP, tcpScore))

	// HTTP Layer
	httpScore := e.scoreHTTP(result.HTTP)
	totalScore += httpScore
	layerCount++
	health.Layers = append(health.Layers, httpScoreToLayerStatus(result.HTTP, httpScore))

	// Calculate overall score
	if layerCount > 0 {
		health.Score = int(math.Round(totalScore / layerCount))
	}

	// Clamp
	if health.Score < 0 {
		health.Score = 0
	}
	if health.Score > 100 {
		health.Score = 100
	}

	// Determine status
	switch {
	case health.Score >= 80:
		health.Status = "HEALTHY"
	case health.Score >= 50:
		health.Status = "DEGRADED"
	case health.Score >= 20:
		health.Status = "UNHEALTHY"
	default:
		health.Status = "CRITICAL"
	}

	// Run root-cause analysis
	rootCause := e.Analyze(result)
	if rootCause.Severity != "info" {
		health.RootCause = rootCause
	}

	health.Message = e.generateHealthMessage(health)
	return health
}

func (e *Engine) scoreDNS(dns *types.DNSResult) float64 {
	if dns == nil {
		return 50 // Unknown
	}
	if !dns.Success {
		return 0
	}
	// Score based on latency
	latencyMs := float64(dns.ResolutionTime.Milliseconds())
	switch {
	case latencyMs < 20:
		return 100
	case latencyMs < 50:
		return 95
	case latencyMs < 100:
		return 90
	case latencyMs < 200:
		return 80
	case latencyMs < 500:
		return 60
	case latencyMs < 1000:
		return 40
	default:
		return 20
	}
}

func (e *Engine) scoreTCP(tcp *types.TCPResult) float64 {
	if tcp == nil {
		return 50
	}
	if !tcp.Connected {
		return 0
	}
	latencyMs := float64(tcp.Latency.Milliseconds())
	switch {
	case latencyMs < 10:
		return 100
	case latencyMs < 30:
		return 95
	case latencyMs < 100:
		return 90
	case latencyMs < 200:
		return 80
	case latencyMs < 500:
		return 60
	case latencyMs < 1000:
		return 40
	default:
		return 20
	}
}

func (e *Engine) scoreHTTP(httpResult *types.HTTPResult) float64 {
	if httpResult == nil {
		return 50
	}
	if !httpResult.Success {
		return 0
	}
	latencyMs := float64(httpResult.TotalDuration.Milliseconds())
	switch {
	case latencyMs < 100:
		return 100
	case latencyMs < 200:
		return 95
	case latencyMs < 500:
		return 85
	case latencyMs < 1000:
		return 70
	case latencyMs < 2000:
		return 50
	case latencyMs < 5000:
		return 30
	default:
		return 10
	}
}

func dnsScoreToLayerStatus(dns *types.DNSResult, score float64) types.LayerStatus {
	status := types.LayerStatus{
		Layer: "DNS",
		Score: score,
	}

	if dns == nil {
		status.Status = "skipped"
		status.Message = "DNS not tested"
		return status
	}

	if !dns.Success {
		status.Status = "failed"
		status.Message = dns.Error
		return status
	}

	status.Status = "ok"
	status.Latency = fmt.Sprintf("%d ms", dns.ResolutionTime.Milliseconds())
	if score < 80 {
		status.Status = "warning"
		status.Message = "DNS latency is elevated"
	}
	return status
}

func tcpScoreToLayerStatus(tcp *types.TCPResult, score float64) types.LayerStatus {
	status := types.LayerStatus{
		Layer: "TCP",
		Score: score,
	}

	if tcp == nil {
		status.Status = "skipped"
		status.Message = "TCP not tested"
		return status
	}

	if !tcp.Connected {
		status.Status = "failed"
		if tcp.ErrorType == "refused" {
			status.Message = "Connection refused"
		} else if tcp.ErrorType == "timeout" {
			status.Message = "Connection timed out"
		} else {
			status.Message = tcp.Error
		}
		return status
	}

	status.Status = "ok"
	status.Latency = fmt.Sprintf("%d ms", tcp.Latency.Milliseconds())
	if score < 80 {
		status.Status = "warning"
		status.Message = "TCP latency is elevated"
	}
	return status
}

func httpScoreToLayerStatus(httpResult *types.HTTPResult, score float64) types.LayerStatus {
	status := types.LayerStatus{
		Layer: "HTTP",
		Score: score,
	}

	if httpResult == nil {
		status.Status = "skipped"
		status.Message = "HTTP not tested"
		return status
	}

	if !httpResult.Success {
		status.Status = "failed"
		if httpResult.Error != "" {
			status.Message = httpResult.Error
		} else {
			status.Message = fmt.Sprintf("HTTP %d", httpResult.StatusCode)
		}
		return status
	}

	status.Status = "ok"
	status.Latency = fmt.Sprintf("%d ms", httpResult.TotalDuration.Milliseconds())
	if score < 80 {
		status.Status = "warning"
		status.Message = "HTTP response time is elevated"
	}
	return status
}

func (e *Engine) generateHealthMessage(health *types.HealthScore) string {
	switch health.Status {
	case "HEALTHY":
		return "All network layers are performing within normal parameters."
	case "DEGRADED":
		return "Some network layers show degraded performance. Check layer details."
	case "UNHEALTHY":
		return "Multiple network layers are experiencing issues. Investigation recommended."
	case "CRITICAL":
		return "Critical network failures detected. Immediate attention required."
	default:
		return "Diagnostic status unknown."
	}
}

// --- Smart Correlation Analysis ---

// CorrelationResult provides deep causality chain analysis.
type CorrelationResult struct {
	Chain      []ChainLink `json:"chain"`
	Summary    string      `json:"summary"`
	RootLayer  string      `json:"root_layer"`
	ImpactDesc string      `json:"impact_description"`
}

// ChainLink is one step in the causality chain.
type ChainLink struct {
	Step    int    `json:"step"`
	Layer   string `json:"layer"`
	Status  string `json:"status"`
	Latency string `json:"latency"`
	Cause   string `json:"cause"`
	Effect  string `json:"effect"`
}

// AnalyzeCorrelation builds a causality chain from diagnostic results.
func (e *Engine) AnalyzeCorrelation(result *types.DiagnosticResult) *CorrelationResult {
	if result == nil {
		return &CorrelationResult{Summary: "No data to analyze"}
	}

	cr := &CorrelationResult{}
	step := 1

	// DNS Layer
	dnsStatus := "ok"
	dnsLatency := "0ms"
	dnsDetail := ""
	if result.DNS != nil {
		if result.DNS.Success {
			dnsLatency = fmt.Sprintf("%dms", result.DNS.ResolutionTime.Milliseconds())
			dnsDetail = fmt.Sprintf("Resolved to %s", joinIPs(result.DNS.IPv4Addresses))
		} else {
			dnsStatus = "failed"
			dnsDetail = result.DNS.Error
		}
	}
	cr.Chain = append(cr.Chain, ChainLink{
		Step:    step,
		Layer:   "DNS",
		Status:  dnsStatus,
		Latency: dnsLatency,
		Cause:   "Hostname resolution",
		Effect:  dnsDetail,
	})
	step++

	// TCP Layer (depends on DNS)
	tcpStatus := "ok"
	tcpLatency := "0ms"
	tcpDetail := ""
	var tcpMs float64
	if result.TCP != nil {
		if result.TCP.Connected {
			tcpMs = float64(result.TCP.Latency.Microseconds()) / 1000
			tcpLatency = fmt.Sprintf("%.1fms", tcpMs)
			tcpDetail = "Connected"
		} else {
			tcpStatus = "failed"
			tcpDetail = result.TCP.Error
		}
	}

	tcpCause := "TCP connection to resolved IP"
	if dnsStatus == "failed" {
		tcpCause = "Cannot connect — DNS failed upstream"
		tcpStatus = "blocked"
	}
	cr.Chain = append(cr.Chain, ChainLink{
		Step:    step,
		Layer:   "TCP",
		Status:  tcpStatus,
		Latency: tcpLatency,
		Cause:   tcpCause,
		Effect:  tcpDetail,
	})
	step++

	// HTTP Layer (depends on TCP)
	httpStatus := "ok"
	httpLatency := "0ms"
	httpDetail := ""
	var httpMs float64
	if result.HTTP != nil {
		if result.HTTP.Success {
			httpMs = float64(result.HTTP.TotalDuration.Microseconds()) / 1000
			httpLatency = fmt.Sprintf("%.1fms", httpMs)
			httpDetail = fmt.Sprintf("%d %s", result.HTTP.StatusCode, result.HTTP.StatusText)
		} else {
			httpStatus = "failed"
			httpDetail = result.HTTP.Error
		}
	}

	httpCause := "HTTP request/response"
	if tcpStatus == "failed" || tcpStatus == "blocked" {
		httpCause = "Cannot request — TCP failed upstream"
		httpStatus = "blocked"
	}
	cr.Chain = append(cr.Chain, ChainLink{
		Step:    step,
		Layer:   "HTTP",
		Status:  httpStatus,
		Latency: httpLatency,
		Cause:   httpCause,
		Effect:  httpDetail,
	})

	// Determine root layer
	switch {
	case dnsStatus == "failed":
		cr.RootLayer = "DNS"
		cr.ImpactDesc = "DNS failure cascaded — TCP and HTTP could not proceed"
	case tcpStatus == "failed":
		cr.RootLayer = "TCP"
		cr.ImpactDesc = "TCP connection failed — HTTP could not proceed"
	case httpStatus == "failed":
		cr.RootLayer = "HTTP"
		cr.ImpactDesc = "HTTP request failed — server-side issue"
	case httpMs > 1000:
		cr.RootLayer = "HTTP"
		cr.ImpactDesc = fmt.Sprintf("Slow HTTP response (%.0fms) — likely server load", httpMs)
	case tcpMs > 500:
		cr.RootLayer = "TCP"
		cr.ImpactDesc = fmt.Sprintf("Slow TCP handshake (%.0fms) — possible network congestion", tcpMs)
	default:
		cr.RootLayer = "none"
		cr.ImpactDesc = "All layers healthy — no cascading issues detected"
	}

	// Build summary
	var parts []string
	for _, l := range cr.Chain {
		parts = append(parts, fmt.Sprintf("%s=%s(%s)", l.Layer, l.Status, l.Latency))
	}
	cr.Summary = fmt.Sprintf("Chain: %s → Root: %s — %s",
		joinChain(parts), cr.RootLayer, cr.ImpactDesc)

	return cr
}

func joinIPs(ips []string) string {
	if len(ips) == 0 {
		return "unknown"
	}
	if len(ips) > 3 {
		return ips[0] + ", " + ips[1] + ", ..."
	}
	result := ""
	for i, ip := range ips {
		if i > 0 {
			result += ", "
		}
		result += ip
	}
	return result
}

func joinChain(parts []string) string {
	result := ""
	for i, p := range parts {
		if i > 0 {
			result += " → "
		}
		result += p
	}
	return result
}
