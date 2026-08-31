// Package types defines shared data structures for NetScope diagnostics.
package types

import "time"

// DiagnosticTarget represents the target of a diagnostic operation.
type DiagnosticTarget struct {
	Host    string `json:"host"`
	Port    int    `json:"port"`
	URL     string `json:"url,omitempty"`
	Proto   string `json:"proto,omitempty"` // "tcp" or "udp" for DNS
	Timeout int    `json:"timeout_ms,omitempty"`
}

// DNSResult holds DNS diagnostic results.
type DNSResult struct {
	Host            string        `json:"host"`
	IPv4Addresses   []string      `json:"ipv4_addresses"`
	IPv6Addresses   []string      `json:"ipv6_addresses"`
	ResolutionTime  time.Duration `json:"resolution_time_ms"`
	Success         bool          `json:"success"`
	Error           string        `json:"error,omitempty"`
	Resolver        string        `json:"resolver"`
	IsTimeout       bool          `json:"is_timeout"`
	TTL             time.Duration `json:"ttl,omitempty"`
}

// TCPResult holds TCP diagnostic results.
type TCPResult struct {
	Host           string        `json:"host"`
	Port           int           `json:"port"`
	Connected      bool          `json:"connected"`
	Latency        time.Duration `json:"latency_ms"`
	Error          string        `json:"error,omitempty"`
	ErrorType      string        `json:"error_type,omitempty"` // "timeout", "refused", "dns", "other"
	IsTimeout      bool          `json:"is_timeout"`
	RemoteAddr     string        `json:"remote_addr,omitempty"`
}

// HTTPResult holds HTTP diagnostic results.
type HTTPResult struct {
	URL              string        `json:"url"`
	StatusCode       int           `json:"status_code"`
	StatusText       string        `json:"status_text"`
	DNSResolution    time.Duration `json:"dns_resolution_ms"`
	TCPConnection    time.Duration `json:"tcp_connection_ms"`
	TLSHandshake     time.Duration `json:"tls_handshake_ms"`
	TimeToFirstByte  time.Duration `json:"time_to_first_byte_ms"`
	TotalDuration    time.Duration `json:"total_duration_ms"`
	ResponseSize     int64         `json:"response_size_bytes"`
	RedirectCount    int           `json:"redirect_count"`
	Headers          []HTTPHeader  `json:"headers,omitempty"`
	Success          bool          `json:"success"`
	Error            string        `json:"error,omitempty"`
	ErrorType        string        `json:"error_type,omitempty"`
	IsTimeout        bool          `json:"is_timeout"`
}

// HTTPHeader represents a response header.
type HTTPHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// LayerStatus represents the health of a single network layer.
type LayerStatus struct {
	Layer   string  `json:"layer"`
	Status  string  `json:"status"` // "ok", "warning", "failed", "skipped"
	Latency string  `json:"latency,omitempty"`
	Message string  `json:"message,omitempty"`
	Score   float64 `json:"score"`
}

// RootCause represents a diagnosed root cause.
type RootCause struct {
	RootCause     string  `json:"root_cause"`
	Evidence      string  `json:"evidence"`
	Severity      string  `json:"severity"` // "critical", "high", "medium", "low", "info"
	Confidence    float64 `json:"confidence"` // 0-1
	AffectedLayer string  `json:"affected_layer"`
	Recommendation string `json:"recommendation"`
}

// HealthScore holds the overall network health assessment.
type HealthScore struct {
	Score      int          `json:"score"`
	Status     string       `json:"status"` // "HEALTHY", "DEGRADED", "UNHEALTHY", "CRITICAL"
	Layers     []LayerStatus `json:"layers"`
	RootCause  *RootCause   `json:"root_cause,omitempty"`
	Message    string       `json:"message,omitempty"`
}

// DiagnosticResult holds the complete result of a diagnostic run.
type DiagnosticResult struct {
	Target   DiagnosticTarget `json:"target"`
	DNS      *DNSResult       `json:"dns,omitempty"`
	TCP      *TCPResult       `json:"tcp,omitempty"`
	HTTP     *HTTPResult      `json:"http,omitempty"`
	Health   *HealthScore     `json:"health"`
	Timestamp time.Time       `json:"timestamp"`
}

// StressTestResult holds results from a stress/concurrency test.
type StressTestResult struct {
	Target          string  `json:"target"`
	Port            int     `json:"port"`
	TotalRequests   int     `json:"total_requests"`
	Successful      int     `json:"successful"`
	Failed          int     `json:"failed"`
	Timeouts        int     `json:"timeouts"`
	SuccessRate     float64 `json:"success_rate"`
	FailureRate     float64 `json:"failure_rate"`
	AvgLatency      float64 `json:"avg_latency_ms"`
	MinLatency      float64 `json:"min_latency_ms"`
	MaxLatency      float64 `json:"max_latency_ms"`
	P50             float64 `json:"p50_ms"`
	P95             float64 `json:"p95_ms"`
	P99             float64 `json:"p99_ms"`
	RequestsPerSec  float64 `json:"requests_per_sec"`
	TotalDuration   float64 `json:"total_duration_ms"`
	Latencies       []float64 `json:"-"`
}

// Event represents a real-time diagnostic event for SSE streaming.
type Event struct {
	Type    string `json:"type"`
	Message string `json:"message"`
	Layer   string `json:"layer,omitempty"`
	Status  string `json:"status,omitempty"`
	Value   any    `json:"value,omitempty"`
}

// SimulatorState holds the current state of the failure simulator.
type SimulatorState struct {
	Mode          string `json:"mode"` // "normal", "break_dns", "break_tcp", "break_http", "add_latency", "http_errors", "timeout"
	LatencyMs     int    `json:"latency_ms"`
	HTTPErrorCode int    `json:"http_error_code"`
}

// PortInUse checks if a common port is in the range.
func ValidPort(p int) bool {
	return p > 0 && p <= 65535
}
