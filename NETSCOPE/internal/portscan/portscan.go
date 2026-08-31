// Package portscan provides concurrent TCP port scanning with timing.
package portscan

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// CommonPorts returns a list of well-known service ports.
var CommonPorts = []int{
	21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
	993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 8888, 9090, 27017,
}

// ServiceName returns the common service name for a port.
func ServiceName(port int) string {
	services := map[int]string{
		21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
		80: "HTTP", 110: "POP3", 111: "RPCBind", 135: "MSRPC", 139: "NetBIOS",
		143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
		1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 3389: "RDP",
		5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt",
		8443: "HTTPS-Alt", 8888: "HTTP-Proxy", 9090: "Admin", 27017: "MongoDB",
	}
	if s, ok := services[port]; ok {
		return s
	}
	return fmt.Sprintf("Port-%d", port)
}

// PortResult holds the scan result for a single port.
type PortResult struct {
	Port    int    `json:"port"`
	Service string `json:"service"`
	Open    bool   `json:"open"`
	Latency int64  `json:"latency_ms"` // milliseconds
	Error   string `json:"error,omitempty"`
}

// ScanRequest holds parameters for a port scan.
type ScanRequest struct {
	Host        string `json:"host"`
	Ports       []int  `json:"ports,omitempty"`
	Timeout     int    `json:"timeout_ms,omitempty"`  // per-port timeout
	Concurrency int    `json:"concurrency,omitempty"` // max concurrent probes
}

// ScanResult holds the full scan result.
type ScanResult struct {
	Host        string       `json:"host"`
	TotalPorts  int          `json:"total_ports"`
	OpenPorts   int          `json:"open_ports"`
	ClosedPorts int          `json:"closed_ports"`
	Results     []PortResult `json:"results"`
	Duration    int64        `json:"duration_ms"`
	StartTime   time.Time    `json:"start_time"`
}

// Scanner performs port scans.
type Scanner struct{}

// New creates a new Scanner.
func New() *Scanner {
	return &Scanner{}
}

// Scan performs a concurrent port scan.
func (s *Scanner) Scan(ctx context.Context, req ScanRequest) ScanResult {
	if len(req.Ports) == 0 {
		req.Ports = CommonPorts
	}
	if req.Timeout <= 0 {
		req.Timeout = 2000
	}
	if req.Concurrency <= 0 {
		req.Concurrency = 50
	}

	start := time.Now()
	results := make([]PortResult, len(req.Ports))
	timeout := time.Duration(req.Timeout) * time.Millisecond

	// Worker pool
	var wg sync.WaitGroup
	var openCount int64
	sem := make(chan struct{}, req.Concurrency)

	for i, port := range req.Ports {
		wg.Add(1)
		sem <- struct{}{}
		go func(idx, p int) {
			defer wg.Done()
			defer func() { <-sem }()

			result := scanPort(ctx, req.Host, p, timeout)
			results[idx] = result
			if result.Open {
				atomic.AddInt64(&openCount, 1)
			}
		}(i, port)
	}

	wg.Wait()

	// Sort by port number
	sort.Slice(results, func(i, j int) bool {
		return results[i].Port < results[j].Port
	})

	elapsed := time.Since(start)
	totalOpen := int(atomic.LoadInt64(&openCount))

	return ScanResult{
		Host:        req.Host,
		TotalPorts:  len(req.Ports),
		OpenPorts:   totalOpen,
		ClosedPorts: len(req.Ports) - totalOpen,
		Results:     results,
		Duration:    elapsed.Milliseconds(),
		StartTime:   start,
	}
}

// scanPort tests a single port.
func scanPort(ctx context.Context, host string, port int, timeout time.Duration) PortResult {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	start := time.Now()

	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	elapsed := time.Since(start)

	result := PortResult{
		Port:    port,
		Service: ServiceName(port),
		Latency: elapsed.Milliseconds(),
	}

	if err != nil {
		result.Open = false
		result.Error = classifyError(err)
	} else {
		result.Open = true
		conn.Close()
	}

	return result
}

// classifyError categorizes a dial error.
func classifyError(err error) string {
	if err == nil {
		return ""
	}
	errStr := err.Error()
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return "timeout"
	}
	// Check for connection refused across platforms (Linux, macOS, Windows)
	if strings.Contains(errStr, "connection refused") ||
		strings.Contains(errStr, "actively refused") ||
		strings.Contains(errStr, "No connection could be made") {
		return "refused"
	}
	if strings.Contains(errStr, "no route to host") || strings.Contains(errStr, "network is unreachable") {
		return "unreachable"
	}
	return errStr
}
