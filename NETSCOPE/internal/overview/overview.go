// Package overview provides a unified network overview that runs all diagnostics
// in parallel and produces a single comprehensive JSON report.
package overview

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/Neel472007/netscope/internal/benchmark"
	"github.com/Neel472007/netscope/internal/dns"
	"github.com/Neel472007/netscope/internal/httpdiag"
	"github.com/Neel472007/netscope/internal/portscan"
	"github.com/Neel472007/netscope/internal/tcp"
	"github.com/Neel472007/netscope/internal/tlsinspector"
	"github.com/Neel472007/netscope/internal/types"
)

// Report is the unified network overview report.
type Report struct {
	Target    string                `json:"target"`
	Host      string                `json:"host"`
	Port      int                   `json:"port"`
	StartedAt time.Time             `json:"started_at"`
	EndedAt   time.Time             `json:"ended_at"`
	Duration  float64               `json:"duration_ms"`
	DNS       *types.DNSResult      `json:"dns,omitempty"`
	TCP       *types.TCPResult      `json:"tcp,omitempty"`
	HTTP      *types.HTTPResult     `json:"http,omitempty"`
	TLS       *tlsinspector.TLSResult `json:"tls,omitempty"`
	Benchmark *benchmark.Result     `json:"benchmark,omitempty"`
	OpenPorts []portscan.PortResult `json:"open_ports,omitempty"`
	Summary   Summary               `json:"summary"`
}

// Summary provides a quick overview of the network state.
type Summary struct {
	Overall    string  `json:"overall"`    // "healthy", "degraded", "critical"
	DNSOK      bool    `json:"dns_ok"`
	TCPMS      float64 `json:"tcp_ms"`
	HTTPMS     float64 `json:"http_ms"`
	TLSValid   bool    `json:"tls_valid"`
	OpenPorts  int     `json:"open_ports"`
	BenchGrade string  `json:"bench_grade"`
	Score      int     `json:"score"`
}

// Engine performs unified network overview.
type Engine struct {
	dnsEng    *dns.Engine
	tcpEng    *tcp.Engine
	httpEng   *httpdiag.Engine
}

// NewEngine creates a new overview engine.
func NewEngine() *Engine {
	return &Engine{
		dnsEng:  dns.NewEngine(),
		tcpEng:  tcp.NewEngine(),
		httpEng: httpdiag.NewEngine(),
	}
}

// Scan runs all diagnostics in parallel and returns a unified report.
func (e *Engine) Scan(ctx context.Context, target string, port int, benchRounds int) *Report {
	report := &Report{
		Target:    target,
		Host:      target,
		Port:      port,
		StartedAt: time.Now(),
	}

	if port == 0 {
		port = 80
	}
	report.Port = port

	var wg sync.WaitGroup
	var mu sync.Mutex

	// Phase 1: DNS (must complete first for other tests)
	dnsCtx, dnsCancel := context.WithTimeout(ctx, 10*time.Second)
	dnsResult := e.dnsEng.Resolve(dnsCtx, target)
	dnsCancel()

	mu.Lock()
	report.DNS = dnsResult
	mu.Unlock()

	if !dnsResult.Success {
		report.EndedAt = time.Now()
		report.Duration = float64(report.EndedAt.Sub(report.StartedAt).Milliseconds())
		report.Summary = Summary{Overall: "critical", DNSOK: false, Score: 0}
		return report
	}

	// Phase 2: Everything else in parallel
	// TCP Test
	wg.Add(1)
	go func() {
		defer wg.Done()
		tcpCtx, tcpCancel := context.WithTimeout(ctx, 10*time.Second)
		defer tcpCancel()
		result := e.tcpEng.Test(tcpCtx, target, port)
		mu.Lock()
		report.TCP = result
		mu.Unlock()
	}()

	// HTTP Test
	wg.Add(1)
	go func() {
		defer wg.Done()
		scheme := "https"
		if port == 80 || port == 8080 {
			scheme = "http"
		}
		httpURL := fmt.Sprintf("%s://%s:%d", scheme, target, port)
		httpCtx, httpCancel := context.WithTimeout(ctx, 15*time.Second)
		defer httpCancel()
		result := e.httpEng.Diagnose(httpCtx, httpURL)
		mu.Lock()
		report.HTTP = result
		mu.Unlock()
	}()

	// TLS Inspection (only for HTTPS)
	if port == 443 || port == 8443 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result := tlsinspector.Inspect(target, port)
			mu.Lock()
			report.TLS = result
			mu.Unlock()
		}()
	}

	// Benchmark (quick: 5 rounds)
	wg.Add(1)
	go func() {
		defer wg.Done()
		if benchRounds <= 0 {
			benchRounds = 5
		}
		result := benchmark.Benchmark(target, port, benchRounds, 3)
		mu.Lock()
		report.Benchmark = result
		mu.Unlock()
	}()

	// Port Scan (common ports only for speed)
	wg.Add(1)
	go func() {
		defer wg.Done()
		scanCtx, scanCancel := context.WithTimeout(ctx, 15*time.Second)
		defer scanCancel()
		scanner := portscan.New()
		result := scanner.Scan(scanCtx, portscan.ScanRequest{
			Host:        target,
			Ports:       portscan.CommonPorts,
			Concurrency: 50,
		})
		mu.Lock()
		for _, r := range result.Results {
			if r.Open {
				report.OpenPorts = append(report.OpenPorts, r)
			}
		}
		mu.Unlock()
	}()

	wg.Wait()

	report.EndedAt = time.Now()
	report.Duration = float64(report.EndedAt.Sub(report.StartedAt).Milliseconds())

	// Build summary
	report.Summary = buildSummary(report)
	return report
}

func buildSummary(r *Report) Summary {
	s := Summary{
		DNSOK:      r.DNS != nil && r.DNS.Success,
		OpenPorts:  len(r.OpenPorts),
		TLSValid:   r.TLS != nil && r.TLS.Verified,
	}

	if r.TCP != nil && r.TCP.Connected {
		s.TCPMS = float64(r.TCP.Latency.Microseconds()) / 1000.0
	}
	if r.HTTP != nil {
		s.HTTPMS = float64(r.HTTP.TotalDuration.Microseconds()) / 1000.0
	}
	if r.Benchmark != nil {
		s.BenchGrade = r.Benchmark.Grade
	}

	// Calculate score
	score := 100
	if !s.DNSOK {
		score -= 40
	}
	if r.TCP == nil || !r.TCP.Connected {
		score -= 30
	} else if s.TCPMS > 200 {
		score -= 10
	} else if s.TCPMS > 100 {
		score -= 5
	}
	if r.HTTP == nil || !r.HTTP.Success {
		score -= 20
	} else if s.HTTPMS > 1000 {
		score -= 10
	} else if s.HTTPMS > 500 {
		score -= 5
	}
	if !s.TLSValid && r.Port == 443 {
		score -= 10
	}
	if s.OpenPorts == 0 {
		score -= 5
	}
	if score < 0 {
		score = 0
	}
	s.Score = score

	switch {
	case score >= 80:
		s.Overall = "healthy"
	case score >= 50:
		s.Overall = "degraded"
	default:
		s.Overall = "critical"
	}

	return s
}
