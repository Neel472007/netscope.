// Package multiscan performs concurrent network diagnostics across multiple targets
// and produces a comparison matrix for side-by-side analysis.
package multiscan

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/Neel472007/netscope/internal/dns"
	"github.com/Neel472007/netscope/internal/httpdiag"
	"github.com/Neel472007/netscope/internal/portscan"
	"github.com/Neel472007/netscope/internal/tcp"
)

// TargetResult holds the diagnostic result for a single target.
type TargetResult struct {
	Host       string                 `json:"host"`
	DNS        *dnsResult             `json:"dns"`
	TCP        *tcpResult             `json:"tcp"`
	HTTP       *httpResult            `json:"http"`
	OpenPorts  int                    `json:"open_ports"`
	Score      int                    `json:"score"`
	Overall    string                 `json:"overall"`
	Error      string                 `json:"error,omitempty"`
}

type dnsResult struct {
	Success bool     `json:"success"`
	Latency float64 `json:"latency_ms"`
	IPs     []string `json:"ips,omitempty"`
}

type tcpResult struct {
	Connected bool    `json:"connected"`
	Latency   float64 `json:"latency_ms"`
	Error     string  `json:"error,omitempty"`
}

type httpResult struct {
	Success    bool    `json:"success"`
	StatusCode int     `json:"status_code"`
	Latency    float64 `json:"latency_ms"`
	Error      string  `json:"error,omitempty"`
}

// ScanResult holds the full multi-target comparison.
type ScanResult struct {
	Targets    []TargetResult `json:"targets"`
	StartedAt  time.Time      `json:"started_at"`
	EndedAt    time.Time      `json:"ended_at"`
	Duration   float64        `json:"duration_ms"`
	TotalHosts int            `json:"total_hosts"`
	Healthy    int            `json:"healthy"`
	Degraded   int            `json:"degraded"`
	Failed     int            `json:"failed"`
}

// Scan performs concurrent diagnostics on multiple targets.
func Scan(ctx context.Context, hosts []string, port int, concurrency int) *ScanResult {
	if port == 0 {
		port = 80
	}
	if concurrency <= 0 {
		concurrency = 5
	}

	result := &ScanResult{
		StartedAt:  time.Now(),
		TotalHosts: len(hosts),
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, concurrency)

	for _, host := range hosts {
		wg.Add(1)
		sem <- struct{}{}
		go func(h string) {
			defer wg.Done()
			defer func() { <-sem }()

			res := scanTarget(ctx, h, port)
			mu.Lock()
			result.Targets = append(result.Targets, res)
			switch res.Overall {
			case "healthy":
				result.Healthy++
			case "degraded":
				result.Degraded++
			default:
				result.Failed++
			}
			mu.Unlock()
		}(host)
	}

	wg.Wait()
	result.EndedAt = time.Now()
	result.Duration = float64(result.EndedAt.Sub(result.StartedAt).Milliseconds())
	return result
}

func scanTarget(ctx context.Context, host string, port int) TargetResult {
	res := TargetResult{Host: host, Overall: "healthy"}
	score := 100

	// DNS
	dnsEng := dns.NewEngine()
	dnsCtx, dnsCancel := context.WithTimeout(ctx, 5*time.Second)
	dnsRes := dnsEng.Resolve(dnsCtx, host)
	dnsCancel()

	if dnsRes.Success {
		res.DNS = &dnsResult{
			Success: true,
			Latency: float64(dnsRes.ResolutionTime.Microseconds()) / 1000.0,
			IPs:     append(dnsRes.IPv4Addresses, dnsRes.IPv6Addresses...),
		}
		if res.DNS.Latency > 200 {
			score -= 10
		}
	} else {
		res.DNS = &dnsResult{Success: false}
		score -= 40
	}

	// TCP
	tcpEng := tcp.NewEngine()
	tcpCtx, tcpCancel := context.WithTimeout(ctx, 5*time.Second)
	tcpRes := tcpEng.Test(tcpCtx, host, port)
	tcpCancel()

	if tcpRes.Connected {
		res.TCP = &tcpResult{
			Connected: true,
			Latency:   float64(tcpRes.Latency.Microseconds()) / 1000.0,
		}
		if res.TCP.Latency > 200 {
			score -= 10
		}
	} else {
		res.TCP = &tcpResult{
			Connected: false,
			Error:     tcpRes.Error,
		}
		score -= 30
	}

	// HTTP
	if res.DNS != nil && res.DNS.Success {
		httpEng := httpdiag.NewEngine()
		scheme := "https"
		if port == 80 || port == 8080 {
			scheme = "http"
		}
		httpURL := fmt.Sprintf("%s://%s:%d", scheme, host, port)
		httpCtx, httpCancel := context.WithTimeout(ctx, 10*time.Second)
		httpRes := httpEng.Diagnose(httpCtx, httpURL)
		httpCancel()

		if httpRes.Success {
			res.HTTP = &httpResult{
				Success:    true,
				StatusCode: httpRes.StatusCode,
				Latency:    float64(httpRes.TotalDuration.Microseconds()) / 1000.0,
			}
			if res.HTTP.Latency > 1000 {
				score -= 10
			}
		} else {
			res.HTTP = &httpResult{
				Success: false,
				Error:   httpRes.Error,
			}
			score -= 15
		}
	}

	// Quick port scan (top 5 ports only)
	scanCtx, scanCancel := context.WithTimeout(ctx, 5*time.Second)
	scanner := portscan.New()
	topPorts := []int{80, 443, 22, 21, 8080}
	scanRes := scanner.Scan(scanCtx, portscan.ScanRequest{
		Host:        host,
		Ports:       topPorts,
		Concurrency: 5,
	})
	scanCancel()
	res.OpenPorts = scanRes.OpenPorts

	if score < 0 {
		score = 0
	}
	res.Score = score

	switch {
	case score >= 80:
		res.Overall = "healthy"
	case score >= 50:
		res.Overall = "degraded"
	default:
		res.Overall = "critical"
	}

	return res
}

// ResolveHosts resolves a list of hostnames to IP addresses for pre-checking.
func ResolveHosts(hosts []string) map[string][]string {
	result := make(map[string][]string)
	for _, host := range hosts {
		ips, err := net.LookupIP(host)
		if err == nil {
			for _, ip := range ips {
				result[host] = append(result[host], ip.String())
			}
		}
	}
	return result
}
