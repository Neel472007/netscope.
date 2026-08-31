package diagnostics

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/Neel472007/netscope/internal/dns"
	"github.com/Neel472007/netscope/internal/httpdiag"
	"github.com/Neel472007/netscope/internal/tcp"
	"github.com/Neel472007/netscope/internal/types"
	"github.com/Neel472007/netscope/internal/validate"
)

// Orchestrator coordinates diagnostic operations.
type Orchestrator struct {
	dnsEngine  *dns.Engine
	tcpEngine  *tcp.Engine
	httpEngine *httpdiag.Engine
	analyzer   *Engine
}

// NewOrchestrator creates a new diagnostic orchestrator.
func NewOrchestrator() *Orchestrator {
	return &Orchestrator{
		dnsEngine:  dns.NewEngine(),
		tcpEngine:  tcp.NewEngine(),
		httpEngine: httpdiag.NewEngine(),
		analyzer:   NewEngine(),
	}
}

// DiagnoseTarget runs all applicable diagnostics against a target concurrently.
func (o *Orchestrator) DiagnoseTarget(ctx context.Context, target string) (*types.DiagnosticResult, error) {
	host, port, useHTTPS, path, err := validate.ParseTarget(target)
	if err != nil {
		return nil, fmt.Errorf("invalid target: %w", err)
	}

	result := &types.DiagnosticResult{
		Target: types.DiagnosticTarget{
			Host:  host,
			Port:  port,
			URL:   target,
			Proto: "tcp",
		},
		Timestamp: time.Now(),
	}

	// Phase 1: DNS resolution (must complete before TCP)
	dnsResult := o.dnsEngine.Resolve(ctx, host)
	result.DNS = dnsResult

	if !dnsResult.Success {
		// DNS failed — cannot proceed with TCP/HTTP
		health := o.analyzer.CalculateHealthScore(result)
		result.Health = health
		return result, nil
	}

	// Phase 2: TCP and HTTP can run concurrently
	var wg sync.WaitGroup
	var mu sync.Mutex

	// TCP check
	wg.Add(1)
	go func() {
		defer wg.Done()
		tcpResult := o.tcpEngine.Test(ctx, host, port)
		mu.Lock()
		result.TCP = tcpResult
		mu.Unlock()
	}()

	// HTTP check (runs concurrently with TCP)
	scheme := "https"
	if !useHTTPS {
		scheme = "http"
	}
	httpURL := fmt.Sprintf("%s://%s:%d%s", scheme, host, port, path)

	wg.Add(1)
	go func() {
		defer wg.Done()
		httpResult := o.httpEngine.Diagnose(ctx, httpURL)
		mu.Lock()
		result.HTTP = httpResult
		mu.Unlock()
	}()

	wg.Wait()

	// Calculate health score
	health := o.analyzer.CalculateHealthScore(result)
	result.Health = health

	return result, nil
}

// DiagnoseTargetStream runs diagnostics and sends progress events via the callback.
func (o *Orchestrator) DiagnoseTargetStream(ctx context.Context, target string, eventFn func(types.Event)) (*types.DiagnosticResult, error) {
	host, port, useHTTPS, path, err := validate.ParseTarget(target)
	if err != nil {
		return nil, fmt.Errorf("invalid target: %w", err)
	}

	result := &types.DiagnosticResult{
		Target: types.DiagnosticTarget{
			Host:  host,
			Port:  port,
			URL:   target,
			Proto: "tcp",
		},
		Timestamp: time.Now(),
	}

	sendEvent := func(e types.Event) {
		if eventFn != nil {
			eventFn(e)
		}
	}

	// DNS
	sendEvent(types.Event{Type: "progress", Layer: "DNS", Status: "running", Message: "Resolving DNS..."})
	dnsResult := o.dnsEngine.Resolve(ctx, host)
	result.DNS = dnsResult
	if dnsResult.Success {
		sendEvent(types.Event{Type: "progress", Layer: "DNS", Status: "ok", Message: fmt.Sprintf("DNS resolved in %d ms", dnsResult.ResolutionTime.Milliseconds())})
	} else {
		sendEvent(types.Event{Type: "progress", Layer: "DNS", Status: "failed", Message: "DNS resolution failed"})
	}

	if !dnsResult.Success {
		health := o.analyzer.CalculateHealthScore(result)
		result.Health = health
		sendEvent(types.Event{Type: "complete", Message: "Diagnostics complete", Value: result})
		return result, nil
	}

	// TCP + HTTP concurrently
	var wg sync.WaitGroup
	var mu sync.Mutex

	scheme := "https"
	if !useHTTPS {
		scheme = "http"
	}
	httpURL := fmt.Sprintf("%s://%s:%d%s", scheme, host, port, path)

	sendEvent(types.Event{Type: "progress", Layer: "TCP", Status: "running", Message: "Testing TCP connectivity..."})
	sendEvent(types.Event{Type: "progress", Layer: "HTTP", Status: "running", Message: "Performing HTTP request..."})

	wg.Add(1)
	go func() {
		defer wg.Done()
		tcpResult := o.tcpEngine.Test(ctx, host, port)
		mu.Lock()
		result.TCP = tcpResult
		mu.Unlock()
		if tcpResult.Connected {
			sendEvent(types.Event{Type: "progress", Layer: "TCP", Status: "ok", Message: fmt.Sprintf("TCP connected in %d ms", tcpResult.Latency.Milliseconds())})
		} else {
			sendEvent(types.Event{Type: "progress", Layer: "TCP", Status: "failed", Message: "TCP connection failed"})
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		httpResult := o.httpEngine.Diagnose(ctx, httpURL)
		mu.Lock()
		result.HTTP = httpResult
		mu.Unlock()
		if httpResult.Success {
			sendEvent(types.Event{Type: "progress", Layer: "HTTP", Status: "ok", Message: fmt.Sprintf("HTTP %d in %d ms", httpResult.StatusCode, httpResult.TotalDuration.Milliseconds())})
		} else {
			sendEvent(types.Event{Type: "progress", Layer: "HTTP", Status: "failed", Message: "HTTP request failed"})
		}
	}()

	wg.Wait()

	sendEvent(types.Event{Type: "progress", Layer: "Analysis", Status: "running", Message: "Analyzing results..."})

	// Calculate health score
	health := o.analyzer.CalculateHealthScore(result)
	result.Health = health

	sendEvent(types.Event{Type: "complete", Message: "Diagnostics complete", Value: result})
	return result, nil
}
