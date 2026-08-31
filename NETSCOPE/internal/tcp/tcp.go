// Package tcp provides TCP connectivity diagnostics.
package tcp

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Neel472007/netscope/internal/types"
)

// Engine performs TCP diagnostics.
type Engine struct {
	timeout time.Duration
}

// NewEngine creates a new TCP engine.
func NewEngine() *Engine {
	return &Engine{
		timeout: 5 * time.Second,
	}
}

// SetTimeout sets the TCP connection timeout.
func (e *Engine) SetTimeout(d time.Duration) {
	e.timeout = d
}

// Test performs a single TCP connectivity test.
func (e *Engine) Test(ctx context.Context, host string, port int) *types.TCPResult {
	result := &types.TCPResult{
		Host: host,
		Port: port,
	}

	addr := fmt.Sprintf("%s:%d", host, port)

	ctx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()

	dialer := &net.Dialer{
		Timeout:   e.timeout,
		KeepAlive: 0, // No keep-alive for diagnostic connections
	}

	start := time.Now()
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	elapsed := time.Since(start)

	if err != nil {
		result.Connected = false
		result.Latency = elapsed
		result.Error = err.Error()
		result.ErrorType = classifyTCPError(err)

		if ctx.Err() == context.DeadlineExceeded {
			result.IsTimeout = true
		}
		return result
	}

	// Get remote address
	if tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		result.RemoteAddr = tcpAddr.IP.String()
	}

	conn.Close()

	result.Connected = true
	result.Latency = elapsed
	return result
}

// TestConcurrent performs multiple concurrent TCP connection tests.
func (e *Engine) TestConcurrent(ctx context.Context, host string, port, concurrency int) []types.TCPResult {
	results := make([]types.TCPResult, concurrency)
	var wg sync.WaitGroup
	var successCount, failCount int64

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			r := e.Test(ctx, host, port)
			results[idx] = *r
			if r.Connected {
				atomic.AddInt64(&successCount, 1)
			} else {
				atomic.AddInt64(&failCount, 1)
			}
		}(i)
	}

	wg.Wait()
	return results
}

// TestStress performs a stress test with the given parameters and returns aggregated results.
func (e *Engine) TestStress(ctx context.Context, host string, port, concurrency int, duration time.Duration) *types.StressTestResult {
	result := &types.StressTestResult{
		Target: host,
		Port:   port,
	}

	var mu sync.Mutex
	var latencies []float64
	var successCount, failCount, timeoutCount int64

	deadline := time.Now().Add(duration)
	var wg sync.WaitGroup

	// Bounded concurrency with semaphore
	sem := make(chan struct{}, concurrency)

	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			goto done
		default:
		}

		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			r := e.Test(ctx, host, port)
			mu.Lock()
			if r.Connected {
				atomic.AddInt64(&successCount, 1)
				latencies = append(latencies, float64(r.Latency.Microseconds())/1000.0)
			} else {
				atomic.AddInt64(&failCount, 1)
				if r.IsTimeout {
					atomic.AddInt64(&timeoutCount, 1)
				}
			}
			mu.Unlock()
		}()
	}

done:
	wg.Wait()

	totalRequests := successCount + failCount
	totalDuration := time.Since(time.Now().Add(-duration)).Seconds() * 1000

	result.TotalRequests = int(totalRequests)
	result.Successful = int(successCount)
	result.Failed = int(failCount)
	result.Timeouts = int(timeoutCount)
	result.TotalDuration = totalDuration

	if totalRequests > 0 {
		result.SuccessRate = float64(successCount) / float64(totalRequests) * 100
		result.FailureRate = float64(failCount) / float64(totalRequests) * 100
		result.RequestsPerSec = float64(totalRequests) / (duration.Seconds())
	}

	result.Latencies = latencies
	return result
}

// classifyTCPError categorizes a TCP error.
func classifyTCPError(err error) string {
	errStr := err.Error()

	if strings.Contains(errStr, "timeout") || strings.Contains(errStr, "deadline exceeded") {
		return "timeout"
	}
	if strings.Contains(errStr, "connection refused") {
		return "refused"
	}
	if strings.Contains(errStr, "no such host") || strings.Contains(errStr, "lookup") {
		return "dns"
	}
	if strings.Contains(errStr, "no route") || strings.Contains(errStr, "network is unreachable") {
		return "unreachable"
	}
	if strings.Contains(errStr, "connection reset") {
		return "reset"
	}
	return "other"
}
