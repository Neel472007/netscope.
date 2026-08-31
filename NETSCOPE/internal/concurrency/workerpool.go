// Package concurrency provides a bounded worker pool for stress testing.
package concurrency

import (
	"context"
	"sync"
	"time"

	"github.com/Neel472007/netscope/internal/types"
)

const (
	MaxConcurrency = 10000
	MinConcurrency = 1
)

// StressTestFunc is the function called for each concurrent request.
type StressTestFunc func(ctx context.Context) (latency time.Duration, success bool, isTimeout bool)

// StressConfig configures a stress test run.
type StressConfig struct {
	Concurrency int
	Duration    time.Duration
	Interval    time.Duration // interval between request bursts
}

// StressRunner executes concurrent stress tests.
type StressRunner struct {
	config StressConfig
}

// NewStressRunner creates a new stress test runner.
func NewStressRunner(config StressConfig) *StressRunner {
	if config.Concurrency < MinConcurrency {
		config.Concurrency = MinConcurrency
	}
	if config.Concurrency > MaxConcurrency {
		config.Concurrency = MaxConcurrency
	}
	if config.Duration <= 0 {
		config.Duration = 5 * time.Second
	}
	if config.Interval <= 0 {
		config.Interval = 10 * time.Millisecond
	}
	return &StressRunner{config: config}
}

// Run executes the stress test and returns aggregated results.
func (sr *StressRunner) Run(ctx context.Context, fn StressTestFunc) *types.StressTestResult {
	result := &types.StressTestResult{}
	var mu sync.Mutex
	var latencies []float64

	sem := make(chan struct{}, sr.config.Concurrency)
	var wg sync.WaitGroup

	deadline := time.Now().Add(sr.config.Duration)
	startTime := time.Now()

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

			latency, success, isTimeout := fn(ctx)

			mu.Lock()
			if success {
				result.Successful++
				latencies = append(latencies, float64(latency.Microseconds())/1000.0)
			} else {
				result.Failed++
				if isTimeout {
					result.Timeouts++
				}
			}
			mu.Unlock()
		}()

		time.Sleep(sr.config.Interval)
	}

done:
	wg.Wait()

	totalElapsed := time.Since(startTime)
	totalRequests := result.Successful + result.Failed

	result.TotalRequests = totalRequests
	result.TotalDuration = float64(totalElapsed.Milliseconds())

	if totalRequests > 0 {
		result.SuccessRate = float64(result.Successful) / float64(totalRequests) * 100
		result.FailureRate = float64(result.Failed) / float64(totalRequests) * 100
		result.RequestsPerSec = float64(totalRequests) / totalElapsed.Seconds()
	}

	// Calculate percentile metrics
	if len(latencies) > 0 {
		result.Latencies = latencies
		result.AvgLatency = calcAvg(latencies)
		result.MinLatency = calcMin(latencies)
		result.MaxLatency = calcMax(latencies)
		result.P50 = calcPercentile(latencies, 50)
		result.P95 = calcPercentile(latencies, 95)
		result.P99 = calcPercentile(latencies, 99)
	}

	return result
}

// RunWithUpdates executes the stress test and sends progress events.
func (sr *StressRunner) RunWithUpdates(ctx context.Context, fn StressTestFunc, updateFn func(event types.Event)) *types.StressTestResult {
	if updateFn != nil {
		updateFn(types.Event{Type: "stress_start", Message: "Starting stress test"})
	}
	result := sr.Run(ctx, fn)
	if updateFn != nil {
		updateFn(types.Event{Type: "stress_complete", Message: "Stress test complete", Value: result})
	}
	return result
}

func calcAvg(data []float64) float64 {
	if len(data) == 0 {
		return 0
	}
	sum := 0.0
	for _, v := range data {
		sum += v
	}
	return sum / float64(len(data))
}

func calcMin(data []float64) float64 {
	if len(data) == 0 {
		return 0
	}
	min := data[0]
	for _, v := range data[1:] {
		if v < min {
			min = v
		}
	}
	return min
}

func calcMax(data []float64) float64 {
	if len(data) == 0 {
		return 0
	}
	max := data[0]
	for _, v := range data[1:] {
		if v > max {
			max = v
		}
	}
	return max
}

// calcPercentile calculates the p-th percentile using nearest-rank method.
func calcPercentile(data []float64, p int) float64 {
	if len(data) == 0 {
		return 0
	}
	// Sort a copy
	sorted := make([]float64, len(data))
	copy(sorted, data)
	sortFloats(sorted)

	idx := int(float64(p) / 100.0 * float64(len(sorted)))
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

// sortFloats sorts float64 slice in ascending order.
func sortFloats(data []float64) {
	for i := 1; i < len(data); i++ {
		key := data[i]
		j := i - 1
		for j >= 0 && data[j] > key {
			data[j+1] = data[j]
			j--
		}
		data[j+1] = key
	}
}
