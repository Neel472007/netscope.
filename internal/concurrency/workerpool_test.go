package concurrency

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestStressRunnerBasic(t *testing.T) {
	runner := NewStressRunner(StressConfig{
		Concurrency: 5,
		Duration:    1 * time.Second,
		Interval:    10 * time.Millisecond,
	})

	var count int64
	result := runner.Run(context.Background(), func(ctx context.Context) (time.Duration, bool, bool) {
		atomic.AddInt64(&count, 1)
		time.Sleep(5 * time.Millisecond)
		return 5 * time.Millisecond, true, false
	})

	if result.TotalRequests == 0 {
		t.Error("expected at least one request")
	}
	if result.Successful == 0 {
		t.Error("expected at least one success")
	}
	if result.Failed != 0 {
		t.Errorf("expected 0 failures, got %d", result.Failed)
	}
	if result.AvgLatency <= 0 {
		t.Error("expected positive average latency")
	}
	t.Logf("Basic stress: %d requests, avg=%.1fms, P50=%.1fms, P95=%.1fms, rps=%.1f",
		result.TotalRequests, result.AvgLatency, result.P50, result.P95, result.RequestsPerSec)
}

func TestStressRunnerCancellation(t *testing.T) {
	runner := NewStressRunner(StressConfig{
		Concurrency: 10,
		Duration:    30 * time.Second, // Long duration, but we'll cancel early
		Interval:    10 * time.Millisecond,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	result := runner.Run(ctx, func(ctx context.Context) (time.Duration, bool, bool) {
		time.Sleep(2 * time.Millisecond)
		return 2 * time.Millisecond, true, false
	})

	// Should have been cancelled before duration expired
	if result.TotalDuration > 2000 {
		t.Errorf("expected early cancellation, but test ran for %.0f ms", result.TotalDuration)
	}
	t.Logf("Cancelled stress: ran for %.0f ms with %d requests", result.TotalDuration, result.TotalRequests)
}

func TestStressRunnerWorkerLimits(t *testing.T) {
	maxConcurrent := int64(0)
	currentConcurrent := int64(0)

	runner := NewStressRunner(StressConfig{
		Concurrency: 5,
		Duration:    2 * time.Second,
		Interval:    10 * time.Millisecond,
	})

	runner.Run(context.Background(), func(ctx context.Context) (time.Duration, bool, bool) {
		cur := atomic.AddInt64(&currentConcurrent, 1)
		// Update max
		for {
			old := atomic.LoadInt64(&maxConcurrent)
			if cur <= old || atomic.CompareAndSwapInt64(&maxConcurrent, old, cur) {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
		atomic.AddInt64(&currentConcurrent, -1)
		return 20 * time.Millisecond, true, false
	})

	if maxConcurrent > 5 {
		t.Errorf("max concurrency %d exceeded limit of 5", maxConcurrent)
	}
	t.Logf("Max concurrent workers: %d", maxConcurrent)
}

func TestStressRunnerMixedResults(t *testing.T) {
	runner := NewStressRunner(StressConfig{
		Concurrency: 5,
		Duration:    1 * time.Second,
		Interval:    20 * time.Millisecond,
	})

	var callCount int64
	result := runner.Run(context.Background(), func(ctx context.Context) (time.Duration, bool, bool) {
		n := atomic.AddInt64(&callCount, 1)
		time.Sleep(5 * time.Millisecond)
		// Fail every 3rd request
		if n%3 == 0 {
			return 5 * time.Millisecond, false, false
		}
		return 5 * time.Millisecond, true, false
	})

	if result.Failed == 0 {
		t.Error("expected some failures")
	}
	if result.Successful == 0 {
		t.Error("expected some successes")
	}
	t.Logf("Mixed stress: total=%d, success=%d, failed=%d, successRate=%.1f%%",
		result.TotalRequests, result.Successful, result.Failed, result.SuccessRate)
}

func TestStressRunnerPercentiles(t *testing.T) {
	runner := NewStressRunner(StressConfig{
		Concurrency: 3,
		Duration:    2 * time.Second,
		Interval:    5 * time.Millisecond,
	})

	result := runner.Run(context.Background(), func(ctx context.Context) (time.Duration, bool, bool) {
		// Varying latencies
		time.Sleep(time.Duration(1+time.Now().UnixNano()%100) * time.Millisecond)
		latency := time.Duration(1+time.Now().UnixNano()%100) * time.Millisecond
		return latency, true, false
	})

	if len(result.Latencies) == 0 {
		t.Error("expected non-empty latencies")
	}
	if result.P50 <= 0 {
		t.Error("expected positive P50")
	}
	if result.P95 <= 0 {
		t.Error("expected positive P95")
	}
	if result.P99 <= 0 {
		t.Error("expected positive P99")
	}
	if result.P95 < result.P50 {
		t.Error("P95 should be >= P50")
	}
	if result.P99 < result.P95 {
		t.Error("P99 should be >= P95")
	}
	t.Logf("Percentiles: P50=%.1fms, P95=%.1fms, P99=%.1fms", result.P50, result.P95, result.P99)
}

func TestConcurrencyValidation(t *testing.T) {
	// Very low concurrency should still work
	runner := NewStressRunner(StressConfig{
		Concurrency: 1,
		Duration:    500 * time.Millisecond,
		Interval:    10 * time.Millisecond,
	})

	result := runner.Run(context.Background(), func(ctx context.Context) (time.Duration, bool, bool) {
		return time.Millisecond, true, false
	})

	if result.TotalRequests == 0 {
		t.Error("expected at least one request with concurrency=1")
	}
}
