package benchmark

import (
	"fmt"
	"math"
	"net"
	"sort"
	"sync"
	"time"
)

// Round holds one benchmark measurement.
type Round struct {
	Round     int           `json:"round"`
	DNS       time.Duration `json:"dns"`
	TCP       time.Duration `json:"tcp"`
	Total     time.Duration `json:"total"`
	Success   bool          `json:"success"`
	Error     string        `json:"error,omitempty"`
}

// Result holds the full benchmark result.
type Result struct {
	Target       string        `json:"target"`
	Rounds       int           `json:"rounds"`
	Successful   int           `json:"successful"`
	Failed       int           `json:"failed"`
	PacketLoss   float64       `json:"packet_loss"`
	AvgRTT       time.Duration `json:"avg_rtt"`
	MinRTT       time.Duration `json:"min_rtt"`
	MaxRTT       time.Duration `json:"max_rtt"`
	P50          time.Duration `json:"p50"`
	P95          time.Duration `json:"p95"`
	P99          time.Duration `json:"p99"`
	Jitter       time.Duration `json:"jitter"`
	Consistency  float64       `json:"consistency"` // 0-100 score
	Grade        string        `json:"grade"`
	Durations    []time.Duration `json:"-"`
	RoundResults []Round       `json:"round_results"`
	TotalTime    time.Duration `json:"total_time"`
}

// Benchmark runs multi-round connectivity tests against a target.
func Benchmark(host string, port int, rounds int, concurrency int) *Result {
	if rounds <= 0 {
		rounds = 10
	}
	if concurrency <= 0 {
		concurrency = 1
	}

	result := &Result{
		Target:     fmt.Sprintf("%s:%d", host, port),
		Rounds:     rounds,
		MinRTT:     time.Hour,
		Durations:  make([]time.Duration, 0, rounds),
		RoundResults: make([]Round, 0, rounds),
	}

	start := time.Now()

	// Run rounds with bounded concurrency
	sem := make(chan struct{}, concurrency)
	var mu sync.Mutex
	var wg sync.WaitGroup

	for i := 0; i < rounds; i++ {
		wg.Add(1)
		sem <- struct{}{}

		go func(roundNum int) {
			defer wg.Done()
			defer func() { <-sem }()

			round := singleRound(host, port, roundNum)

			mu.Lock()
			result.RoundResults = append(result.RoundResults, round)
			if round.Success {
				result.Successful++
				result.Durations = append(result.Durations, round.Total)
				if round.Total < result.MinRTT {
					result.MinRTT = round.Total
				}
				if round.Total > result.MaxRTT {
					result.MaxRTT = round.Total
				}
			} else {
				result.Failed++
			}
			mu.Unlock()
		}(i)
	}

	wg.Wait()

	// Calculate statistics
	if len(result.Durations) > 0 {
		sort.Slice(result.Durations, func(i, j int) bool {
			return result.Durations[i] < result.Durations[j]
		})

		var total time.Duration
		for _, d := range result.Durations {
			total += d
		}
		result.AvgRTT = total / time.Duration(len(result.Durations))

		// Percentiles
		result.P50 = percentile(result.Durations, 50)
		result.P95 = percentile(result.Durations, 95)
		result.P99 = percentile(result.Durations, 99)

		// Jitter: avg absolute deviation from mean
		var jitterSum float64
		for _, d := range result.Durations {
			diff := float64(d - result.AvgRTT)
			jitterSum += math.Abs(diff)
		}
		result.Jitter = time.Duration(jitterSum / float64(len(result.Durations)))

		// Consistency score (inverse of coefficient of variation)
		if result.AvgRTT > 0 {
			varianceSum := 0.0
			for _, d := range result.Durations {
				diff := float64(d - result.AvgRTT)
				varianceSum += diff * diff
			}
			stddev := math.Sqrt(varianceSum / float64(len(result.Durations)))
			cv := stddev / float64(result.AvgRTT)
			consistency := math.Max(0, 100-cv*100)
			result.Consistency = math.Round(consistency*10) / 10
		}
	}

	result.PacketLoss = float64(result.Failed) / float64(result.Rounds) * 100
	result.TotalTime = time.Since(start)

	// Grade
	result.Grade = calculateGrade(result)

	return result
}

func singleRound(host string, port int, roundNum int) Round {
	round := Round{Round: roundNum + 1}
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	start := time.Now()

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		round.Error = err.Error()
		round.Total = time.Since(start)
		return round
	}
	conn.Close()

	round.TCP = time.Since(start)
	round.Total = round.TCP
	round.Success = true
	return round
}

func percentile(sorted []time.Duration, p int) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(math.Ceil(float64(p)/100*float64(len(sorted)))) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

func calculateGrade(r *Result) string {
	score := 100.0

	// Penalize packet loss
	score -= r.PacketLoss * 2

	// Penalize high latency
	if r.AvgRTT > 200*time.Millisecond {
		score -= 20
	} else if r.AvgRTT > 100*time.Millisecond {
		score -= 10
	} else if r.AvgRTT > 50*time.Millisecond {
		score -= 5
	}

	// Penalize jitter
	if r.Jitter > 50*time.Millisecond {
		score -= 20
	} else if r.Jitter > 20*time.Millisecond {
		score -= 10
	}

	// Penalize inconsistency
	if r.Consistency < 50 {
		score -= 20
	} else if r.Consistency < 80 {
		score -= 10
	}

	switch {
	case score >= 90:
		return "A+"
	case score >= 80:
		return "A"
	case score >= 70:
		return "B"
	case score >= 60:
		return "C"
	case score >= 50:
		return "D"
	default:
		return "F"
	}
}

// BenchmarkHTTP benchmarks HTTP response times.
func BenchmarkHTTP(url string, rounds int) *Result {
	// Placeholder - would use net/http to benchmark HTTP targets
	return &Result{
		Target: url,
		Rounds: rounds,
		Grade:  "N/A",
	}
}
