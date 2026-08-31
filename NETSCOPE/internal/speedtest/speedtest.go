// Package speedtest measures network download throughput.
// It downloads test payloads from known endpoints and calculates
// throughput, jitter, and connection quality — all using the standard library.
package speedtest

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"sync"
	"time"
)

// Result holds the full speed test result.
type Result struct {
	Target        string        `json:"target"`
	StartedAt     time.Time     `json:"started_at"`
	EndedAt       time.Time     `json:"ended_at"`
	TotalBytes    int64         `json:"total_bytes"`
	TotalDuration float64       `json:"total_duration_ms"`
	AvgSpeedMbps  float64       `json:"avg_speed_mbps"`
	MaxSpeedMbps  float64       `json:"max_speed_mbps"`
	MinSpeedMbps  float64       `json:"min_speed_mbps"`
	MedianMbps    float64       `json:"median_mbps"`
	P95Mbps       float64       `json:"p95_mbps"`
	JitterMbps    float64       `json:"jitter_mbps"`
	AvgLatencyMs  float64       `json:"avg_latency_ms"`
	PacketLoss    float64       `json:"packet_loss_pct"`
	Connections   int           `json:"connections"`
	Rounds        int           `json:"rounds"`
	Successful    int           `json:"successful"`
	Failed        int           `json:"failed"`
	Grade         string        `json:"grade"`
	RoundResults  []RoundResult `json:"round_results"`
	Error         string        `json:"error,omitempty"`
}

// RoundResult holds one round of speed measurement.
type RoundResult struct {
	Round     int     `json:"round"`
	Bytes     int64   `json:"bytes"`
	Duration  float64 `json:"duration_ms"`
	SpeedMbps float64 `json:"speed_mbps"`
	LatencyMs float64 `json:"latency_ms"`
	Success   bool    `json:"success"`
	Error     string  `json:"error,omitempty"`
}

// TestTargets are known endpoints for speed testing.
var TestTargets = []string{
	"http://speedtest.tele2.net/10MB.zip",
	"http://speedtest.tele2.net/1MB.zip",
	"https://proof.ovh.net/files/10Mb.dat",
	"https://proof.ovh.net/files/100Mb.dat",
}

// Test performs a download speed test against the given URL.
// If url is empty, it picks the fastest available target.
func Test(ctx context.Context, url string, rounds int, concurrency int) *Result {
	if rounds <= 0 {
		rounds = 5
	}
	if concurrency <= 0 {
		concurrency = 3
	}
	if url == "" {
		url = TestTargets[0]
	}

	result := &Result{
		Target:    url,
		Rounds:    rounds,
		StartedAt: time.Now(),
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        concurrency,
			MaxIdleConnsPerHost: concurrency,
			IdleConnTimeout:     30 * time.Second,
			DialContext: (&net.Dialer{
				Timeout:   10 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
		},
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, concurrency)

	speeds := make([]float64, 0, rounds)
	latencies := make([]float64, 0, rounds)

	for i := 0; i < rounds; i++ {
		select {
		case <-ctx.Done():
			break
		default:
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(roundNum int) {
			defer wg.Done()
			defer func() { <-sem }()

			round := measureRound(ctx, client, url, roundNum+1)

			mu.Lock()
			result.RoundResults = append(result.RoundResults, round)
			if round.Success {
				speeds = append(speeds, round.SpeedMbps)
				latencies = append(latencies, round.LatencyMs)
				result.TotalBytes += round.Bytes
				result.Successful++
			} else {
				result.Failed++
			}
			mu.Unlock()
		}(i)
	}

	wg.Wait()

	result.EndedAt = time.Now()
	result.TotalDuration = float64(result.EndedAt.Sub(result.StartedAt).Milliseconds())
	result.Connections = concurrency

	if len(speeds) > 0 {
		sort.Float64s(speeds)
		sort.Float64s(latencies)

		var sum float64
		for _, s := range speeds {
			sum += s
		}
		result.AvgSpeedMbps = sum / float64(len(speeds))
		result.MinSpeedMbps = speeds[0]
		result.MaxSpeedMbps = speeds[len(speeds)-1]
		result.MedianMbps = speeds[len(speeds)/2]

		if len(speeds) > 1 {
			p95Idx := int(float64(len(speeds)) * 0.95)
			if p95Idx >= len(speeds) {
				p95Idx = len(speeds) - 1
			}
			result.P95Mbps = speeds[p95Idx]
		}

		// Jitter
		var jitterSum float64
		for _, s := range speeds {
			jitterSum += s - result.AvgSpeedMbps
			if jitterSum < 0 {
				jitterSum = -jitterSum
			}
		}
		result.JitterMbps = jitterSum / float64(len(speeds))

		// Latency
		var latSum float64
		for _, l := range latencies {
			latSum += l
		}
		result.AvgLatencyMs = latSum / float64(len(latencies))
	}

	result.PacketLoss = float64(result.Failed) / float64(result.Rounds) * 100
	result.Grade = calculateGrade(result)
	return result
}

func measureRound(ctx context.Context, client *http.Client, url string, roundNum int) RoundResult {
	round := RoundResult{Round: roundNum}

	// Measure latency first
	start := time.Now()
	latencyClient := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequestWithContext(ctx, "HEAD", url, nil)
	if err != nil {
		round.Error = err.Error()
		return round
	}
	_, err = latencyClient.Do(req)
	round.LatencyMs = float64(time.Since(start).Microseconds()) / 1000.0
	if err != nil {
		round.Error = err.Error()
		return round
	}

	// Download and measure throughput
	start = time.Now()
	req, err = http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		round.Error = err.Error()
		return round
	}

	resp, err := client.Do(req)
	if err != nil {
		round.Error = err.Error()
		return round
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		round.Error = fmt.Sprintf("HTTP %d", resp.StatusCode)
		return round
	}

	// Read with limited buffer to measure throughput
	n, _ := io.Copy(io.Discard, io.LimitReader(resp.Body, 50*1024*1024)) // max 50MB
	elapsed := time.Since(start)

	round.Bytes = n
	round.Duration = float64(elapsed.Microseconds()) / 1000.0
	if elapsed.Seconds() > 0 {
		round.SpeedMbps = float64(n*8) / (elapsed.Seconds() * 1024 * 1024)
	}
	round.Success = true
	return round
}

func calculateGrade(r *Result) string {
	score := 100.0

	// Speed scoring
	if r.AvgSpeedMbps >= 100 {
		score += 0 // already 100
	} else if r.AvgSpeedMbps >= 50 {
		score -= 5
	} else if r.AvgSpeedMbps >= 20 {
		score -= 15
	} else if r.AvgSpeedMbps >= 10 {
		score -= 25
	} else {
		score -= 40
	}

	// Packet loss
	score -= r.PacketLoss * 3

	// Jitter
	if r.JitterMbps > r.AvgSpeedMbps*0.3 {
		score -= 15
	} else if r.JitterMbps > r.AvgSpeedMbps*0.1 {
		score -= 5
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

// GeneratePayload creates random data for upload testing (unused currently, available for future).
func GeneratePayload(size int) []byte {
	data := make([]byte, size)
	rand.Read(data)
	return data
}
