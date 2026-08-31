// Package ping provides real-time latency monitoring via TCP probing.
// It measures round-trip time by timing TCP connection attempts to the target,
// which works without raw socket privileges on all platforms.
package ping

import (
	"context"
	"fmt"
	"math"
	"net"
	"sort"
	"sync"
	"time"
)

// PingProbe represents a single probe result.
type PingProbe struct {
	Seq       int           `json:"seq"`
	RTT       time.Duration `json:"rtt_ns"`
	RTTMs     float64       `json:"rtt_ms"`
	Success   bool          `json:"success"`
	Error     string        `json:"error,omitempty"`
	Timestamp time.Time     `json:"timestamp"`
}

// PingStats holds aggregate statistics.
type PingStats struct {
	Total      int     `json:"total"`
	Sent       int     `json:"sent"`
	Received   int     `json:"received"`
	Lost       int     `json:"lost"`
	PacketLoss float64 `json:"packet_loss_pct"`
	MinRTTMs   float64 `json:"min_rtt_ms"`
	MaxRTTMs   float64 `json:"max_rtt_ms"`
	AvgRTTMs   float64 `json:"avg_rtt_ms"`
	MedianMs   float64 `json:"median_ms"`
	P95Ms      float64 `json:"p95_ms"`
	P99Ms      float64 `json:"p99_ms"`
	JitterMs   float64 `json:"jitter_ms"`
	StdDevMs   float64 `json:"stddev_ms"`
}

// PingResult holds the full result of a ping session.
type PingResult struct {
	Host      string     `json:"host"`
	Port      int        `json:"port"`
	StartedAt time.Time  `json:"started_at"`
	EndedAt   time.Time  `json:"ended_at"`
	Duration  float64    `json:"duration_ms"`
	Stats     PingStats  `json:"stats"`
	Probes    []PingProbe `json:"probes"`
	Complete  bool       `json:"complete"`
}

// PingUpdate is a live update emitted during a ping session.
type PingUpdate struct {
	Type  string     `json:"type"` // "probe", "stats", "complete"
	Probe PingProbe  `json:"probe,omitempty"`
	Stats PingStats  `json:"stats,omitempty"`
}

// Config holds ping session configuration.
type Config struct {
	Host       string
	Port       int
	Interval   time.Duration // time between probes
	Count      int           // number of probes (0 = infinite until cancelled)
	Timeout    time.Duration // per-probe timeout
}

// Engine performs ping monitoring.
type Engine struct{}

// NewEngine creates a new ping engine.
func NewEngine() *Engine {
	return &Engine{}
}

// Ping runs a single probe to the target and returns the RTT.
func (e *Engine) Ping(ctx context.Context, host string, port int, timeout time.Duration) PingProbe {
	if timeout == 0 {
		timeout = 2 * time.Second
	}
	if port == 0 {
		port = 80
	}

	addr := fmt.Sprintf("%s:%d", host, port)
	start := time.Now()

	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	elapsed := time.Since(start)

	probe := PingProbe{
		RTT:       elapsed,
		RTTMs:     float64(elapsed.Microseconds()) / 1000.0,
		Timestamp: start,
		Success:   err == nil,
	}

	if err != nil {
		probe.Error = err.Error()
		// Classify the error
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			probe.Error = "timeout"
		}
	} else {
		conn.Close()
	}

	return probe
}

// Monitor runs a continuous ping session and sends updates to the channel.
// It blocks until the context is cancelled or the count is reached.
func (e *Engine) Monitor(ctx context.Context, cfg Config, updates chan<- PingUpdate) PingResult {
	if cfg.Port == 0 {
		cfg.Port = 80
	}
	if cfg.Interval == 0 {
		cfg.Interval = 1 * time.Second
	}
	if cfg.Count == 0 {
		cfg.Count = 100 // max probes for a session
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 2 * time.Second
	}

	result := PingResult{
		Host:      cfg.Host,
		Port:      cfg.Port,
		StartedAt: time.Now(),
	}

	probes := make([]PingProbe, 0, cfg.Count)
	var mu sync.Mutex

loop:
	for i := 0; i < cfg.Count; i++ {
		select {
		case <-ctx.Done():
			result.EndedAt = time.Now()
			result.Duration = float64(result.EndedAt.Sub(result.StartedAt).Milliseconds())
			result.Probes = probes
			result.Stats = computeStats(probes)
			result.Complete = false
			return result
		default:
		}

		probe := e.Ping(ctx, cfg.Host, cfg.Port, cfg.Timeout)
		probe.Seq = i + 1

		mu.Lock()
		probes = append(probes, probe)
		currentStats := computeStats(probes)
		mu.Unlock()

		// Send probe update
		if updates != nil {
			select {
			case updates <- PingUpdate{Type: "probe", Probe: probe, Stats: currentStats}:
			default:
			}
		}

		// Wait for next interval (unless last probe)
		if i < cfg.Count-1 {
			select {
			case <-ctx.Done():
				break loop
			case <-time.After(cfg.Interval):
			}
		}
	}

	result.EndedAt = time.Now()
	result.Duration = float64(result.EndedAt.Sub(result.StartedAt).Milliseconds())
	result.Probes = probes
	result.Stats = computeStats(probes)
	result.Complete = ctx.Err() == nil

	if updates != nil {
		select {
		case updates <- PingUpdate{Type: "complete", Stats: result.Stats}:
		default:
		}
	}

	return result
}

// computeStats calculates aggregate statistics from probes.
func computeStats(probes []PingProbe) PingStats {
	stats := PingStats{Total: len(probes)}
	if len(probes) == 0 {
		return stats
	}

	rtts := make([]float64, 0, len(probes))
	for _, p := range probes {
		stats.Sent++
		if p.Success {
			stats.Received++
			rtts = append(rtts, p.RTTMs)
		}
	}

	stats.Lost = stats.Sent - stats.Received
	if stats.Sent > 0 {
		stats.PacketLoss = float64(stats.Lost) / float64(stats.Sent) * 100
	}

	if len(rtts) == 0 {
		return stats
	}

	sort.Float64s(rtts)

	stats.MinRTTMs = rtts[0]
	stats.MaxRTTMs = rtts[len(rtts)-1]

	// Average
	var sum float64
	for _, r := range rtts {
		sum += r
	}
	stats.AvgRTTMs = sum / float64(len(rtts))

	// Median
	mid := len(rtts) / 2
	if len(rtts)%2 == 0 {
		stats.MedianMs = (rtts[mid-1] + rtts[mid]) / 2
	} else {
		stats.MedianMs = rtts[mid]
	}

	// P95
	p95Idx := int(math.Ceil(float64(len(rtts))*0.95)) - 1
	if p95Idx < 0 {
		p95Idx = 0
	}
	if p95Idx >= len(rtts) {
		p95Idx = len(rtts) - 1
	}
	stats.P95Ms = rtts[p95Idx]

	// P99
	p99Idx := int(math.Ceil(float64(len(rtts))*0.99)) - 1
	if p99Idx < 0 {
		p99Idx = 0
	}
	if p99Idx >= len(rtts) {
		p99Idx = len(rtts) - 1
	}
	stats.P99Ms = rtts[p99Idx]

	// Jitter (mean deviation from average)
	var jitterSum float64
	for _, r := range rtts {
		jitterSum += math.Abs(r - stats.AvgRTTMs)
	}
	stats.JitterMs = jitterSum / float64(len(rtts))

	// Standard deviation
	var varianceSum float64
	for _, r := range rtts {
		diff := r - stats.AvgRTTMs
		varianceSum += diff * diff
	}
	stats.StdDevMs = math.Sqrt(varianceSum / float64(len(rtts)))

	return stats
}

// QuickPing performs a single ping and returns the result.
func QuickPing(host string, port int) PingProbe {
	e := NewEngine()
	return e.Ping(context.Background(), host, port, 2*time.Second)
}
