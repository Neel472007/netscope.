// Package healthmon provides continuous health monitoring with spike detection.
// It runs background ping loops, tracks latency over time, and raises alerts
// when latency exceeds adaptive thresholds.
package healthmon

import (
	"context"
	"fmt"
	"math"
	"net"
	"sort"
	"sync"
	"time"
)

// SpikeAlert represents a detected latency spike.
type SpikeAlert struct {
	Timestamp time.Time `json:"timestamp"`
	RTTMs     float64   `json:"rtt_ms"`
	Threshold float64   `json:"threshold_ms"`
	Seq       int       `json:"seq"`
	Message   string    `json:"message"`
}

// MonitorStatus indicates the overall health.
type MonitorStatus string

const (
	StatusHealthy  MonitorStatus = "healthy"
	StatusDegraded MonitorStatus = "degraded"
	StatusCritical MonitorStatus = "critical"
	StatusStopped  MonitorStatus = "stopped"
)

// ProbeRecord is a single probe result.
type ProbeRecord struct {
	Seq    int     `json:"seq"`
	RTTMs  float64 `json:"rtt_ms"`
	OK     bool    `json:"ok"`
	Error  string  `json:"error,omitempty"`
	Time   string  `json:"time"`
}

// MonitorConfig configures a monitoring session.
type MonitorConfig struct {
	Host              string        `json:"host"`
	Port              int           `json:"port"`
	Interval          time.Duration `json:"interval"`
	Timeout           time.Duration `json:"timeout"`
	SpikeThresholdMs  float64       `json:"spike_threshold_ms"`  // absolute threshold
	SpikePercentile   float64       `json:"spike_percentile"`     // adaptive: e.g. 95th percentile multiplier
WindowSize         int           `json:"window_size"`          // rolling window for adaptive threshold
}

// MonitorSnapshot is a point-in-time view of the monitoring session.
type MonitorSnapshot struct {
	Config        MonitorConfig `json:"config"`
	Status        MonitorStatus `json:"status"`
	Running       bool          `json:"running"`
	StartedAt     string        `json:"started_at"`
	UptimeSec     float64       `json:"uptime_sec"`
	TotalProbes   int           `json:"total_probes"`
	SuccessCount  int           `json:"success_count"`
	FailCount     int           `json:"fail_count"`
	LossPct       float64       `json:"loss_pct"`
	AvgRTTMs      float64       `json:"avg_rtt_ms"`
	MinRTTMs      float64       `json:"min_rtt_ms"`
	MaxRTTMs      float64       `json:"max_rtt_ms"`
	P95RTTMs      float64       `json:"p95_rtt_ms"`
	JitterMs      float64       `json:"jitter_ms"`
	CurrentRTTMs  float64       `json:"current_rtt_ms"`
	ThresholdMs   float64       `json:"threshold_ms"`
	SpikeCount    int           `json:"spike_count"`
	RecentAlerts  []SpikeAlert  `json:"recent_alerts"`
	RecentProbes  []ProbeRecord `json:"recent_probes"`
	StatusMsg     string        `json:"status_msg"`
}

// Monitor manages a continuous health monitoring session.
type Monitor struct {
	mu      sync.Mutex
	config  MonitorConfig
	running bool
	cancel  context.CancelFunc

	startedAt time.Time
	probes    []ProbeRecord
	alerts    []SpikeAlert

	// Stats
	successCount int
	failCount    int
	rtts         []float64 // recent window for adaptive threshold
	currentRTT   float64
	thresholdMs  float64
	status       MonitorStatus
	statusMsg    string
}

// NewMonitor creates a new health monitor.
func NewMonitor(cfg MonitorConfig) *Monitor {
	if cfg.Interval <= 0 {
		cfg.Interval = 1 * time.Second
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 2 * time.Second
	}
	if cfg.WindowSize <= 0 {
		cfg.WindowSize = 30
	}
	if cfg.SpikeThresholdMs <= 0 {
		cfg.SpikeThresholdMs = 500 // default absolute threshold
	}
	if cfg.SpikePercentile <= 0 {
		cfg.SpikePercentile = 2.5 // default: spike if > 2.5x the median
	}
	return &Monitor{
		config:    cfg,
		status:    StatusStopped,
		statusMsg: "Not started",
	}
}

// Start begins the monitoring loop.
func (m *Monitor) Start() {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return
	}
	m.running = true
	m.startedAt = time.Now()
	m.probes = nil
	m.alerts = nil
	m.successCount = 0
	m.failCount = 0
	m.rtts = nil
	m.currentRTT = 0
	m.thresholdMs = m.config.SpikeThresholdMs
	m.status = StatusHealthy
	m.statusMsg = "Monitoring..."
	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel
	m.mu.Unlock()

	go m.loop(ctx)
}

// Stop halts the monitoring loop.
func (m *Monitor) Stop() {
	m.mu.Lock()
	if m.cancel != nil {
		m.cancel()
	}
	m.running = false
	m.status = StatusStopped
	m.statusMsg = "Stopped"
	m.mu.Unlock()
}

// Snapshot returns the current state.
func (m *Monitor) Snapshot() *MonitorSnapshot {
	m.mu.Lock()
	defer m.mu.Unlock()

	snap := &MonitorSnapshot{
		Config:       m.config,
		Status:       m.status,
		Running:      m.running,
		StartedAt:    m.startedAt.Format(time.RFC3339),
		UptimeSec:    time.Since(m.startedAt).Seconds(),
		TotalProbes:  m.successCount + m.failCount,
		SuccessCount: m.successCount,
		FailCount:    m.failCount,
		CurrentRTTMs: m.currentRTT,
		ThresholdMs:  m.thresholdMs,
		SpikeCount:   len(m.alerts),
		StatusMsg:    m.statusMsg,
	}

	if snap.TotalProbes > 0 {
		snap.LossPct = float64(m.failCount) / float64(snap.TotalProbes) * 100
	}

	// Compute stats from all rtts
	if len(m.rtts) > 0 {
		sorted := make([]float64, len(m.rtts))
		copy(sorted, m.rtts)
		sort.Float64s(sorted)

		var sum float64
		for _, v := range sorted {
			sum += v
		}
		snap.AvgRTTMs = sum / float64(len(sorted))
		snap.MinRTTMs = sorted[0]
		snap.MaxRTTMs = sorted[len(sorted)-1]

		// P95
		p95Idx := int(math.Ceil(float64(len(sorted))*0.95)) - 1
		if p95Idx < 0 {
			p95Idx = 0
		}
		snap.P95RTTMs = sorted[p95Idx]

		// Jitter (mean absolute deviation from average)
		var jitterSum float64
		for _, v := range sorted {
			jitterSum += math.Abs(v - snap.AvgRTTMs)
		}
		snap.JitterMs = jitterSum / float64(len(sorted))
	}

	// Recent alerts (last 20)
	n := len(m.alerts)
	if n > 20 {
		n = 20
	}
	if n > 0 {
		snap.RecentAlerts = make([]SpikeAlert, n)
		copy(snap.RecentAlerts, m.alerts[len(m.alerts)-n:])
	}

	// Recent probes (last 100)
	pn := len(m.probes)
	if pn > 100 {
		pn = 100
	}
	if pn > 0 {
		snap.RecentProbes = make([]ProbeRecord, pn)
		copy(snap.RecentProbes, m.probes[len(m.probes)-pn:])
	}

	return snap
}

func (m *Monitor) loop(ctx context.Context) {
	ticker := time.NewTicker(m.config.Interval)
	defer ticker.Stop()

	seq := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			seq++
			m.probe(ctx, seq)
		}
	}
}

func (m *Monitor) probe(ctx context.Context, seq int) {
	start := time.Now()

	probeCtx, cancel := context.WithTimeout(ctx, m.config.Timeout)
	defer cancel()

	conn, err := net.DialTimeout("tcp", net.JoinHostPort(m.config.Host, fmt.Sprintf("%d", m.config.Port)), m.config.Timeout)
	elapsed := time.Since(start)
	rttMs := float64(elapsed.Microseconds()) / 1000.0

	if err != nil {
		m.mu.Lock()
		m.failCount++
		m.probes = append(m.probes, ProbeRecord{
			Seq:   seq,
			OK:    false,
			Error: err.Error(),
			Time:  time.Now().Format(time.RFC3339),
		})
		m.updateStatus()
		m.mu.Unlock()
		return
	}
	conn.Close()

	// Record successful probe
	record := ProbeRecord{
		Seq:   seq,
		RTTMs: rttMs,
		OK:    true,
		Time:  time.Now().Format(time.RFC3339),
	}

	m.mu.Lock()
	m.successCount++
	m.currentRTT = rttMs

	// Add to rolling window
	m.rtts = append(m.rtts, rttMs)
	if len(m.rtts) > m.config.WindowSize {
		m.rtts = m.rtts[1:]
	}

	// Compute adaptive threshold: max of absolute threshold and percentile-based
	adaptiveThreshold := m.computeAdaptiveThreshold()
	m.thresholdMs = adaptiveThreshold

	// Check for spike
	if m.successCount > 5 { // need at least 5 samples for adaptive threshold
		isSpike := rttMs > adaptiveThreshold
		if isSpike {
			alert := SpikeAlert{
				Timestamp: time.Now(),
				RTTMs:     rttMs,
				Threshold: adaptiveThreshold,
				Seq:       seq,
				Message:   fmt.Sprintf("Latency spike: %.1fms exceeds threshold %.1fms", rttMs, adaptiveThreshold),
			}
			m.alerts = append(m.alerts, alert)
		}
	}

	m.probes = append(m.probes, record)
	m.updateStatus()
	m.mu.Unlock()

	// Suppress unused variable
	_ = probeCtx
}

func (m *Monitor) computeAdaptiveThreshold() float64 {
	if len(m.rtts) < 3 {
		return m.config.SpikeThresholdMs
	}

	sorted := make([]float64, len(m.rtts))
	copy(sorted, m.rtts)
	sort.Float64s(sorted)

	// Median
	median := sorted[len(sorted)/2]

	// Absolute threshold as floor
	absThreshold := m.config.SpikeThresholdMs

	// Percentile-based: spike if > N * median
	pctThreshold := median * m.config.SpikePercentile

	// Use the larger of the two
	threshold := absThreshold
	if pctThreshold > absThreshold {
		threshold = pctThreshold
	}

	return threshold
}

func (m *Monitor) updateStatus() {
	total := m.successCount + m.failCount
	if total == 0 {
		return
	}

	lossPct := float64(m.failCount) / float64(total) * 100
	recentSpikes := 0
	cutoff := time.Now().Add(-2 * time.Minute)
	for i := len(m.alerts) - 1; i >= 0; i-- {
		if m.alerts[i].Timestamp.After(cutoff) {
			recentSpikes++
		} else {
			break
		}
	}

	switch {
	case lossPct > 30 || recentSpikes > 5:
		m.status = StatusCritical
		m.statusMsg = fmt.Sprintf("Critical: %.0f%% loss, %d spikes in 2min", lossPct, recentSpikes)
	case lossPct > 10 || recentSpikes > 2:
		m.status = StatusDegraded
		m.statusMsg = fmt.Sprintf("Degraded: %.0f%% loss, %d spikes in 2min", lossPct, recentSpikes)
	default:
		m.status = StatusHealthy
		avg := 0.0
		if len(m.rtts) > 0 {
			var s float64
			for _, v := range m.rtts {
				s += v
			}
			avg = s / float64(len(m.rtts))
		}
		m.statusMsg = fmt.Sprintf("Healthy: avg %.1fms, %.0f%% loss", avg, lossPct)
	}
}
