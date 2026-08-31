// Package history provides in-memory diagnostic history tracking.
// It stores the most recent diagnostic results in a ring buffer
// and provides export and comparison capabilities.
package history

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/Neel472007/netscope/internal/types"
)

// Entry represents a single historical diagnostic entry.
type Entry struct {
	ID        int                     `json:"id"`
	Target    string                  `json:"target"`
	Score     int                     `json:"score"`
	Status    string                  `json:"status"`
	Result    *types.DiagnosticResult `json:"result,omitempty"`
	Timestamp time.Time              `json:"timestamp"`
}

// History is a thread-safe ring buffer of diagnostic entries.
type History struct {
	mu      sync.RWMutex
	entries []Entry
	maxSize int
	nextID  int
}

// New creates a new History with the given maximum size.
func New(maxSize int) *History {
	if maxSize <= 0 {
		maxSize = 100
	}
	return &History{
		entries: make([]Entry, 0, maxSize),
		maxSize: maxSize,
		nextID:  1,
	}
}

// Add adds a diagnostic result to the history.
func (h *History) Add(result *types.DiagnosticResult) Entry {
	h.mu.Lock()
	defer h.mu.Unlock()

	entry := Entry{
		ID:        h.nextID,
		Timestamp: time.Now(),
		Result:    result,
	}
	h.nextID++

	if result != nil {
		entry.Target = result.Target.Host
		if result.Target.URL != "" {
			entry.Target = result.Target.URL
		}
		if result.Health != nil {
			entry.Score = result.Health.Score
			entry.Status = result.Health.Status
		}
	}

	if len(h.entries) >= h.maxSize {
		// Ring buffer: remove oldest
		h.entries = h.entries[1:]
	}

	h.entries = append(h.entries, entry)
	return entry
}

// List returns the most recent entries, newest first.
func (h *History) List(limit int) []Entry {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if limit <= 0 || limit > len(h.entries) {
		limit = len(h.entries)
	}

	result := make([]Entry, limit)
	for i := 0; i < limit; i++ {
		result[i] = h.entries[len(h.entries)-1-i]
	}
	return result
}

// Get returns a specific entry by ID.
func (h *History) Get(id int) *Entry {
	h.mu.RLock()
	defer h.mu.RUnlock()

	for i := len(h.entries) - 1; i >= 0; i-- {
		if h.entries[i].ID == id {
			return &h.entries[i]
		}
	}
	return nil
}

// Stats returns aggregate statistics about the history.
type Stats struct {
	TotalRuns    int            `json:"total_runs"`
	UniqueTargets int           `json:"unique_targets"`
	AverageScore float64        `json:"average_score"`
	BestScore    int            `json:"best_score"`
	WorstScore   int            `json:"worst_score"`
	ByTarget     map[string]int `json:"by_target"`
}

// GetStats returns aggregate statistics.
func (h *History) GetStats() Stats {
	h.mu.RLock()
	defer h.mu.RUnlock()

	stats := Stats{
		TotalRuns: len(h.entries),
		ByTarget:  make(map[string]int),
	}

	if len(h.entries) == 0 {
		return stats
	}

	var totalScore int
	stats.BestScore = 0
	stats.WorstScore = 100

	seen := make(map[string]bool)
	for _, e := range h.entries {
		totalScore += e.Score
		if e.Score > stats.BestScore {
			stats.BestScore = e.Score
		}
		if e.Score < stats.WorstScore {
			stats.WorstScore = e.Score
		}
		stats.ByTarget[e.Target]++
		if !seen[e.Target] {
			seen[e.Target] = true
		}
	}

	stats.UniqueTargets = len(seen)
	stats.AverageScore = float64(totalScore) / float64(len(h.entries))
	return stats
}

// CompareTargets returns side-by-side comparison of recent results for 2+ targets.
type Comparison struct {
	Targets []string       `json:"targets"`
	Results []CompareEntry `json:"results"`
}

// CompareEntry holds one target's latest result.
type CompareEntry struct {
	Target     string                  `json:"target"`
	Score      int                     `json:"score"`
	Status     string                  `json:"status"`
	DNSMs      float64                 `json:"dns_ms"`
	TCPMs      float64                 `json:"tcp_ms"`
	HTTPMs     float64                 `json:"http_ms"`
	Result     *types.DiagnosticResult `json:"result,omitempty"`
}

// CompareTargets returns the latest result for each of the given targets.
func (h *History) CompareTargets(targets []string) Comparison {
	h.mu.RLock()
	defer h.mu.RUnlock()

	comp := Comparison{
		Targets: targets,
		Results: make([]CompareEntry, 0, len(targets)),
	}

	for _, target := range targets {
		// Find the most recent entry for this target
		var best *Entry
		for i := len(h.entries) - 1; i >= 0; i-- {
			if h.entries[i].Target == target {
				best = &h.entries[i]
				break
			}
		}

		entry := CompareEntry{Target: target}
		if best != nil && best.Result != nil {
			entry.Score = best.Score
			entry.Status = best.Status
			entry.Result = best.Result

			if best.Result.DNS != nil {
				entry.DNSMs = float64(best.Result.DNS.ResolutionTime.Nanoseconds()) / 1e6
			}
			if best.Result.TCP != nil {
				entry.TCPMs = float64(best.Result.TCP.Latency.Nanoseconds()) / 1e6
			}
			if best.Result.HTTP != nil {
				entry.HTTPMs = float64(best.Result.HTTP.TotalDuration.Nanoseconds()) / 1e6
			}
		}
		comp.Results = append(comp.Results, entry)
	}

	return comp
}

// Timeline returns score data points sorted by time for charting.
type TimelinePoint struct {
	Timestamp time.Time `json:"timestamp"`
	Score     int       `json:"score"`
	Target    string    `json:"target"`
}

// GetTimeline returns historical scores for charting.
func (h *History) GetTimeline() []TimelinePoint {
	h.mu.RLock()
	defer h.mu.RUnlock()

	points := make([]TimelinePoint, 0, len(h.entries))
	for _, e := range h.entries {
		points = append(points, TimelinePoint{
			Timestamp: e.Timestamp,
			Score:     e.Score,
			Target:    e.Target,
		})
	}

	sort.Slice(points, func(i, j int) bool {
		return points[i].Timestamp.Before(points[j].Timestamp)
	})

	return points
}

// Clear removes all entries from the history.
func (h *History) Clear() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.entries = h.entries[:0]
	h.nextID = 1
}

// Len returns the number of entries.
func (h *History) Len() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.entries)
}

// --- Diagnostic Diff Mode ---

// Baseline stores a snapshot for comparison.
type Baseline struct {
	Target    string                  `json:"target"`
	Result    *types.DiagnosticResult `json:"result"`
	Timestamp time.Time              `json:"timestamp"`
}

// DiffResult represents the difference between two diagnostic snapshots.
type DiffResult struct {
	Target        string          `json:"target"`
	BeforeTime    string          `json:"before_time"`
	AfterTime     string          `json:"after_time"`
	ScoreChange   int             `json:"score_change"` // positive = improved
	DNSChanged    DiffField       `json:"dns"`
	TCPChanged    DiffField       `json:"tcp"`
	HTTPChanged   DiffField       `json:"http"`
	OverallChange string          `json:"overall_change"` // "improved", "degraded", "unchanged"
	Changes       []ChangeItem    `json:"changes"`
}

// DiffField represents change in a specific layer.
type DiffField struct {
	Before string `json:"before"`
	After  string `json:"after"`
	Changed bool  `json:"changed"`
}

// ChangeItem is a single detected change.
type ChangeItem struct {
	Layer   string `json:"layer"`
	Field   string `json:"field"`
	Before  string `json:"before"`
	After   string `json:"after"`
	Impact  string `json:"impact"` // "positive", "negative", "neutral"
}

var baselines = make(map[string]*Baseline)

// SetBaseline saves a diagnostic result as a baseline for the given target.
func (h *History) SetBaseline(target string, result *types.DiagnosticResult) *Baseline {
	bl := &Baseline{
		Target:    target,
		Result:    result,
		Timestamp: time.Now(),
	}
	baselines[target] = bl
	return bl
}

// GetBaseline retrieves the stored baseline for a target.
func (h *History) GetBaseline(target string) *Baseline {
	return baselines[target]
}

// Diff compares a new result against the stored baseline and returns the differences.
func (h *History) Diff(target string, current *types.DiagnosticResult) *DiffResult {
	bl := baselines[target]
	if bl == nil || bl.Result == nil || current == nil {
		return &DiffResult{
			Target: target,
			Changes: []ChangeItem{{Layer: "info", Field: "baseline", Before: "none", After: "new", Impact: "neutral"}},
		}
	}

	diff := &DiffResult{
		Target:     target,
		BeforeTime: bl.Timestamp.Format(time.RFC3339),
		AfterTime:  time.Now().Format(time.RFC3339),
	}

	oldScore := 0
	if bl.Result.Health != nil {
		oldScore = bl.Result.Health.Score
	}
	newScore := 0
	if current.Health != nil {
		newScore = current.Health.Score
	}
	diff.ScoreChange = newScore - oldScore

	if diff.ScoreChange > 5 {
		diff.OverallChange = "improved"
	} else if diff.ScoreChange < -5 {
		diff.OverallChange = "degraded"
	} else {
		diff.OverallChange = "unchanged"
	}

	// Compare DNS
	if bl.Result.DNS != nil && current.DNS != nil {
		dnsBefore := "ok"
		if !bl.Result.DNS.Success {
			dnsBefore = "failed: " + bl.Result.DNS.Error
		}
		dnsAfter := "ok"
		if !current.DNS.Success {
			dnsAfter = "failed: " + current.DNS.Error
		}
		dnsChanged := dnsBefore != dnsAfter
		diff.DNSChanged = DiffField{Before: dnsBefore, After: dnsAfter, Changed: dnsChanged}
		if dnsChanged {
			impact := "neutral"
			if bl.Result.DNS.Success && !current.DNS.Success {
				impact = "negative"
			} else if !bl.Result.DNS.Success && current.DNS.Success {
				impact = "positive"
			}
			diff.Changes = append(diff.Changes, ChangeItem{Layer: "DNS", Field: "resolution", Before: dnsBefore, After: dnsAfter, Impact: impact})
		}
	
		// Check IP changes
		if len(bl.Result.DNS.IPv4Addresses) > 0 && len(current.DNS.IPv4Addresses) > 0 {
			if bl.Result.DNS.IPv4Addresses[0] != current.DNS.IPv4Addresses[0] {
				diff.Changes = append(diff.Changes, ChangeItem{
					Layer:  "DNS",
					Field:  "ip_address",
					Before: bl.Result.DNS.IPv4Addresses[0],
					After:  current.DNS.IPv4Addresses[0],
					Impact: "neutral",
				})
			}
		}
	}

	// Compare TCP
	if bl.Result.TCP != nil && current.TCP != nil {
		tcpBefore := bl.Result.TCP.Connected
		tcpAfter := current.TCP.Connected
		if tcpBefore != tcpAfter {
			impact := "neutral"
			if tcpBefore && !tcpAfter {
				impact = "negative"
			} else if !tcpBefore && tcpAfter {
				impact = "positive"
			}
			diff.TCPChanged = DiffField{
				Before:  fmt.Sprintf("connected=%v", tcpBefore),
				After:   fmt.Sprintf("connected=%v", tcpAfter),
				Changed: true,
			}
			diff.Changes = append(diff.Changes, ChangeItem{Layer: "TCP", Field: "connectivity", Before: fmt.Sprintf("%v", tcpBefore), After: fmt.Sprintf("%v", tcpAfter), Impact: impact})
		}
	}

	// Compare HTTP
	if bl.Result.HTTP != nil && current.HTTP != nil {
		httpBefore := bl.Result.HTTP.StatusCode
		httpAfter := current.HTTP.StatusCode
		if httpBefore != httpAfter {
			impact := "neutral"
			if httpBefore >= 200 && httpBefore < 400 && (httpAfter >= 400 || httpAfter < 200) {
				impact = "negative"
			} else if (httpBefore >= 400 || httpBefore < 200) && httpAfter >= 200 && httpAfter < 400 {
				impact = "positive"
			}
			diff.HTTPChanged = DiffField{
				Before:  fmt.Sprintf("%d", httpBefore),
				After:   fmt.Sprintf("%d", httpAfter),
				Changed: true,
			}
			diff.Changes = append(diff.Changes, ChangeItem{Layer: "HTTP", Field: "status_code", Before: fmt.Sprintf("%d", httpBefore), After: fmt.Sprintf("%d", httpAfter), Impact: impact})
		}
	}

	// Compare latency changes (if >20% difference)
	if bl.Result.TCP != nil && current.TCP != nil && bl.Result.TCP.Connected && current.TCP.Connected {
		oldMs := float64(bl.Result.TCP.Latency.Microseconds()) / 1000
		newMs := float64(current.TCP.Latency.Microseconds()) / 1000
		if oldMs > 0 {
			pctChange := ((newMs - oldMs) / oldMs) * 100
			if pctChange > 20 || pctChange < -20 {
				impact := "positive"
				if pctChange > 0 {
					impact = "negative"
				}
				diff.Changes = append(diff.Changes, ChangeItem{
					Layer:  "TCP",
					Field:  "latency",
					Before: fmt.Sprintf("%.1fms", oldMs),
					After:  fmt.Sprintf("%.1fms", newMs),
					Impact: impact,
				})
			}
		}
	}

	if len(diff.Changes) == 0 {
		diff.Changes = append(diff.Changes, ChangeItem{Layer: "all", Field: "overall", Before: "same", After: "same", Impact: "neutral"})
	}

	return diff
}
