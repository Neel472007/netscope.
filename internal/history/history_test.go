package history

import (
	"testing"
	"time"

	"github.com/Neel472007/netscope/internal/types"
)

func TestHistoryAddAndGet(t *testing.T) {
	h := New(10)

	result := &types.DiagnosticResult{
		Target: types.DiagnosticTarget{Host: "example.com"},
		Health: &types.HealthScore{Score: 95, Status: "HEALTHY"},
	}

	entry := h.Add(result)
	if entry.ID != 1 {
		t.Errorf("expected ID 1, got %d", entry.ID)
	}
	if entry.Target != "example.com" {
		t.Errorf("expected target example.com, got %s", entry.Target)
	}
	if entry.Score != 95 {
		t.Errorf("expected score 95, got %d", entry.Score)
	}

	got := h.Get(1)
	if got == nil {
		t.Fatal("expected to get entry 1")
	}
	if got.Target != "example.com" {
		t.Errorf("expected target example.com, got %s", got.Target)
	}
}

func TestHistoryRingBuffer(t *testing.T) {
	h := New(3)

	for i := 0; i < 5; i++ {
		h.Add(&types.DiagnosticResult{
			Target: types.DiagnosticTarget{Host: "host" + string(rune('A'+i))},
			Health: &types.HealthScore{Score: 50 + i*10},
		})
	}

	if h.Len() != 3 {
		t.Errorf("expected length 3, got %d", h.Len())
	}

	list := h.List(10)
	if len(list) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(list))
	}

	// Newest first
	if list[0].Score != 90 {
		t.Errorf("expected newest score 90, got %d", list[0].Score)
	}
}

func TestHistoryList(t *testing.T) {
	h := New(20)

	for i := 0; i < 10; i++ {
		h.Add(&types.DiagnosticResult{
			Target: types.DiagnosticTarget{Host: "example.com"},
			Health: &types.HealthScore{Score: 80},
		})
	}

	list := h.List(5)
	if len(list) != 5 {
		t.Errorf("expected 5 entries, got %d", len(list))
	}
}

func TestHistoryStats(t *testing.T) {
	h := New(50)

	h.Add(&types.DiagnosticResult{
		Target: types.DiagnosticTarget{Host: "example.com"},
		Health: &types.HealthScore{Score: 95},
	})
	h.Add(&types.DiagnosticResult{
		Target: types.DiagnosticTarget{Host: "google.com"},
		Health: &types.HealthScore{Score: 85},
	})
	h.Add(&types.DiagnosticResult{
		Target: types.DiagnosticTarget{Host: "example.com"},
		Health: &types.HealthScore{Score: 70},
	})

	stats := h.GetStats()
	if stats.TotalRuns != 3 {
		t.Errorf("expected 3 runs, got %d", stats.TotalRuns)
	}
	if stats.UniqueTargets != 2 {
		t.Errorf("expected 2 unique targets, got %d", stats.UniqueTargets)
	}
	if stats.BestScore != 95 {
		t.Errorf("expected best score 95, got %d", stats.BestScore)
	}
	if stats.WorstScore != 70 {
		t.Errorf("expected worst score 70, got %d", stats.WorstScore)
	}
}

func TestHistoryCompareTargets(t *testing.T) {
	h := New(50)

	h.Add(&types.DiagnosticResult{
		Target: types.DiagnosticTarget{Host: "example.com"},
		Health: &types.HealthScore{Score: 90, Status: "HEALTHY"},
		DNS:    &types.DNSResult{ResolutionTime: 20 * time.Millisecond},
		TCP:    &types.TCPResult{Latency: 50 * time.Millisecond},
		HTTP:   &types.HTTPResult{TotalDuration: 150 * time.Millisecond},
	})
	h.Add(&types.DiagnosticResult{
		Target: types.DiagnosticTarget{Host: "google.com"},
		Health: &types.HealthScore{Score: 85, Status: "HEALTHY"},
		DNS:    &types.DNSResult{ResolutionTime: 15 * time.Millisecond},
		TCP:    &types.TCPResult{Latency: 30 * time.Millisecond},
		HTTP:   &types.HTTPResult{TotalDuration: 100 * time.Millisecond},
	})

	comp := h.CompareTargets([]string{"example.com", "google.com"})
	if len(comp.Results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(comp.Results))
	}
	if comp.Results[0].Score != 90 {
		t.Errorf("expected example.com score 90, got %d", comp.Results[0].Score)
	}
}

func TestHistoryTimeline(t *testing.T) {
	h := New(50)

	h.Add(&types.DiagnosticResult{
		Target: types.DiagnosticTarget{Host: "example.com"},
		Health: &types.HealthScore{Score: 90},
	})

	time.Sleep(10 * time.Millisecond)

	h.Add(&types.DiagnosticResult{
		Target: types.DiagnosticTarget{Host: "example.com"},
		Health: &types.HealthScore{Score: 85},
	})

	timeline := h.GetTimeline()
	if len(timeline) != 2 {
		t.Fatalf("expected 2 timeline points, got %d", len(timeline))
	}
	if timeline[0].Score != 90 {
		t.Errorf("expected first score 90, got %d", timeline[0].Score)
	}
	if timeline[1].Score != 85 {
		t.Errorf("expected second score 85, got %d", timeline[1].Score)
	}
}

func TestHistoryClear(t *testing.T) {
	h := New(10)
	h.Add(&types.DiagnosticResult{
		Target: types.DiagnosticTarget{Host: "example.com"},
		Health: &types.HealthScore{Score: 90},
	})

	h.Clear()
	if h.Len() != 0 {
		t.Errorf("expected empty history, got %d", h.Len())
	}

	// IDs should reset
	entry := h.Add(&types.DiagnosticResult{
		Target: types.DiagnosticTarget{Host: "example.com"},
		Health: &types.HealthScore{Score: 80},
	})
	if entry.ID != 1 {
		t.Errorf("expected ID 1 after clear, got %d", entry.ID)
	}
}

func TestHistoryGetMissing(t *testing.T) {
	h := New(10)
	got := h.Get(999)
	if got != nil {
		t.Error("expected nil for missing entry")
	}
}

func TestHistoryEmptyStats(t *testing.T) {
	h := New(10)
	stats := h.GetStats()
	if stats.TotalRuns != 0 {
		t.Errorf("expected 0 runs, got %d", stats.TotalRuns)
	}
}

func TestHistoryEmptyCompare(t *testing.T) {
	h := New(10)
	comp := h.CompareTargets([]string{"example.com"})
	if len(comp.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(comp.Results))
	}
	if comp.Results[0].Score != 0 {
		t.Errorf("expected score 0 for missing target, got %d", comp.Results[0].Score)
	}
}

func TestHistoryConcurrency(t *testing.T) {
	h := New(100)

	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(n int) {
			for j := 0; j < 50; j++ {
				h.Add(&types.DiagnosticResult{
					Target: types.DiagnosticTarget{Host: "host"},
					Health: &types.HealthScore{Score: 80},
				})
			}
			done <- true
		}(i)
	}

	for i := 0; i < 10; i++ {
		<-done
	}

	if h.Len() != 100 {
		t.Errorf("expected 100 entries (max), got %d", h.Len())
	}
}
