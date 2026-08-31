package ping

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"
)

func TestQuickPing(t *testing.T) {
	// Start a local TCP server
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	var port int
	fmt.Sscanf(portStr, "%d", &port)

	probe := QuickPing(host, port)
	if !probe.Success {
		t.Errorf("expected success, got error: %s", probe.Error)
	}
	// RTT can be 0 for ultra-fast localhost connections, so just check it's non-negative
	if probe.RTT < 0 {
		t.Errorf("expected non-negative RTT, got %v", probe.RTT)
	}
	if probe.RTTMs < 0 {
		t.Errorf("expected non-negative RTTMs, got %f", probe.RTTMs)
	}
}

func TestEnginePingTimeout(t *testing.T) {
	// Try to ping a non-routable address
	probe := QuickPing("192.0.2.1", 1) // TEST-NET, should timeout
	if probe.Success {
		t.Error("expected failure for non-routable address")
	}
}

func TestMonitorContinuous(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	var port int
	fmt.Sscanf(portStr, "%d", &port)

	e := NewEngine()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	updates := make(chan PingUpdate, 100)
	cfg := Config{
		Host:     host,
		Port:     port,
		Interval: 200 * time.Millisecond,
		Count:    10,
		Timeout:  2 * time.Second,
	}

	result := e.Monitor(ctx, cfg, updates)

	if result.Stats.Sent == 0 {
		t.Error("expected at least one probe sent")
	}
	if result.Stats.AvgRTTMs <= 0 {
		t.Errorf("expected positive avg RTT, got %f", result.Stats.AvgRTTMs)
	}
	if result.Stats.PacketLoss > 50 {
		t.Errorf("expected < 50%% loss for localhost, got %f%%", result.Stats.PacketLoss)
	}

	// Check that we received updates
	close(updates)
	probeCount := 0
	for range updates {
		probeCount++
	}
	if probeCount == 0 {
		t.Error("expected at least one update")
	}
}

func TestComputeStats(t *testing.T) {
	probes := []PingProbe{
		{Success: true, RTTMs: 10.0},
		{Success: true, RTTMs: 20.0},
		{Success: false, RTTMs: 0},
		{Success: true, RTTMs: 15.0},
	}

	stats := computeStats(probes)

	if stats.Sent != 4 {
		t.Errorf("expected 4 sent, got %d", stats.Sent)
	}
	if stats.Received != 3 {
		t.Errorf("expected 3 received, got %d", stats.Received)
	}
	if stats.Lost != 1 {
		t.Errorf("expected 1 lost, got %d", stats.Lost)
	}
	if stats.PacketLoss != 25.0 {
		t.Errorf("expected 25%% loss, got %f%%", stats.PacketLoss)
	}
	if stats.MinRTTMs != 10.0 {
		t.Errorf("expected min 10ms, got %f", stats.MinRTTMs)
	}
	if stats.MaxRTTMs != 20.0 {
		t.Errorf("expected max 20ms, got %f", stats.MaxRTTMs)
	}

	// avg of 10, 20, 15 = 15
	if stats.AvgRTTMs != 15.0 {
		t.Errorf("expected avg 15ms, got %f", stats.AvgRTTMs)
	}
}

func TestComputeStatsEmpty(t *testing.T) {
	stats := computeStats(nil)
	if stats.Total != 0 {
		t.Errorf("expected 0 total, got %d", stats.Total)
	}
}

func TestComputeStatsAllFailed(t *testing.T) {
	probes := []PingProbe{
		{Success: false, RTTMs: 0},
		{Success: false, RTTMs: 0},
	}
	stats := computeStats(probes)
	if stats.PacketLoss != 100.0 {
		t.Errorf("expected 100%% loss, got %f%%", stats.PacketLoss)
	}
	if stats.AvgRTTMs != 0 {
		t.Errorf("expected 0 avg, got %f", stats.AvgRTTMs)
	}
}

func TestMonitorCancellation(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	var port int
	fmt.Sscanf(portStr, "%d", &port)

	e := NewEngine()
	ctx, cancel := context.WithCancel(context.Background())

	updates := make(chan PingUpdate, 100)
	cfg := Config{
		Host:     host,
		Port:     port,
		Interval: 100 * time.Millisecond,
		Count:    100, // many — will be cancelled
		Timeout:  2 * time.Second,
	}

	// Cancel after 600ms
	go func() {
		time.Sleep(600 * time.Millisecond)
		cancel()
	}()

	result := e.Monitor(ctx, cfg, updates)

	if result.Stats.Sent > 10 {
		t.Errorf("expected cancellation to stop early, but sent %d", result.Stats.Sent)
	}
	if result.Complete {
		t.Error("expected incomplete result due to cancellation")
	}
}
