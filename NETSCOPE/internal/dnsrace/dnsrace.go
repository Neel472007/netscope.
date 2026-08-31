// Package dnsrace tests multiple DNS resolvers simultaneously and ranks them
// by resolution speed, providing a clear comparison of public DNS providers.
package dnsrace

import (
	"context"
	"net"
	"sort"
	"sync"
	"time"
)

// ResolverResult holds the result from a single resolver.
type ResolverResult struct {
	Name      string `json:"name"`
	Address   string `json:"address"`
	Protocol  string `json:"protocol"` // "doh", "dot", "udp"
	Success   bool   `json:"success"`
	IPs       []string `json:"ips,omitempty"`
	LatencyMs float64 `json:"latency_ms"`
	Error     string  `json:"error,omitempty"`
	Rank      int     `json:"rank"`
}

// RaceResult holds the full resolver race result.
type RaceResult struct {
	Host      string           `json:"host"`
	StartedAt time.Time        `json:"started_at"`
	EndedAt   time.Time        `json:"ended_at"`
	Duration  float64          `json:"duration_ms"`
	Results   []ResolverResult `json:"results"`
	Fastest   *ResolverResult  `json:"fastest,omitempty"`
	Winner    string           `json:"winner,omitempty"`
}

// DefaultResolvers are public DNS resolvers to test.
var DefaultResolvers = []struct {
	Name    string
	Address string
}{
	{"Google", "8.8.8.8:53"},
	{"Google Alt", "8.8.4.4:53"},
	{"Cloudflare", "1.1.1.1:53"},
	{"Cloudflare Alt", "1.0.0.1:53"},
	{"Quad9", "9.9.9.9:53"},
	{"Quad9 Alt", "149.112.112.112:53"},
	{"OpenDNS", "208.67.222.222:53"},
	{"OpenDNS Alt", "208.67.220.220:53"},
	{"AdGuard", "94.140.14.14:53"},
	{"AdGuard Alt", "94.140.15.15:53"},
	{"NextDNS", "45.90.28.0:53"},
	{"CleanBrowsing", "185.228.168.9:53"},
	{"Mullvad", "194.242.2.2:53"},
	{"Yandex", "77.88.8.8:53"},
}

// Race runs DNS resolution against all resolvers simultaneously and ranks them.
func Race(ctx context.Context, host string) *RaceResult {
	result := &RaceResult{
		Host:      host,
		StartedAt: time.Now(),
	}

	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, resolver := range DefaultResolvers {
		wg.Add(1)
		go func(r struct{ Name, Address string }) {
			defer wg.Done()
			res := testResolver(ctx, host, r.Name, r.Address)
			mu.Lock()
			result.Results = append(result.Results, res)
			mu.Unlock()
		}(resolver)
	}

	wg.Wait()

	result.EndedAt = time.Now()
	result.Duration = float64(result.EndedAt.Sub(result.StartedAt).Milliseconds())

	// Sort by latency (fastest first)
	sort.Slice(result.Results, func(i, j int) bool {
		if result.Results[i].Success != result.Results[j].Success {
			return result.Results[i].Success
		}
		return result.Results[i].LatencyMs < result.Results[j].LatencyMs
	})

	// Assign ranks
	for i := range result.Results {
		result.Results[i].Rank = i + 1
	}

	// Find fastest
	for i := range result.Results {
		if result.Results[i].Success {
			result.Fastest = &result.Results[i]
			result.Winner = result.Results[i].Name
			break
		}
	}

	return result
}

func testResolver(ctx context.Context, host, name, addr string) ResolverResult {
	res := ResolverResult{
		Name:     name,
		Address:  addr,
		Protocol: "udp",
	}

	resolver := &net.Resolver{
		PreferGo: false,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(ctx, "udp", addr)
		},
	}

	start := time.Now()
	ips, err := resolver.LookupHost(ctx, host)
	elapsed := time.Since(start)

	res.LatencyMs = float64(elapsed.Microseconds()) / 1000.0

	if err != nil {
		res.Error = err.Error()
		return res
	}

	res.Success = true
	res.IPs = ips
	return res
}

// QuickRace performs a fast race with fewer resolvers.
func QuickRace(host string) *RaceResult {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return Race(ctx, host)
}
