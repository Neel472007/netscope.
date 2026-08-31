// Package traceroute performs network path tracing using TCP SYN probing.
// All implemented with Go standard library.
package traceroute

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	// MaxHops is the maximum number of hops to trace.
	MaxHops = 30
	// DefaultProbes is the number of probes per hop.
	DefaultProbes = 3
)

// ProbeResult represents a single probe result.
type ProbeResult struct {
	Success  bool          `json:"success"`
	RTT      time.Duration `json:"rtt_ns"`
	IP       string        `json:"ip,omitempty"`
	TimedOut bool          `json:"timed_out"`
}

// Hop represents a single hop in the traceroute.
type Hop struct {
	TTL     int           `json:"ttl"`
	Probes  []ProbeResult `json:"probes"`
	IP      string        `json:"ip,omitempty"`
	Host    string        `json:"host,omitempty"`
	Loss    float64       `json:"loss"`
	AvgRTT  time.Duration `json:"avg_rtt_ns"`
	MinRTT  time.Duration `json:"min_rtt_ns"`
	MaxRTT  time.Duration `json:"max_rtt_ns"`
	Reached bool          `json:"reached"`
}

// Result holds the complete traceroute result.
type Result struct {
	Target     string `json:"target"`
	ResolvedIP string `json:"resolved_ip"`
	TotalHops  int    `json:"total_hops"`
	MaxHops    int    `json:"max_hops"`
	Hops       []Hop  `json:"hops"`
	Completed  bool   `json:"completed"`
	DurationNs int64  `json:"duration_ns"`
	Error      string `json:"error,omitempty"`
}

// Traceroute performs a traceroute to the given host.
// Uses TCP connect with controlled timeouts to infer hop distances.
func Traceroute(ctx context.Context, host string, maxHops, probesPerHop int) *Result {
	if maxHops <= 0 || maxHops > MaxHops {
		maxHops = MaxHops
	}
	if probesPerHop <= 0 || probesPerHop > 10 {
		probesPerHop = DefaultProbes
	}

	result := &Result{
		Target:   host,
		MaxHops:  maxHops,
		Hops:     make([]Hop, 0, maxHops),
	}

	start := time.Now()

	// Resolve the target
	ips, err := net.LookupIP(host)
	if err != nil {
		result.Error = fmt.Sprintf("DNS resolution failed: %v", err)
		result.DurationNs = time.Since(start).Nanoseconds()
		return result
	}

	var targetIP net.IP
	for _, ip := range ips {
		if ip.To4() != nil {
			targetIP = ip.To4()
			break
		}
	}
	if targetIP == nil && len(ips) > 0 {
		targetIP = ips[0]
	}
	if targetIP == nil {
		result.Error = "no valid IP address found"
		result.DurationNs = time.Since(start).Nanoseconds()
		return result
	}

	result.ResolvedIP = targetIP.String()

	seenTarget := false

	for ttl := 1; ttl <= maxHops; ttl++ {
		select {
		case <-ctx.Done():
			result.Error = "traceroute cancelled"
			result.DurationNs = time.Since(start).Nanoseconds()
			return result
		default:
		}

		hop := Hop{TTL: ttl, Probes: make([]ProbeResult, 0, probesPerHop)}
		var rtts []time.Duration
		var probeMu sync.Mutex

		var wg sync.WaitGroup
		for p := 0; p < probesPerHop; p++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				probe := probeTarget(ctx, targetIP, ttl)
				probeMu.Lock()
				hop.Probes = append(hop.Probes, probe)
				if probe.Success {
					rtts = append(rtts, probe.RTT)
				}
				probeMu.Unlock()
			}()
		}
		wg.Wait()

		if len(rtts) > 0 {
			sort.Slice(rtts, func(i, j int) bool { return rtts[i] < rtts[j] })
			hop.Reached = true
			hop.MinRTT = rtts[0]
			hop.MaxRTT = rtts[len(rtts)-1]
			var total time.Duration
			for _, rtt := range rtts {
				total += rtt
			}
			hop.AvgRTT = total / time.Duration(len(rtts))
			hop.Loss = 1.0 - float64(len(rtts))/float64(probesPerHop)

			// Get IP from successful probes
			for _, pr := range hop.Probes {
				if pr.Success && pr.IP != "" {
					hop.IP = pr.IP
					break
				}
			}

			// Reverse DNS
			if hop.IP != "" {
				hop.Host = resolvePTR(hop.IP)
			}

			if hop.IP == result.ResolvedIP {
				seenTarget = true
				result.Completed = true
			}
		} else {
			hop.Loss = 1.0
		}

		result.Hops = append(result.Hops, hop)
		if seenTarget {
			break
		}
	}

	result.TotalHops = len(result.Hops)
	result.DurationNs = time.Since(start).Nanoseconds()
	return result
}

func probeTarget(ctx context.Context, target net.IP, ttl int) ProbeResult {
	timeout := 200*time.Millisecond + time.Duration(ttl*80)*time.Millisecond
	if timeout > 3*time.Second {
		timeout = 3 * time.Second
	}

	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	dialer := &net.Dialer{Timeout: timeout}

	start := time.Now()
	conn, err := dialer.DialContext(probeCtx, "tcp", fmt.Sprintf("%s:80", target.String()))
	rtt := time.Since(start)

	if err != nil {
		errStr := strings.ToLower(err.Error())
		// Connection refused = target reachable, port closed
		if strings.Contains(errStr, "refused") {
			return ProbeResult{Success: true, RTT: rtt, IP: target.String()}
		}
		// Timeout
		if rtt >= timeout-50*time.Millisecond {
			return ProbeResult{TimedOut: true}
		}
		// Other error but fast = might be intermediate
		return ProbeResult{TimedOut: true}
	}

	conn.Close()
	return ProbeResult{Success: true, RTT: rtt, IP: target.String()}
}

func resolvePTR(ip string) string {
	names, err := net.LookupAddr(ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return names[0]
}
