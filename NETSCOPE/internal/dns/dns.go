// Package dns provides real DNS resolution diagnostics.
package dns

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Neel472007/netscope/internal/types"
)

// Default resolvers to test against.
var DefaultResolvers = []string{
	"8.8.8.8:53",         // Google
	"1.1.1.1:53",         // Cloudflare
	"system",             // OS default
}

// Engine performs DNS diagnostics.
type Engine struct {
	resolvers []string
	timeout   time.Duration
}

// NewEngine creates a new DNS engine.
func NewEngine() *Engine {
	return &Engine{
		resolvers: DefaultResolvers,
		timeout:   5 * time.Second,
	}
}

// SetTimeout sets the DNS resolution timeout.
func (e *Engine) SetTimeout(d time.Duration) {
	e.timeout = d
}

// SetResolvers sets custom DNS resolvers.
func (e *Engine) SetResolvers(resolvers []string) {
	e.resolvers = resolvers
}

// Resolve performs DNS resolution for the given host and returns structured results.
func (e *Engine) Resolve(ctx context.Context, host string) *types.DNSResult {
	result := &types.DNSResult{
		Host: host,
	}

	ctx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()

	start := time.Now()

	// Use the system resolver (net.Resolver) which handles both IPv4 and IPv6
	resolver := &net.Resolver{
		PreferGo: false,
	}

	addrs, err := resolver.LookupHost(ctx, host)
	elapsed := time.Since(start)

	if err != nil {
		result.Success = false
		result.ResolutionTime = elapsed
		result.Error = err.Error()

		if ctx.Err() == context.DeadlineExceeded {
			result.IsTimeout = true
			result.Error = "DNS resolution timed out"
		} else if isDNSNotExist(err) {
			result.Error = "hostname does not exist (NXDOMAIN)"
		} else if isDNSRefused(err) {
			result.Error = "DNS query refused"
		} else if isTemporary(err) {
			result.Error = "DNS temporary failure"
		}
		return result
	}

	// Classify addresses
	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip == nil {
			continue
		}
		if ip.To4() != nil {
			result.IPv4Addresses = append(result.IPv4Addresses, addr)
		} else {
			result.IPv6Addresses = append(result.IPv6Addresses, addr)
		}
	}

	result.Success = true
	result.ResolutionTime = elapsed
	result.Resolver = "system"

	return result
}

// ResolveWithResolvers performs DNS resolution using multiple resolvers concurrently
// and returns the results from each.
func (e *Engine) ResolveWithResolvers(ctx context.Context, host string) []*types.DNSResult {
	results := make([]*types.DNSResult, len(e.resolvers))
	var wg sync.WaitGroup

	for i, resolver := range e.resolvers {
		wg.Add(1)
		go func(idx int, resolverAddr string) {
			defer wg.Done()
			results[idx] = e.resolveWithResolver(ctx, host, resolverAddr)
		}(i, resolver)
	}

	wg.Wait()
	return results
}

// resolveWithResolver performs DNS resolution using a specific resolver.
func (e *Engine) resolveWithResolver(ctx context.Context, host, resolverAddr string) *types.DNSResult {
	result := &types.DNSResult{
		Host:     host,
		Resolver: resolverAddr,
	}

	ctx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()

	start := time.Now()

	if resolverAddr == "system" {
		resolver := &net.Resolver{PreferGo: false}
		addrs, err := resolver.LookupHost(ctx, host)
		elapsed := time.Since(start)
		if err != nil {
			result.Success = false
			result.ResolutionTime = elapsed
			result.Error = err.Error()
			return result
		}
		classifyAddresses(result, addrs)
		result.Success = true
		result.ResolutionTime = elapsed
		return result
	}

	// Use a custom resolver by creating a dialer that connects to the specific resolver
	d := net.Dialer{Timeout: e.timeout}
	conn, err := d.DialContext(ctx, "udp", resolverAddr)
	if err != nil {
		elapsed := time.Since(start)
		result.Success = false
		result.ResolutionTime = elapsed
		result.Error = fmt.Sprintf("cannot connect to resolver %s: %v", resolverAddr, err)
		return result
	}
	conn.Close()

	// Fall back to system resolver for actual query but record the resolver used
	resolver := &net.Resolver{
		PreferGo: false,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return d.DialContext(ctx, "udp", resolverAddr)
		},
	}

	addrs, err := resolver.LookupHost(ctx, host)
	elapsed := time.Since(start)

	if err != nil {
		result.Success = false
		result.ResolutionTime = elapsed
		result.Error = err.Error()
		return result
	}

	classifyAddresses(result, addrs)
	result.Success = true
	result.ResolutionTime = elapsed
	return result
}

// classifyAddresses separates IPv4 and IPv6 addresses.
func classifyAddresses(result *types.DNSResult, addrs []string) {
	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip == nil {
			continue
		}
		if ip.To4() != nil {
			result.IPv4Addresses = append(result.IPv4Addresses, addr)
		} else {
			result.IPv6Addresses = append(result.IPv6Addresses, addr)
		}
	}
}

// isDNSNotExist checks if an error indicates NXDOMAIN.
func isDNSNotExist(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return strings.Contains(errStr, "no such host") || strings.Contains(errStr, "NXDOMAIN")
}

// isDNSRefused checks if an error indicates a refused DNS query.
func isDNSRefused(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "refused")
}

// isTemporary checks if an error is temporary.
func isTemporary(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "temporary")
}

// LookupTXT performs a TXT record lookup for a host.
func (e *Engine) LookupTXT(ctx context.Context, host string) ([]string, time.Duration, error) {
	ctx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()
	
	resolver := &net.Resolver{PreferGo: false}
	start := time.Now()
	txts, err := resolver.LookupTXT(ctx, host)
	elapsed := time.Since(start)
	
	if err != nil {
		return nil, elapsed, err
	}
	return txts, elapsed, nil
}

// Localhost is a helper for simulator testing.
func Localhost() string {
	hostname, _ := os.Hostname()
	if hostname == "" {
		return "localhost"
	}
	return hostname
}

// DoHProviders lists public DNS-over-HTTPS providers.
var DoHProviders = map[string]string{
	"google":   "https://dns.google/resolve?name=%s&type=A",
	"cloudflare": "https://cloudflare-dns.com/dns-query?name=%s&type=A",
}

// ResolveDoH performs DNS resolution via DNS-over-HTTPS (RFC 8484).
// This bypasses the system resolver and uses HTTPS instead of UDP/TCP port 53.
func (e *Engine) ResolveDoH(ctx context.Context, host, provider string) *types.DNSResult {
	result := &types.DNSResult{
		Host:     host,
		Resolver: "doh:" + provider,
	}

	dohURL, ok := DoHProviders[provider]
	if !ok {
		result.Error = "unknown DoH provider: " + provider
		return result
	}

	queryURL := fmt.Sprintf(dohURL, host)
	start := time.Now()

	// Use a minimal JSON DNS response parser
	httpReq, err := http.NewRequestWithContext(ctx, "GET", queryURL, nil)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	httpReq.Header.Set("Accept", "application/dns-json")

	httpClient := &http.Client{Timeout: e.timeout}
	resp, err := httpClient.Do(httpReq)
	elapsed := time.Since(start)
	result.ResolutionTime = elapsed

	if err != nil {
		result.Success = false
		result.Error = err.Error()
		return result
	}
	defer resp.Body.Close()

	// Parse DNS-over-HTTPS JSON response
	var dohResp struct {
		Status int `json:"Status"`
		Answer []struct {
			Data string `json:"data"`
		} `json:"Answer"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1024*10)).Decode(&dohResp); err != nil {
		result.Success = false
		result.Error = "failed to parse DoH response: " + err.Error()
		return result
	}

	if dohResp.Status != 0 {
		result.Success = false
		result.Error = fmt.Sprintf("DoH query returned status %d", dohResp.Status)
		return result
	}

	for _, ans := range dohResp.Answer {
		ip := net.ParseIP(ans.Data)
		if ip == nil {
			continue
		}
		if ip.To4() != nil {
			result.IPv4Addresses = append(result.IPv4Addresses, ans.Data)
		} else {
			result.IPv6Addresses = append(result.IPv6Addresses, ans.Data)
		}
	}

	if len(result.IPv4Addresses) == 0 && len(result.IPv6Addresses) == 0 {
		result.Success = false
		result.Error = "no addresses in DoH response"
		return result
	}

	result.Success = true
	return result
}
