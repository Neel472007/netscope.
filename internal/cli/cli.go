// Package cli provides the command-line interface for NetScope.
package cli

import (
	"context"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/Neel472007/netscope/internal/benchmark"
	"github.com/Neel472007/netscope/internal/concurrency"
	"github.com/Neel472007/netscope/internal/diagnostics"
	"github.com/Neel472007/netscope/internal/dns"
	"github.com/Neel472007/netscope/internal/httpdiag"
	"github.com/Neel472007/netscope/internal/lbsim"
	"github.com/Neel472007/netscope/internal/ping"
	"github.com/Neel472007/netscope/internal/portscan"
	"github.com/Neel472007/netscope/internal/tcp"
	"github.com/Neel472007/netscope/internal/tlsinspector"
	"github.com/Neel472007/netscope/internal/dnsrace"
	"github.com/Neel472007/netscope/internal/multiscan"
	"github.com/Neel472007/netscope/internal/overview"
	"github.com/Neel472007/netscope/internal/speedtest"
	"github.com/Neel472007/netscope/internal/traceroute"
	"github.com/Neel472007/netscope/internal/types"
	"github.com/Neel472007/netscope/internal/whois"
)

// Run executes the CLI command.
func Run(args []string) {
	if len(args) < 2 {
		printUsage()
		return
	}

	cmd := args[1]
	target := ""
	if len(args) > 2 {
		target = args[2]
	}

	switch cmd {
	case "diagnose", "diag":
		cmdDiagnose(target)
	case "dns":
		cmdDNS(target)
	case "tcp":
		extra := []string{}
		if len(args) > 3 {
			extra = args[3:]
		}
		cmdTCP(target, extra)
	case "http":
		cmdHTTP(target)
	case "stress":
		stressArgs := []string{}
		if len(args) > 2 {
			stressArgs = args[2:]
		}
		cmdStress(stressArgs)
	case "lbsim":
		lbArgs := []string{}
		if len(args) > 2 {
			lbArgs = args[2:]
		}
		cmdLBSim(lbArgs)
	case "ports", "portscan":
		portArgs := []string{}
		if len(args) > 2 {
			portArgs = args[2:]
		}
		cmdPortScan(portArgs)
	case "tls":
		cmdTLS(target)
	case "benchmark", "bench":
		benchArgs := []string{}
		if len(args) > 2 {
			benchArgs = args[2:]
		}
		cmdBenchmark(benchArgs)
	case "traceroute", "trace":
		traceArgs := []string{}
		if len(args) > 2 {
			traceArgs = args[2:]
		}
		cmdTraceroute(traceArgs)
	case "ping":
		pingArgs := []string{}
		if len(args) > 2 {
			pingArgs = args[2:]
		}
		cmdPing(pingArgs)
	case "overview":
		cmdOverview(target)
	case "whois":
		cmdWhois(target)
	case "speed":
		cmdSpeed(args[2:])
	case "dnsrace":
		cmdDNSRace(target)
	case "multiscan":
		cmdMultiScan(args[2:])
	case "help", "--help", "-h":
		printUsage()
	default:
		if cmd != "" && !strings.HasPrefix(cmd, "-") {
			cmdDiagnose(cmd)
		} else {
			fmt.Fprintf(os.Stderr, "Unknown command: %s\n", cmd)
			printUsage()
		}
	}
}

func printUsage() {
	fmt.Println(`NetScope — Network Diagnostics & Failure Intelligence

Usage:
  netscope <command> [arguments]

Commands:
  diagnose <target>              Run full diagnostics against a target
  dns <host>                     Run DNS resolution test
  tcp <host> <port>              Run TCP connectivity test
  http <url>                     Run HTTP diagnostic test
  ports <host> [port1,port2]     Scan ports on a host
  tls <host>                     Inspect TLS certificate
  traceroute <host>              Trace network path to host
  benchmark <host> <port>        Run network quality benchmark
  stress [options]               Run stress test
  lbsim [options]                Start load balancer simulator
  help                           Show this help message

Examples:
  netscope diagnose example.com
  netscope dns example.com
  netscope tcp example.com 443
  netscope http https://example.com
  netscope ports example.com 80,443,8080
  netscope tls example.com
  netscope traceroute example.com
  netscope trace 8.8.8.8
  netscope benchmark example.com 443
  netscope stress --host example.com --port 443 --connections 100 --duration 10
  netscope lbsim --port 8080`)
}

func cmdDiagnose(target string) {
	if target == "" {
		fmt.Fprintln(os.Stderr, "Error: target required. Example: netscope diagnose example.com")
		return
	}

	fmt.Printf("Diagnosing %s ...\n\n", target)

	orch := diagnostics.NewOrchestrator()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := orch.DiagnoseTarget(ctx, target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return
	}

	printDiagnosticResult(result)
}

func cmdDNS(host string) {
	if host == "" {
		fmt.Fprintln(os.Stderr, "Error: hostname required. Example: netscope dns example.com")
		return
	}

	engine := dns.NewEngine()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	fmt.Printf("DNS Resolution: %s\n\n", host)

	result := engine.Resolve(ctx, host)

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "Host:\t%s\n", result.Host)
	successStr := "FAIL"
	if result.Success {
		successStr = "OK"
	}
	fmt.Fprintf(w, "Success:\t%s\n", successStr)
	fmt.Fprintf(w, "Resolver:\t%s\n", result.Resolver)
	fmt.Fprintf(w, "Time:\t%s\n", result.ResolutionTime.Round(time.Millisecond))

	if result.Success {
		if len(result.IPv4Addresses) > 0 {
			fmt.Fprintf(w, "IPv4:\t%s\n", strings.Join(result.IPv4Addresses, ", "))
		}
		if len(result.IPv6Addresses) > 0 {
			fmt.Fprintf(w, "IPv6:\t%s\n", strings.Join(result.IPv6Addresses, ", "))
		}
	} else {
		fmt.Fprintf(w, "Error:\t%s\n", result.Error)
	}
	w.Flush()
}

func cmdTCP(host string, extraArgs []string) {
	if host == "" {
		fmt.Fprintln(os.Stderr, "Error: host and port required. Example: netscope tcp example.com 443")
		return
	}

	port := 80
	if len(extraArgs) > 0 {
		fmt.Sscanf(extraArgs[0], "%d", &port)
	}

	engine := tcp.NewEngine()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	fmt.Printf("TCP Connectivity: %s:%d\n\n", host, port)

	result := engine.Test(ctx, host, port)

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "Host:\t%s:%d\n", result.Host, result.Port)
	connStr := "FAIL"
	if result.Connected {
		connStr = "OK"
	}
	fmt.Fprintf(w, "Connected:\t%s\n", connStr)
	fmt.Fprintf(w, "Latency:\t%s\n", result.Latency.Round(time.Millisecond))
	if result.RemoteAddr != "" {
		fmt.Fprintf(w, "Remote:\t%s\n", result.RemoteAddr)
	}
	if result.Error != "" {
		fmt.Fprintf(w, "Error:\t%s\n", result.Error)
		fmt.Fprintf(w, "Type:\t%s\n", result.ErrorType)
	}
	w.Flush()
}

func cmdHTTP(rawURL string) {
	if rawURL == "" {
		fmt.Fprintln(os.Stderr, "Error: URL required. Example: netscope http https://example.com")
		return
	}

	engine := httpdiag.NewEngine()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	fmt.Printf("HTTP Diagnostic: %s\n\n", rawURL)

	result := engine.Diagnose(ctx, rawURL)

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "URL:\t%s\n", result.URL)
	fmt.Fprintf(w, "Status:\t%d %s\n", result.StatusCode, result.StatusText)
	successStr := "FAIL"
	if result.Success {
		successStr = "OK"
	}
	fmt.Fprintf(w, "Success:\t%s\n", successStr)
	fmt.Fprintf(w, "DNS:\t%s\n", result.DNSResolution.Round(time.Millisecond))
	fmt.Fprintf(w, "TCP:\t%s\n", result.TCPConnection.Round(time.Millisecond))
	if result.TLSHandshake > 0 {
		fmt.Fprintf(w, "TLS:\t%s\n", result.TLSHandshake.Round(time.Millisecond))
	}
	fmt.Fprintf(w, "TTFB:\t%s\n", result.TimeToFirstByte.Round(time.Millisecond))
	fmt.Fprintf(w, "Total:\t%s\n", result.TotalDuration.Round(time.Millisecond))
	fmt.Fprintf(w, "Size:\t%s\n", formatBytes(result.ResponseSize))
	fmt.Fprintf(w, "Redirects:\t%d\n", result.RedirectCount)

	if result.Error != "" {
		fmt.Fprintf(w, "Error:\t%s\n", result.Error)
	}

	for _, h := range result.Headers {
		fmt.Fprintf(w, "%s:\t%s\n", h.Name, h.Value)
	}
	w.Flush()
}

func cmdStress(args []string) {
	host := ""
	port := 443
	conns := 10
	duration := 5

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--host", "-H":
			if i+1 < len(args) {
				host = args[i+1]
				i++
			}
		case "--port", "-p":
			if i+1 < len(args) {
				fmt.Sscanf(args[i+1], "%d", &port)
				i++
			}
		case "--connections", "-c":
			if i+1 < len(args) {
				fmt.Sscanf(args[i+1], "%d", &conns)
				i++
			}
		case "--duration", "-d":
			if i+1 < len(args) {
				fmt.Sscanf(args[i+1], "%d", &duration)
				i++
			}
		default:
			if host == "" && !strings.HasPrefix(args[i], "-") {
				host = args[i]
			}
		}
	}

	if host == "" {
		fmt.Fprintln(os.Stderr, "Error: --host required. Example: netscope stress --host example.com --port 443 --connections 100")
		return
	}

	if conns > 10000 {
		conns = 10000
	}

	fmt.Printf("Stress Test: %s:%d\n", host, port)
	fmt.Printf("  Connections: %d\n", conns)
	fmt.Printf("  Duration:    %ds\n\n", duration)

	tcpEngine := tcp.NewEngine()
	runner := concurrency.NewStressRunner(concurrency.StressConfig{
		Concurrency: conns,
		Duration:    time.Duration(duration) * time.Second,
	})

	result := runner.Run(context.Background(), func(ctx context.Context) (time.Duration, bool, bool) {
		start := time.Now()
		r := tcpEngine.Test(ctx, host, port)
		elapsed := time.Since(start)
		return elapsed, r.Connected, r.IsTimeout
	})

	printStressResult(result)
}

func cmdLBSim(args []string) {
	port := 8080
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--port", "-p":
			if i+1 < len(args) {
				fmt.Sscanf(args[i+1], "%d", &port)
				i++
			}
		}
	}

	cfg := lbsim.DefaultConfig()
	cfg.Port = port

	lb, err := lbsim.New(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return
	}

	fmt.Println("Starting Load Balancer Simulator...")
	if err := lb.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
	}
}

func cmdPortScan(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Error: host required. Example: netscope ports example.com 80,443,8080")
		return
	}

	host := args[0]
	ports := portscan.CommonPorts
	if len(args) > 1 {
		ports = parsePorts(args[1])
	}

	fmt.Printf("Port Scan: %s\n\n", host)

	scanner := portscan.New()
	result := scanner.Scan(context.Background(), portscan.ScanRequest{
		Host:  host,
		Ports: ports,
	})

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "Host:\t%s\n", result.Host)
	fmt.Fprintf(w, "Scanned:\t%d ports\n", result.TotalPorts)
	fmt.Fprintf(w, "Open:\t%d\n", result.OpenPorts)
	fmt.Fprintf(w, "Closed:\t%d\n", result.ClosedPorts)
	fmt.Fprintf(w, "Time:\t%dms\n", result.Duration)
	fmt.Fprintln(w)

	for _, p := range result.Results {
		status := "CLOSED"
		if p.Open {
			status = "OPEN"
		}
		fmt.Fprintf(w, "%d\t%s\t%s\t%dms\n", p.Port, p.Service, status, p.Latency)
	}
	w.Flush()
}

func cmdTLS(host string) {
	if host == "" {
		fmt.Fprintln(os.Stderr, "Error: host required. Example: netscope tls example.com")
		return
	}

	fmt.Printf("TLS Certificate: %s\n\n", host)

	result := tlsinspector.Inspect(host, 443)

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "Host:\t%s:%d\n", result.Host, result.Port)
	if result.Error != "" {
		fmt.Fprintf(w, "Error:\t%s\n", result.Error)
		w.Flush()
		return
	}

	fmt.Fprintf(w, "Protocol:\t%s\n", result.Protocol)
	fmt.Fprintf(w, "Cipher:\t%s\n", result.CipherSuite)
	fmt.Fprintf(w, "Verified:\t%v\n", result.Verified)
	fmt.Fprintf(w, "Connect Time:\t%s\n", result.ConnectTime.Round(time.Millisecond))
	fmt.Fprintln(w)

	fmt.Fprintf(w, "\t--- Certificate ---\n")
	fmt.Fprintf(w, "Subject:\t%s\n", result.Certificate.Subject)
	fmt.Fprintf(w, "Issuer:\t%s\n", result.Certificate.Issuer)
	fmt.Fprintf(w, "Expires:\t%s (%d days)\n", result.Certificate.NotAfter, result.Certificate.DaysExpiry)
	if result.Certificate.IsExpired {
		fmt.Fprintf(w, "Status:\tEXPIRED\n")
	} else {
		fmt.Fprintf(w, "Status:\tVALID\n")
	}
	fmt.Fprintf(w, "Key:\t%s %d-bit\n", result.Certificate.KeyAlgorithm, result.Certificate.KeySize)
	fmt.Fprintf(w, "Signature:\t%s\n", result.Certificate.SignatureAlgo)
	if len(result.Certificate.SANs) > 0 {
		fmt.Fprintf(w, "SANs:\t%s\n", strings.Join(result.Certificate.SANs, ", "))
	}

	if len(result.CertificateChain) > 1 {
		fmt.Fprintf(w, "\t--- Chain (%d certs) ---\n", len(result.CertificateChain))
		for i, c := range result.CertificateChain {
			fmt.Fprintf(w, "[%d]\t%s → %s\n", i, c.Subject, c.Issuer)
		}
	}

	w.Flush()
}

func cmdBenchmark(args []string) {
	if len(args) < 2 {
		fmt.Fprintln(os.Stderr, "Error: host and port required. Example: netscope benchmark example.com 443")
		return
	}

	host := args[0]
	port := 0
	fmt.Sscanf(args[1], "%d", &port)

	rounds := 20
	concurrency := 5

	for i := 2; i < len(args); i++ {
		switch args[i] {
		case "--rounds", "-r":
			if i+1 < len(args) {
				fmt.Sscanf(args[i+1], "%d", &rounds)
				i++
			}
		case "--concurrency", "-c":
			if i+1 < len(args) {
				fmt.Sscanf(args[i+1], "%d", &concurrency)
				i++
			}
		}
	}

	fmt.Printf("Network Benchmark: %s:%d\n", host, port)
	fmt.Printf("  Rounds: %d, Concurrency: %d\n\n", rounds, concurrency)

	result := benchmark.Benchmark(host, port, rounds, concurrency)

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "Target:\t%s\n", result.Target)
	fmt.Fprintf(w, "Grade:\t%s\n", result.Grade)
	fmt.Fprintf(w, "Score:\t%.1f%%\n", result.Consistency)
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Successful:\t%d/%d\n", result.Successful, result.Rounds)
	fmt.Fprintf(w, "Failed:\t%d\n", result.Failed)
	fmt.Fprintf(w, "Packet Loss:\t%.1f%%\n", result.PacketLoss)
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Avg RTT:\t%s\n", result.AvgRTT.Round(time.Millisecond))
	fmt.Fprintf(w, "Min RTT:\t%s\n", result.MinRTT.Round(time.Millisecond))
	fmt.Fprintf(w, "Max RTT:\t%s\n", result.MaxRTT.Round(time.Millisecond))
	fmt.Fprintf(w, "P50:\t%s\n", result.P50.Round(time.Millisecond))
	fmt.Fprintf(w, "P95:\t%s\n", result.P95.Round(time.Millisecond))
	fmt.Fprintf(w, "P99:\t%s\n", result.P99.Round(time.Millisecond))
	fmt.Fprintf(w, "Jitter:\t%s\n", result.Jitter.Round(time.Millisecond))
	w.Flush()
}

func cmdTraceroute(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Error: host required. Example: netscope traceroute example.com")
		return
	}

	host := args[0]
	maxHops := 30
	probes := 3

	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--max-hops", "-m":
			if i+1 < len(args) {
				fmt.Sscanf(args[i+1], "%d", &maxHops)
				i++
			}
		case "--probes", "-q":
			if i+1 < len(args) {
				fmt.Sscanf(args[i+1], "%d", &probes)
				i++
			}
		}
	}

	fmt.Printf("Traceroute to %s (max %d hops, %d probes/hop)\n\n", host, maxHops, probes)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	result := traceroute.Traceroute(ctx, host, maxHops, probes)

	if result.Error != "" {
		fmt.Fprintf(os.Stderr, "Error: %s\n", result.Error)
		return
	}

	fmt.Printf("Traceroute to %s [%s]:\n\n", result.Target, result.ResolvedIP)

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	for _, hop := range result.Hops {
		if hop.Reached {
			hostDisplay := hop.IP
			if hop.Host != "" {
			hostDisplay = hop.Host + " (" + hop.IP + ")"
			}
			lossStr := ""
			if hop.Loss > 0 {
				lossStr = fmt.Sprintf(" (%.0f%% loss)", hop.Loss*100)
			}
			fmt.Fprintf(w, "%2d\t%s\t%s avg=%s min=%s max=%s%s\n",
				hop.TTL, hostDisplay, "",
				hop.AvgRTT.Round(time.Millisecond),
				hop.MinRTT.Round(time.Millisecond),
				hop.MaxRTT.Round(time.Millisecond),
				lossStr)
		} else {
			fmt.Fprintf(w, "%2d\t*\t*\n", hop.TTL)
		}
	}
	w.Flush()

	fmt.Printf("\nCompleted: %v, Hops: %d, Duration: %dms\n",
		result.Completed, result.TotalHops, result.DurationNs/1e6)
}

func cmdPing(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Error: host required. Example: netscope ping example.com 80")
		return
	}

	host := args[0]
	port := 80
	count := 10
	interval := 1 * time.Second

	if len(args) > 1 {
		fmt.Sscanf(args[1], "%d", &port)
	}
	for i := 2; i < len(args); i++ {
		switch args[i] {
		case "-c", "--count":
			if i+1 < len(args) {
				fmt.Sscanf(args[i+1], "%d", &count)
				i++
			}
		case "-i", "--interval":
			if i+1 < len(args) {
				var ms int
				fmt.Sscanf(args[i+1], "%d", &ms)
				interval = time.Duration(ms) * time.Millisecond
				i++
			}
		}
	}

	fmt.Printf("PING %s:%d — %d probes, interval %v\n\n", host, port, count, interval)

	e := ping.NewEngine()
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(count)*interval+30*time.Second)
	defer cancel()

	cfg := ping.Config{
		Host:     host,
		Port:     port,
		Interval: interval,
		Count:    count,
		Timeout:  2 * time.Second,
	}

	result := e.Monitor(ctx, cfg, nil)

	// Print results
	for _, p := range result.Probes {
		if p.Success {
			fmt.Printf("%3d  %.2f ms\n", p.Seq, p.RTTMs)
		} else {
			fmt.Printf("%3d  timeout\n", p.Seq)
		}
	}

	fmt.Printf("\n--- %s ping statistics ---\n", host)
	fmt.Printf("%d probes sent, %d received, %.1f%% loss\n",
		result.Stats.Sent, result.Stats.Received, result.Stats.PacketLoss)
	fmt.Printf("rtt min=%.2f ms avg=%.2f ms max=%.2f ms\n",
		result.Stats.MinRTTMs, result.Stats.AvgRTTMs, result.Stats.MaxRTTMs)
	fmt.Printf("median=%.2f ms p95=%.2f ms jitter=%.2f ms stddev=%.2f ms\n",
		result.Stats.MedianMs, result.Stats.P95Ms, result.Stats.JitterMs, result.Stats.StdDevMs)
}

func cmdOverview(target string) {
		if target == "" {
			fmt.Fprintln(os.Stderr, "Error: host required. Example: netscope overview example.com")
			return
		}
		fmt.Printf("Running full network overview for %s ...\n\n", target)
		e := overview.NewEngine()
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		result := e.Scan(ctx, target, 443, 5)
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintf(w, "Target:\t%s\n", result.Target)
		fmt.Fprintf(w, "Duration:\t%.0f ms\n", result.Duration)
		fmt.Fprintf(w, "Score:\t%d/100 (%s)\n", result.Summary.Score, result.Summary.Overall)
		fmt.Fprintln(w)
		if result.DNS != nil {
			status := "FAIL"
			if result.DNS.Success {
				status = "OK"
			}
			fmt.Fprintf(w, "DNS:\t%s\n", status)
		}
		if result.TCP != nil {
			fmt.Fprintf(w, "TCP:\tconnected=%v latency=%.0fms\n", result.TCP.Connected, float64(result.TCP.Latency.Microseconds())/1000)
		}
		if result.HTTP != nil {
			fmt.Fprintf(w, "HTTP:\t%d %s (%.0fms)\n", result.HTTP.StatusCode, result.HTTP.StatusText, float64(result.HTTP.TotalDuration.Microseconds())/1000)
		}
		if result.TLS != nil {
			fmt.Fprintf(w, "TLS:\t%s %s\n", result.TLS.Protocol, result.TLS.CipherSuite)
		}
		if result.Benchmark != nil {
			fmt.Fprintf(w, "Benchmark:\tGrade=%s Avg=%.0fms Consistency=%.0f%%\n", result.Benchmark.Grade, float64(result.Benchmark.AvgRTT.Microseconds())/1000, result.Benchmark.Consistency)
		}
		if len(result.OpenPorts) > 0 {
			fmt.Fprintf(w, "Open Ports:\t")
			for i, p := range result.OpenPorts {
				if i > 0 {
					fmt.Fprint(w, ", ")
				}
				fmt.Fprintf(w, "%d(%s)", p.Port, p.Service)
			}
			fmt.Fprintln(w)
		}
		w.Flush()
	}

	func cmdWhois(target string) {
		if target == "" {
			fmt.Fprintln(os.Stderr, "Error: domain required. Example: netscope whois example.com")
			return
		}
		domain := whois.ExtractRootDomain(target)
		fmt.Printf("WHOIS lookup for %s ...\n\n", domain)
		result := whois.LookupDefault(domain)
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintf(w, "Domain:\t%s\n", result.Domain)
		fmt.Fprintf(w, "Server:\t%s\n", result.Server)
		if result.Error != "" {
			fmt.Fprintf(w, "Error:\t%s\n", result.Error)
		} else {
			if result.Registrar != "" {
				fmt.Fprintf(w, "Registrar:\t%s\n", result.Registrar)
			}
			if result.Registration != "" {
				fmt.Fprintf(w, "Registered:\t%s\n", result.Registration)
			}
			if result.Expiration != "" {
				fmt.Fprintf(w, "Expires:\t%s\n", result.Expiration)
			}
			if result.Updated != "" {
				fmt.Fprintf(w, "Updated:\t%s\n", result.Updated)
			}
			if result.NameServers != "" {
				fmt.Fprintf(w, "Name Servers:\t%s\n", result.NameServers)
			}
			if result.Status != "" {
				fmt.Fprintf(w, "Status:\t%s\n", result.Status)
			}
			if result.Country != "" {
				fmt.Fprintf(w, "Country:\t%s\n", result.Country)
			}
			if result.DNSSEC != "" {
				fmt.Fprintf(w, "DNSSEC:\t%s\n", result.DNSSEC)
			}
		}
		fmt.Fprintf(w, "Response:\t%d bytes in %.0fms\n", result.RawLength, result.Duration)
		w.Flush()
	}

	func cmdSpeed(args []string) {
		url := ""
		rounds := 5
		if len(args) > 0 {
			url = args[0]
		}
		if len(args) > 1 {
			fmt.Sscanf(args[1], "%d", &rounds)
		}
		fmt.Printf("Speed test: %s (%d rounds)\n\n", url, rounds)
		e := context.Background()
		result := speedtest.Test(e, url, rounds, 3)
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintf(w, "Target:\t%s\n", result.Target)
		fmt.Fprintf(w, "Grade:\t%s\n", result.Grade)
		fmt.Fprintf(w, "Avg Speed:\t%.1f Mbps\n", result.AvgSpeedMbps)
		fmt.Fprintf(w, "Max Speed:\t%.1f Mbps\n", result.MaxSpeedMbps)
		fmt.Fprintf(w, "Min Speed:\t%.1f Mbps\n", result.MinSpeedMbps)
		fmt.Fprintf(w, "Median:\t%.1f Mbps\n", result.MedianMbps)
		fmt.Fprintf(w, "Jitter:\t%.1f Mbps\n", result.JitterMbps)
		fmt.Fprintf(w, "Latency:\t%.1f ms\n", result.AvgLatencyMs)
		fmt.Fprintf(w, "Packet Loss:\t%.1f%%\n", result.PacketLoss)
		fmt.Fprintf(w, "Total Download:\t%.2f MB\n", float64(result.TotalBytes)/(1024*1024))
		fmt.Fprintf(w, "Duration:\t%.0f ms\n", result.TotalDuration)
		fmt.Fprintf(w, "Successful:\t%d/%d\n", result.Successful, result.Rounds)
		w.Flush()
	}

	func cmdDNSRace(target string) {
		if target == "" {
			fmt.Fprintln(os.Stderr, "Error: host required. Example: netscope dnsrace example.com")
			return
		}
		fmt.Printf("DNS Resolver Race: %s\n\n", target)
		result := dnsrace.Race(context.Background(), target)
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintf(w, "Host:\t%s\n", result.Host)
		fmt.Fprintf(w, "Duration:\t%.0f ms\n", result.Duration)
		if result.Winner != "" {
			fmt.Fprintf(w, "Winner:\t%s (%.1f ms)\n", result.Winner, result.Fastest.LatencyMs)
		}
		fmt.Fprintln(w)
		fmt.Fprintf(w, "Rank\tName\tAddress\tLatency\tStatus\n")
		for _, r := range result.Results {
			status := "FAIL"
			if r.Success {
				status = "OK"
			}
			fmt.Fprintf(w, "%d\t%s\t%s\t%.1f ms\t%s\n", r.Rank, r.Name, r.Address, r.LatencyMs, status)
		}
		w.Flush()
	}

	func cmdMultiScan(args []string) {
		if len(args) == 0 {
			fmt.Fprintln(os.Stderr, "Error: hosts required. Example: netscope multiscan example.com google.com cloudflare.com")
			return
		}
		fmt.Printf("Multi-target scan: %d hosts\n\n", len(args))
		result := multiscan.Scan(context.Background(), args, 80, 5)
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintf(w, "Host\tScore\tStatus\tDNS\tTCP\tHTTP\tOpen Ports\n")
		for _, t := range result.Targets {
			dnsStatus := "FAIL"
			if t.DNS != nil && t.DNS.Success {
				dnsStatus = "OK"
			}
			tcpStatus := "FAIL"
			if t.TCP != nil && t.TCP.Connected {
				tcpStatus = "OK"
			}
			httpStatus := "—"
			if t.HTTP != nil {
				if t.HTTP.Success {
					httpStatus = "OK"
				} else {
					httpStatus = "FAIL"
				}
			}
			fmt.Fprintf(w, "%s\t%d\t%s\t%s\t%s\t%s\t%d\n", t.Host, t.Score, t.Overall, dnsStatus, tcpStatus, httpStatus, t.OpenPorts)
		}
		fmt.Fprintf(w, "\nHealthy: %d  Degraded: %d  Failed: %d  Duration: %.0fms\n", result.Healthy, result.Degraded, result.Failed, result.Duration)
		w.Flush()
	}

	func printDiagnosticResult(result *types.DiagnosticResult) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

	fmt.Fprintf(w, "Target:\t%s\n", result.Target.Host)
	if result.Target.Port > 0 {
		fmt.Fprintf(w, "Port:\t%d\n", result.Target.Port)
	}
	fmt.Fprintf(w, "Timestamp:\t%s\n", result.Timestamp.Format(time.RFC3339))
	fmt.Fprintln(w)

	// DNS
	if result.DNS != nil {
		dnsStatus := "FAIL"
		if result.DNS.Success {
			dnsStatus = "OK"
		}
		fmt.Fprintf(w, "DNS:\t%s %s\n", dnsStatus, result.DNS.ResolutionTime.Round(time.Millisecond))
		if result.DNS.Success && len(result.DNS.IPv4Addresses) > 0 {
			fmt.Fprintf(w, "  IPv4:\t%s\n", strings.Join(result.DNS.IPv4Addresses, ", "))
		}
		if result.DNS.Error != "" {
			fmt.Fprintf(w, "  Error:\t%s\n", result.DNS.Error)
		}
	}

	// TCP
	if result.TCP != nil {
		tcpStatus := "FAIL"
		if result.TCP.Connected {
			tcpStatus = "OK"
		}
		fmt.Fprintf(w, "TCP:\t%s %s\n", tcpStatus, result.TCP.Latency.Round(time.Millisecond))
		if result.TCP.Error != "" {
			fmt.Fprintf(w, "  Error:\t%s\n", result.TCP.Error)
		}
	}

	// HTTP
	if result.HTTP != nil {
		httpStatus := "FAIL"
		if result.HTTP.Success {
			httpStatus = "OK"
		}
		fmt.Fprintf(w, "HTTP:\t%s %d %s %s\n", httpStatus, result.HTTP.StatusCode, result.HTTP.StatusText, result.HTTP.TotalDuration.Round(time.Millisecond))
		fmt.Fprintf(w, "  DNS:\t%s\n", result.HTTP.DNSResolution.Round(time.Millisecond))
		fmt.Fprintf(w, "  TCP:\t%s\n", result.HTTP.TCPConnection.Round(time.Millisecond))
		if result.HTTP.TLSHandshake > 0 {
			fmt.Fprintf(w, "  TLS:\t%s\n", result.HTTP.TLSHandshake.Round(time.Millisecond))
		}
		fmt.Fprintf(w, "  TTFB:\t%s\n", result.HTTP.TimeToFirstByte.Round(time.Millisecond))
		fmt.Fprintf(w, "  Size:\t%s\n", formatBytes(result.HTTP.ResponseSize))
		if result.HTTP.Error != "" {
			fmt.Fprintf(w, "  Error:\t%s\n", result.HTTP.Error)
		}
	}

	// Health
	fmt.Fprintln(w)
	if result.Health != nil {
		fmt.Fprintf(w, "Health Score:\t%d/100\n", result.Health.Score)
		fmt.Fprintf(w, "Status:\t%s\n", result.Health.Status)
		if result.Health.Message != "" {
			fmt.Fprintf(w, "Message:\t%s\n", result.Health.Message)
		}
	}

	// Root cause
	if result.Health != nil && result.Health.RootCause != nil {
		fmt.Fprintln(w)
		fmt.Fprintf(w, "--- ROOT CAUSE ---\n")
		fmt.Fprintf(w, "Cause:\t%s\n", result.Health.RootCause.RootCause)
		fmt.Fprintf(w, "Severity:\t%s\n", result.Health.RootCause.Severity)
		fmt.Fprintf(w, "Confidence:\t%.0f%%\n", result.Health.RootCause.Confidence*100)
		fmt.Fprintf(w, "Layer:\t%s\n", result.Health.RootCause.AffectedLayer)
		fmt.Fprintf(w, "Evidence:\t%s\n", result.Health.RootCause.Evidence)
		fmt.Fprintf(w, "Recommendation:\t%s\n", result.Health.RootCause.Recommendation)
	}

	w.Flush()
}

func printStressResult(result *types.StressTestResult) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

	fmt.Fprintf(w, "Target:\t%s:%d\n", result.Target, result.Port)
	fmt.Fprintf(w, "Total Requests:\t%d\n", result.TotalRequests)
	fmt.Fprintf(w, "Successful:\t%d (%.1f%%)\n", result.Successful, result.SuccessRate)
	fmt.Fprintf(w, "Failed:\t%d (%.1f%%)\n", result.Failed, result.FailureRate)
	fmt.Fprintf(w, "Timeouts:\t%d\n", result.Timeouts)
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Avg Latency:\t%.1f ms\n", result.AvgLatency)
	fmt.Fprintf(w, "Min Latency:\t%.1f ms\n", result.MinLatency)
	fmt.Fprintf(w, "Max Latency:\t%.1f ms\n", result.MaxLatency)
	fmt.Fprintf(w, "P50:\t%.1f ms\n", result.P50)
	fmt.Fprintf(w, "P95:\t%.1f ms\n", result.P95)
	fmt.Fprintf(w, "P99:\t%.1f ms\n", result.P99)
	fmt.Fprintf(w, "Requests/sec:\t%.1f\n", result.RequestsPerSec)
	fmt.Fprintf(w, "Duration:\t%.0f ms\n", result.TotalDuration)

	w.Flush()
}

func parsePorts(s string) []int {
	var ports []int
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		var port int
		if _, err := fmt.Sscanf(p, "%d", &port); err == nil {
			ports = append(ports, port)
		}
	}
	return ports
}

func formatBytes(b int64) string {
	switch {
	case b >= 1024*1024:
		return fmt.Sprintf("%.1f MB", float64(b)/(1024*1024))
	case b >= 1024:
		return fmt.Sprintf("%.1f KB", float64(b)/1024)
	default:
		return fmt.Sprintf("%d B", b)
	}
}
