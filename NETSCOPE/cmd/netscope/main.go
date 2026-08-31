// NetScope — Network Diagnostics & Failure Intelligence
//
// A zero-runtime-dependency network diagnostics and observability platform.
package main

import (
	"flag"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Neel472007/netscope/internal/cli"
	"github.com/Neel472007/netscope/internal/server"
	"github.com/Neel472007/netscope/web"
)

func main() {
	// Check if this is a CLI command
	args := os.Args
	if len(args) > 1 && args[1] != "serve" && args[1] != "server" && args[1] != "start" {
		cli.Run(args)
		return
	}

	// Server mode
	var (
		addr    = flag.String("addr", ":8199", "Address to listen on")
		webDir  = flag.String("web", "", "Path to web directory (default: use embedded files)")
		simAddr = flag.String("sim", ":8200", "Simulator listen address")
		lbAddr  = flag.String("lb", ":8080", "Load balancer simulator port (0 to disable)")
		lbPorts = flag.String("lb-ports", "8081,8082,8083", "Comma-separated backend ports for LB simulator")
		useTLS  = flag.Bool("tls", false, "Enable HTTPS with auto-generated self-signed certificate")
	)

	// Handle "serve" / "start" subcommand
	if len(args) > 1 && (args[1] == "serve" || args[1] == "server" || args[1] == "start") {
		os.Args = []string{args[0]}
	}

	flag.Parse()

	// Parse LB backend ports
	var lbPortList []int
	if *lbPorts != "" {
		for _, p := range strings.Split(*lbPorts, ",") {
			p = strings.TrimSpace(p)
			if port, err := strconv.Atoi(p); err == nil && port > 0 {
				lbPortList = append(lbPortList, port)
			}
		}
	}

	// If lb=0, disable LB simulator
	if *lbAddr == "0" || *lbAddr == ":0" {
		lbPortList = nil
	}

	config := server.Config{
		Addr:    *addr,
		SimAddr: *simAddr,
		LBAddr:  *lbAddr,
		LBPorts: lbPortList,
	}

	// Use embedded web files by default, or fall back to filesystem
	if *webDir != "" {
		// Explicit --web flag: use filesystem
		config.WebDir = *webDir
	} else {
		// Try embedded files first, fall back to local web/ directory
		sub, err := fs.Sub(web.Static, ".")
		if err == nil {
			config.WebFS = http.FS(sub)
			fmt.Println("  📦 Using embedded web assets")
		} else {
			// Fallback: look for web/ directory next to executable
			config.WebDir = findWebDir()
		}
	}

	srv := server.NewServer(config)

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-quit
		fmt.Println("\nShutting down NetScope...")
		srv.Stop()
		os.Exit(0)
	}()

	// Auto-open browser after a short delay
	go func() {
		time.Sleep(1 * time.Second)
		scheme := "http"
		if *useTLS {
			scheme = "https"
		}
		url := scheme + "://localhost" + *addr
		fmt.Printf("\n  ✅ NetScope is running!\n")
		if *useTLS {
			fmt.Printf("  🔒 HTTPS: %s (self-signed certificate)\n", url)
		} else {
			fmt.Printf("  🌐 Dashboard: %s\n", url)
		}
		fmt.Printf("  ⚡ Simulator: %s\n", *simAddr)
		if len(lbPortList) > 0 {
			fmt.Printf("  ⚖️  LB Simulator: %s://localhost%s/lbsim/health\n", scheme, *lbAddr)
		}
		fmt.Println()
		openBrowser(url)
	}()

	// Start with or without TLS
	var err error
	if *useTLS {
		err = srv.StartTLS()
	} else {
		err = srv.Start()
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
		os.Exit(1)
	}
}

// findWebDir looks for the web/ directory relative to the executable or CWD.
func findWebDir() string {
	// Try next to the executable
	if exe, err := os.Executable(); err == nil {
		d := filepath.Join(filepath.Dir(exe), "web")
		if _, err := os.Stat(d); err == nil {
			return d
		}
	}
	// Try current directory
	if _, err := os.Stat("web"); err == nil {
		return "web"
	}
	// Try netscope/web (from project root)
	if _, err := os.Stat(filepath.Join("netscope", "web")); err == nil {
		return filepath.Join("netscope", "web")
	}
	return "web"
}

// openBrowser opens the default browser to the given URL.
func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	cmd.Start()
}
