# 🔬 NetScope

### Network Diagnostics & Failure Intelligence

> **Find where the network breaks, why it breaks, and prove it with real measurements.**

---

## ⚡ One-Line Pitch

> **NetScope is a zero-dependency network diagnostics platform that performs real DNS, TCP, and HTTP measurements, identifies root causes, and proves it with data — all in a single 12MB binary.**

---

## 🎬 Quick Start (One Command)

```bash
# Build and run — opens dashboard at http://localhost:8199
go build ./cmd/netscope && ./netscope serve

# Or with HTTPS (self-signed certificate)
go build ./cmd/netscope && ./netscope serve --tls
```

---

## 🏆 Why NetScope

| Feature | NetScope | Typical Hackathon Project |
|---------|----------|---------------------------|
| **Dependencies** | **Zero** | 50+ npm packages |
| **Binary size** | **12MB self-contained** | Needs Docker + Node.js |
| **Build command** | **`go build`** | npm install && npm run build |
| **Measurements** | **Real network calls** | Mock/simulated data |
| **Security** | **16-layer protection** | Basic or none |
| **Features** | **25 diagnostic tools** | 1-2 basic features |
| **API endpoints** | **30+ REST endpoints** | 3-5 endpoints |
| **Test coverage** | **16 test packages** | 0-2 test files |

---

## 🎯 The Problem

When a website or network service becomes slow or unreachable, users only know "it isn't working." Engineers need to determine whether the problem originates from DNS resolution, TCP connectivity, HTTP performance, latency, timeouts, or the server itself.

## 💡 The Solution

NetScope is a zero-runtime-dependency network diagnostics and observability platform that:

1. Performs **real** DNS, TCP, and HTTP measurements concurrently
2. Analyzes collected evidence with a **rule-based diagnostic engine**
3. Identifies likely **root causes** with confidence scores
4. Presents results through a **live web dashboard** and **CLI**
5. Includes a **failure simulator** for controlled demonstrations

---

## 🧰 Features (25 Tools)

### Core Diagnostics
- **DNS Diagnostics** — Real resolution, IPv4/IPv6 detection, multi-resolver testing
- **TCP Diagnostics** — Connectivity testing with concurrent connections, error classification
- **HTTP Diagnostics** — Full timing breakdown: DNS, TCP, TLS, TTFB, total duration
- **Port Scanner** — Concurrent port scanning with service detection
- **TLS Certificate Inspector** — Certificate details, chain, protocol, cipher suite, expiry
- **Network Benchmark** — Multi-round testing with P50/P95/P99, jitter, consistency scoring
- **Traceroute** — Network path tracing with hop-by-hop latency
- **Ping Monitor** — TCP-based continuous latency monitoring with live chart

### Power Tools
- **Stress Test** — 1 to 10,000 concurrent connections with metrics
- **Failure Simulator** — Local failure simulation for demonstrations
- **Load Balancer Simulator** — 3 mock backends, health checking, failover
- **DNS Resolver Race** — Compare multiple DNS resolvers simultaneously
- **Speed Test** — Download/upload performance measurement
- **WHOIS Lookup** — Domain registration information

### Advanced Intelligence
- **Packet Flow Diagram** — Visual DNS→TCP→TLS→HTTP timing breakdown
- **Network Fingerprint** — Identify CDN, hosting, WAF, server software
- **Diagnostic Diff** — Compare snapshots to detect changes
- **Smart Causality Chain** — Root cause analysis with confidence scores
- **Executive Report** — Self-contained HTML report for sharing

### Dashboard
- **Dark/Light Theme** — Toggle between themes
- **SVG Topology** — Visual network path visualization
- **Multi-Target Compare** — Side-by-side diagnostics
- **API Reference** — Complete endpoint documentation
- **Live Activity Log** — Real-time request tracking

---

## 🔒 Security (16 Layers)

| # | Layer | Description |
|---|-------|-------------|
| 1 | **Panic Recovery** | Catches crashes, returns safe 500 error |
| 2 | **Security Headers** | CSP, X-Frame-Options, X-Content-Type, X-XSS-Protection, Referrer-Policy |
| 3 | **Private IP Blocking** | Prevents scanning of 10.x, 192.168.x, 127.x networks |
| 4 | **Rate Limiting** | 120 requests per minute per IP |
| 5 | **Concurrent Limiter** | Max 50 simultaneous requests |
| 6 | **CORS Restriction** | Only localhost origins allowed |
| 7 | **CSRF Protection** | Token required for all POST requests |
| 8 | **Content-Type Enforce** | POST requests require Content-Type header |
| 9 | **Audit Trail** | Full request logging with IP, method, path, status |
| 10 | **Request ID Tracking** | Unique ID per request for debugging |
| 11 | **Version Masking** | No technology disclosure in headers |
| 12 | **Directory Traversal** | Blocks path traversal attacks (../) |
| 13 | **Input Length Limits** | Query max 2KB, params max 512B |
| 14 | **Cache Control** | No caching for API responses |
| 15 | **HTTPS/TLS Support** | `--tls` flag with auto-generated self-signed certificate |
| 16 | **Stress Test Auth** | Requires `?confirm=yes` parameter |

---

## 🏗️ Architecture

```
┌─────────────┐
│   Browser   │
└──────┬──────┘
       │ HTTP/HTTPS
┌──────▼──────┐
│ 16-Layer    │
│ Security    │
└──────┬──────┘
       │
┌──────▼──────┐
│ Go HTTP     │
│ Server      │
└──────┬──────┘
       │
┌──────▼──────────┐
│ Diagnostic      │
│ Orchestrator    │
├────┬────┬───┬───┤
│DNS │TCP │HTTP│Met│
│Eng │Eng │Eng │Eng│
└──┬─┴──┬─┴─┬─┴───┘
   │    │   │
   └────┼───┘
        │
   ┌────▼────┐
   │ Root    │
   │ Cause   │
   │ Engine  │
   └────┬────┘
        │
   ┌────▼────┐
   │ Dashboard│
   │ / CLI   │
   └─────────┘
```

## 🧪 Testing

```bash
# Run all tests
go test ./internal/...

# Run with verbose output
go test -v ./internal/...

# Run specific package
go test -v ./internal/dns/
go test -v ./internal/tcp/
go test -v ./internal/httpdiag/
go test -v ./internal/diagnostics/
go test -v ./internal/server/
```

### Test Results

```
✅ go build ./cmd/netscope    — PASS
✅ go vet ./...               — PASS (zero warnings)
✅ go test ./internal/...     — 16/16 packages PASS
✅ 82+ individual tests
```

---

## 🛠️ Technology

| Component | Technology | Why |
|-----------|-----------|-----|
| Backend | Go standard library | Zero dependencies |
| HTTP Server | `net/http` | Production-ready |
| DNS | `net.Resolver` | Real system DNS |
| TCP | `net.Dial` | Direct socket testing |
| HTTP Client | `net/http.Client` | Full HTTP/TLS support |
| TLS | `crypto/tls` | Certificate inspection |
| Frontend | HTML/CSS/vanilla JS | Zero frontend deps |
| Charts | Canvas 2D API | Browser-native |
| Live Updates | Server-Sent Events | No WebSocket needed |
| Security | Custom middleware | 16-layer protection |

---

## 📁 Project Structure

```
netscope/
├── cmd/netscope/main.go          # Entry point
├── internal/
│   ├── benchmark/                # Network quality benchmark
│   ├── concurrency/              # Worker pool for stress tests
│   ├── diagnostics/              # Root cause analysis engine
│   ├── dns/                      # DNS resolution engine
│   ├── dnsrace/                  # Multi-resolver DNS race
│   ├── fingerprint/              # Network fingerprinting
│   ├── healthmon/                # Continuous health monitor
│   ├── history/                  # Diagnostic history + diff
│   ├── httpdiag/                 # HTTP diagnostics engine
│   ├── lbsim/                    # Load balancer simulator
│   ├── multiscan/                # Multi-target scanning
│   ├── overview/                 # Overview engine
│   ├── packetflow/               # Packet flow tracing
│   ├── ping/                     # TCP-based ping monitor
│   ├── portscan/                 # Port scanner
│   ├── report/                   # Executive report generator
│   ├── server/                   # HTTP server + API + security
│   ├── simulator/                # Failure simulator
│   ├── speedtest/                # Speed test engine
│   ├── tcp/                      # TCP diagnostics engine
│   ├── tlsinspector/             # TLS certificate inspection
│   ├── traceroute/               # Network traceroute
│   ├── types/                    # Shared data types
│   ├── validate/                 # Input validation
│   └── whois/                    # WHOIS lookup
├── web/
│   ├── index.html                # Dashboard UI
│   ├── style.css                 # Dashboard styles
│   ├── app.js                    # Dashboard logic
│   └── embed.go                  # Embedded web assets
├── COMPLIANCE.md                 # Hackathon compliance
├── STDLIB.md                     # Standard library usage
├── LICENSE                       # MIT License
├── README.md                     # This file
├── go.mod                        # Go module (zero deps)
├── start.bat                     # Windows launcher
└── start.sh                      # Linux/Mac launcher
```

## 📜 Compliance

| Rule | Status |
|------|--------|
| Zero third-party runtime dependencies | ✅ |
| Single build command | ✅ |
| No copied third-party source | ✅ |
| Public GitHub repo | ✅ |
| MIT License | ✅ |
| AI assistants allowed | ✅ |
| STDLIB.md discloses dev deps | ✅ |
| Genuinely useful | ✅ |

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

## 🏁 Track

**Track C — Web & Network**

---

*NetScope: Real networking. Real measurements. Real diagnostics. Zero dependencies.*
