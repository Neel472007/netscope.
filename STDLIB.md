# STDLIB.md — NetScope Dependency Documentation

## Runtime Dependencies

**None.** NetScope has zero third-party runtime dependencies.

## Development-only Third-party Dependencies

**None.** All source code is original and written during the hackathon using only Go's standard library and browser-native APIs.

## Go Standard Library Packages Used

| Package | Purpose |
|---------|---------|
| `context` | Request context, timeouts, cancellation |
| `crypto/tls` | TLS handshake for HTTPS diagnostics |
| `embed` | Embed web dashboard files into the binary |
| `encoding/json` | JSON serialization for API responses |
| `fmt` | Formatted I/O for CLI and error messages |
| `io` | I/O primitives, response body reading |
| `io/fs` | Filesystem abstraction for embedded assets |
| `log` | Server logging |
| `math` | Mathematical operations for scoring |
| `net` | DNS resolution, TCP connections, network utilities |
| `net/http` | HTTP server and client |
| `net/url` | URL parsing and validation |
| `os` | Filesystem access, signal handling, executable path |
| `os/signal` | Graceful shutdown signal handling |
| `path/filepath` | File path manipulation |
| `regexp` | Input validation patterns |
| `sort` | Data sorting for percentile calculations |
| `strconv` | String/integer conversion for CLI and API |
| `strings` | String manipulation utilities |
| `sync` | Mutexes, WaitGroups for concurrent operations |
| `syscall` | System call constants for signal handling |
| `testing` | Standard Go testing framework |
| `text/tabwriter` | CLI formatted output |
| `time` | Time measurement, durations, timeouts |
| `sort` | Sorted percentile calculations |
| `sync/atomic` | Atomic counters for concurrent metrics |
| `math/rand` | Jitter and port randomization |

## Browser-native APIs Used

| API | Purpose |
|-----|---------|
| `fetch()` | HTTP API requests to backend |
| `EventSource` | Server-Sent Events for live diagnostics |
| `Canvas 2D` | Latency and stress test chart rendering |
| `requestAnimationFrame` | Smooth health score animation |
| `DOM API` | UI manipulation and updates |
| `JSON.parse/stringify` | Data serialization |

## Development-only Dependencies

Development-only third-party dependencies: **None.**

All code was written from scratch. No third-party source code was copied. No external CDN resources are used in the frontend.

## Licensing

This project is released under the MIT License. All source code is original.
