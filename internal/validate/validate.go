// Package validate provides input validation for NetScope.
package validate

import (
	"errors"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

var (
	hostnameRegex = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z]{2,}$`)
	ipRegex       = regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}$`)
	maxHostLen    = 253
	maxURLLen     = 2048
)

// Host validates and sanitizes a hostname or IP address.
func Host(host string) (string, error) {
	host = strings.TrimSpace(host)
	if host == "" {
		return "", errors.New("host cannot be empty")
	}
	if len(host) > maxHostLen {
		return "", errors.New("host name too long")
	}
	// Check if it's an IP address
	if ipRegex.MatchString(host) {
		parts := strings.Split(host, ".")
		for _, p := range parts {
			n, err := strconv.Atoi(p)
			if err != nil || n < 0 || n > 255 {
				return "", errors.New("invalid IP address")
			}
		}
		return host, nil
	}
	// Check if it's a valid hostname
	if !hostnameRegex.MatchString(host) {
		// Try parsing as IP
		if net.ParseIP(host) != nil {
			return host, nil
		}
		return "", errors.New("invalid hostname")
	}
	return host, nil
}

// Port validates a port number.
func Port(port int) (int, error) {
	if port < 1 || port > 65535 {
		return 0, errors.New("port must be between 1 and 65535")
	}
	return port, nil
}

// PortString validates a port string.
func PortString(s string) (int, error) {
	p, err := strconv.Atoi(s)
	if err != nil {
		return 0, errors.New("invalid port number")
	}
	return Port(p)
}

// URL validates and parses a URL.
func URL(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("URL cannot be empty")
	}
	if len(raw) > maxURLLen {
		return nil, errors.New("URL too long")
	}
	// Add scheme if missing
	if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, errors.New("invalid URL")
	}
	if u.Host == "" {
		return nil, errors.New("URL must have a host")
	}
	return u, nil
}

// ParseTarget parses a target string like "example.com" or "https://example.com:8443/path".
func ParseTarget(input string) (host string, port int, useHTTPS bool, path string, err error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return "", 0, false, "", errors.New("empty target")
	}

	// If it looks like a URL
	if strings.HasPrefix(input, "http://") || strings.HasPrefix(input, "https://") {
		u, err := url.Parse(input)
		if err != nil {
			return "", 0, false, "", err
		}
		host = u.Hostname()
		useHTTPS = u.Scheme == "https"
		path = u.Path
		if u.Port() != "" {
			port, _ = strconv.Atoi(u.Port())
		} else if useHTTPS {
			port = 443
		} else {
			port = 80
		}
		return host, port, useHTTPS, path, nil
	}

	// Plain hostname or IP, possibly with port
	h, portStr, splitErr := net.SplitHostPort(input)
	if splitErr != nil {
		// No port specified — treat entire input as hostname
		h = input
	}

	host, err2 := Host(h)
	if err2 != nil {
		return "", 0, false, "", err2
	}

	if splitErr == nil && portStr != "" {
		port, err = strconv.Atoi(portStr)
		if err != nil {
			return "", 0, false, "", errors.New("invalid port")
		}
	} else {
		port = 443
	}
	useHTTPS = port == 443

	return host, port, useHTTPS, "/", nil
}

// Concurrency validates a concurrency limit.
func Concurrency(n int) (int, error) {
	if n < 1 {
		return 0, errors.New("concurrency must be at least 1")
	}
	if n > 10000 {
		return 0, errors.New("concurrency cannot exceed 10000")
	}
	return n, nil
}

// Timeout validates a timeout in milliseconds.
func Timeout(ms int) (int, error) {
	if ms < 100 {
		return 0, errors.New("timeout must be at least 100ms")
	}
	if ms > 120000 {
		return 0, errors.New("timeout cannot exceed 120000ms")
	}
	return ms, nil
}
