package validate

import (
	"testing"
)

func TestHostValid(t *testing.T) {
	tests := []struct {
		input string
		valid bool
	}{
		{"example.com", true},
		{"google.com", true},
		{"1.1.1.1", true},
		{"192.168.1.1", true},
		{"localhost", true}, // localhost is a valid single-label hostname
		{"", false},
		{"invalid host!", false},
		{"a.com", true},
		{"sub.domain.example.com", true},
	}

	for _, tt := range tests {
		_, err := Host(tt.input)
		if (err == nil) != tt.valid {
			t.Errorf("Host(%q): expected valid=%v, got err=%v", tt.input, tt.valid, err)
		}
	}
}

func TestPortValid(t *testing.T) {
	tests := []struct {
		port  int
		valid bool
	}{
		{80, true},
		{443, true},
		{1, true},
		{65535, true},
		{0, false},
		{-1, false},
		{70000, false},
	}

	for _, tt := range tests {
		_, err := Port(tt.port)
		if (err == nil) != tt.valid {
			t.Errorf("Port(%d): expected valid=%v, got err=%v", tt.port, tt.valid, err)
		}
	}
}

func TestURLValid(t *testing.T) {
	tests := []struct {
		input string
		valid bool
	}{
		{"https://example.com", true},
		{"http://example.com/path", true},
		{"example.com", true},
		{"https://example.com:8443/path", true},
		{"", false},
	}

	for _, tt := range tests {
		_, err := URL(tt.input)
		if (err == nil) != tt.valid {
			t.Errorf("URL(%q): expected valid=%v, got err=%v", tt.input, tt.valid, err)
		}
	}
}

func TestParseTarget(t *testing.T) {
	tests := []struct {
		input    string
		wantHost string
		wantPort int
		wantHTTPS bool
	}{
		{"example.com", "example.com", 443, true},
		{"https://example.com", "example.com", 443, true},
		{"http://example.com", "example.com", 80, false},
		{"https://example.com:8443/path", "example.com", 8443, true},
		{"1.1.1.1", "1.1.1.1", 443, true},
	}

	for _, tt := range tests {
		host, port, https, _, err := ParseTarget(tt.input)
		if err != nil {
			t.Errorf("ParseTarget(%q): unexpected error: %v", tt.input, err)
			continue
		}
		if host != tt.wantHost {
			t.Errorf("ParseTarget(%q): host=%q, want=%q", tt.input, host, tt.wantHost)
		}
		if port != tt.wantPort {
			t.Errorf("ParseTarget(%q): port=%d, want=%d", tt.input, port, tt.wantPort)
		}
		if https != tt.wantHTTPS {
			t.Errorf("ParseTarget(%q): https=%v, want=%v", tt.input, https, tt.wantHTTPS)
		}
	}
}

func TestConcurrency(t *testing.T) {
	tests := []struct {
		input int
		valid bool
	}{
		{1, true},
		{100, true},
		{10000, true},
		{0, false},
		{-1, false},
		{10001, false},
	}

	for _, tt := range tests {
		_, err := Concurrency(tt.input)
		if (err == nil) != tt.valid {
			t.Errorf("Concurrency(%d): expected valid=%v, got err=%v", tt.input, tt.valid, err)
		}
	}
}
