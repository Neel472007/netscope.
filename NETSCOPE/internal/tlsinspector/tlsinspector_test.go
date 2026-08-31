package tlsinspector

import (
	"testing"
)

func TestInspectHTTPS(t *testing.T) {
	result := Inspect("example.com", 443)
	if result == nil {
		t.Fatal("expected result, got nil")
	}
	if result.Error != "" {
		t.Fatalf("unexpected error: %s", result.Error)
	}
	if result.Certificate.Subject == "" {
		t.Error("expected non-empty certificate subject")
	}
	if result.Protocol == "" {
		t.Error("expected non-empty TLS protocol")
	}
	t.Logf("Protocol: %s, Cipher: %s, Subject: %s, Expiry: %d days",
		result.Protocol, result.CipherSuite, result.Certificate.Subject, result.Certificate.DaysExpiry)
}

func TestInspectNonTLS(t *testing.T) {
	result := Inspect("example.com", 80)
	if result == nil {
		t.Fatal("expected result, got nil")
	}
	if result.Error == "" {
		t.Error("expected error for non-TLS port")
	}
}

func TestInspectInvalidHost(t *testing.T) {
	result := Inspect("nonexistent.invalid", 443)
	if result == nil {
		t.Fatal("expected result, got nil")
	}
	if result.Error == "" {
		t.Error("expected error for invalid host")
	}
}
