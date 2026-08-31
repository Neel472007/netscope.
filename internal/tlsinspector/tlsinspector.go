package tlsinspector

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"time"
)

// CertificateInfo holds details about a TLS certificate.
type CertificateInfo struct {
	Subject       string   `json:"subject"`
	Issuer        string   `json:"issuer"`
	SerialNumber  string   `json:"serial_number"`
	NotBefore     string   `json:"not_before"`
	NotAfter      string   `json:"not_after"`
	DaysExpiry    int      `json:"days_expiry"`
	IsExpired     bool     `json:"is_expired"`
	IsSelfSigned  bool     `json:"is_self_signed"`
	KeySize       int      `json:"key_size"`
	KeyAlgorithm  string   `json:"key_algorithm"`
	SignatureAlgo string   `json:"signature_algorithm"`
	SANs          []string `json:"sans"`
}

// TLSResult holds the full TLS inspection result.
type TLSResult struct {
	Host            string            `json:"host"`
	Port            int               `json:"port"`
	Protocol        string            `json:"protocol"`
	CipherSuite     string            `json:"cipher_suite"`
	ServerName      string            `json:"server_name"`
	Verified        bool              `json:"verified"`
	Certificate     CertificateInfo   `json:"certificate"`
	CertificateChain []CertificateInfo `json:"certificate_chain"`
	ConnectTime     time.Duration     `json:"connect_time"`
	TLSHandshakeTime time.Duration    `json:"tls_handshake_time"`
	TotalTime       time.Duration     `json:"total_time"`
	Error           string            `json:"error,omitempty"`
}

// Inspect performs a TLS inspection on the given host.
func Inspect(host string, port int) *TLSResult {
	result := &TLSResult{
		Host: host,
		Port: port,
	}

	start := time.Now()

	addr := fmt.Sprintf("%s:%d", host, port)
	dialer := &net.Dialer{Timeout: 10 * time.Second}

	tlsConfig := &tls.Config{
		ServerName: host,
	}

	// Phase 1: TCP connect
	tcpStart := time.Now()
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, tlsConfig)
	if err != nil {
		result.Error = err.Error()
		result.TotalTime = time.Since(start)
		return result
	}
	tcpTime := time.Since(tcpStart)
	result.ConnectTime = tcpTime
	result.TLSHandshakeTime = tcpTime // TLS dial includes handshake

	defer conn.Close()

	// Phase 2: Get connection state
	state := conn.ConnectionState()
	result.Protocol = tls.VersionName(state.Version)
	result.CipherSuite = tls.CipherSuiteName(state.CipherSuite)
	result.ServerName = state.ServerName
	result.Verified = len(state.VerifiedChains) > 0

	// Phase 3: Parse certificate chain
	for i, cert := range state.PeerCertificates {
		certInfo := parseCert(cert)
		if i == 0 {
			result.Certificate = certInfo
		}
		result.CertificateChain = append(result.CertificateChain, certInfo)
	}

	result.TotalTime = time.Since(start)
	return result
}

func parseCert(cert *x509.Certificate) CertificateInfo {
	var keySize int
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		keySize = pub.N.BitLen()
	case *ecdsa.PublicKey:
		keySize = pub.Curve.Params().BitSize
	}

	info := CertificateInfo{
		Subject:       cert.Subject.CommonName,
		Issuer:        cert.Issuer.CommonName,
		SerialNumber:  cert.SerialNumber.String(),
		NotBefore:     cert.NotBefore.Format(time.RFC3339),
		NotAfter:      cert.NotAfter.Format(time.RFC3339),
		DaysExpiry:    int(time.Until(cert.NotAfter).Hours() / 24),
		IsExpired:     time.Now().After(cert.NotAfter),
		IsSelfSigned:  cert.Issuer.CommonName == cert.Subject.CommonName,
		KeySize:       keySize,
		KeyAlgorithm:  cert.PublicKeyAlgorithm.String(),
		SignatureAlgo: cert.SignatureAlgorithm.String(),
		SANs:          cert.DNSNames,
	}
	return info
}
