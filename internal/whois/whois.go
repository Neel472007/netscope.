// Package whois provides domain WHOIS lookup using direct TCP queries.
// It queries public WHOIS servers and parses the response for domain
// registration information — all using the Go standard library.
package whois

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"
)

// Result holds the parsed WHOIS lookup result.
type Result struct {
	Domain        string `json:"domain"`
 Registrar     string `json:"registrar,omitempty"`
	Registration  string `json:"registration_date,omitempty"`
	Expiration    string `json:"expiration_date,omitempty"`
	Updated       string `json:"updated_date,omitempty"`
	NameServers   string `json:"name_servers,omitempty"`
	Status        string `json:"status,omitempty"`
	DNSSEC        string `json:"dnssec,omitempty"`
	RegistrantOrg string `json:"registrant_org,omitempty"`
	Country       string `json:"country,omitempty"`
	RawLength     int    `json:"raw_length"`
	Error         string `json:"error,omitempty"`
	QueriedAt     string `json:"queried_at"`
	Server        string `json:"server"`
	Duration      float64 `json:"duration_ms"`
}

// whoisServers maps TLDs to their WHOIS servers.
var whoisServers = map[string]string{
	"com": "whois.verisign-grs.com",
	"net": "whois.verisign-grs.com",
	"org": "whois.pir.org",
	"edu": "whois.educause.edu",
	"gov": "whois.dotgov.gov",
	"io":  "whois.nic.io",
	"dev": "whois.nic.google",
	"app": "whois.nic.google",
	"co":  "whois.nic.co",
	"me":  "whois.nic.me",
	"uk":  "whois.nic.uk",
	"de":  "whois.denic.de",
	"fr":  "whois.nic.fr",
	"nl":  "whois.sidn.nl",
	"be":  "whois.dns.be",
	"au":  "whois.auda.org.au",
	"ca":  "whois.cira.ca",
	"in":  "whois.inregistry.net",
	"jp":  "whois.jprs.jp",
	"cn":  "whois.cnnic.cn",
	"br":  "whois.registro.br",
	"ru":  "whois.tcinet.ru",
	"za":  "whois.registry.net.za",
	"mx":  "whois.nic.mx",
	"se":  "whois.iis.se",
	"no":  "whois.norid.no",
	"dk":  "whois.dk-hostmaster.dk",
	"pl":  "whois.dns.pl",
	"cz":  "whois.nic.cz",
	"ch":  "whois.nic.ch",
	"at":  "whois.nic.at",
	"it":  "whois.nic.it",
	"es":  "whois.nic.es",
	"pt":  "whois.dns.pt",
	"ie":  "whois.iedr.ie",
	"nz":  "whois.srs.net.nz",
	"sg":  "whois.sgnic.sg",
	"hk":  "whois.hkirc.hk",
	"kr":  "whois.kr",
	"tw":  "whois.twnic.net.tw",
	"th":  "whois.thnic.co.th",
	"ph":  "whois.phdomains.com",
	"cl":  "whois.nic.cl",
	"pe":  "whois.nic.pe",
	"ar":  "whois.nic.ar",
	"global": "whois.nic.global",
}

// Lookup performs a WHOIS lookup for the given domain.
func Lookup(ctx context.Context, domain string) *Result {
	start := time.Now()
	result := &Result{
		Domain:    domain,
		QueriedAt: time.Now().Format(time.RFC3339),
	}

	// Extract TLD
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		result.Error = "invalid domain format"
		return result
	}
	tld := parts[len(parts)-1]

	// Find WHOIS server
	server, ok := whoisServers[tld]
	if !ok {
		server = "whois." + tld
	}
	result.Server = server

	// Query WHOIS server
	raw, err := queryWhois(ctx, server, domain)
	if err != nil {
		result.Error = err.Error()
		result.Duration = float64(time.Since(start).Microseconds()) / 1000.0
		return result
	}

	result.RawLength = len(raw)
	result.Duration = float64(time.Since(start).Microseconds()) / 1000.0

	// Parse the response
	parseWhoisResponse(result, raw)
	return result
}

// queryWhois sends a WHOIS query to the specified server.
func queryWhois(ctx context.Context, server, domain string) (string, error) {
	addr := net.JoinHostPort(server, "43")
	dialer := &net.Dialer{Timeout: 10 * time.Second}

	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return "", fmt.Errorf("failed to connect to WHOIS server %s: %v", server, err)
	}
	defer conn.Close()

	// Set deadline
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	// Send query
	query := domain + "\r\n"
	if _, err := conn.Write([]byte(query)); err != nil {
		return "", fmt.Errorf("failed to send WHOIS query: %v", err)
	}

	// Read response
	var sb strings.Builder
	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 64*1024), 64*1024)
	for scanner.Scan() {
		line := scanner.Text()
		sb.WriteString(line)
		sb.WriteString("\n")
	}

	return sb.String(), scanner.Err()
}

// parseWhoisResponse extracts structured data from raw WHOIS text.
func parseWhoisResponse(r *Result, raw string) {
	// Common field patterns
	fieldMap := map[string]*string{
		"Registrar:":             &r.Registrar,
		"Registration Date:":     &r.Registration,
		"Creation Date:":         &r.Registration,
		"Registered:":            &r.Registration,
		"Expiry Date:":           &r.Expiration,
		"Registry Expiry Date:":  &r.Expiration,
		"Expiration Date:":       &r.Expiration,
		"Updated Date:":          &r.Updated,
		"Last Modified:":         &r.Updated,
		"Name Server:":           &r.NameServers,
		"nserver:":               &r.NameServers,
		"Domain Status:":         &r.Status,
		"status:":                &r.Status,
		"DNSSEC:":                &r.DNSSEC,
		"Registrant Organization:": &r.RegistrantOrg,
		"Registrant Org:":        &r.RegistrantOrg,
		"Registrant Country:":    &r.Country,
		"Country:":               &r.Country,
	}

	scanner := bufio.NewScanner(strings.NewReader(raw))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "%") || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ">>>") {
			continue
		}

		for field, target := range fieldMap {
			if strings.HasPrefix(line, field) {
				val := strings.TrimSpace(strings.TrimPrefix(line, field))
				if val != "" && *target == "" {
					*target = val
				}
			}
		}
	}
}

// ExtractRootDomain extracts the root domain from a FQDN.
// e.g., "www.example.com" -> "example.com"
func ExtractRootDomain(input string) string {
	input = strings.TrimSpace(input)
	input = strings.TrimPrefix(input, "http://")
	input = strings.TrimPrefix(input, "https://")
	input = strings.TrimSuffix(input, "/")
	parts := strings.Split(input, "/")
	domain := parts[0]
	if idx := strings.Index(domain, ":"); idx != -1 {
		domain = domain[:idx]
	}
	return domain
}

// LookupDefault performs a WHOIS lookup with default settings.
func LookupDefault(domain string) *Result {
	return Lookup(context.Background(), domain)
}

// ValidateDomain checks if a string looks like a valid domain.
func ValidateDomain(domain string) bool {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return false
	}
	re := regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$`)
	return re.MatchString(domain)
}
