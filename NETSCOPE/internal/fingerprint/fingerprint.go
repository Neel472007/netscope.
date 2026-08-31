// Package fingerprint identifies network infrastructure behind a target:
// CDN provider, hosting platform, WAF, server software, and more —
// using HTTP headers, TLS certificates, DNS records, and IP analysis.
// No external APIs needed; all identification is signature-based.
package fingerprint

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// Finding represents a single infrastructure identification.
type Finding struct {
	Category string `json:"category"` // "cdn", "hosting", "waf", "server", "os", "language", "framework"
	Name     string `json:"name"`
	Evidence string `json:"evidence"`
	Confidence float64 `json:"confidence"` // 0.0 - 1.0
}

// Result holds the complete fingerprint.
type Result struct {
	Target    string    `json:"target"`
	ResolvedIP string   `json:"resolved_ip"`
	Findings  []Finding `json:"findings"`
	Summary   string    `json:"summary"`
	Score     float64   `json:"score"` // confidence score 0-100
}

// Fingerprint performs a full infrastructure fingerprint of the target.
func Fingerprint(ctx context.Context, target string) *Result {
	result := &Result{Target: target}

	// Resolve IP
	ips, err := net.DefaultResolver.LookupHost(ctx, target)
	if err == nil && len(ips) > 0 {
		result.ResolvedIP = ips[0]
		// Check IP ranges for hosting identification
		result.Findings = append(result.Findings, identifyHostingByIP(ips[0])...)
	}

	// HTTP header analysis
	result.Findings = append(result.Findings, analyzeHTTPHeaders(ctx, target)...)

	// TLS certificate analysis
	result.Findings = append(result.Findings, analyzeTLSCert(target)...)

	// DNS analysis
	result.Findings = append(result.Findings, analyzeDNS(target)...)

	// Build summary
	if len(result.Findings) > 0 {
		result.Score = computeConfidence(result.Findings)
		result.Summary = buildSummary(result.Findings)
	} else {
		result.Summary = "No specific infrastructure identified"
	}

	return result
}

// --- HTTP Header Analysis ---

func analyzeHTTPHeaders(ctx context.Context, target string) []Finding {
	var findings []Finding

	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequestWithContext(ctx, "GET", "https://"+target, nil)
	if err != nil {
		return findings
	}
	req.Header.Set("User-Agent", "NetScope/1.0")

	resp, err := client.Do(req)
	if err != nil {
		// Try HTTP
		req.URL.Scheme = "http"
		resp, err = client.Do(req)
		if err != nil {
			return findings
		}
	}
	defer resp.Body.Close()

	// Server header
	server := resp.Header.Get("Server")
	if server != "" {
		findings = append(findings, identifyServer(server)...)
	}

	// X-Powered-By
	poweredBy := resp.Header.Get("X-Powered-By")
	if poweredBy != "" {
		findings = append(findings, Finding{
			Category:   "language",
			Name:       poweredBy,
			Evidence:   "X-Powered-By header",
			Confidence: 0.95,
		})
	}

	// CDN detection via headers
	for header, val := range map[string]string{
		"CF-Ray":             "Cloudflare",
		"X-CDN":              "CDN",
		"X-Cache":            "CDN Cache",
		"X-Served-By":        "CDN",
		"X-Akamai-Transformed": "Akamai",
		"Via":                "Proxy/CDN",
		"X-Fastly-Request-ID": "Fastly",
		"X-Azure-Ref":        "Azure CDN",
		"X-Amz-Cf-Id":        "AWS CloudFront",
		"X-Cf-Request-Id":    "Cloudflare",
	} {
		if v := resp.Header.Get(header); v != "" {
			if name, ok := cdnSignatures[header]; ok {
				findings = append(findings, Finding{
					Category:   "cdn",
					Name:       name,
					Evidence:   fmt.Sprintf("%s: %s", header, v),
					Confidence: 0.9,
				})
			} else if val != "" {
				findings = append(findings, Finding{
					Category:   "cdn",
					Name:       val,
					Evidence:   fmt.Sprintf("%s: %s", header, v),
					Confidence: 0.7,
				})
			}
		}
	}

	// WAF detection
	wafHeaders := map[string]string{
		"X-CDN":              "Imperva/Incapsula",
		"X-Mod-Security":     "ModSecurity WAF",
		"X-DataDome":         "DataDome WAF",
		"X-Sucuri-ID":        "Sucuri WAF",
		"X-Profiling-LB":     "F5 WAF",
	}
	for header, name := range wafHeaders {
		if v := resp.Header.Get(header); v != "" {
			findings = append(findings, Finding{
				Category:   "waf",
				Name:       name,
				Evidence:   fmt.Sprintf("%s: %s", header, v),
				Confidence: 0.85,
			})
		}
	}

	// Framework detection from headers
	frameworkHeaders := map[string]string{
		"X-Rack-Cache":      "Ruby/Rack",
		"X-Drupal-Cache":    "Drupal",
		"X-AspNet-Version":  "ASP.NET",
		"X-Generator":       "CMS",
		"Liferay-Portal":    "Liferay Portal",
	}
	for header, name := range frameworkHeaders {
		if v := resp.Header.Get(header); v != "" {
			findings = append(findings, Finding{
				Category:   "framework",
				Name:       name,
				Evidence:   fmt.Sprintf("%s: %s", header, v),
				Confidence: 0.8,
			})
		}
	}

	return findings
}

// --- TLS Certificate Analysis ---

func analyzeTLSCert(host string) []Finding {
	var findings []Finding

	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 5 * time.Second},
		"tcp",
		host+":443",
		&tls.Config{ServerName: host},
	)
	if err != nil {
		return findings
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return findings
	}
	cert := state.PeerCertificates[0]

	issuer := cert.Issuer.CommonName
	org := strings.Join(cert.Issuer.Organization, " ")

	// CDN detection from cert issuer
	certCDNs := map[string]string{
		"Cloudflare":    "Cloudflare",
		"Let's Encrypt": "Let's Encrypt (Free TLS)",
		"AWS":           "Amazon Web Services",
		"Google":        "Google Cloud",
		"Azure":         "Microsoft Azure",
		"Akamai":        "Akamai",
		"Fastly":        "Fastly",
		"Sucuri":        "Sucuri",
	}
	for keyword, name := range certCDNs {
		if strings.Contains(issuer, keyword) || strings.Contains(org, keyword) {
			findings = append(findings, Finding{
				Category:   "cdn",
				Name:       name,
				Evidence:   fmt.Sprintf("Cert issuer: %s (%s)", issuer, org),
				Confidence: 0.85,
			})
			break
		}
	}

	// Hosting detection from cert SANs
	for _, san := range cert.DNSNames {
		sanLower := strings.ToLower(san)
		hostingPatterns := map[string]string{
			"amazonaws.com": "Amazon Web Services",
			"azurewebsites": "Microsoft Azure",
			"herokuapp.com": "Heroku",
			"vercel.app":    "Vercel",
			"netlify.app":   "Netlify",
			"github.io":     "GitHub Pages",
			"pages.dev":     "Cloudflare Pages",
			"appspot.com":   "Google App Engine",
			"firebaseapp.com": "Firebase",
		}
		for pattern, name := range hostingPatterns {
			if strings.Contains(sanLower, pattern) {
				findings = append(findings, Finding{
					Category:   "hosting",
					Name:       name,
					Evidence:   fmt.Sprintf("SAN: %s", san),
					Confidence: 0.9,
				})
				break
			}
		}
	}

	return findings
}

// --- DNS Analysis ---

func analyzeDNS(host string) []Finding {
	var findings []Finding

	resolver := &net.Resolver{}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// CNAME records (check via lookup)
	cname, err := resolver.LookupCNAME(ctx, host)
	if err == nil && cname != "" && cname != host+"." {
		cnameLower := strings.ToLower(cname)
		cdnCNAMEs := map[string]string{
			"cloudflare":   "Cloudflare",
			"amazonaws":    "Amazon CloudFront",
			"akamaiedge":   "Akamai",
			"fastly":       "Fastly",
			"edgekey":      "Akamai",
			"cdn":          "CDN",
			"azureedge":    "Azure CDN",
			"googlehosted": "Google Cloud",
			"shopifycdn":   "Shopify CDN",
		}
		for pattern, name := range cdnCNAMEs {
			if strings.Contains(cnameLower, pattern) {
				findings = append(findings, Finding{
					Category:   "cdn",
					Name:       name,
					Evidence:   fmt.Sprintf("CNAME: %s", cname),
					Confidence: 0.9,
				})
				break
			}
		}
	}

	// MX records for email provider detection
	mxRecords, err := resolver.LookupMX(ctx, host)
	if err == nil {
		for _, mx := range mxRecords {
			mxHost := strings.ToLower(mx.Host)
			emailProviders := map[string]string{
				"google.com":    "Google Workspace",
				"microsoft.com": "Microsoft 365",
				"protonmail":    "ProtonMail",
				"zoho.com":      "Zoho Mail",
				"mimecast":      "Mimecast (Email Security)",
			}
			for pattern, name := range emailProviders {
				if strings.Contains(mxHost, pattern) {
					findings = append(findings, Finding{
						Category:   "service",
						Name:       name,
						Evidence:   fmt.Sprintf("MX: %s (priority %d)", mx.Host, mx.Pref),
						Confidence: 0.85,
					})
					break
				}
			}
		}
	}

	return findings
}

// --- Hosting by IP Range ---

func identifyHostingByIP(ip string) []Finding {
	var findings []Finding

	parsed := net.ParseIP(ip)
	if parsed == nil {
		return findings
	}

	// Check against known cloud IP ranges (simplified)
	cloudRanges := []struct {
		CIDR string
		Name string
	}{
		{"13.0.0.0/8", "Amazon Web Services"},
		{"18.0.0.0/8", "Amazon Web Services"},
		{"35.0.0.0/8", "Google Cloud"},
		{"34.0.0.0/8", "Google Cloud"},
		{"20.0.0.0/8", "Microsoft Azure"},
		{"40.0.0.0/8", "Microsoft Azure"},
		{"104.16.0.0/12", "Cloudflare"},
		{"172.64.0.0/13", "Cloudflare"},
	}

	for _, cr := range cloudRanges {
		_, cidr, err := net.ParseCIDR(cr.CIDR)
		if err == nil && cidr.Contains(parsed) {
			findings = append(findings, Finding{
				Category:   "hosting",
				Name:       cr.Name,
				Evidence:   fmt.Sprintf("IP %s in %s range", ip, cr.CIDR),
				Confidence: 0.6,
			})
			break
		}
	}

	return findings
}

// --- Helper Functions ---

var cdnSignatures = map[string]string{
	"CF-Ray":               "Cloudflare",
	"X-Akamai-Transformed": "Akamai",
	"X-Fastly-Request-ID":  "Fastly",
	"X-Amz-Cf-Id":          "AWS CloudFront",
	"X-Azure-Ref":          "Azure CDN",
}

func identifyServer(server string) []Finding {
	var findings []Finding

	serverPatterns := []struct {
		pattern *regexp.Regexp
		name    string
		cat     string
	}{
		{regexp.MustCompile(`(?i)nginx`), "Nginx", "server"},
		{regexp.MustCompile(`(?i)apache`), "Apache", "server"},
		{regexp.MustCompile(`(?i)microsoft-iis`), "Microsoft IIS", "server"},
		{regexp.MustCompile(`(?i)cloudflare`), "Cloudflare", "cdn"},
		{regexp.MustCompile(`(?i)litespeed`), "LiteSpeed", "server"},
		{regexp.MustCompile(`(?i)caddy`), "Caddy", "server"},
		{regexp.MustCompile(`(?i)gunicorn`), "Gunicorn (Python)", "server"},
		{regexp.MustCompile(`(?i)uvicorn`), "Uvicorn (Python)", "server"},
		{regexp.MustCompile(`(?i)puma`), "Puma (Ruby)", "server"},
		{regexp.MustCompile(`(?i)express`), "Express (Node.js)", "framework"},
		{regexp.MustCompile(`(?i)openresty`), "OpenResty", "server"},
		{regexp.MustCompile(`(?i)envoy`), "Envoy Proxy", "server"},
		{regexp.MustCompile(`(?i)traefik`), "Traefik", "server"},
	}

	for _, sp := range serverPatterns {
		if sp.pattern.MatchString(server) {
			findings = append(findings, Finding{
				Category:   sp.cat,
				Name:       sp.name,
				Evidence:   fmt.Sprintf("Server header: %s", server),
				Confidence: 0.9,
			})
		}
	}

	// OS detection from server header
	osPatterns := map[string]string{
		"(Windows)": "Windows",
		"(Ubuntu)":  "Ubuntu Linux",
		"(CentOS)":  "CentOS",
		"(Debian)":  "Debian",
	}
	for pattern, name := range osPatterns {
		if strings.Contains(server, pattern) {
			findings = append(findings, Finding{
				Category:   "os",
				Name:       name,
				Evidence:   fmt.Sprintf("Server header: %s", server),
				Confidence: 0.8,
			})
		}
	}

	return findings
}

func computeConfidence(findings []Finding) float64 {
	if len(findings) == 0 {
		return 0
	}
	var total float64
	for _, f := range findings {
		total += f.Confidence
	}
	avg := total / float64(len(findings))
	return avg * 100
}

func buildSummary(findings []Finding) string {
	categories := make(map[string][]string)
	for _, f := range findings {
		categories[f.Category] = append(categories[f.Category], f.Name)
	}

	parts := []string{}
	order := []string{"cdn", "hosting", "server", "waf", "framework", "language", "os", "service"}
	for _, cat := range order {
		if names, ok := categories[cat]; ok {
			// Deduplicate
			seen := make(map[string]bool)
			unique := []string{}
			for _, n := range names {
				if !seen[n] {
					seen[n] = true
					unique = append(unique, n)
				}
			}
			parts = append(parts, fmt.Sprintf("%s: %s", strings.ToUpper(cat), strings.Join(unique, ", ")))
		}
	}
	return strings.Join(parts, " | ")
}
