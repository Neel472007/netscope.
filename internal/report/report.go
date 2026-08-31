// Package report generates self-contained HTML executive summary reports
// from diagnostic results. The generated HTML embeds all CSS and JS inline,
// making it shareable as a single file with no external dependencies.
package report

import (
	"fmt"
	"html"
	"strings"
	"time"

	"github.com/Neel472007/netscope/internal/diagnostics"
	"github.com/Neel472007/netscope/internal/types"
)

// Generate creates a self-contained HTML report from diagnostic results.
func Generate(result *types.DiagnosticResult) string {
	if result == nil {
		return "<html><body><h1>No data</h1></body></html>"
	}

	// Run correlation analysis
	engine := diagnostics.NewEngine()
	correlation := engine.AnalyzeCorrelation(result)

	// Run root cause
	rootCause := engine.Analyze(result)

	// Build health score
	score := 0
	status := "UNKNOWN"
	if result.Health != nil {
		score = result.Health.Score
		status = result.Health.Status
	}

	// Build layer details
	dnsLine := layerLine("DNS", result.DNS != nil && result.DNS.Success,
		func() string {
			if result.DNS == nil { return "Not tested" }
			if !result.DNS.Success { return "FAILED: " + result.DNS.Error }
			return fmt.Sprintf("OK — %dms — %s", result.DNS.ResolutionTime.Milliseconds(), joinIPs(result.DNS.IPv4Addresses))
		}())

	tcpLine := layerLine("TCP", result.TCP != nil && result.TCP.Connected,
		func() string {
			if result.TCP == nil { return "Not tested" }
			if !result.TCP.Connected { return "FAILED: " + result.TCP.Error }
			return fmt.Sprintf("OK — %.1fms", float64(result.TCP.Latency.Microseconds())/1000)
		}())

	httpLine := layerLine("HTTP", result.HTTP != nil && result.HTTP.Success,
		func() string {
			if result.HTTP == nil { return "Not tested" }
			if !result.HTTP.Success { return "FAILED: " + result.HTTP.Error }
			return fmt.Sprintf("OK — %d %s — %.1fms", result.HTTP.StatusCode, result.HTTP.StatusText, float64(result.HTTP.TotalDuration.Microseconds())/1000)
		}())

	// Chain visualization
	chainHTML := ""
	for _, link := range correlation.Chain {
		statusClass := "ok"
		if link.Status == "failed" { statusClass = "fail" }
		if link.Status == "blocked" { statusClass = "warn" }
		chainHTML += fmt.Sprintf(`<div class="chain-link"><span class="chain-step">%d</span><span class="chain-layer">%s</span><span class="chain-status %s">%s</span><span class="chain-latency">%s</span><span class="chain-detail">%s</span></div>`,
			link.Step, link.Layer, statusClass, strings.ToUpper(link.Status), link.Latency, html.EscapeString(link.Effect))
	}

	// Recommendations
	recs := []string{}
	if rootCause != nil {
		recs = append(recs, rootCause.Recommendation)
	}
	if score < 80 {
		recs = append(recs, "Consider running additional diagnostics to identify bottlenecks.")
	}
	if len(recs) == 0 {
		recs = append(recs, "No action required. Network is healthy.")
	}
	recsHTML := ""
	for _, r := range recs {
		recsHTML += `<li>` + html.EscapeString(r) + `</li>`
	}

	// Score color
	scoreColor := "#22c55e"
	if score < 50 { scoreColor = "#ef4444" } else if score < 80 { scoreColor = "#eab308" }

	now := time.Now().Format("2006-01-02 15:04:05")

	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NetScope Diagnostic Report — %s</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0a0e17;color:#e2e8f0;line-height:1.6;padding:32px}
.container{max-width:800px;margin:0 auto}
h1{font-size:1.8rem;font-weight:800;margin-bottom:4px}
.subtitle{color:#94a3b8;font-size:0.9rem;margin-bottom:24px}
.score-card{text-align:center;padding:32px;background:#1a2332;border-radius:16px;border:1px solid #2a3548;margin-bottom:24px}
.score-num{font-size:4rem;font-weight:900;color:%s}
.score-max{font-size:1.2rem;color:#64748b}
.score-status{font-size:1.1rem;font-weight:700;text-transform:uppercase;margin-top:8px}
.section{background:#1a2332;border:1px solid #2a3548;border-radius:12px;padding:20px;margin-bottom:16px}
.section h2{font-size:1rem;font-weight:700;margin-bottom:12px;color:#3b82f6;text-transform:uppercase;letter-spacing:0.05em}
.layer{display:flex;align-items:center;gap:12px;padding:10px;border-bottom:1px solid #2a3548}
.layer:last-child{border-bottom:none}
.layer-icon{width:32px;height:32px;border-radius:8px;display:flex;align-items:center;justify-content:center;font-weight:700;font-size:0.75rem}
.layer-icon.ok{background:#166534;color:#4ade80}
.layer-icon.fail{background:#7f1d1d;color:#fca5a5}
.layer-name{font-weight:700;min-width:50px}
.layer-detail{color:#94a3b8;font-size:0.85rem;flex:1}
.chain-link{display:flex;align-items:center;gap:8px;padding:8px 0;border-bottom:1px solid #1e293b;font-size:0.85rem;font-family:monospace}
.chain-step{color:#64748b;min-width:20px}
.chain-layer{font-weight:700;color:#3b82f6;min-width:40px}
.chain-status{font-weight:700;min-width:60px}
.chain-status.ok{color:#4ade80}
.chain-status.fail{color:#fca5a5}
.chain-status.warn{color:#fbbf24}
.chain-latency{color:#94a3b8;min-width:70px}
.chain-detail{color:#64748b;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.rec-list{list-style:none;padding:0}
.rec-list li{padding:8px 12px;border-left:3px solid #3b82f6;margin-bottom:8px;background:rgba(59,130,246,0.05);border-radius:0 6px 6px 0;font-size:0.9rem}
.footer{text-align:center;color:#64748b;font-size:0.75rem;margin-top:32px;padding-top:16px;border-top:1px solid #2a3548}
.rootcause{padding:16px;border-radius:10px;margin-bottom:12px}
.rootcause.critical{background:#7f1d1d;border:1px solid #ef4444}
.rootcause.medium{background:#78350f;border:1px solid #f59e0b}
.rootcause.info{background:#14532d;border:1px solid #22c55e}
.rootcause-title{font-weight:700;font-size:1.1rem}
.rootcause-evidence{color:#94a3b8;font-size:0.85rem;margin-top:6px}
.rootcause-rec{color:#60a5fa;font-size:0.85rem;margin-top:4px}
@media print{body{background:#fff;color:#1e293b}.score-card,.section{border-color:#e2e8f0}}
</style>
</head>
<body>
<div class="container">
<h1>🔬 NetScope Diagnostic Report</h1>
<div class="subtitle">Target: %s | Generated: %s</div>

<div class="score-card">
<div class="score-num">%d</div>
<div class="score-max">/ 100</div>
<div class="score-status">%s</div>
</div>

<div class="section">
<h2>🔍 Layer Analysis</h2>
%s
%s
%s
</div>

<div class="section">
<h2>🔗 Causality Chain</h2>
<p style="color:#94a3b8;font-size:0.85rem;margin-bottom:8px">Root layer: <strong>%s</strong> — %s</p>
%s
</div>

<div class="section">
<h2>🎯 Root Cause Analysis</h2>
<div class="rootcause %s">
<div class="rootcause-title">%s</div>
<div class="rootcause-evidence">%s</div>
<div class="rootcause-rec">→ %s</div>
</div>
</div>

<div class="section">
<h2>📋 Recommendations</h2>
<ul class="rec-list">%s</ul>
</div>

<div class="footer">
Generated by NetScope v1.0 — Zero runtime dependencies — %s
</div>
</div>
</body>
</html>`,
		html.EscapeString(result.Target.Host),
		scoreColor,
		html.EscapeString(result.Target.Host),
		now,
		score,
		status,
		dnsLine,
		tcpLine,
		httpLine,
		correlation.RootLayer,
		html.EscapeString(correlation.ImpactDesc),
		chainHTML,
		rootCauseSeverityClass(rootCause),
		html.EscapeString(rootCause.RootCause),
		html.EscapeString(rootCause.Evidence),
		html.EscapeString(rootCause.Recommendation),
		recsHTML,
		now,
	)
}

func layerLine(name string, ok bool, detail string) string {
	statusClass := "ok"
	icon := "✓"
	if !ok {
		statusClass = "fail"
		icon = "✗"
	}
	return fmt.Sprintf(`<div class="layer"><div class="layer-icon %s">%s</div><div class="layer-name">%s</div><div class="layer-detail">%s</div></div>`,
		statusClass, icon, name, html.EscapeString(detail))
}

func rootCauseSeverityClass(rc *types.RootCause) string {
	if rc == nil { return "info" }
	switch rc.Severity {
	case "critical": return "critical"
	case "medium": return "medium"
	default: return "info"
	}
}

func joinIPs(ips []string) string {
	if len(ips) == 0 { return "N/A" }
	return strings.Join(ips, ", ")
}
