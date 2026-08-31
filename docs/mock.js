// NetScope Mock Data Interceptor for GitHub Pages
// When the Go server isn't available, this provides realistic mock data
// so the dashboard works fully in static hosting environments.
(function () {
    'use strict';

    // Only activate if the server is not reachable
    var serverAvailable = false;

    function generateMockDiagnosis(target) {
        // Generate realistic, target-specific mock data
        var seed = 0;
        for (var i = 0; i < target.length; i++) seed += target.charCodeAt(i);
        var rng = function() { seed = (seed * 9301 + 49297) % 233280; return seed / 233280; };

        var dnsMs = Math.round(3 + rng() * 45);
        var tcpMs = Math.round(5 + rng() * 120);
        var httpMs = Math.round(30 + rng() * 400);
        var totalMs = dnsMs + tcpMs + httpMs;

        // Generate realistic IPs
        var ips = [
            (Math.floor(rng()*200)+20) + '.' + Math.floor(rng()*255) + '.' + Math.floor(rng()*255) + '.' + Math.floor(rng()*254+1),
            (Math.floor(rng()*200)+20) + '.' + Math.floor(rng()*255) + '.' + Math.floor(rng()*255) + '.' + Math.floor(rng()*254+1)
        ];

        // Determine health
        var score = 100;
        var status = 'Healthy';
        var message = 'All network layers are performing within normal parameters.';
        var severity = 'info';
        var rootCause = 'No issues detected';
        var confidence = 100;
        var recommendation = 'All layers responding normally.';

        if (dnsMs > 50) { score -= 15; }
        if (tcpMs > 100) { score -= 20; status = 'Degraded'; message = 'Some network layers show degraded performance.'; }
        if (httpMs > 300) { score -= 25; status = 'Degraded'; severity = 'medium'; rootCause = 'Elevated HTTP response time'; confidence = 70 + Math.floor(rng()*20); recommendation = 'Monitor server response times. Check for increased load or resource contention.'; }
        if (httpMs > 800) { score -= 15; severity = 'high'; }
        if (score < 0) score = 0;
        if (score >= 90) { status = 'Healthy'; severity = 'info'; rootCause = 'No issues detected'; confidence = 100; recommendation = 'All layers responding normally.'; message = 'All network layers are performing within normal parameters.'; }

        return {
            target: { host: target, port: 443 },
            timestamp: new Date().toISOString(),
            dns: {
                host: target,
                success: true,
                resolver: 'system',
                resolution_time_ms: dnsMs * 1000000,
                ipv4_addresses: ips,
                ipv6_addresses: [],
                error: '',
                server: '8.8.8.8'
            },
            tcp: {
                host: target,
                port: 443,
                connected: true,
                latency_ms: tcpMs * 1000000,
                remote_addr: ips[0] + ':443',
                error: '',
                error_type: ''
            },
            http: {
                url: 'https://' + target,
                status_code: 200,
                status_text: 'OK',
                success: true,
                dns_resolution_ms: dnsMs * 1000000,
                tcp_connection_ms: tcpMs * 1000000,
                tls_handshake_ms: Math.round(tcpMs * 0.6) * 1000000,
                time_to_first_byte_ms: Math.round(httpMs * 0.7) * 1000000,
                total_duration_ms: httpMs * 1000000,
                response_size: Math.floor(rng() * 50000) + 1000,
                redirect_count: 0,
                error: '',
                headers: [
                    { name: 'Content-Type', value: 'text/html; charset=utf-8' },
                    { name: 'Server', value: 'nginx/1.24.0' }
                ]
            },
            health: {
                score: score,
                status: status,
                message: message,
                layers: [
                    { layer: 'DNS', status: dnsMs > 50 ? 'warn' : 'ok', latency_ms: dnsMs * 1000000, message: dnsMs > 50 ? 'DNS resolution is slow' : '' },
                    { layer: 'TCP', status: tcpMs > 100 ? 'warn' : 'ok', latency_ms: tcpMs * 1000000, message: tcpMs > 100 ? 'TCP latency is elevated' : '' },
                    { layer: 'HTTP', status: httpMs > 300 ? 'warn' : 'ok', latency_ms: httpMs * 1000000, message: httpMs > 300 ? 'HTTP response time is elevated' : '' }
                ],
                root_cause: {
                    root_cause: rootCause,
                    severity: severity,
                    confidence: confidence / 100,
                    affected_layer: severity === 'info' ? 'None' : 'HTTP',
                    evidence: 'DNS: ' + dnsMs + ' ms, TCP: ' + tcpMs + ' ms, HTTP: ' + httpMs + ' ms',
                    recommendation: recommendation
                }
            }
        };
    }

    // Check server availability, then patch functions
    fetch('/api/health').then(function (r) {
        if (r.ok) { serverAvailable = true; }
    }).catch(function () {
        serverAvailable = false;
        // Show demo mode banner
        var banner = document.createElement('div');
        banner.id = 'demoBanner';
        banner.style.cssText = 'background:linear-gradient(135deg,#1e3a5f,#0d2137);border:1px solid #2563eb;border-radius:8px;padding:12px 20px;margin:16px 20px;color:#93c5fd;font-family:system-ui,sans-serif;display:flex;align-items:center;gap:10px;font-size:14px;';
        banner.innerHTML = '<span style="font-size:18px;">📋</span> <strong>DEMO MODE</strong> — GitHub Pages (static). Showing simulated results. For real measurements, run the Go binary.';
        document.body.insertBefore(banner, document.body.firstChild.nextSibling);
        window.__MOCK_MODE = true;
    });

    // Expose mock generator globally for the patched functions
    window.__generateMockDiagnosis = generateMockDiagnosis;
    window.__isServerAvailable = function () { return serverAvailable; };
})();
