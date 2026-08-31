// NetScope Mock Interceptor for GitHub Pages
// When the Go server isn't available, this intercepts ALL API calls
// and returns realistic mock data so the dashboard works fully.
(function () {
    'use strict';

    var serverAvailable = false;

    // Deterministic RNG from target string
    function makeRng(seed) {
        var s = seed;
        return function () {
            s = (s * 9301 + 49297) % 233280;
            return s / 233280;
        };
    }

    function hashStr(str) {
        var h = 0;
        for (var i = 0; i < str.length; i++) h = ((h << 5) - h + str.charCodeAt(i)) | 0;
        return Math.abs(h);
    }

    function genIp(rng) {
        return Math.floor(rng() * 200 + 20) + '.' + Math.floor(rng() * 255) + '.' + Math.floor(rng() * 255) + '.' + Math.floor(rng() * 254 + 1);
    }

    function genMac(rng) {
        var parts = [];
        for (var i = 0; i < 6; i++) parts.push(('0' + Math.floor(rng() * 256).toString(16)).slice(-2));
        return parts.join(':');
    }

    // --- Mock generators for each endpoint ---

    function mockDiagnose(target) {
        var rng = makeRng(hashStr(target));
        var dnsMs = Math.round(3 + rng() * 45);
        var tcpMs = Math.round(5 + rng() * 120);
        var httpMs = Math.round(30 + rng() * 400);
        var ips = [genIp(rng), genIp(rng)];

        var score = 100, status = 'Healthy', message = 'All network layers are performing within normal parameters.';
        var severity = 'info', rootCause = 'No issues detected', confidence = 100;
        var recommendation = 'All layers responding normally.';

        if (tcpMs > 100) { score -= 20; status = 'Degraded'; message = 'Some network layers show degraded performance.'; }
        if (httpMs > 300) { score -= 25; status = 'Degraded'; severity = 'medium'; rootCause = 'Elevated HTTP response time'; confidence = 70 + Math.floor(rng() * 20); recommendation = 'Monitor server response times. Check for increased load or resource contention.'; }
        if (dnsMs > 50) { score -= 15; }
        if (score < 0) score = 0;
        if (score >= 90) { status = 'Healthy'; severity = 'info'; rootCause = 'No issues detected'; confidence = 100; recommendation = 'All layers responding normally.'; message = 'All network layers are performing within normal parameters.'; }

        return {
            target: { host: target, port: 443 },
            timestamp: new Date().toISOString(),
            dns: { host: target, success: true, resolver: 'system', resolution_time_ms: dnsMs * 1000000, ipv4_addresses: ips, ipv6_addresses: [], error: '', server: '8.8.8.8' },
            tcp: { host: target, port: 443, connected: true, latency_ms: tcpMs * 1000000, remote_addr: ips[0] + ':443', error: '', error_type: '' },
            http: { url: 'https://' + target, status_code: 200, status_text: 'OK', success: true, dns_resolution_ms: dnsMs * 1000000, tcp_connection_ms: tcpMs * 1000000, tls_handshake_ms: Math.round(tcpMs * 0.6) * 1000000, time_to_first_byte_ms: Math.round(httpMs * 0.7) * 1000000, total_duration_ms: httpMs * 1000000, response_size: Math.floor(rng() * 50000) + 1000, redirect_count: 0, error: '', headers: [{ name: 'Content-Type', value: 'text/html; charset=utf-8' }, { name: 'Server', value: 'nginx/1.24.0' }] },
            health: {
                score: score, status: status, message: message,
                layers: [
                    { layer: 'DNS', status: dnsMs > 50 ? 'warning' : 'ok', latency: dnsMs + ' ms', message: dnsMs > 50 ? 'DNS resolution is slow' : '' },
                    { layer: 'TCP', status: tcpMs > 100 ? 'warning' : 'ok', latency: tcpMs + ' ms', message: tcpMs > 100 ? 'TCP latency is elevated' : '' },
                    { layer: 'HTTP', status: httpMs > 300 ? 'warning' : 'ok', latency: httpMs + ' ms', message: httpMs > 300 ? 'HTTP response time is elevated' : '' }
                ],
                root_cause: { root_cause: rootCause, severity: severity, confidence: confidence / 100, affected_layer: severity === 'info' ? 'None' : 'HTTP', evidence: 'DNS: ' + dnsMs + ' ms, TCP: ' + tcpMs + ' ms, HTTP: ' + httpMs + ' ms', recommendation: recommendation }
            }
        };
    }

    function mockTLS(host) {
        var rng = makeRng(hashStr(host));
        var daysLeft = Math.floor(rng() * 300 + 30);
        var issued = new Date(); issued.setDate(issued.getDate() - (365 - daysLeft));
        var expires = new Date(); expires.setDate(expires.getDate() + daysLeft);
        return {
            host: host, port: 443, protocol: 'TLS 1.3', cipher: 'TLS_AES_256_GCM_SHA384',
            certificate: {
                subject: 'CN=' + host, issuer: "CN=R3, O=Let's Encrypt, C=US",
                serial: '04:AB:CD:EF:12:34:56:78:90',
                not_before: issued.toISOString(), not_after: expires.toISOString(),
                days_until_expiry: daysLeft,
                san: [host, '*.' + host.split('.').slice(-2).join('.')],
                self_signed: false, key_size: 256, signature_algorithm: 'SHA256-RSA'
            },
            chain: [
                { subject: 'CN=' + host, issuer: "CN=R3, O=Let's Encrypt" },
                { subject: "CN=R3, O=Let's Encrypt", issuer: 'CN=ISRG Root X1, O=Internet Security Research Group' }
            ],
            warnings: daysLeft < 60 ? ['Certificate expires in ' + daysLeft + ' days'] : []
        };
    }

    function mockTraceroute(host) {
        var rng = makeRng(hashStr(host));
        var hops = [];
        var hopCount = 8 + Math.floor(rng() * 8);
        for (var i = 0; i < hopCount; i++) {
            var lat = Math.round(2 + rng() * 30 + i * 5);
            hops.push({ hop: i + 1, ip: i === hopCount - 1 ? genIp(rng) : genIp(rng), hostname: i === hopCount - 1 ? host : 'hop-' + (i + 1) + '.network.net', latency_ms: lat, loss_pct: rng() > 0.95 ? Math.round(rng() * 10) : 0 });
        }
        return { host: host, hops: hops, total_hops: hopCount };
    }

    function mockPortScan(host) {
        var rng = makeRng(hashStr(host));
        var ports = [
            { port: 22, service: 'SSH', state: rng() > 0.3 ? 'open' : 'closed' },
            { port: 80, service: 'HTTP', state: 'open' },
            { port: 443, service: 'HTTPS', state: 'open' },
            { port: 3306, service: 'MySQL', state: rng() > 0.7 ? 'open' : 'closed' },
            { port: 5432, service: 'PostgreSQL', state: rng() > 0.8 ? 'open' : 'closed' },
            { port: 6379, service: 'Redis', state: rng() > 0.85 ? 'open' : 'closed' },
            { port: 8080, service: 'Alt-HTTP', state: rng() > 0.5 ? 'open' : 'closed' },
            { port: 8443, service: 'Alt-HTTPS', state: rng() > 0.6 ? 'open' : 'closed' },
            { port: 27017, service: 'MongoDB', state: rng() > 0.9 ? 'open' : 'closed' }
        ];
        return { host: host, ports: ports.filter(function (p) { return p.state === 'open'; }), total_scanned: 1024, duration_ms: Math.round(1000 + rng() * 3000) };
    }

    function mockDNSRace(host) {
        var rng = makeRng(hashStr(host));
        var resolvers = [
            { name: 'Google (8.8.8.8)', server: '8.8.8.8', time_ms: Math.round(5 + rng() * 20) },
            { name: 'Cloudflare (1.1.1.1)', server: '1.1.1.1', time_ms: Math.round(3 + rng() * 15) },
            { name: 'System Default', server: 'system', time_ms: Math.round(8 + rng() * 35) }
        ];
        resolvers.sort(function (a, b) { return a.time_ms - b.time_ms; });
        return { host: host, resolvers: resolvers, winner: resolvers[0].name };
    }

    function mockSpeedTest() {
        var rng = makeRng(Date.now());
        return { download_mbps: Math.round(50 + rng() * 150), upload_mbps: Math.round(10 + rng() * 50), ping_ms: Math.round(5 + rng() * 30), jitter_ms: Math.round(1 + rng() * 10), rounds: 5 };
    }

    function mockWHOIS(domain) {
        var rng = makeRng(hashStr(domain));
        return { domain: domain, registrar: 'GoDaddy.com, LLC', created: '2010-03-15', expires: '2025-03-15', nameservers: ['ns1.' + domain, 'ns2.' + domain], status: ['clientTransferProhibited'] };
    }

    function mockHealth() {
        return { status: 'ok', version: '1.0.0', uptime: Math.round(Date.now() / 1000 - 1000), demo_mode: true };
    }

    function mockSimulator() {
        return { mode: 'off', nodes: [] };
    }

    function mockLBSim() {
        return { status: 'ok', backends: [
            { host: 'localhost:8081', alive: true, reqs: Math.floor(Math.random() * 100) },
            { host: 'localhost:8082', alive: true, reqs: Math.floor(Math.random() * 100) },
            { host: 'localhost:8083', alive: Math.random() > 0.2, reqs: Math.floor(Math.random() * 80) }
        ], total_requests: Math.floor(Math.random() * 5000), failed_requests: Math.floor(Math.random() * 20) };
    }

    function mockHistory() {
        return [];
    }

    function mockFingerprint(host) {
        return { host: host, server: 'nginx', cdn: 'none', framework: 'unknown', tls_version: 'TLS 1.3', technologies: ['HTTP/2', 'HSTS', 'X-Content-Type-Options'] };
    }

    function mockPacketFlow(target) {
        return { target: target, port: 443, flow: [
            { step: 1, direction: 'outgoing', protocol: 'TCP SYN', from: 'client', to: target },
            { step: 2, direction: 'incoming', protocol: 'TCP SYN-ACK', from: target, to: 'client' },
            { step: 3, direction: 'outgoing', protocol: 'TCP ACK', from: 'client', to: target },
            { step: 4, direction: 'outgoing', protocol: 'TLS ClientHello', from: 'client', to: target },
            { step: 5, direction: 'incoming', protocol: 'TLS ServerHello', from: target, to: 'client' },
            { step: 6, direction: 'outgoing', protocol: 'HTTP GET /', from: 'client', to: target },
            { step: 7, direction: 'incoming', protocol: 'HTTP 200 OK', from: target, to: 'client' }
        ]};
    }

    function mockOverview(host) {
        return { host: host, http_status: 200, response_time_ms: 120 + Math.floor(Math.random() * 200), tls_valid: true, dns_resolved: true, reachable: true };
    }

    // --- URL router ---
    function handleMockFetch(url) {
        // Parse URL
        var path = url.split('?')[0];
        var params = {};
        var qStr = url.split('?')[1] || '';
        qStr.split('&').forEach(function (p) {
            var kv = p.split('=');
            params[decodeURIComponent(kv[0])] = decodeURIComponent(kv[1] || '');
        });

        // Health check
        if (path === '/api/health') return mockHealth();

        // Diagnosis
        if (path === '/api/diagnose') return mockDiagnose(params.target || 'example.com');

        // TLS
        if (path === '/api/tls') return mockTLS(params.host || 'example.com');

        // Traceroute
        if (path === '/api/traceroute') return mockTraceroute(params.host || 'example.com');

        // Port scan
        if (path === '/api/ports' || path === '/api/portscan') return mockPortScan(params.host || 'example.com');

        // DNS Race
        if (path === '/api/dnsrace') return mockDNSRace(params.host || 'example.com');

        // Speed test
        if (path === '/api/speedtest') return mockSpeedTest();

        // WHOIS
        if (path === '/api/whois') return mockWHOIS(params.domain || 'example.com');

        // Simulator
        if (path === '/api/simulator') return mockSimulator();

        // LB sim
        if (path === '/api/lbsim') return mockLBSim();

        // History
        if (path === '/api/history') return mockHistory();
        if (path === '/api/history/compare') return [];

        // Fingerprint
        if (path === '/api/fingerprint') return mockFingerprint(params.target || 'example.com');

        // Packet flow
        if (path === '/api/packetflow') return mockPacketFlow(params.target || 'example.com');

        // Overview
        if (path === '/api/overview') return mockOverview(params.host || 'example.com');

        // Stress test
        if (path === '/api/stress') return { status: 'completed', requests: 1000, successful: 995, failed: 5, duration_ms: 5000, rps: 200 };

        // Health monitor
        if (path === '/api/healthmon') return { host: params.host || 'example.com', latency_ms: 15 + Math.floor(Math.random() * 30), timestamp: new Date().toISOString() };
        if (path === '/api/healthmon/start') return { status: 'started' };
        if (path === '/api/healthmon/stop') return { status: 'stopped' };

        // Multi-target
        if (path === '/api/multiscan') return { targets: (params.hosts || 'example.com').split(',').map(function (h) { return mockDiagnose(h.trim()); }) };

        // Baseline, diff, correlation
        if (path === '/api/baseline') return { status: 'saved', timestamp: new Date().toISOString() };
        if (path === '/api/diff') return { changes: [], baseline: null };
        if (path === '/api/correlation') return { correlations: [] };

        // Default
        return { status: 'ok', message: 'Mock response' };
    }

    // --- Intercept fetch ---
    var originalFetch = window.fetch;
    window.fetch = function (url, opts) {
        if (typeof url === 'string' && url.indexOf('/api/') === 0) {
            // Check server availability first, then mock
            return originalFetch.call(window, url, opts).then(function (r) {
                if (r.ok) {
                    serverAvailable = true;
                    return r;
                }
                throw new Error('server error');
            }).catch(function () {
                // Server not available — use mock
                var mockData = handleMockFetch(url);
                var body = JSON.stringify(mockData);
                return new Response(body, { status: 200, headers: { 'Content-Type': 'application/json' } });
            });
        }
        return originalFetch.apply(window, arguments);
    };

    // --- Intercept EventSource (SSE) ---
    var OriginalES = window.EventSource;
    window.EventSource = function (url) {
        if (typeof url === 'string' && url.indexOf('/api/') === 0) {
            // Return a fake EventSource that emits mock data
            var target = 'example.com';
            var match = url.match(/target=([^&]*)/);
            if (match) target = decodeURIComponent(match[1]);

            var result = mockDiagnose(target);
            var es = { readyState: 0, onopen: null, onmessage: null, onerror: null, close: function () {}, addEventListener: function () {} };

            // Simulate SSE events
            setTimeout(function () {
                es.readyState = 1;
                if (es.onopen) es.onopen({ type: 'open' });
                // Emit layers one by one
                var layers = ['dns', 'tcp', 'http'];
                layers.forEach(function (layer, i) {
                    setTimeout(function () {
                        if (es.onmessage) es.onmessage({ data: JSON.stringify({ type: 'layer', layer: layer, value: result[layer] }) });
                    }, 200 * (i + 1));
                });
                setTimeout(function () {
                    if (es.onmessage) es.onmessage({ data: JSON.stringify({ type: 'health', value: result.health }) });
                    setTimeout(function () {
                        if (es.onmessage) es.onmessage({ data: JSON.stringify({ type: 'complete', value: result }) });
                        es.readyState = 0;
                    }, 200);
                }, 800);
            }, 100);

            return es;
        }
        if (OriginalES) return new OriginalES(url);
        return { readyState: 0, onopen: null, onmessage: null, onerror: null, close: function () {} };
    };

    // --- Check server availability ---
    originalFetch.call(window, '/api/health').then(function (r) {
        if (r.ok) {
            serverAvailable = true;
            // Restore original fetch if server is up
            window.fetch = originalFetch;
            if (OriginalES) window.EventSource = OriginalES;
        }
    }).catch(function () {
        // Server not available — show demo banner
        serverAvailable = false;
        window.addEventListener('DOMContentLoaded', function () {
            var banner = document.createElement('div');
            banner.style.cssText = 'background:linear-gradient(135deg,#1e3a5f,#0d2137);border:1px solid #2563eb;border-radius:8px;padding:14px 20px;margin:16px 20px;color:#93c5fd;font-family:system-ui,sans-serif;display:flex;align-items:center;gap:10px;font-size:14px;z-index:999;position:relative;';
            banner.innerHTML = '<span style="font-size:18px;">📋</span> <strong>DEMO MODE</strong> — GitHub Pages (static). Showing simulated results. For real measurements, build and run the Go binary: <code style="background:#0f172a;padding:2px 6px;border-radius:3px;">go build && ./netscope serve</code>';
            var header = document.querySelector('.header') || document.querySelector('header');
            if (header && header.parentNode) {
                header.parentNode.insertBefore(banner, header.nextSibling);
            } else {
                document.body.insertBefore(banner, document.body.firstChild);
            }
        });
        window.__MOCK_MODE = true;
    });

    // Expose for app.js
    window.__isServerAvailable = function () { return serverAvailable; };
})();
