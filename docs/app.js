// NetScope Dashboard Application
// Standalone mode: mock data when no server available
(function () {
    'use strict';

    // Mock fallback for GitHub Pages / standalone mode
    var USE_MOCK = (window.location.protocol === 'file:' || !window.location.port || window.location.port === '443' || window.location.port === '80');
    var _origFetch = window.fetch;
    window.fetch = function(url, opts) {
        if (USE_MOCK && typeof url === 'string' && url.startsWith('/api/')) {
            return Promise.resolve({
                ok: true,
                json: function() { return Promise.resolve(mockAPI(url)); }
            });
        }
        return _origFetch.apply(this, arguments);
    };
    window.fetch = window.fetch.bind(window);

    function mockAPI(url) {
        var target = 'example.com';
        var m = url.match(/[?&]target=([^&]+)/);
        if (m) target = decodeURIComponent(m[1]);
        var dnsTime = 15000000 + Math.random()*30000000;
        var tcpTime = 8000000 + Math.random()*15000000;
        var httpTime = 50000000 + Math.random()*100000000;
        if (url.includes('/diagnose')) {
            return {
                target: target,
                health: { score: 85+Math.floor(Math.random()*15), status: 'Healthy', message: 'All layers responding normally', layers: [
                    {name:'DNS',status:'ok',latency:'31ms'},
                    {name:'TCP',status:'ok',latency:'8ms'},
                    {name:'HTTP',status:'ok',latency:'174ms'}
                ]},
                dns: {success:true,resolution_time_ns:dnsTime,ipv4_addresses:['93.184.216.34'],ipv6_addresses:['2606:2800:220:1:248:1893:25c8:1946'],resolvers_tested:3,all_resolved:true},
                tcp: {connected:true,latency_ns:tcpTime,concurrent_connections:3,error_classification:'none'},
                http: {status_code:200,status_text:'OK',response_time_ns:httpTime,timing:{dns_ns:dnsTime,tcp_ns:tcpTime,tls_ns:45000000,ttfb_ns:80000000,total_ns:httpTime},headers:{'server':'nginx','content-type':'text/html'}},
                root_cause: {layer:'none',severity:'info',message:'Network is healthy — all layers responding normally',confidence:97,suggestions:['No issues detected']},
                packet_flow: {target:target,timing:{dns_ns:dnsTime,tcp_ns:tcpTime,tls_ns:45000000,http_ns:httpTime,total_ns:httpTime},steps:[{layer:'DNS',status:'ok'},{layer:'TCP',status:'ok'},{layer:'TLS',status:'ok'},{layer:'HTTP',status:'ok'}]},
                fingerprint: {target:target,confidence:85,detected:{server:'nginx/1.24.0',cdn:'Cloudflare',waf:'None',hosting:'Cloudflare Pages',framework:'None'},raw_headers:{'server':'nginx/1.24.0','cf-ray':'test123'}}
            };
        }
        if (url.includes('/stream')) return {type:'complete',value:mockAPI('/api/diagnose?target='+target)};
        if (url.includes('/dns')) return {success:true,resolution_time_ns:dnsTime,ipv4_addresses:['93.184.216.34'],resolvers:[]};
        if (url.includes('/tcp')) return {connected:true,latency_ns:tcpTime};
        if (url.includes('/http')) return {status_code:200,response_time_ns:httpTime};
        if (url.includes('/health')) return {status:'healthy',uptime:'1h 23m',version:'v1.0.0'};
        if (url.includes('/history')) return [];
        if (url.includes('/tls')) return {subject:'CN='+target,issuer:'Let\'s Encrypt',not_before:'2026-01-01',not_after:'2026-12-31',protocol:'TLS 1.3',cipher:'TLS_AES_256_GCM_SHA388',key_size:256,chain:[],san:[]};
        if (url.includes('/traceroute')) return {hops:[{ttl:1,ip:'192.168.1.1',hostname:'gateway',latency_ms:1},{ttl:2,ip:'10.0.0.1',hostname:'isp-router',latency_ms:5},{ttl:3,ip:'72.14.236.1',hostname:'google-gw',latency_ms:12},{ttl:4,ip:'142.250.80.46',hostname:'google.com',latency_ms:18}],complete:true};
        if (url.includes('/portscan')) return {host:target,open_ports:[{port:80,state:'open',service:'HTTP'},{port:443,state:'open',service:'HTTPS'}],closed_ports:[22,21,25],filtered_ports:[]};
        if (url.includes('/ping')) return {host:target,packets_sent:10,packets_received:10,loss_percent:0,avg_ms:18.5,min_ms:15.2,max_ms:24.1,stddev_ms:2.8,times:[15.2,16.8,17.1,18.3,18.9,19.2,20.1,21.5,22.8,24.1]};
        if (url.includes('/benchmark')) return {target:target,rounds:10,results:{p50_ms:18.5,p95_ms:22.3,p99_ms:24.1,avg_ms:19.2,min_ms:15.2,max_ms:24.1,jitter_ms:2.8,consistency:'A'},grade:'A'};
        if (url.includes('/stress')) return {target:target,total_requests:1000,successful:998,failed:2,avg_latency_ms:45,p50_ms:38,p99_ms:120,throughput_rps:2200};
        if (url.includes('/fingerprint')) return {target:target,confidence:85,server:'nginx',cdn:'Cloudflare',framework:'None'};
        if (url.includes('/packetflow')) return mockAPI('/api/diagnose?target='+target).packet_flow;
        if (url.includes('/correlation')) return {target:target,chain:[{layer:'DNS',status:'ok'},{layer:'TCP',status:'ok'},{layer:'HTTP',status:'ok'}],root_cause:{layer:'none',message:'All healthy',confidence:97}};
        if (url.includes('/export')||url.includes('/report')) return {html:'<h1>NetScope Report</h1><p>Report for '+target+'</p>'};
        if (url.includes('/csrf-token')) return {token:'mock-csrf-token-12345'};
        return {};
    }


    // DOM Elements
    const targetInput = document.getElementById('targetInput');
    const btnDiagnose = document.getElementById('btnDiagnose');
    const btnSpinner = document.getElementById('btnSpinner');
    const btnText = document.querySelector('.btn-text');
    const healthSection = document.getElementById('healthSection');
    const healthScore = document.getElementById('healthScore');
    const healthNumber = document.getElementById('healthNumber');
    const healthStatus = document.getElementById('healthStatus');
    const healthMessage = document.getElementById('healthMessage');
    const timelineSection = document.getElementById('timelineSection');
    const rootcauseSection = document.getElementById('rootcauseSection');
    const chartSection = document.getElementById('chartSection');
    const activitySection = document.getElementById('activitySection');
    const activityLog = document.getElementById('activityLog');
    const btnSimulator = document.getElementById('btnSimulator');
    const simulatorSection = document.getElementById('simulatorSection');
    const simTarget = document.getElementById('simTarget');
    const simAddrEl = document.getElementById('simAddr');
    const btnStress = document.getElementById('btnStress');

    let isRunning = false;
    let history = [];
    let lbUpdateInterval = null;

    // Go's time.Duration marshals to JSON as nanoseconds;
    // convert to human-readable milliseconds.
    function nsToMs(ns) {
        if (!ns || ns <= 0) return 0;
        return ns / 1000000;
    }

    // Check if the backend server is reachable on page load.
    if (window.location.protocol === 'file:') {
        // HTML opened directly — show setup instructions.
        document.body.insertAdjacentHTML('afterbegin',
            '<div id="serverWarning" style="background:#7f1d1d;border:1px solid #ef4444;border-radius:8px;padding:24px 28px;margin:20px;color:#fca5a5;font-family:system-ui,sans-serif;position:relative;z-index:200;line-height:1.7;">' +
            '<div style="display:flex;align-items:center;gap:10px;margin-bottom:12px;">' +
            '<span style="font-size:22px;">⚠️</span>' +
            '<strong style="font-size:17px;color:#fecaca;">NetScope requires its server to run</strong></div>' +
            '<p style="margin:0 0 14px 0;">You opened <code>index.html</code> directly. The dashboard needs the Go backend to perform real network diagnostics.</p>' +
            '<p style="margin:0 0 8px 0;font-weight:700;color:#fca5a5;">Quick start:</p>' +
            '<ol style="margin:0;padding-left:20px;">' +
            '<li>Open a terminal in the <code>netscope</code> folder</li>' +
            '<li>Run: <code style="background:#1e293b;padding:4px 10px;border-radius:4px;">go run ./cmd/netscope</code></li>' +
            '<li>Open <a href="http://localhost:8199" style="color:#60a5fa;text-decoration:underline;">http://localhost:8199</a></li>' +
            '</ol>' +
            '<p style="margin:12px 0 0 0;font-size:0.85rem;color:#f87171;">Or double-click <code>start.bat</code> (Windows) / <code>start.sh</code> (Linux/Mac).</p>' +
            '</div>');
    } else {
        fetch('/api/health').then(function (r) {
            if (!r.ok) throw new Error('server error');
            return r.json();
        }).then(function () {
            // Server is up — all good.
        }).catch(function () {
            document.body.insertAdjacentHTML('afterbegin',
                '<div id="serverWarning" style="background:#7f1d1d;border:1px solid #ef4444;border-radius:8px;padding:20px;margin:20px;color:#fca5a5;font-family:sans-serif;position:relative;z-index:200;">' +
                '<strong style="font-size:16px;">⚠️ NetScope server is not responding</strong><br><br>' +
                'The server may be starting up. <a href="javascript:location.reload()" style="color:#60a5fa;">Click here to retry</a>, or restart the server.' +
                '</div>');
        });
    }

    // Example buttons
    document.querySelectorAll('.btn-example').forEach(function (btn) {
        btn.addEventListener('click', function () {
            targetInput.value = btn.dataset.target;
            runDiagnosis(btn.dataset.target);
        });
    });

    // Enter key
    targetInput.addEventListener('keydown', function (e) {
        if (e.key === 'Enter') {
            runDiagnosis(targetInput.value.trim());
        }
    });

    // Diagnose button
    btnDiagnose.addEventListener('click', function () {
        runDiagnosis(targetInput.value.trim());
    });

    // Stress test button
    btnStress.addEventListener('click', runStressTest);

    // ---- Theme Toggle ----
    var btnTheme = document.getElementById('btnTheme');
    if (btnTheme) {
        var savedTheme = localStorage.getItem('netscope-theme') || 'dark';
        if (savedTheme === 'light') {
            document.body.classList.add('light');
            btnTheme.textContent = '☀️';
        }
        btnTheme.addEventListener('click', function () {
            document.body.classList.toggle('light');
            var isLight = document.body.classList.contains('light');
            btnTheme.textContent = isLight ? '☀️' : '🌙';
            localStorage.setItem('netscope-theme', isLight ? 'light' : 'dark');
        });
    }

    // Simulator toggle
    btnSimulator.addEventListener('click', function () {
        var simVisible = simulatorSection.style.display !== 'none';
        var lbVisible = document.getElementById('lbsimSection').style.display !== 'none';
        
        if (!simVisible && !lbVisible) {
            simulatorSection.style.display = '';
            document.getElementById('lbsimSection').style.display = '';
            startLBPolling();
        } else {
            simulatorSection.style.display = 'none';
            document.getElementById('lbsimSection').style.display = 'none';
            stopLBPolling();
        }
    });

    // Simulator mode buttons
    document.querySelectorAll('.btn-sim-mode').forEach(function (btn) {
        btn.addEventListener('click', function () {
            setSimulatorMode(btn.dataset.mode);
            document.querySelectorAll('.btn-sim-mode').forEach(function (b) {
                b.classList.remove('active');
            });
            btn.classList.add('active');
        });
    });

    // Latency control visibility
    var simLatencyCtrl = document.getElementById('simLatencyCtrl');
    function checkSimLatencyVisibility() {
        var activeBtn = document.querySelector('.btn-sim-mode.active');
        if (activeBtn && activeBtn.dataset.mode === 'add_latency') {
            simLatencyCtrl.style.display = '';
        } else {
            simLatencyCtrl.style.display = 'none';
        }
    }

    // Init simulator
    fetch('/api/simulator').then(function (r) { return r.json(); }).then(function (s) {
        simAddrEl.textContent = window.location.hostname + ':8200';
        simTarget.textContent = window.location.hostname + ':8200';
        document.querySelectorAll('.btn-sim-mode').forEach(function (b) {
            if (b.dataset.mode === s.mode) b.classList.add('active');
        });
        checkSimLatencyVisibility();
    }).catch(function () {});

    // Start LB polling on page load since sections are visible by default
    startLBPolling();

    // ---- Diagnosis ----

    function runDiagnosis(target) {
        if (!target || isRunning) return;
        isRunning = true;

        btnDiagnose.disabled = true;
        btnText.style.display = 'none';
        btnSpinner.style.display = '';

        resetUI();
        showSections(true);
        logActivity('Starting diagnosis: ' + target, 'running');

        // Use SSE stream for live updates
        var es = new EventSource('/api/stream?target=' + encodeURIComponent(target));
        var lastData = null;

        es.onmessage = function (e) {
            try {
                var data = JSON.parse(e.data);
                handleEvent(data);
                if (data.type === 'complete') {
                    lastData = data.value;
                }
            } catch (err) {
                // ignore parse errors
            }
        };

        es.onerror = function () {
            es.close();
            if (!lastData) {
                // Fallback to non-streaming API
                fetchDiagnosis(target);
            }
        };

        // Timeout fallback
        setTimeout(function () {
            if (isRunning) {
                es.close();
                if (!lastData) {
                    fetchDiagnosis(target);
                }
            }
        }, 30000);
    }

    function fetchDiagnosis(target) {
        fetch('/api/diagnose?target=' + encodeURIComponent(target))
            .then(function (r) { return r.json(); })
            .then(function (result) {
                if (result.error) {
                    logActivity('Error: ' + result.error, 'fail');
                    finishLoading();
                    return;
                }
                displayResult(result);
                logActivity('Diagnosis complete', 'ok');
                finishLoading();
            })
            .catch(function (err) {
                logActivity('Request failed: ' + err.message, 'fail');
                finishLoading();
            });
    }

    function handleEvent(evt) {
        if (evt.type === 'progress') {
            var status = evt.status || 'running';
            var msg = evt.message || '';
            updateTimeline(evt.layer, status, msg);
            logActivity(msg, status === 'ok' ? 'ok' : status === 'failed' ? 'fail' : 'running');
        } else if (evt.type === 'complete') {
            if (evt.value) {
                displayResult(evt.value);
            }
            logActivity('Diagnosis complete', 'ok');
            finishLoading();
        }
    }

    function displayResult(result) {
        // Health score
        if (result.health) {
            animateScore(result.health.score);
            healthStatus.textContent = result.health.status;
            healthMessage.textContent = result.health.message || '';
            healthScore.className = 'health-card ' + result.health.status.toLowerCase();

            // Layer cards
            if (result.health.layers) {
                result.health.layers.forEach(function (layer) {
                    updateLayerCard(layer);
                });
            }
        }

        // Update timeline with final results
        if (result.dns) {
            var dnsMsg = result.dns.success ? 'OK ' + Math.round(nsToMs(result.dns.resolution_time_ms)) + ' ms' : 'Failed: ' + result.dns.error;
            // Show resolved IPs including IPv6
            if (result.dns.success && result.dns.ipv4_addresses && result.dns.ipv4_addresses.length > 0) {
                dnsMsg += ' — IPv4: ' + result.dns.ipv4_addresses.join(', ');
            }
            if (result.dns.success && result.dns.ipv6_addresses && result.dns.ipv6_addresses.length > 0) {
                dnsMsg += ' — IPv6: ' + result.dns.ipv6_addresses.join(', ');
            }
            updateTimeline('DNS', result.dns.success ? 'ok' : 'failed', dnsMsg);
        }
        if (result.tcp) {
            updateTimeline('TCP', result.tcp.connected ? 'ok' : 'failed',
                result.tcp.connected ? 'OK ' + Math.round(nsToMs(result.tcp.latency_ms)) + ' ms' : 'Failed: ' + result.tcp.error);
        }
        if (result.http) {
            updateTimeline('HTTP', result.http.success ? 'ok' : 'failed',
                result.http.success ? 'OK ' + Math.round(nsToMs(result.http.total_duration_ms)) + ' ms' : 'Failed: ' + result.http.error);
        }
        updateTimeline('Analysis', 'ok', 'Complete');

        // Root cause
        if (result.health && result.health.root_cause) {
            showRootCause(result.health.root_cause);
        } else if (result.health && result.health.score >= 80) {
            showRootCause({
                root_cause: 'Network is healthy',
                severity: 'info',
                confidence: 1.0,
                affected_layer: 'none',
                evidence: 'All network layers are performing within normal parameters.',
                recommendation: 'No action required.'
            });
        }

        // Latency chart
        drawLatencyChart(result);

        // Store in history
        history.push({
            target: result.target ? result.target.host : '',
            score: result.health ? result.health.score : 0,
            time: new Date()
        });
    }

    // ---- UI Updates ----

    function resetUI() {
        healthNumber.textContent = '0';
        healthStatus.textContent = 'UNKNOWN';
        healthMessage.textContent = '';
        healthScore.className = 'health-card';

        ['DNS', 'TCP', 'HTTP', 'Analysis'].forEach(function (layer) {
            var item = document.getElementById('tl' + layer);
            if (item) {
                item.className = 'timeline-item';
                document.getElementById('tl' + layer + 'Detail').textContent = 'Waiting...';
            }
        });

        rootcauseSection.style.display = 'none';
        chartSection.style.display = 'none';
        document.getElementById('layerDNS').className = 'layer-card';
        document.getElementById('layerTCP').className = 'layer-card';
        document.getElementById('layerHTTP').className = 'layer-card';
    }

    function showSections(show) {
        var display = show ? '' : 'none';
        healthSection.style.display = display;
        timelineSection.style.display = display;
        activitySection.style.display = display;
    }

    function updateTimeline(layer, status, detail) {
        var item = document.getElementById('tl' + layer);
        var detailEl = document.getElementById('tl' + layer + 'Detail');
        if (item) {
            item.className = 'timeline-item ' + status;
        }
        if (detailEl) {
            detailEl.textContent = detail;
        }
    }

    function updateLayerCard(layer) {
        var id = 'layer' + layer.layer.toUpperCase();
        var card = document.getElementById(id);
        if (!card) return;

        card.className = 'layer-card ' + layer.status;

        var statusEl = document.getElementById(id + 'Status');
        var latencyEl = document.getElementById(id + 'Latency');
        var msgEl = document.getElementById(id + 'Msg');

        if (statusEl) {
            switch (layer.status) {
                case 'ok': statusEl.textContent = '✓'; break;
                case 'warning': statusEl.textContent = '⚠'; break;
                case 'failed': statusEl.textContent = '✗'; break;
                default: statusEl.textContent = '—';
            }
        }
        if (latencyEl) latencyEl.textContent = layer.latency || '';
        if (msgEl) msgEl.textContent = layer.message || '';
    }

    function animateScore(target) {
        var current = 0;
        var step = Math.max(1, Math.ceil(target / 30));
        var el = healthNumber;
        function tick() {
            current = Math.min(current + step, target);
            el.textContent = current;
            if (current < target) requestAnimationFrame(tick);
        }
        tick();
    }

    function showRootCause(rc) {
        rootcauseSection.style.display = '';
        var card = document.getElementById('rootcauseCard');
        card.className = 'rootcause-card severity-' + rc.severity;

        document.getElementById('rcSeverity').textContent = rc.severity.toUpperCase();
        document.getElementById('rcSeverity').className = 'rc-severity ' + rc.severity;
        document.getElementById('rcCause').textContent = rc.root_cause;
        document.getElementById('rcConfidence').textContent = 'Confidence: ' + Math.round(rc.confidence * 100) + '%';
        document.getElementById('rcEvidence').textContent = 'Evidence: ' + rc.evidence;
        document.getElementById('rcRecommendation').textContent = 'Recommendation: ' + rc.recommendation;
    }

    // ---- Latency Chart ----

    function drawLatencyChart(result) {
        chartSection.style.display = '';
        var canvas = document.getElementById('latencyChart');
        var ctx = canvas.getContext('2d');
        var W = canvas.width;
        var H = canvas.height;

        ctx.clearRect(0, 0, W, H);

        // Gather data points
        var bars = [];
        if (result.dns && result.dns.success) {
            bars.push({ label: 'DNS', value: nsToMs(result.dns.resolution_time_ms) || 0, color: '#3b82f6' });
        } else {
            bars.push({ label: 'DNS', value: 0, color: '#ef4444' });
        }
        if (result.tcp && result.tcp.connected) {
            bars.push({ label: 'TCP', value: nsToMs(result.tcp.latency_ms) || 0, color: '#22c55e' });
        } else {
            bars.push({ label: 'TCP', value: 0, color: '#ef4444' });
        }
        if (result.http && result.http.success) {
            bars.push({ label: 'HTTP Total', value: nsToMs(result.http.total_duration_ms) || 0, color: '#f97316' });
            if (result.http.time_to_first_byte_ms) {
                bars.push({ label: 'TTFB', value: nsToMs(result.http.time_to_first_byte_ms), color: '#eab308' });
            }
        } else {
            bars.push({ label: 'HTTP', value: 0, color: '#ef4444' });
        }

        var maxVal = Math.max.apply(null, bars.map(function (b) { return b.value; }));
        if (maxVal === 0) maxVal = 100;

        var padding = { top: 30, bottom: 40, left: 60, right: 20 };
        var chartW = W - padding.left - padding.right;
        var chartH = H - padding.top - padding.bottom;
        var barWidth = Math.min(80, (chartW / bars.length) * 0.6);
        var gap = (chartW - barWidth * bars.length) / (bars.length + 1);

        // Draw grid lines
        ctx.strokeStyle = '#1f2b3d';
        ctx.lineWidth = 1;
        for (var i = 0; i <= 4; i++) {
            var y = padding.top + chartH * (1 - i / 4);
            ctx.beginPath();
            ctx.moveTo(padding.left, y);
            ctx.lineTo(W - padding.right, y);
            ctx.stroke();

            ctx.fillStyle = '#64748b';
            ctx.font = '11px monospace';
            ctx.textAlign = 'right';
            ctx.fillText(Math.round(maxVal * i / 4) + ' ms', padding.left - 8, y + 4);
        }

        // Draw bars
        bars.forEach(function (bar, idx) {
            var x = padding.left + gap + idx * (barWidth + gap);
            var barH = (bar.value / maxVal) * chartH;
            var y = padding.top + chartH - barH;

            // Bar
            ctx.fillStyle = bar.color;
            ctx.beginPath();
            ctx.roundRect(x, y, barWidth, barH, [4, 4, 0, 0]);
            ctx.fill();

            // Value label
            if (bar.value > 0) {
                ctx.fillStyle = '#e2e8f0';
                ctx.font = '12px monospace';
                ctx.textAlign = 'center';
                ctx.fillText(Math.round(bar.value) + ' ms', x + barWidth / 2, y - 8);
            }

            // X label
            ctx.fillStyle = '#94a3b8';
            ctx.font = '12px sans-serif';
            ctx.textAlign = 'center';
            ctx.fillText(bar.label, x + barWidth / 2, H - padding.bottom + 20);
        });
    }

    // ---- Stress Test ----

    function runStressTest() {
        var host = targetInput.value.trim();
        if (!host) {
            host = 'example.com';
            targetInput.value = host;
        }

        var conns = parseInt(document.getElementById('stressConns').value, 10);
        var duration = parseInt(document.getElementById('stressDuration').value, 10);
        var port = parseInt(document.getElementById('stressPort').value, 10);

        btnStress.disabled = true;
        btnStress.textContent = 'Running...';

        fetch('/api/stress', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                host: host,
                port: String(port),
                connections: String(conns),
                duration: String(duration)
            })
        })
        .then(function (r) { return r.json(); })
        .then(function (result) {
            if (result.error) {
                logActivity('Stress test error: ' + result.error, 'fail');
                btnStress.disabled = false;
                btnStress.textContent = 'Run Stress Test';
                return;
            }
            displayStressResults(result);
            btnStress.disabled = false;
            btnStress.textContent = 'Run Stress Test';
        })
        .catch(function (err) {
            logActivity('Stress test failed: ' + err.message, 'fail');
            btnStress.disabled = false;
            btnStress.textContent = 'Run Stress Test';
        });
    }

    function displayStressResults(r) {
        document.getElementById('stressResults').style.display = '';
        document.getElementById('stressTotal').textContent = r.total_requests;
        document.getElementById('stressSuccess').textContent = r.successful;
        document.getElementById('stressFailed').textContent = r.failed;
        document.getElementById('stressRPS').textContent = r.requests_per_sec ? r.requests_per_sec.toFixed(1) : '0';
        document.getElementById('stressP50').textContent = r.p50_ms ? r.p50_ms.toFixed(1) : '0';
        document.getElementById('stressP95').textContent = r.p95_ms ? r.p95_ms.toFixed(1) : '0';
        document.getElementById('stressP99').textContent = r.p99_ms ? r.p99_ms.toFixed(1) : '0';
        document.getElementById('stressAvg').textContent = r.avg_latency_ms ? r.avg_latency_ms.toFixed(1) : '0';

        drawStressChart(r);
        logActivity('Stress test complete: ' + r.successful + '/' + r.total_requests + ' succeeded', 'ok');
    }

    function drawStressChart(r) {
        var canvas = document.getElementById('stressChart');
        var ctx = canvas.getContext('2d');
        var W = canvas.width;
        var H = canvas.height;

        ctx.clearRect(0, 0, W, H);

        // Draw success rate bar
        var successPct = r.success_rate || 0;
        var failPct = r.failure_rate || 0;

        var padding = { top: 20, bottom: 30, left: 40, right: 20 };
        var barH = 30;
        var y = (H - barH) / 2;
        var chartW = W - padding.left - padding.right;

        // Success bar
        ctx.fillStyle = '#22c55e';
        ctx.beginPath();
        ctx.roundRect(padding.left, y, chartW * successPct / 100, barH, [4, 0, 0, 4]);
        ctx.fill();

        // Fail bar
        if (failPct > 0) {
            ctx.fillStyle = '#ef4444';
            ctx.beginPath();
            ctx.roundRect(padding.left + chartW * successPct / 100, y, chartW * failPct / 100, barH, [0, 4, 4, 0]);
            ctx.fill();
        }

        // Labels
        ctx.fillStyle = '#e2e8f0';
        ctx.font = '14px monospace';
        ctx.textAlign = 'center';
        if (successPct > 10) {
            ctx.fillText(successPct.toFixed(1) + '% Success', padding.left + chartW * successPct / 200, y + barH / 2 + 5);
        }
        if (failPct > 10) {
            ctx.fillText(failPct.toFixed(1) + '% Failed', padding.left + chartW * successPct / 100 + chartW * failPct / 200, y + barH / 2 + 5);
        }

        // Percentile labels
        ctx.fillStyle = '#94a3b8';
        ctx.font = '12px sans-serif';
        ctx.textAlign = 'center';
        ctx.fillText('P50: ' + (r.p50_ms || 0).toFixed(1) + ' ms  |  P95: ' + (r.p95_ms || 0).toFixed(1) + ' ms  |  P99: ' + (r.p99_ms || 0).toFixed(1) + ' ms', W / 2, H - 8);
    }

    // ---- Simulator ----

    function setSimulatorMode(mode) {
        var latencyMs = document.getElementById('simLatency').value || '2000';
        var body = { mode: mode, latency_ms: latencyMs, http_error_code: '500' };

        fetch('/api/simulator', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        })
        .then(function (r) { return r.json(); })
        .then(function (s) {
            document.getElementById('simCurrentState').textContent = 'Current mode: ' + s.mode;
            logActivity('Simulator mode: ' + s.mode, 'running');
            checkSimLatencyVisibility();
        })
        .catch(function () {
            logActivity('Failed to set simulator mode', 'fail');
        });
    }

    // ---- Activity Log ----

    function logActivity(msg, cls) {
        var entry = document.createElement('div');
        entry.className = 'activity-entry';
        var now = new Date();
        var time = now.toLocaleTimeString();
        entry.innerHTML = '<span class="activity-time">' + time + '</span><span class="activity-msg ' + (cls || '') + '">' + escapeHtml(msg) + '</span>';
        activityLog.insertBefore(entry, activityLog.firstChild);

        // Keep max 50 entries
        while (activityLog.children.length > 50) {
            activityLog.removeChild(activityLog.lastChild);
        }
    }

    function escapeHtml(s) {
        var div = document.createElement('div');
        div.appendChild(document.createTextNode(s));
        return div.innerHTML;
    }

    function finishLoading() {
        isRunning = false;
        btnDiagnose.disabled = false;
        btnText.style.display = '';
        btnSpinner.style.display = 'none';
    }

    // ---- Load Balancer Simulator ----

    function startLBPolling() {
        updateLBSim();
        lbUpdateInterval = setInterval(updateLBSim, 1000);
    }

    function stopLBPolling() {
        if (lbUpdateInterval) {
            clearInterval(lbUpdateInterval);
            lbUpdateInterval = null;
        }
    }

    function updateLBSim() {
        fetch('/api/lbsim').then(function (r) {
            if (!r.ok) throw new Error('not available');
            return r.json();
        }).then(function (data) {
            // Update stats
            document.getElementById('lbTotalReqs').textContent = (data.total_requests || 0).toLocaleString();
            document.getElementById('lbActive').textContent = data.active_clients || 0;
            document.getElementById('lbFailed').textContent = data.failed_requests || 0;
            
            // Format uptime
            var secs = Math.floor(data.uptime_seconds || 0);
            var h = Math.floor(secs / 3600);
            var m = Math.floor((secs % 3600) / 60);
            var s = secs % 60;
            document.getElementById('lbUptime').textContent = 
                String(h).padStart(2, '0') + ':' + String(m).padStart(2, '0') + ':' + String(s).padStart(2, '0');
            
            // Security level
            var secEl = document.getElementById('lbSecurity');
            secEl.textContent = data.security_level || 'SECURE';
            secEl.style.color = data.security_level === 'SECURE' ? '#22c55e' : '#eab308';
            
            // Backend nodes
            if (data.backends && data.backends.length > 0) {
                var html = '';
                data.backends.forEach(function (b) {
                    var isOff = b.forced_down || !b.alive;
                    html += '<div class="lb-node-card' + (isOff ? ' offline' : '') + '">';
                    html += '<div class="lb-node-header">';
                    html += '<span class="lb-node-host">' + escapeHtml(b.host) + '</span>';
                    html += '<button class="btn-lb-' + (b.forced_down ? 'restore' : 'crash') + '" ';
                    html += 'onclick="lbAction(\'' + (b.forced_down ? 'revive' : 'kill') + '\', \'' + escapeHtml(b.host) + '\')">';
                    html += b.forced_down ? 'RESTORE' : 'CRASH TEST';
                    html += '</button>';
                    html += '</div>';
                    html += '<div class="lb-node-status">';
                    html += '<span class="lb-node-dot ' + (isOff ? 'offline' : 'online') + '"></span>';
                    html += isOff ? 'Disabled' : 'Operational';
                    html += '</div>';
                    html += '<div class="lb-node-reqs">Requests: ' + (b.reqs || 0).toLocaleString() + '</div>';
                    html += '</div>';
                });
                document.getElementById('lbNodes').innerHTML = html;
            }
            
            // Notifications
            if (data.notifications && data.notifications.length > 0) {
                document.getElementById('lbNotifications').style.display = '';
                var notifHtml = '';
                data.notifications.forEach(function (n) {
                    notifHtml += '<div class="lb-notif-entry">' + escapeHtml(n) + '</div>';
                });
                document.getElementById('lbNotifList').innerHTML = notifHtml;
            }
        }).catch(function () {
            // LB simulator not available - hide section
            document.getElementById('lbsimSection').style.display = 'none';
        });
    }

    // Global function for LB node actions
    window.lbAction = function (action, node) {
        fetch('/api/lbsim/' + action + '?node=' + encodeURIComponent(node), { method: 'POST' })
            .then(function (r) { return r.json(); })
            .then(function () {
                logActivity('LB: ' + action + ' ' + node, action === 'kill' ? 'fail' : 'ok');
                updateLBSim();
            })
            .catch(function () {
                logActivity('LB action failed', 'fail');
            });
    };

    // ---- Keyboard shortcuts ----
    function bindEnterToButton(inputId, buttonId) {
        var input = document.getElementById(inputId);
        var btn = document.getElementById(buttonId);
        if (input && btn) {
            input.addEventListener('keydown', function (e) {
                if (e.key === 'Enter') { e.preventDefault(); btn.click(); }
            });
        }
    }
    bindEnterToButton('portscanHost', 'btnPortScan');
    bindEnterToButton('tlsHost', 'btnTLS');
    bindEnterToButton('benchHost', 'btnBench');
    bindEnterToButton('traceHost', 'btnTrace');
    bindEnterToButton('pingHost', 'btnPing');

    // ---- Port Scanner ----
    var btnPortScan = document.getElementById('btnPortScan');
    if (btnPortScan) {
        btnPortScan.addEventListener('click', function () {
            var host = document.getElementById('portscanHost').value.trim();
            if (!host) {
                alert('Enter a host to scan');
                return;
            }
            btnPortScan.disabled = true;
            btnPortScan.textContent = 'Scanning...';

            var ports = document.getElementById('portscanPorts').value.trim();
            var url = '/api/portscan?host=' + encodeURIComponent(host);
            if (ports) url += '&ports=' + encodeURIComponent(ports);

            fetch(url)
                .then(function (r) { return r.json(); })
                .then(function (data) {
                    document.getElementById('portscanResults').style.display = '';
                    document.getElementById('psTotal').textContent = data.total_ports;
                    document.getElementById('psOpen').textContent = data.open_ports;
                    document.getElementById('psClosed').textContent = data.closed_ports;
                    document.getElementById('psDuration').textContent = data.duration_ms + 'ms';

                    var tbody = document.getElementById('portscanTableBody');
                    tbody.innerHTML = '';
                    (data.results || []).forEach(function (p) {
                        var tr = document.createElement('tr');
                        tr.className = p.open ? 'open' : 'closed';
                        tr.innerHTML = '<td>' + p.port + '</td><td>' + (p.service || '') + '</td><td>' + (p.open ? 'OPEN' : 'CLOSED') + '</td><td>' + p.latency_ms + 'ms</td>';
                        tbody.appendChild(tr);
                    });
                    logActivity('Port scan: ' + host + ' — ' + data.open_ports + ' open / ' + data.closed_ports + ' closed', data.open_ports > 0 ? 'ok' : 'fail');
                })
                .catch(function (e) {
                    logActivity('Port scan failed: ' + e.message, 'fail');
                })
                .then(function () {
                    btnPortScan.disabled = false;
                    btnPortScan.textContent = 'Scan Ports';
                });
        });
    }

    // ---- TLS Inspector ----
    var btnTLS = document.getElementById('btnTLS');
    if (btnTLS) {
        btnTLS.addEventListener('click', function () {
            var host = document.getElementById('tlsHost').value.trim();
            if (!host) {
                alert('Enter a host to inspect');
                return;
            }
            btnTLS.disabled = true;
            btnTLS.textContent = 'Inspecting...';

            fetch('/api/tls?host=' + encodeURIComponent(host))
                .then(function (r) { return r.json(); })
                .then(function (data) {
                    document.getElementById('tlsResults').style.display = '';

                    if (data.error) {
                        document.getElementById('tlsSubject').textContent = 'Error';
                        document.getElementById('tlsValidity').textContent = data.error;
                        document.getElementById('tlsValidity').className = 'tls-validity expired';
                        return;
                    }

                    document.getElementById('tlsSubject').textContent = data.certificate.subject || host;
                    var validity = data.certificate.is_expired ? 'EXPIRED' : 'VALID (' + data.certificate.days_expiry + ' days)';
                    var vEl = document.getElementById('tlsValidity');
                    vEl.textContent = validity;
                    vEl.className = 'tls-validity ' + (data.certificate.is_expired ? 'expired' : 'valid');

                    document.getElementById('tlsIssuer').textContent = data.certificate.issuer || '—';
                    document.getElementById('tlsProtocol').textContent = data.protocol || '—';
                    document.getElementById('tlsCipher').textContent = data.cipher_suite || '—';
                    document.getElementById('tlsKey').textContent = (data.certificate.key_algorithm || '') + ' ' + (data.certificate.key_size || '') + '-bit';
                    document.getElementById('tlsSig').textContent = data.certificate.signature_algorithm || '—';
                    document.getElementById('tlsExpiry').textContent = data.certificate.not_after || '—';
                    document.getElementById('tlsChain').textContent = (data.certificate_chain || []).length + ' certificates';
                    document.getElementById('tlsSANs').textContent = (data.certificate.sans || []).join(', ') || '—';
                    logActivity('TLS inspection: ' + host + ' — ' + validity, data.certificate.is_expired ? 'fail' : 'ok');
                })
                .catch(function (e) {
                    logActivity('TLS inspection failed: ' + e.message, 'fail');
                })
                .then(function () {
                    btnTLS.disabled = false;
                    btnTLS.textContent = 'Inspect TLS';
                });
        });
    }

    // ---- Network Benchmark ----
    var btnBench = document.getElementById('btnBench');
    if (btnBench) {
        btnBench.addEventListener('click', function () {
            var host = document.getElementById('benchHost').value.trim();
            if (!host) {
                alert('Enter a host to benchmark');
                return;
            }
            var port = document.getElementById('benchPort').value || '443';
            var rounds = document.getElementById('benchRounds').value || '20';
            btnBench.disabled = true;
            btnBench.textContent = 'Benchmarking...';

            var url = '/api/benchmark?host=' + encodeURIComponent(host) + '&port=' + port + '&rounds=' + rounds;

            fetch(url)
                .then(function (r) { return r.json(); })
                .then(function (data) {
                    document.getElementById('benchResults').style.display = '';

                    var gradeEl = document.getElementById('benchGrade');
                    gradeEl.textContent = data.grade || '—';
                    var grade = (data.grade || 'F')[0].toLowerCase();
                    gradeEl.className = 'bench-grade grade-' + grade;

                    document.getElementById('benchScore').textContent = 'Consistency: ' + (data.consistency || 0).toFixed(1) + '% — ' + data.successful + '/' + data.rounds + ' successful';
                    document.getElementById('benchSuccess').textContent = data.successful;
                    document.getElementById('benchFailed').textContent = data.failed;
                    document.getElementById('benchLoss').textContent = (data.packet_loss || 0).toFixed(1) + '%';

                    function fmtDur(ns) {
                        return Math.round(ns / 1e6) + 'ms';
                    }

                    document.getElementById('benchAvg').textContent = fmtDur(data.avg_rtt || 0);
                    document.getElementById('benchMin').textContent = fmtDur(data.min_rtt || 0);
                    document.getElementById('benchMax').textContent = fmtDur(data.max_rtt || 0);
                    document.getElementById('benchP50').textContent = fmtDur(data.p50 || 0);
                    document.getElementById('benchP95').textContent = fmtDur(data.p95 || 0);
                    document.getElementById('benchJitter').textContent = fmtDur(data.jitter || 0);
                    document.getElementById('benchConsistency').textContent = (data.consistency || 0).toFixed(1) + '%';

                    logActivity('Benchmark: ' + host + ':' + port + ' — Grade: ' + data.grade, 'ok');
                })
                .catch(function (e) {
                    logActivity('Benchmark failed: ' + e.message, 'fail');
                })
                .then(function () {
                    btnBench.disabled = false;
                    btnBench.textContent = 'Run Benchmark';
                });
        });
    }

    // ---- Traceroute ----
    var btnTrace = document.getElementById('btnTrace');
    if (btnTrace) {
        btnTrace.addEventListener('click', function () {
            var host = document.getElementById('traceHost').value.trim();
            if (!host) {
                alert('Enter a host to trace');
                return;
            }
            btnTrace.disabled = true;
            btnTrace.textContent = 'Tracing...';

            fetch('/api/traceroute?host=' + encodeURIComponent(host))
                .then(function (r) { return r.json(); })
                .then(function (data) {
                    document.getElementById('traceResults').style.display = '';
                    document.getElementById('traceHops').textContent = data.total_hops || 0;
                    document.getElementById('traceCompleted').textContent = data.completed ? 'Yes' : 'No';
                    document.getElementById('traceResolvedIP').textContent = data.resolved_ip || '—';
                    document.getElementById('traceDuration').textContent = Math.round((data.duration_ns || 0) / 1e6) + 'ms';

                    // Render hop visualization
                    var viz = document.getElementById('traceViz');
                    var html = '';
                    (data.hops || []).forEach(function (hop, idx) {
                        if (hop.reached) {
                            var display = hop.host ? hop.host + ' (' + hop.ip + ')' : hop.ip;
                            var rtt = Math.round(hop.avg_rtt_ns / 1e6);
                            html += '<div class="trace-hop">';
                            html += '<span class="trace-hop-num">' + hop.ttl + '</span>';
                            html += '<span class="trace-hop-ip">' + escapeHtml(display) + '</span>';
                            html += '<span class="trace-hop-rtt">' + rtt + ' ms</span>';
                            html += '</div>';
                        } else {
                            html += '<div class="trace-hop"><span class="trace-hop-num">' + hop.ttl + '</span><span class="trace-hop-star">* * *</span></div>';
                        }
                        if (idx < data.hops.length - 1) {
                            html += '<div class="trace-connector"></div>';
                        }
                    });
                    viz.innerHTML = html || '<p style="color:var(--text-muted);">No hops detected</p>';
                    logActivity('Traceroute: ' + host + ' — ' + (data.total_hops || 0) + ' hops', data.completed ? 'ok' : 'fail');

                    // Draw topology visualization
                    drawTopology(data);
                })
                .catch(function (e) {
                    logActivity('Traceroute failed: ' + e.message, 'fail');
                })
                .then(function () {
                    btnTrace.disabled = false;
                    btnTrace.textContent = 'Trace Route';
                });
        });
    }

    // ---- History ----
    function loadHistory() {
        fetch('/api/history?limit=50')
            .then(function (r) { return r.json(); })
            .then(function (entries) {
                if (!entries || entries.length === 0) return;

                // Render table
                var tbody = document.getElementById('historyTableBody');
                var wrap = document.getElementById('historyTableWrap');
                if (entries.length > 0) {
                    wrap.style.display = '';
                    tbody.innerHTML = '';
                    entries.slice(0, 20).forEach(function (e) {
                        var tr = document.createElement('tr');
                        var scoreClass = e.score >= 80 ? 'open' : 'closed';
                        tr.className = scoreClass;
                        tr.innerHTML = '<td>' + escapeHtml(e.target || '') + '</td><td>' + e.score + '</td><td>' + (e.status || '') + '</td><td>' + new Date(e.timestamp).toLocaleTimeString() + '</td>';
                        tbody.appendChild(tr);
                    });
                }

                // Draw history chart
                drawHistoryChart(entries.reverse());
            })
            .catch(function () {});
    }

    function drawHistoryChart(entries) {
        var canvas = document.getElementById('historyChart');
        if (!canvas) return;
        var ctx = canvas.getContext('2d');
        var W = canvas.width;
        var H = canvas.height;
        ctx.clearRect(0, 0, W, H);

        if (!entries || entries.length < 2) {
            ctx.fillStyle = '#64748b';
            ctx.font = '14px sans-serif';
            ctx.textAlign = 'center';
            ctx.fillText('Run multiple diagnoses to see the history chart', W / 2, H / 2);
            return;
        }

        var padding = { top: 20, bottom: 30, left: 40, right: 20 };
        var chartW = W - padding.left - padding.right;
        var chartH = H - padding.top - padding.bottom;
        var stepX = chartW / Math.max(entries.length - 1, 1);

        // Draw grid lines
        ctx.strokeStyle = '#1f2b3d';
        ctx.lineWidth = 1;
        for (var i = 0; i <= 4; i++) {
            var y = padding.top + chartH * (1 - i / 4);
            ctx.beginPath();
            ctx.moveTo(padding.left, y);
            ctx.lineTo(W - padding.right, y);
            ctx.stroke();
            ctx.fillStyle = '#64748b';
            ctx.font = '11px monospace';
            ctx.textAlign = 'right';
            ctx.fillText(String(i * 25), padding.left - 8, y + 4);
        }

        // Draw line
        ctx.beginPath();
        ctx.strokeStyle = '#3b82f6';
        ctx.lineWidth = 2;
        entries.forEach(function (e, idx) {
            var x = padding.left + idx * stepX;
            var y = padding.top + chartH * (1 - e.score / 100);
            if (idx === 0) ctx.moveTo(x, y);
            else ctx.lineTo(x, y);
        });
        ctx.stroke();

        // Draw dots
        entries.forEach(function (e, idx) {
            var x = padding.left + idx * stepX;
            var y = padding.top + chartH * (1 - e.score / 100);
            ctx.beginPath();
            ctx.arc(x, y, 4, 0, Math.PI * 2);
            ctx.fillStyle = e.score >= 80 ? '#22c55e' : e.score >= 50 ? '#eab308' : '#ef4444';
            ctx.fill();
        });
    }

    // Load history on page load
    loadHistory();

    // ---- Export ----
    var btnExport = document.getElementById('btnExport');
    if (btnExport) {
        btnExport.addEventListener('click', function () {
            window.location.href = '/api/export?limit=20';
            logActivity('Exported diagnostic report', 'ok');
        });
    }

    // ---- Multi-Target Comparison ----
    var btnCompare = document.getElementById('btnCompare');
    if (btnCompare) {
        btnCompare.addEventListener('click', function () {
            var input = document.getElementById('compareTargets').value.trim();
            if (!input) { alert('Enter targets to compare (comma-separated)'); return; }
            var targets = input.split(',').map(function (t) { return t.trim(); }).filter(Boolean);
            if (targets.length < 2) { alert('Enter at least 2 targets'); return; }

            btnCompare.disabled = true;
            btnCompare.textContent = 'Comparing...';

            fetch('/api/history/compare?targets=' + encodeURIComponent(targets.join(',')))
                .then(function (r) { return r.json(); })
                .then(function (data) {
                    document.getElementById('compareResults').style.display = '';
                    var tbody = document.getElementById('compareTableBody');
                    tbody.innerHTML = '';
                    (data.results || []).forEach(function (r) {
                        var tr = document.createElement('tr');
                        var scoreClass = r.score >= 80 ? 'open' : 'closed';
                        tr.className = scoreClass;
                        tr.innerHTML = '<td>' + escapeHtml(r.target) + '</td><td>' + (r.score || '—') + '</td><td>' + (r.status || '—') + '</td><td>' + (r.dns_ms ? r.dns_ms.toFixed(1) + 'ms' : '—') + '</td><td>' + (r.tcp_ms ? r.tcp_ms.toFixed(1) + 'ms' : '—') + '</td><td>' + (r.http_ms ? r.http_ms.toFixed(1) + 'ms' : '—') + '</td>';
                        tbody.appendChild(tr);
                    });
                    logActivity('Compared ' + targets.length + ' targets', 'ok');
                })
                .catch(function (e) {
                    logActivity('Comparison failed: ' + e.message, 'fail');
                })
                .then(function () {
                    btnCompare.disabled = false;
                    btnCompare.textContent = 'Compare';
                });
        });
    }

    // ---- Real-Time Ping Monitor ----
    var pingData = [];
    var pingSSE = null;
    var btnPing = document.getElementById('btnPing');
    var btnPingStop = document.getElementById('btnPingStop');

    if (btnPing) {
        btnPing.addEventListener('click', startPing);
        btnPingStop.addEventListener('click', stopPing);
    }

    function startPing() {
        var host = document.getElementById('pingHost').value.trim();
        if (!host) { alert('Enter a host to ping'); return; }

        var port = document.getElementById('pingPort').value || '80';
        var count = document.getElementById('pingCount').value || '30';
        var interval = document.getElementById('pingInterval').value || '1000';

        pingData = [];
        document.getElementById('pingStats').style.display = '';
        document.getElementById('pingChartWrap').style.display = '';
        document.getElementById('pingLog').style.display = '';
        document.getElementById('pingLogEntries').innerHTML = '';
        btnPing.style.display = 'none';
        btnPingStop.style.display = '';

        var url = '/api/ping/stream?host=' + encodeURIComponent(host) + '&port=' + port + '&count=' + count + '&interval=' + interval;
        pingSSE = new EventSource(url);

        pingSSE.onmessage = function (e) {
            try {
                var update = JSON.parse(e.data);
                if (update.type === 'probe') {
                    handlePingProbe(update.probe, update.stats);
                } else if (update.type === 'complete') {
                    handlePingComplete(update.stats);
                }
            } catch (err) { /* ignore */ }
        };

        pingSSE.onerror = function () {
            pingSSE.close();
            pingSSE = null;
            btnPing.style.display = '';
            btnPingStop.style.display = 'none';
        };

        logActivity('Ping monitor started: ' + host + ':' + port, 'running');
    }

    function stopPing() {
        if (pingSSE) {
            pingSSE.close();
            pingSSE = null;
        }
        btnPing.style.display = '';
        btnPingStop.style.display = 'none';
        logActivity('Ping monitor stopped', 'ok');
    }

    function handlePingProbe(probe, stats) {
        pingData.push(probe);

        // Update stats cards
        document.getElementById('pingSent').textContent = stats.sent;
        document.getElementById('pingReceived').textContent = stats.received;
        document.getElementById('pingLost').textContent = stats.packet_loss_pct.toFixed(1) + '%';
        document.getElementById('pingAvgRTT').textContent = stats.avg_rtt_ms.toFixed(1) + 'ms';
        document.getElementById('pingMinRTT').textContent = stats.min_rtt_ms.toFixed(1) + 'ms';
        document.getElementById('pingMaxRTT').textContent = stats.max_rtt_ms.toFixed(1) + 'ms';
        document.getElementById('pingJitter').textContent = stats.jitter_ms.toFixed(1) + 'ms';
        document.getElementById('pingP95').textContent = stats.p95_ms.toFixed(1) + 'ms';

        // Color packet loss
        var lostEl = document.getElementById('pingLost');
        if (stats.packet_loss_pct > 10) {
            lostEl.parentElement.style.borderColor = '#ef4444';
        } else if (stats.packet_loss_pct > 0) {
            lostEl.parentElement.style.borderColor = '#eab308';
        } else {
            lostEl.parentElement.style.borderColor = '';
        }

        // Add to log
        var logEl = document.getElementById('pingLogEntries');
        var entry = document.createElement('div');
        entry.className = 'ping-log-entry ' + (probe.success ? 'success' : 'fail');
        entry.innerHTML = '<span>#' + probe.seq + '</span><span>' + (probe.success ? probe.rtt_ms.toFixed(2) + ' ms' : probe.error) + '</span><span>' + (probe.success ? '✓ OK' : '✗ FAIL') + '</span>';
        logEl.appendChild(entry);

        // Auto-scroll log
        var logWrap = document.getElementById('pingLog');
        logWrap.scrollTop = logWrap.scrollHeight;

        // Keep log to max 200 entries
        while (logEl.children.length > 200) {
            logEl.removeChild(logEl.firstChild);
        }

        // Draw live chart
        drawPingChart();
    }

    function handlePingComplete(stats) {
        stopPing();
        logActivity('Ping complete: ' + stats.received + '/' + stats.sent + ' received, avg=' + stats.avg_rtt_ms.toFixed(1) + 'ms', 'ok');
    }

    function drawPingChart() {
        var canvas = document.getElementById('pingChart');
        if (!canvas) return;
        var ctx = canvas.getContext('2d');
        var W = canvas.width;
        var H = canvas.height;

        ctx.clearRect(0, 0, W, H);

        if (pingData.length < 2) return;

        var padding = { top: 20, bottom: 35, left: 55, right: 15 };
        var chartW = W - padding.left - padding.right;
        var chartH = H - padding.top - padding.bottom;

        // Get successful probes for range
        var successes = pingData.filter(function (p) { return p.success; });
        if (successes.length === 0) return;

        var rtts = successes.map(function (p) { return p.rtt_ms; });
        var minRTT = Math.min.apply(null, rtts);
        var maxRTT = Math.max.apply(null, rtts);
        var range = maxRTT - minRTT;
        if (range < 5) range = 5; // minimum 5ms range
        var yMin = Math.max(0, minRTT - range * 0.1);
        var yMax = maxRTT + range * 0.1;

        // Draw grid lines
        ctx.strokeStyle = '#e5e7eb';
        ctx.lineWidth = 1;
        for (var i = 0; i <= 5; i++) {
            var y = padding.top + chartH * (1 - i / 5);
            ctx.beginPath();
            ctx.setLineDash([3, 3]);
            ctx.moveTo(padding.left, y);
            ctx.lineTo(W - padding.right, y);
            ctx.stroke();

            var val = yMin + (yMax - yMin) * i / 5;
            ctx.fillStyle = '#94a3b8';
            ctx.font = '10px monospace';
            ctx.textAlign = 'right';
            ctx.fillText(val.toFixed(1) + 'ms', padding.left - 6, y + 3);
        }
        ctx.setLineDash([]);

        // Draw time axis labels
        var totalProbes = pingData.length;
        var showEvery = Math.max(1, Math.floor(totalProbes / 8));
        for (var i = 0; i < totalProbes; i += showEvery) {
            var x = padding.left + (i / Math.max(totalProbes - 1, 1)) * chartW;
            ctx.fillStyle = '#94a3b8';
            ctx.font = '10px monospace';
            ctx.textAlign = 'center';
            ctx.fillText('#' + pingData[i].seq, x, H - padding.bottom + 18);
        }

        // Draw average line (dashed)
        var avgRTT = successes.reduce(function (sum, p) { return sum + p.rtt_ms; }, 0) / successes.length;
        var avgY = padding.top + chartH * (1 - (avgRTT - yMin) / (yMax - yMin));
        ctx.strokeStyle = '#f59e0b';
        ctx.lineWidth = 1;
        ctx.setLineDash([6, 4]);
        ctx.beginPath();
        ctx.moveTo(padding.left, avgY);
        ctx.lineTo(W - padding.right, avgY);
        ctx.stroke();
        ctx.setLineDash([]);

        // Draw avg label
        ctx.fillStyle = '#f59e0b';
        ctx.font = '10px monospace';
        ctx.textAlign = 'left';
        ctx.fillText('avg ' + avgRTT.toFixed(1) + 'ms', W - padding.right - 90, avgY - 5);

        // Draw P95 line (dashed)
        var sortedRTT = rtts.slice().sort(function (a, b) { return a - b; });
        var p95Idx = Math.ceil(sortedRTT.length * 0.95) - 1;
        if (p95Idx < 0) p95Idx = 0;
        var p95RTT = sortedRTT[p95Idx];
        var p95Y = padding.top + chartH * (1 - (p95RTT - yMin) / (yMax - yMin));
        if (p95Y >= padding.top && p95Y <= padding.top + chartH) {
            ctx.strokeStyle = '#ef4444';
            ctx.lineWidth = 1;
            ctx.setLineDash([4, 4]);
            ctx.beginPath();
            ctx.moveTo(padding.left, p95Y);
            ctx.lineTo(W - padding.right, p95Y);
            ctx.stroke();
            ctx.setLineDash([]);
            ctx.fillStyle = '#ef4444';
            ctx.font = '10px monospace';
            ctx.fillText('p95 ' + p95RTT.toFixed(1) + 'ms', W - padding.right - 90, p95Y - 5);
        }

        // Draw the line
        ctx.beginPath();
        ctx.strokeStyle = '#3b82f6';
        ctx.lineWidth = 2;
        var first = true;
        pingData.forEach(function (p, idx) {
            var x = padding.left + (idx / Math.max(totalProbes - 1, 1)) * chartW;
            var val = p.success ? p.rtt_ms : null;
            var y;
            if (val !== null) {
                y = padding.top + chartH * (1 - (val - yMin) / (yMax - yMin));
            } else {
                y = padding.top + chartH; // bottom for failures
            }
            if (first) {
                ctx.moveTo(x, y);
                first = false;
            } else {
                ctx.lineTo(x, y);
            }
        });
        ctx.stroke();

        // Draw gradient fill under the line
        var gradient = ctx.createLinearGradient(0, padding.top, 0, padding.top + chartH);
        gradient.addColorStop(0, 'rgba(59, 130, 246, 0.15)');
        gradient.addColorStop(1, 'rgba(59, 130, 246, 0.02)');
        ctx.lineTo(padding.left + chartW, padding.top + chartH);
        ctx.lineTo(padding.left, padding.top + chartH);
        ctx.closePath();
        ctx.fillStyle = gradient;
        ctx.fill();

        // Draw data points
        pingData.forEach(function (p, idx) {
            var x = padding.left + (idx / Math.max(totalProbes - 1, 1)) * chartW;
            if (p.success) {
                var y = padding.top + chartH * (1 - (p.rtt_ms - yMin) / (yMax - yMin));
                ctx.beginPath();
                ctx.arc(x, y, 3, 0, Math.PI * 2);
                ctx.fillStyle = p.rtt_ms > p95RTT ? '#ef4444' : '#3b82f6';
                ctx.fill();
            } else {
                // Draw red X for failures
                var fy = padding.top + chartH;
                ctx.fillStyle = '#ef4444';
                ctx.font = '10px sans-serif';
                ctx.textAlign = 'center';
                ctx.fillText('✕', x, fy - 4);
            }
        });
    }

    // ---- SVG Network Topology Visualization ----
    var topoTooltip = null;
    function ensureTopoTooltip() {
        if (!topoTooltip) {
            topoTooltip = document.createElement('div');
            topoTooltip.className = 'topo-tooltip';
            document.body.appendChild(topoTooltip);
        }
    }

    function latencyColor(t) {
        // t: 0=fast(green) → 1=slow(red)
        var r, g, b;
        if (t < 0.33) {
            var s = t / 0.33;
            r = Math.round(34 + s * 191); g = Math.round(197 - s * 18); b = Math.round(94 - s * 56);
        } else if (t < 0.66) {
            var s = (t - 0.33) / 0.33;
            r = Math.round(225 + s * 14); g = Math.round(179 - s * 121); b = Math.round(38 - s * 32);
        } else {
            var s = (t - 0.66) / 0.34;
            r = Math.round(239 - s * 19); g = Math.round(58 + s * 10); b = Math.round(6 + s * 62);
        }
        return 'rgb(' + r + ',' + g + ',' + b + ')';
    }

    function svgEl(tag, attrs) {
        var el = document.createElementNS('http://www.w3.org/2000/svg', tag);
        if (attrs) for (var k in attrs) el.setAttribute(k, attrs[k]);
        return el;
    }

    function drawTopology(data) {
        var container = document.getElementById('topologyContainer');
        var svg = document.getElementById('topologySVG');
        var legendEl = document.getElementById('topoLegend');
        if (!svg || !data || !data.hops || data.hops.length === 0) return;
        ensureTopoTooltip();
        container.style.display = '';

        var reached = data.hops.filter(function (h) { return h.reached; });
        if (reached.length === 0) { svg.innerHTML = '<text x="50%" y="50%" text-anchor="middle" fill="#64748b" font-size="14">No reachable hops</text>'; return; }

        // Limit displayed hops for readability (max 12, sample if more)
        var hops = reached;
        if (hops.length > 12) {
            var sampled = [hops[0]];
            var step = (hops.length - 2) / 10;
            for (var si = 1; si <= 10; si++) { sampled.push(hops[Math.min(Math.round(si * step + 1), hops.length - 1)]); }
            sampled.push(hops[hops.length - 1]);
            hops = sampled;
        }

        var W = 900, H = 340;
        var padL = 50, padR = 50, padT = 70, padB = 80;
        var centerY = 160;
        var n = hops.length;
        var spacing = (W - padL - padR) / Math.max(n - 1, 1);

        // RTT range
        var rtts = hops.map(function (h) { return h.avg_rtt_ns / 1e6; });
        var minRTT = Math.min.apply(null, rtts);
        var maxRTT = Math.max.apply(null, rtts);
        if (maxRTT <= minRTT) maxRTT = minRTT + 10;

        // Node positions
        var positions = hops.map(function (h, i) {
            var x = padL + i * spacing;
            var t = (h.avg_rtt_ns / 1e6 - minRTT) / (maxRTT - minRTT);
            var yOff = Math.sin(i * 0.7) * 12; // subtle wave
            return { x: x, y: centerY + yOff, t: t, hop: h };
        });

        // Clear SVG
        svg.innerHTML = '';
        svg.setAttribute('viewBox', '0 0 ' + W + ' ' + H);

        // Defs: gradients, filters, arrow markers
        var defs = svgEl('defs');

        // Glow filter
        var glow = svgEl('filter', { id: 'topoGlow', x: '-50%', y: '-50%', width: '200%', height: '200%' });
        var blur = svgEl('feGaussianBlur', { stdDeviation: '3', result: 'blur' });
        var merge = svgEl('feMerge');
        var mn1 = svgEl('feMergeNode', { in: 'blur' });
        var mn2 = svgEl('feMergeNode', { in: 'SourceGraphic' });
        merge.appendChild(mn1); merge.appendChild(mn2);
        glow.appendChild(blur); glow.appendChild(merge);
        defs.appendChild(glow);

        // Drop shadow filter
        var shadow = svgEl('filter', { id: 'topoShadow', x: '-20%', y: '-20%', width: '140%', height: '140%' });
        shadow.appendChild(svgEl('feDropShadow', { dx: '0', dy: '2', stdDeviation: '3', 'flood-color': '#000', 'flood-opacity': '0.4' }));
        defs.appendChild(shadow);

        svg.appendChild(defs);

        // Background (use inline style for CSS variable support)
        var bgRect = svgEl('rect', { width: W, height: H, rx: 12 });
        bgRect.style.fill = getComputedStyle(document.documentElement).getPropertyValue('--bg-card').trim() || '#1a2332';
        svg.appendChild(bgRect);

        // Draw curved paths between consecutive nodes
        var pathGroup = svgEl('g');
        var allPaths = [];
        for (var i = 0; i < positions.length - 1; i++) {
            var p1 = positions[i], p2 = positions[i + 1];
            var mx = (p1.x + p2.x) / 2;
            var my = centerY - 15 + Math.sin(i * 1.2) * 8;
            var d = 'M' + p1.x + ',' + p1.y + ' Q' + mx + ',' + my + ' ' + p2.x + ',' + p2.y;

            // Path glow
            var glowPath = svgEl('path', { d: d, stroke: latencyColor((p1.t + p2.t) / 2), 'stroke-width': 5, 'stroke-opacity': 0.15, fill: 'none', 'stroke-linecap': 'round' });
            pathGroup.appendChild(glowPath);

            // Main path
            var path = svgEl('path', { d: d, class: 'topo-path', stroke: latencyColor((p1.t + p2.t) / 2), 'stroke-opacity': 0.7 });
            allPaths.push(path);
            pathGroup.appendChild(path);

            // Animated dash overlay
            var dashPath = svgEl('path', { d: d, stroke: '#fff', 'stroke-width': 1, 'stroke-opacity': 0.2, fill: 'none', 'stroke-dasharray': '6 10', 'stroke-linecap': 'round' });
            var animDash = svgEl('animate', { attributeName: 'stroke-dashoffset', from: '16', to: '0', dur: (1.5 + i * 0.1) + 's', repeatCount: 'indefinite' });
            dashPath.appendChild(animDash);
            pathGroup.appendChild(dashPath);
        }
        svg.appendChild(pathGroup);

        // Animated particles along the first full path
        if (positions.length >= 2) {
            var fullD = 'M' + positions[0].x + ',' + positions[0].y;
            for (var i = 1; i < positions.length; i++) {
                var p1 = positions[i-1], p2 = positions[i];
                var mx = (p1.x + p2.x) / 2;
                var my = centerY - 15 + Math.sin((i-1) * 1.2) * 8;
                fullD += ' Q' + mx + ',' + my + ' ' + p2.x + ',' + p2.y;
            }
            var particlePath = svgEl('path', { id: 'topoFlowPath', d: fullD, fill: 'none', stroke: 'none' });
            svg.appendChild(particlePath);

            for (var pi = 0; pi < 3; pi++) {
                var circle = svgEl('circle', { r: 3, fill: '#60a5fa', filter: 'url(#topoGlow)', class: 'topo-particle' });
                var anim = svgEl('animateMotion', { dur: (2.5 + pi * 0.8) + 's', repeatCount: 'indefinite', begin: (pi * 0.8) + 's' });
                var mpath = svgEl('mpath', { href: '#topoFlowPath' });
                anim.appendChild(mpath);
                circle.appendChild(anim);
                svg.appendChild(circle);
            }
        }

        // Draw nodes
        var nodesGroup = svgEl('g');
        positions.forEach(function (pos, idx) {
            var g = svgEl('g', { class: 'topo-node-group', 'data-idx': idx });
            var col = latencyColor(pos.t);
            var hop = pos.hop;

            // Outer glow ring
            g.appendChild(svgEl('circle', { cx: pos.x, cy: pos.y, r: 22, fill: col, opacity: 0.12, class: 'topo-node-glow' }));

            // Node circle with shadow
            g.appendChild(svgEl('circle', { cx: pos.x, cy: pos.y, r: 16, fill: col, filter: 'url(#topoShadow)', class: 'topo-node-circle', stroke: 'rgba(255,255,255,0.15)', 'stroke-width': 2 }));

            // Inner highlight
            g.appendChild(svgEl('circle', { cx: pos.x - 3, cy: pos.y - 3, r: 5, fill: 'rgba(255,255,255,0.2)' }));

            // TTL inside
            var ttlText = svgEl('text', { x: pos.x, y: pos.y + 4, 'text-anchor': 'middle', fill: '#fff', 'font-size': '10', 'font-weight': '700', 'font-family': 'monospace', 'pointer-events': 'none' });
            ttlText.textContent = hop.ttl;
            g.appendChild(ttlText);

            // RTT above
            var rttText = svgEl('text', { x: pos.x, y: pos.y - 26, 'text-anchor': 'middle', fill: col, 'font-size': '11', 'font-weight': '700', 'font-family': 'monospace', class: 'topo-label-rtt' });
            rttText.textContent = Math.round(hop.avg_rtt_ns / 1e6) + 'ms';
            g.appendChild(rttText);

            // IP below
            var displayIP = hop.ip.length > 14 ? hop.ip.substring(0, 14) + '…' : hop.ip;
            var ipText = svgEl('text', { x: pos.x, y: pos.y + 34, 'text-anchor': 'middle', fill: '#94a3b8', 'font-size': '9', 'font-family': 'monospace' });
            ipText.textContent = displayIP;
            g.appendChild(ipText);

            // Hostname below IP
            if (hop.host) {
                var displayHost = hop.host.length > 16 ? hop.host.substring(0, 16) + '…' : hop.host;
                var hostText = svgEl('text', { x: pos.x, y: pos.y + 46, 'text-anchor': 'middle', fill: '#64748b', 'font-size': '8', class: 'topo-label-host' });
                hostText.textContent = displayHost;
                g.appendChild(hostText);
            }

            // Hover tooltip
            g.addEventListener('mouseenter', function (ev) {
                var rect = svg.getBoundingClientRect();
                var tipX = rect.left + (pos.x / W) * rect.width;
                var tipY = rect.top + (pos.y / H) * rect.height - 80;
                topoTooltip.innerHTML = '<b>Hop #' + hop.ttl + '</b><br>IP: ' + hop.ip + (hop.host ? '<br>Host: ' + hop.host : '') + '<br>RTT: ' + (hop.avg_rtt_ns / 1e6).toFixed(1) + 'ms' + '<br>Probes: ' + (hop.probes_reached || 0) + '/' + (hop.probes_sent || 3);
                topoTooltip.style.left = tipX + 'px';
                topoTooltip.style.top = tipY + 'px';
                topoTooltip.classList.add('show');
            });
            g.addEventListener('mouseleave', function () { topoTooltip.classList.remove('show'); });

            nodesGroup.appendChild(g);
        });
        svg.appendChild(nodesGroup);

        // Source label "YOU"
        var youText = svgEl('text', { x: positions[0].x, y: padT - 20, 'text-anchor': 'middle', class: 'topo-label-you' });
        youText.textContent = '📍 YOU';
        svg.appendChild(youText);

        // Target label
        var lastPos = positions[positions.length - 1];
        var tgtText = svgEl('text', { x: lastPos.x, y: padT - 20, 'text-anchor': 'middle', class: 'topo-label-target' });
        tgtText.textContent = '🎯 ' + (data.target || 'TARGET');
        svg.appendChild(tgtText);

        // Legend
        if (legendEl) {
            legendEl.innerHTML = '<span>Fast</span>' +
                '<div class="topo-legend-bar" style="background:linear-gradient(to right, rgb(34,197,94), rgb(225,179,38), rgb(239,68,68));"></div>' +
                '<span>Slow</span>' +
                '<span style="margin-left:16px;color:var(--text-muted);">Nodes: ' + hops.length + ' hops</span>' +
                '<span style="color:var(--text-muted);">Range: ' + Math.round(minRTT) + 'ms – ' + Math.round(maxRTT) + 'ms</span>';
        }
    }

    // ---- Tab Navigation ----
    (function() {
        var tabBtns = document.querySelectorAll('.tab-btn');
        if (!tabBtns.length) return;

        var tabMap = {
            'diagnose': ['.target-section', '.health-section', '.timeline-section', '.rootcause-section', '.chart-section', '.history-section'],
            'tools': ['.portscan-section', '.tls-section', '.traceroute-section', '.benchmark-section'],
            'monitor': ['.ping-section', '.healthmon-section', '.stress-section'],
            'intel': ['.power-section', '.api-section'],
            'sim': ['.simulator-section', '.lbsim-section']
        };

        function switchTab(tabName) {
            tabBtns.forEach(function(btn) {
                btn.classList.toggle('active', btn.dataset.tab === tabName);
            });

            // Hide all sections first
            Object.values(tabMap).forEach(function(selectors) {
                selectors.forEach(function(sel) {
                    var el = document.querySelector(sel);
                    if (el) el.style.display = 'none';
                });
            });

            // Show selected tab sections
            var selectors = tabMap[tabName];
            if (selectors) {
                selectors.forEach(function(sel) {
                    var el = document.querySelector(sel);
                    if (el) el.style.display = '';
                });
            }
        }

        tabBtns.forEach(function(btn) {
            btn.addEventListener('click', function() {
                switchTab(btn.dataset.tab);
            });
        });

        // Start on diagnose tab
        switchTab('diagnose');
    })();

    // ---- Continuous Health Monitor ----
    var hmInterval = null;
    var hmChartHistory = [];
    var btnHMStart = document.getElementById('btnHMStart');
    var btnHMStop = document.getElementById('btnHMStop');

    if (btnHMStart) {
        btnHMStart.addEventListener('click', startHealthMon);
    }
    if (btnHMStop) {
        btnHMStop.addEventListener('click', stopHealthMon);
    }
    // Enter key on host input
    var hmHostEl = document.getElementById('hmHost');
    if (hmHostEl) {
        hmHostEl.addEventListener('keydown', function (e) {
            if (e.key === 'Enter') startHealthMon();
        });
    }

    function startHealthMon() {
        var host = document.getElementById('hmHost').value.trim();
        if (!host) { alert('Enter a host to monitor'); return; }
        var port = document.getElementById('hmPort').value || '80';
        var interval = document.getElementById('hmInterval').value || '1000';
        var threshold = document.getElementById('hmThreshold').value || '500';

        hmChartHistory = [];
        document.getElementById('hmStats').style.display = '';
        document.getElementById('hmChartWrap').style.display = '';
        document.getElementById('hmAlerts').style.display = '';
        document.getElementById('hmStatusBar').style.display = '';
        btnHMStart.style.display = 'none';
        btnHMStop.style.display = '';

        // Start the monitor on the server
        fetch('/api/healthmon/start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                host: host,
                port: port,
                interval_ms: interval,
                spike_threshold_ms: threshold
            })
        })
        .then(function (r) { return r.json(); })
        .then(function (data) {
            logActivity('Health monitor started: ' + host + ':' + port, 'running');
        })
        .catch(function (e) {
            logActivity('Health monitor start failed: ' + e.message, 'fail');
        });

        // Poll every second for updates
        hmInterval = setInterval(function () {
            fetch('/api/healthmon?host=' + encodeURIComponent(host) + '&port=' + port)
                .then(function (r) { return r.json(); })
                .then(function (snap) { updateHealthMonUI(snap, host, port); })
                .catch(function () {});
        }, 1000);
    }

    function stopHealthMon() {
        if (hmInterval) { clearInterval(hmInterval); hmInterval = null; }
        var host = document.getElementById('hmHost').value.trim();
        var port = document.getElementById('hmPort').value || '80';
        fetch('/api/healthmon/stop', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ host: host, port: port })
        }).catch(function () {});
        btnHMStart.style.display = '';
        btnHMStop.style.display = 'none';
        var dot = document.getElementById('hmStatusDot');
        if (dot) dot.className = 'hm-status-dot stopped';
        var text = document.getElementById('hmStatusText');
        if (text) text.textContent = 'Stopped';
        logActivity('Health monitor stopped', 'ok');
    }

    function updateHealthMonUI(snap, host, port) {
        if (!snap) return;

        // Status bar
        var dot = document.getElementById('hmStatusDot');
        var text = document.getElementById('hmStatusText');
        var uptime = document.getElementById('hmUptime');
        if (dot) dot.className = 'hm-status-dot ' + (snap.status || 'stopped');
        if (text) text.textContent = snap.status_msg || snap.status || 'Unknown';
        if (uptime) {
            var secs = Math.floor(snap.uptime_sec || 0);
            var h = Math.floor(secs / 3600);
            var m = Math.floor((secs % 3600) / 60);
            var s = secs % 60;
            uptime.textContent = 'Uptime: ' + String(h).padStart(2, '0') + ':' + String(m).padStart(2, '0') + ':' + String(s).padStart(2, '0');
        }

        // Stats cards
        document.getElementById('hmProbes').textContent = snap.total_probes || 0;
        document.getElementById('hmSuccess').textContent = snap.success_count || 0;
        document.getElementById('hmLoss').textContent = (snap.loss_pct || 0).toFixed(1) + '%';
        document.getElementById('hmAvgRTT').textContent = (snap.avg_rtt_ms || 0).toFixed(1) + 'ms';
        document.getElementById('hmCurrentRTT').textContent = (snap.current_rtt_ms || 0).toFixed(1) + 'ms';
        document.getElementById('hmThresholdVal').textContent = (snap.threshold_ms || 0).toFixed(0) + 'ms';
        document.getElementById('hmSpikes').textContent = snap.spike_count || 0;
        document.getElementById('hmJitter').textContent = (snap.jitter_ms || 0).toFixed(1) + 'ms';

        // Color current RTT card based on spike
        var curCard = document.getElementById('hmCurrentRTT').parentElement;
        if (snap.current_rtt_ms > snap.threshold_ms && snap.total_probes > 5) {
            curCard.style.borderColor = 'var(--red)';
        } else {
            curCard.style.borderColor = '';
        }

        // Color loss card
        var lossEl = document.getElementById('hmLoss');
        if (snap.loss_pct > 10) { lossEl.parentElement.style.borderColor = 'var(--red)'; }
        else if (snap.loss_pct > 0) { lossEl.parentElement.style.borderColor = 'var(--yellow)'; }
        else { lossEl.parentElement.style.borderColor = ''; }

        // Chart history
        hmChartHistory.push({
            time: Date.now(),
            rtt: snap.current_rtt_ms || 0,
            threshold: snap.threshold_ms || 500,
            ok: (snap.current_rtt_ms || 0) <= (snap.threshold_ms || 500) || snap.total_probes <= 5
        });
        if (hmChartHistory.length > 120) hmChartHistory = hmChartHistory.slice(-120);
        drawHealthMonChart();

        // Spike alerts
        if (snap.recent_alerts && snap.recent_alerts.length > 0) {
            var alertCount = document.getElementById('hmAlertsCount');
            if (alertCount) alertCount.textContent = snap.spike_count + ' alerts';
            var alertList = document.getElementById('hmAlertsList');
            if (alertList) {
                alertList.innerHTML = '';
                var alerts = snap.recent_alerts.slice().reverse();
                alerts.forEach(function (a) {
                    var entry = document.createElement('div');
                    entry.className = 'hm-alert-entry';
                    var t = new Date(a.timestamp);
                    entry.innerHTML = '<span class="hm-alert-time">' + t.toLocaleTimeString() + '</span>' +
                        '<span class="hm-alert-val">' + a.rtt_ms.toFixed(1) + 'ms at #' + a.seq + '</span>' +
                        '<span class="hm-alert-threshold">threshold: ' + a.threshold_ms.toFixed(0) + 'ms</span>';
                    alertList.appendChild(entry);
                });
            }
        }
    }

    function drawHealthMonChart() {
        var canvas = document.getElementById('hmChart');
        if (!canvas || hmChartHistory.length < 2) return;
        var ctx = canvas.getContext('2d');
        var W = canvas.width;
        var H = canvas.height;
        ctx.clearRect(0, 0, W, H);

        var padding = { top: 15, bottom: 25, left: 50, right: 15 };
        var chartW = W - padding.left - padding.right;
        var chartH = H - padding.top - padding.bottom;

        var rtts = hmChartHistory.map(function (d) { return d.rtt; });
        var maxRTT = Math.max.apply(null, rtts);
        var maxThresh = Math.max.apply(null, hmChartHistory.map(function (d) { return d.threshold; }));
        var yMax = Math.max(maxRTT, maxThresh) * 1.2;
        if (yMax < 50) yMax = 50;

        // Grid lines
        ctx.strokeStyle = '#e5e7eb';
        ctx.lineWidth = 1;
        for (var i = 0; i <= 4; i++) {
            var y = padding.top + chartH * (1 - i / 4);
            ctx.beginPath();
            ctx.setLineDash([3, 3]);
            ctx.moveTo(padding.left, y);
            ctx.lineTo(W - padding.right, y);
            ctx.stroke();
            ctx.fillStyle = '#94a3b8';
            ctx.font = '10px monospace';
            ctx.textAlign = 'right';
            ctx.fillText(Math.round(yMax * i / 4) + 'ms', padding.left - 6, y + 3);
        }
        ctx.setLineDash([]);

        // Threshold line (dashed red)
        var threshVal = hmChartHistory[hmChartHistory.length - 1].threshold;
        var threshY = padding.top + chartH * (1 - threshVal / yMax);
        ctx.strokeStyle = '#ef4444';
        ctx.lineWidth = 1.5;
        ctx.setLineDash([6, 4]);
        ctx.beginPath();
        ctx.moveTo(padding.left, threshY);
        ctx.lineTo(W - padding.right, threshY);
        ctx.stroke();
        ctx.setLineDash([]);
        ctx.fillStyle = '#ef4444';
        ctx.font = '10px monospace';
        ctx.textAlign = 'left';
        ctx.fillText('threshold ' + threshVal.toFixed(0) + 'ms', W - padding.right - 110, threshY - 5);

        // Draw RTT line
        ctx.beginPath();
        ctx.strokeStyle = '#3b82f6';
        ctx.lineWidth = 2;
        var first = true;
        hmChartHistory.forEach(function (d, idx) {
            var x = padding.left + (idx / Math.max(hmChartHistory.length - 1, 1)) * chartW;
            var y = padding.top + chartH * (1 - Math.min(d.rtt, yMax) / yMax);
            if (first) { ctx.moveTo(x, y); first = false; } else { ctx.lineTo(x, y); }
        });
        ctx.stroke();

        // Gradient fill
        var gradient = ctx.createLinearGradient(0, padding.top, 0, padding.top + chartH);
        gradient.addColorStop(0, 'rgba(59, 130, 246, 0.15)');
        gradient.addColorStop(1, 'rgba(59, 130, 246, 0.02)');
        ctx.lineTo(padding.left + chartW, padding.top + chartH);
        ctx.lineTo(padding.left, padding.top + chartH);
        ctx.closePath();
        ctx.fillStyle = gradient;
        ctx.fill();

        // Draw spike dots (red for spikes, blue for normal)
        hmChartHistory.forEach(function (d, idx) {
            var x = padding.left + (idx / Math.max(hmChartHistory.length - 1, 1)) * chartW;
            var y = padding.top + chartH * (1 - Math.min(d.rtt, yMax) / yMax);
            ctx.beginPath();
            ctx.arc(x, y, d.ok ? 2 : 4, 0, Math.PI * 2);
            ctx.fillStyle = d.ok ? '#3b82f6' : '#ef4444';
            ctx.fill();
        });

        // Labels
        ctx.fillStyle = '#94a3b8';
        ctx.font = '10px sans-serif';
        ctx.textAlign = 'left';
        ctx.fillText('RTT (ms)', padding.left, padding.top - 4);
    }

    // ---- Advanced Intelligence Features ----

    // Feature 1: Packet Flow Diagram
    var btnPacketFlow = document.getElementById('btnPacketFlow');
    if (btnPacketFlow) {
        btnPacketFlow.addEventListener('click', function () {
            var target = document.getElementById('pfTarget').value.trim();
            if (!target) { alert('Enter a target'); return; }
            var port = document.getElementById('pfPort').value || '443';
            btnPacketFlow.disabled = true;
            btnPacketFlow.textContent = 'Tracing...';
            document.getElementById('pfResults').style.display = 'none';
            fetch('/api/packetflow?target=' + encodeURIComponent(target) + '&port=' + port)
                .then(function (r) { return r.json(); })
                .then(function (data) {
                    document.getElementById('pfResults').style.display = '';
                    renderPacketFlow(data);
                    logActivity('Packet flow traced: ' + target + ' — ' + (data.total_ms || 0).toFixed(1) + 'ms', data.success ? 'ok' : 'fail');
                })
                .catch(function (e) { logActivity('Packet flow failed: ' + e.message, 'fail'); })
                .then(function () { btnPacketFlow.disabled = false; btnPacketFlow.textContent = 'Trace Flow'; });
        });
    }
    function renderPacketFlow(data) {
        var timeline = document.getElementById('pfTimeline');
        var summary = document.getElementById('pfSummary');
        var html = '';
        if (data.steps) {
            data.steps.forEach(function (step, idx) {
                var cls = step.success ? 'ok' : (step.error ? 'fail' : 'warn');
                var ms = (step.duration_ns / 1e6).toFixed(1);
                var pct = data.total_ns > 0 ? (step.duration_ns / data.total_ns * 100).toFixed(0) : 0;
                html += '<div class="pf-step">';
                html += '<div class="pf-step-bar-container">';
                html += '<div class="pf-step-bar ' + cls + '"></div>';
                if (idx < data.steps.length - 1) html += '<div class="pf-step-connector"></div>';
                html += '</div>';
                html += '<div class="pf-step-content">';
                html += '<div class="pf-step-header">';
                html += '<span class="pf-step-label">' + escapeHtml(step.label) + '</span>';
                html += '<span class="pf-step-time ' + cls + '">' + ms + 'ms (' + pct + '%)</span>';
                html += '</div>';
                html += '<div class="pf-step-detail">' + escapeHtml(step.detail || step.error || step.description) + '</div>';
                if (step.sub_steps && step.sub_steps.length > 0) {
                    step.sub_steps.forEach(function (sub) {
                        html += '<div style="font-size:0.75rem;color:var(--text-muted);margin-top:2px;">↳ ' + escapeHtml(sub.label) + (sub.detail ? ': ' + escapeHtml(sub.detail) : '') + '</div>';
                    });
                }
                html += '</div></div>';
            });
        }
        timeline.innerHTML = html || '<p style="color:var(--text-muted);">No steps traced</p>';
        summary.innerHTML = '<strong>Total: ' + (data.total_ms || 0).toFixed(1) + 'ms</strong> — ' + escapeHtml(data.summary || '');
    }

    // Feature 2: Network Fingerprint
    var btnFP = document.getElementById('btnFingerprint');
    if (btnFP) {
        btnFP.addEventListener('click', function () {
            var target = document.getElementById('fpTarget').value.trim();
            if (!target) { alert('Enter a target'); return; }
            btnFP.disabled = true;
            btnFP.textContent = 'Fingerprinting...';
            document.getElementById('fpResults').style.display = 'none';
            fetch('/api/fingerprint?target=' + encodeURIComponent(target))
                .then(function (r) { return r.json(); })
                .then(function (data) {
                    document.getElementById('fpResults').style.display = '';
                    renderFingerprint(data);
                    logActivity('Fingerprinted: ' + target + ' — score: ' + (data.score || 0).toFixed(0), 'ok');
                })
                .catch(function (e) { logActivity('Fingerprint failed: ' + e.message, 'fail'); })
                .then(function () { btnFP.disabled = false; btnFP.textContent = 'Fingerprint'; });
        });
    }
    function renderFingerprint(data) {
        var scoreEl = document.getElementById('fpScore');
        var findingsEl = document.getElementById('fpFindings');
        var score = data.score || 0;
        var color = score > 70 ? 'var(--green)' : score > 40 ? 'var(--yellow)' : 'var(--red)';
        scoreEl.innerHTML = '<span style="font-size:1.2rem;font-weight:800;color:' + color + ';">' + score.toFixed(0) + '%</span> <span style="color:var(--text-muted);font-size:0.85rem;">confidence — ' + escapeHtml(data.summary || '') + '</span>';
        var html = '';
        if (data.findings) {
            data.findings.forEach(function (f) {
                var cat = (f.category || 'other').toLowerCase();
                html += '<div class="fp-finding">';
                html += '<span class="fp-badge ' + cat + '">' + escapeHtml(f.category) + '</span>';
                html += '<span class="fp-name">' + escapeHtml(f.name) + '</span>';
                html += '<span class="fp-evidence">' + escapeHtml(f.evidence) + '</span>';
                html += '<span class="fp-conf">' + (f.confidence * 100).toFixed(0) + '%</span>';
                html += '</div>';
            });
        }
        findingsEl.innerHTML = html || '<p style="color:var(--text-muted);">No infrastructure identified</p>';
    }

    // Feature 3: Diagnostic Diff
    var btnBaseline = document.getElementById('btnSetBaseline');
    var btnDiff = document.getElementById('btnDiff');
    if (btnBaseline) {
        btnBaseline.addEventListener('click', function () {
            var target = document.getElementById('diffTarget').value.trim();
            if (!target) { alert('Enter a target'); return; }
            btnBaseline.disabled = true;
            btnBaseline.textContent = 'Setting...';
            fetch('/api/baseline', {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target: target })
            })
            .then(function (r) { return r.json(); })
            .then(function (data) {
                logActivity('Baseline set for ' + target, 'ok');
                document.getElementById('diffResults').style.display = '';
                document.getElementById('diffResults').innerHTML = '<div style="padding:10px;background:#16653420;border:1px solid var(--green);border-radius:8px;color:var(--green);font-size:0.85rem;">✓ Baseline captured for ' + escapeHtml(target) + '. Click "Compare Now" later to see changes.</div>';
            })
            .catch(function (e) { logActivity('Baseline failed: ' + e.message, 'fail'); })
            .then(function () { btnBaseline.disabled = false; btnBaseline.textContent = '📌 Set Baseline'; });
        });
    }
    if (btnDiff) {
        btnDiff.addEventListener('click', function () {
            var target = document.getElementById('diffTarget').value.trim();
            if (!target) { alert('Enter a target'); return; }
            btnDiff.disabled = true;
            btnDiff.textContent = 'Comparing...';
            document.getElementById('diffResults').style.display = 'none';
            fetch('/api/diff?target=' + encodeURIComponent(target))
                .then(function (r) { return r.json(); })
                .then(function (data) {
                    document.getElementById('diffResults').style.display = '';
                    renderDiff(data);
                    logActivity('Diff for ' + target + ': ' + (data.overall_change || 'unknown'), 'ok');
                })
                .catch(function (e) { logActivity('Diff failed: ' + e.message, 'fail'); })
                .then(function () { btnDiff.disabled = false; btnDiff.textContent = '🔄 Compare Now'; });
        });
    }
    function renderDiff(data) {
        var el = document.getElementById('diffResults');
        var change = data.overall_change || 'unchanged';
        var scoreChange = data.score_change || 0;
        var sign = scoreChange > 0 ? '+' : '';
        var html = '<div class="diff-header ' + change + '">' + change.toUpperCase() + ' — Score: ' + sign + scoreChange + '</div>';
        html += '<div style="font-size:0.75rem;color:var(--text-muted);margin-bottom:6px;">Before: ' + (data.before_time || 'N/A') + ' → After: ' + (data.after_time || 'N/A') + '</div>';
        if (data.changes && data.changes.length > 0) {
            html += '<div class="diff-change" style="font-weight:700;color:var(--text-muted);font-size:0.75rem;"><span>Layer</span><span>Before</span><span></span><span>After</span><span>Impact</span></div>';
            data.changes.forEach(function (c) {
                html += '<div class="diff-change">';
                html += '<span class="diff-change-layer">' + escapeHtml(c.layer) + '</span>';
                html += '<span class="diff-change-before">' + escapeHtml(c.before) + '</span>';
                html += '<span style="color:var(--text-muted);">→</span>';
                html += '<span class="diff-change-after">' + escapeHtml(c.after) + '</span>';
                html += '<span class="diff-impact ' + c.impact + '">' + escapeHtml(c.impact) + '</span>';
                html += '</div>';
            });
        } else {
            html += '<p style="color:var(--text-muted);font-size:0.85rem;padding:8px;">No changes detected</p>';
        }
        el.innerHTML = html;
    }

    // Feature 4: Smart Correlation
    var btnCorr = document.getElementById('btnCorrelation');
    if (btnCorr) {
        btnCorr.addEventListener('click', function () {
            var target = document.getElementById('corrTarget').value.trim();
            if (!target) { alert('Enter a target'); return; }
            btnCorr.disabled = true;
            btnCorr.textContent = 'Analyzing...';
            document.getElementById('corrResults').style.display = 'none';
            fetch('/api/correlation?target=' + encodeURIComponent(target))
                .then(function (r) { return r.json(); })
                .then(function (data) {
                    document.getElementById('corrResults').style.display = '';
                    renderCorrelation(data);
                    logActivity('Correlation analyzed: ' + target, 'ok');
                })
                .catch(function (e) { logActivity('Correlation failed: ' + e.message, 'fail'); })
                .then(function () { btnCorr.disabled = false; btnCorr.textContent = 'Analyze Chain'; });
        });
    }
    function renderCorrelation(data) {
        var el = document.getElementById('corrResults');
        var corr = data.correlation || {};
        var rc = data.root_cause || {};
        var html = '<div class="corr-chain">';
        if (corr.chain) {
            corr.chain.forEach(function (link) {
                html += '<div class="corr-link">';
                html += '<span class="corr-num">' + link.step + '.</span>';
                html += '<span class="corr-layer">' + escapeHtml(link.layer) + '</span>';
                html += '<span class="corr-status ' + link.status + '">' + escapeHtml(link.status) + '</span>';
                html += '<span class="corr-latency">' + escapeHtml(link.latency) + '</span>';
                html += '<span class="corr-effect">' + escapeHtml(link.effect || '') + '</span>';
                html += '</div>';
            });
        }
        html += '</div>';
        var rootCls = corr.root_layer === 'none' ? 'healthy' : 'issue';
        html += '<div class="corr-root ' + rootCls + '"><strong>Root Layer: ' + escapeHtml(corr.root_layer || 'unknown') + '</strong> — ' + escapeHtml(corr.impact_description || '') + '</div>';
        if (rc.root_cause) {
            html += '<div style="margin-top:8px;padding:10px;background:var(--bg-card);border:1px solid var(--border);border-radius:8px;font-size:0.85rem;">';
            html += '<div style="font-weight:700;">🎯 ' + escapeHtml(rc.root_cause) + '</div>';
            html += '<div style="color:var(--text-muted);margin-top:4px;">Evidence: ' + escapeHtml(rc.evidence || '') + '</div>';
            html += '<div style="color:var(--accent);margin-top:4px;">→ ' + escapeHtml(rc.recommendation || '') + '</div>';
            html += '</div>';
        }
        el.innerHTML = html;
    }

    // Feature 5: Executive Report
    var btnRpt = document.getElementById('btnReport');
    if (btnRpt) {
        btnRpt.addEventListener('click', function () {
            var target = document.getElementById('rptTarget').value.trim();
            if (!target) { alert('Enter a target'); return; }
            btnRpt.disabled = true;
            btnRpt.textContent = 'Generating...';
            document.getElementById('rptStatus').style.display = 'none';
            window.location.href = '/api/report?target=' + encodeURIComponent(target);
            setTimeout(function () {
                btnRpt.disabled = false;
                btnRpt.textContent = '📥 Generate Report';
                var statusEl = document.getElementById('rptStatus');
                statusEl.style.display = '';
                statusEl.textContent = '✓ Report downloaded — open the HTML file in any browser to view.';
                logActivity('Report generated for ' + target, 'ok');
            }, 2000);
        });
    }

    // ---- Power Features ----

    // Network Overview
    var btnOverview = document.getElementById('btnOverview');
    if (btnOverview) {
        btnOverview.addEventListener('click', function () {
            var host = document.getElementById('overviewHost').value.trim();
            if (!host) { alert('Enter a host'); return; }
            btnOverview.disabled = true;
            btnOverview.textContent = 'Scanning...';
            document.getElementById('overviewResults').style.display = 'none';
            fetch('/api/overview?target=' + encodeURIComponent(host))
                .then(function (r) { return r.json(); })
                .then(function (data) {
                    document.getElementById('overviewResults').style.display = '';
                    document.getElementById('ovScore').textContent = data.summary ? data.summary.score : '—';
                    document.getElementById('ovOverall').textContent = data.summary ? data.summary.overall : '—';
                    document.getElementById('ovPorts').textContent = data.open_ports ? data.open_ports.length : 0;
                    document.getElementById('ovTCP').textContent = data.tcp && data.tcp.connected ? 'OK' : 'FAIL';
                    document.getElementById('ovHTTP').textContent = data.http && data.http.success ? 'OK ' + data.http.status_code : 'FAIL';
                    document.getElementById('ovBench').textContent = data.benchmark ? data.benchmark.grade : '—';
                    logActivity('Overview: ' + host + ' — Score: ' + (data.summary ? data.summary.score : '?'), 'ok');
                })
                .catch(function (e) { logActivity('Overview failed: ' + e.message, 'fail'); })
                .then(function () { btnOverview.disabled = false; btnOverview.textContent = 'Full Scan'; });
        });
    }

    // DNS Resolver Race
    var btnDNSRace = document.getElementById('btnDNSRace');
    if (btnDNSRace) {
        btnDNSRace.addEventListener('click', function () {
            var host = document.getElementById('dnsRaceHost').value.trim();
            if (!host) { alert('Enter a host'); return; }
            btnDNSRace.disabled = true;
            btnDNSRace.textContent = 'Racing...';
            document.getElementById('dnsRaceResults').style.display = 'none';
            fetch('/api/dnsrace?host=' + encodeURIComponent(host))
                .then(function (r) { return r.json(); })
                .then(function (data) {
                    document.getElementById('dnsRaceResults').style.display = '';
                    var winner = data.winner ? '🏆 Winner: ' + data.winner + ' (' + (data.fastest ? data.fastest.latency_ms.toFixed(1) : '?') + ' ms)' : 'No resolver succeeded';
                    document.getElementById('dnsRaceWinner').textContent = winner;
                    var html = '<table class="portscan-table" style="font-size:0.8rem;"><thead><tr><th>#</th><th>Name</th><th>Address</th><th>Latency</th><th>Status</th></tr></thead><tbody>';
                    (data.results || []).forEach(function (r) {
                        var cls = r.success ? 'open' : 'closed';
                        html += '<tr class="' + cls + '"><td>' + r.rank + '</td><td>' + r.name + '</td><td style="font-family:monospace;">' + r.address + '</td><td>' + r.latency_ms.toFixed(1) + ' ms</td><td>' + (r.success ? '✓' : '✗') + '</td></tr>';
                    });
                    html += '</tbody></table>';
                    document.getElementById('dnsRaceTable').innerHTML = html;
                    logActivity('DNS Race: ' + host + ' — Winner: ' + (data.winner || 'none'), 'ok');
                })
                .catch(function (e) { logActivity('DNS Race failed: ' + e.message, 'fail'); })
                .then(function () { btnDNSRace.disabled = false; btnDNSRace.textContent = 'Start Race'; });
        });
    }

    // Speed Test
    var btnSpeedTest = document.getElementById('btnSpeedTest');
    if (btnSpeedTest) {
        btnSpeedTest.addEventListener('click', function () {
            btnSpeedTest.disabled = true;
            btnSpeedTest.textContent = 'Testing...';
            document.getElementById('speedResults').style.display = 'none';
            fetch('/api/speedtest?rounds=5')
                .then(function (r) { return r.json(); })
                .then(function (data) {
                    document.getElementById('speedResults').style.display = '';
                    document.getElementById('speedGrade').textContent = data.grade || '—';
                    document.getElementById('speedAvg').textContent = data.avg_speed_mbps ? data.avg_speed_mbps.toFixed(1) + ' Mbps' : '—';
                    document.getElementById('speedMax').textContent = data.max_speed_mbps ? data.max_speed_mbps.toFixed(1) + ' Mbps' : '—';
                    document.getElementById('speedJitter').textContent = data.jitter_mbps ? data.jitter_mbps.toFixed(1) + ' Mbps' : '—';
                    document.getElementById('speedLatency').textContent = data.avg_latency_ms ? data.avg_latency_ms.toFixed(1) + ' ms' : '—';
                    document.getElementById('speedLoss').textContent = data.packet_loss_pct ? data.packet_loss_pct.toFixed(1) + '%' : '0%';
                    logActivity('Speed test: Grade=' + data.grade + ' Avg=' + (data.avg_speed_mbps || 0).toFixed(1) + ' Mbps', 'ok');
                })
                .catch(function (e) { logActivity('Speed test failed: ' + e.message, 'fail'); })
                .then(function () { btnSpeedTest.disabled = false; btnSpeedTest.textContent = 'Run Speed Test'; });
        });
    }

    // WHOIS Lookup
    var btnWhois = document.getElementById('btnWhois');
    if (btnWhois) {
        btnWhois.addEventListener('click', function () {
            var domain = document.getElementById('whoisDomain').value.trim();
            if (!domain) { alert('Enter a domain'); return; }
            btnWhois.disabled = true;
            btnWhois.textContent = 'Looking up...';
            document.getElementById('whoisResults').style.display = 'none';
            fetch('/api/whois?domain=' + encodeURIComponent(domain))
                .then(function (r) { return r.json(); })
                .then(function (data) {
                    document.getElementById('whoisResults').style.display = '';
                    var html = '';
                    var fields = [
                        ['Domain', data.domain], ['Registrar', data.registrar],
                        ['Registered', data.registration_date], ['Expires', data.expiration_date],
                        ['Updated', data.updated_date], ['Name Servers', data.name_servers],
                        ['Status', data.status], ['Country', data.country],
                        ['DNSSEC', data.dnssec], ['Response', data.raw_length + ' bytes']
                    ];
                    fields.forEach(function (f) {
                        if (f[1]) html += '<div style="display:flex;gap:8px;padding:4px 0;border-bottom:1px solid var(--border);"><span style="font-weight:600;min-width:100px;color:var(--text-muted);">' + f[0] + '</span><span>' + escapeHtml(f[1]) + '</span></div>';
                    });
                    if (data.error) html += '<div style="color:var(--red);padding:8px 0;">Error: ' + escapeHtml(data.error) + '</div>';
                    document.getElementById('whoisData').innerHTML = html || '<p style="color:var(--text-muted);">No data found</p>';
                    logActivity('WHOIS: ' + domain + (data.registrar ? ' — ' + data.registrar : ''), 'ok');
                })
                .catch(function (e) { logActivity('WHOIS failed: ' + e.message, 'fail'); })
                .then(function () { btnWhois.disabled = false; btnWhois.textContent = 'Lookup'; });
        });
    }

    // Multi-Target Scan
    var btnMultiScan = document.getElementById('btnMultiScan');
    if (btnMultiScan) {
        btnMultiScan.addEventListener('click', function () {
            var hosts = document.getElementById('multiScanHosts').value.trim();
            if (!hosts) { alert('Enter hosts to scan'); return; }
            btnMultiScan.disabled = true;
            btnMultiScan.textContent = 'Scanning...';
            document.getElementById('multiScanResults').style.display = 'none';
            fetch('/api/multiscan?hosts=' + encodeURIComponent(hosts))
                .then(function (r) { return r.json(); })
                .then(function (data) {
                    document.getElementById('multiScanResults').style.display = '';
                    var tbody = document.getElementById('multiScanBody');
                    tbody.innerHTML = '';
                    (data.targets || []).forEach(function (t) {
                        var tr = document.createElement('tr');
                        var cls = t.overall === 'healthy' ? 'open' : 'closed';
                        tr.className = cls;
                        var dnsStatus = t.dns && t.dns.success ? '✓' : '✗';
                        var tcpStatus = t.tcp && t.tcp.connected ? '✓' : '✗';
                        var httpStatus = t.http && t.http.success ? '✓' : '✗';
                        tr.innerHTML = '<td>' + escapeHtml(t.host) + '</td><td>' + t.score + '</td><td>' + t.overall + '</td><td>' + dnsStatus + '</td><td>' + tcpStatus + '</td><td>' + httpStatus + '</td><td>' + t.open_ports + '</td>';
                        tbody.appendChild(tr);
                    });
                    logActivity('Multi-scan: ' + (data.targets ? data.targets.length : 0) + ' hosts — ' + (data.healthy || 0) + ' healthy', 'ok');
                })
                .catch(function (e) { logActivity('Multi-scan failed: ' + e.message, 'fail'); })
                .then(function () { btnMultiScan.disabled = false; btnMultiScan.textContent = 'Scan All'; });
        });
    }

    // ---- Copy as cURL ----
    window.copyCurl = function (path) {
        var url = window.location.origin + path;
        var curl = 'curl -s "' + url + '"';
        var el = document.getElementById('curlCopied');
        function showCopied() {
            if (el) {
                el.style.display = '';
                setTimeout(function () { el.style.display = 'none'; }, 2000);
            }
            logActivity('Copied cURL: ' + path, 'ok');
        }
        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(curl).then(showCopied).catch(function () {
                copyFallback(curl);
                showCopied();
            });
        } else {
            copyFallback(curl);
            showCopied();
        }
    };
    function copyFallback(text) {
        var ta = document.createElement('textarea');
        ta.value = text;
        ta.style.cssText = 'position:fixed;left:-9999px;';
        document.body.appendChild(ta);
        ta.select();
        try { document.execCommand('copy'); } catch (e) { /* ignore */ }
        document.body.removeChild(ta);
    }

    // ---- roundRect polyfill ----
    if (!CanvasRenderingContext2D.prototype.roundRect) {
        CanvasRenderingContext2D.prototype.roundRect = function (x, y, w, h, radii) {
            var r = radii;
            if (typeof r === 'number') r = [r, r, r, r];
            this.moveTo(x + r[0], y);
            this.lineTo(x + w - r[1], y);
            this.arcTo(x + w, y, x + w, y + r[1], r[1]);
            this.lineTo(x + w, y + h - r[2]);
            this.arcTo(x + w, y + h, x + w - r[2], y + h, r[2]);
            this.lineTo(x + r[3], y + h);
            this.arcTo(x, y + h, x, y + h - r[3], r[3]);
            this.lineTo(x, y + r[0]);
            this.arcTo(x, y, x + r[0], y, r[0]);
            this.closePath();
        };
    }

})();
