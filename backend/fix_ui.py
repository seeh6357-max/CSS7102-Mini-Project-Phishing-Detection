import os

html_content = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PhishShield Enterprise Glass SOC</title>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        :root {
            --bg-dark: #070913;
            --glass-card: rgba(15, 23, 42, 0.65);
            --glass-border: rgba(255, 255, 255, 0.12);
            --glass-hover: rgba(255, 255, 255, 0.08);
            --neon-cyan: #38bdf8;
            --neon-purple: #a855f7;
            --neon-pink: #ec4899;
            --neon-green: #10b981;
            --neon-red: #f43f5e;
            --neon-amber: #f59e0b;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --text-dim: #64748b;
        }

        * { margin: 0; padding: 0; box-sizing: border-box; font-family: "Plus Jakarta Sans", sans-serif; }
        
        body {
            background-color: var(--bg-dark);
            background-image: 
                radial-gradient(at 0% 0%, rgba(56, 189, 248, 0.15) 0px, transparent 50%),
                radial-gradient(at 100% 0%, rgba(168, 85, 247, 0.15) 0px, transparent 50%),
                radial-gradient(at 50% 100%, rgba(236, 72, 153, 0.1) 0px, transparent 50%);
            background-attachment: fixed;
            color: var(--text-main);
            min-height: 100vh;
            padding: 28px;
            overflow-x: hidden;
        }

        .container {
            max-width: 1440px;
            margin: 0 auto;
            display: flex;
            flex-direction: column;
            gap: 28px;
        }

        /* Top Header Navigation */
        header {
            background: var(--glass-card);
            backdrop-filter: blur(20px);
            -webkit-backdrop-filter: blur(20px);
            border: 1px solid var(--glass-border);
            border-radius: 20px;
            padding: 18px 32px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            box-shadow: 0 20px 50px rgba(0, 0, 0, 0.5);
        }

        .brand { display: flex; align-items: center; gap: 16px; }
        .brand-icon {
            width: 44px; height: 44px;
            background: linear-gradient(135deg, var(--neon-cyan), var(--neon-purple));
            border-radius: 12px;
            display: flex; align-items: center; justify-content: center;
            font-size: 22px; color: #fff;
            box-shadow: 0 0 20px rgba(56, 189, 248, 0.4);
        }
        .brand h1 {
            font-size: 22px; font-weight: 800; letter-spacing: -0.5px;
            background: linear-gradient(to right, #38bdf8, #c084fc, #f43f5e);
            -webkit-background-clip: text; -webkit-text-fill-color: transparent;
        }

        .badge-live {
            display: flex; align-items: center; gap: 10px;
            background: rgba(16, 185, 129, 0.12);
            border: 1px solid rgba(16, 185, 129, 0.3);
            padding: 8px 18px; border-radius: 30px;
            color: var(--neon-green); font-size: 13px; font-weight: 700;
            letter-spacing: 0.5px;
        }
        .pulse {
            width: 9px; height: 9px;
            background: var(--neon-green); border-radius: 50%;
            box-shadow: 0 0 12px var(--neon-green);
            animation: pulse 1.6s infinite;
        }
        @keyframes pulse { 0%, 100% { opacity: 0.3; transform: scale(0.9); } 50% { opacity: 1; transform: scale(1.2); } }

        /* Main Inspection Card */
        .scan-card {
            background: var(--glass-card);
            backdrop-filter: blur(24px);
            -webkit-backdrop-filter: blur(24px);
            border: 1px solid var(--glass-border);
            border-radius: 24px;
            padding: 36px;
            box-shadow: 0 20px 50px rgba(0,0,0,0.4);
            position: relative; overflow: hidden;
        }
        .scan-card::before {
            content: ''; position: absolute; top: 0; left: 0; right: 0; height: 2px;
            background: linear-gradient(90deg, var(--neon-cyan), var(--neon-purple), var(--neon-pink));
        }

        .scan-card h2 { font-size: 22px; font-weight: 800; margin-bottom: 6px; }
        .scan-card p { color: var(--text-muted); font-size: 14px; margin-bottom: 28px; }

        .input-group {
            display: flex; gap: 14px; position: relative; width: 100%;
        }
        .input-wrapper {
            position: relative; flex: 1; display: flex; align-items: center;
        }
        .input-wrapper i {
            position: absolute; left: 20px; color: var(--neon-cyan); font-size: 18px;
        }
        .input-wrapper input {
            width: 100%;
            background: rgba(7, 9, 19, 0.7);
            border: 1px solid var(--glass-border);
            border-radius: 16px;
            padding: 18px 24px 18px 54px;
            color: #fff; font-size: 15px; font-family: 'JetBrains Mono', monospace;
            outline: none; transition: all 0.3s ease;
        }
        .input-wrapper input:focus {
            border-color: var(--neon-cyan);
            box-shadow: 0 0 25px rgba(56, 189, 248, 0.25);
            background: rgba(7, 9, 19, 0.9);
        }

        .btn-scan {
            background: linear-gradient(135deg, #38bdf8 0%, #6366f1 50%, #a855f7 100%);
            color: #fff; border: none; padding: 0 36px;
            border-radius: 16px; font-weight: 700; font-size: 15px;
            cursor: pointer; transition: all 0.3s ease;
            display: flex; align-items: center; gap: 10px; white-space: nowrap;
            box-shadow: 0 8px 25px rgba(99, 102, 241, 0.35);
        }
        .btn-scan:hover {
            transform: translateY(-2px);
            box-shadow: 0 12px 30px rgba(168, 85, 247, 0.5);
        }

        /* Result Panel */
        .result-panel {
            display: none; margin-top: 28px;
            background: rgba(7, 9, 19, 0.8);
            border: 1px solid var(--glass-border);
            border-radius: 20px; padding: 28px;
            animation: slideDown 0.4s cubic-bezier(0.16, 1, 0.3, 1);
        }
        @keyframes slideDown { from { opacity: 0; transform: translateY(-12px); } to { opacity: 1; transform: translateY(0); } }

        .result-header {
            display: flex; justify-content: space-between; align-items: center;
            padding-bottom: 20px; border-bottom: 1px solid var(--glass-border);
        }
        .verdict-tag {
            font-size: 16px; font-weight: 800; padding: 10px 24px;
            border-radius: 14px; letter-spacing: 1px; text-transform: uppercase;
        }
        .verdict-safe { background: rgba(16, 185, 129, 0.15); color: var(--neon-green); border: 1px solid var(--neon-green); box-shadow: 0 0 20px rgba(16, 185, 129, 0.2); }
        .verdict-suspicious { background: rgba(245, 158, 11, 0.15); color: var(--neon-amber); border: 1px solid var(--neon-amber); box-shadow: 0 0 20px rgba(245, 158, 11, 0.2); }
        .verdict-malicious { background: rgba(244, 63, 94, 0.15); color: var(--neon-red); border: 1px solid var(--neon-red); box-shadow: 0 0 20px rgba(244, 63, 94, 0.2); }

        .metrics-grid {
            display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 18px; margin-top: 20px;
        }
        .metric-box {
            background: var(--glass-card); border: 1px solid var(--glass-border);
            border-radius: 14px; padding: 16px 20px;
        }
        .metric-box label { font-size: 11px; color: var(--text-dim); display: block; margin-bottom: 6px; text-transform: uppercase; font-weight: 700; letter-spacing: 0.5px; }
        .metric-box span { font-size: 18px; font-weight: 800; color: #fff; font-family: 'JetBrains Mono', monospace; }

        /* Dashboard Grid Layout */
        .dashboard-grid { display: grid; grid-template-columns: 2.2fr 1fr; gap: 28px; }
        @media (max-width: 1024px) { .dashboard-grid { grid-template-columns: 1fr; } }

        /* Table Section */
        .table-card {
            background: var(--glass-card); backdrop-filter: blur(24px);
            -webkit-backdrop-filter: blur(24px); border: 1px solid var(--glass-border);
            border-radius: 24px; padding: 32px; box-shadow: 0 20px 50px rgba(0,0,0,0.4);
        }
        .table-card h3 { font-size: 18px; font-weight: 800; margin-bottom: 22px; display: flex; align-items: center; gap: 12px; }

        table { width: 100%; border-collapse: collapse; }
        th { text-align: left; padding: 14px 18px; color: var(--text-dim); font-size: 11px; text-transform: uppercase; font-weight: 700; letter-spacing: 0.8px; border-bottom: 1px solid var(--glass-border); }
        td { padding: 16px 18px; font-size: 13px; border-bottom: 1px solid rgba(255,255,255,0.04); }
        tr:hover { background: var(--glass-hover); }

        .url-cell { font-family: 'JetBrains Mono', monospace; color: var(--text-muted); max-width: 320px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

        /* Sidebar Section */
        .sidebar-card {
            background: var(--glass-card); backdrop-filter: blur(24px);
            -webkit-backdrop-filter: blur(24px); border: 1px solid var(--glass-border);
            border-radius: 24px; padding: 32px; display: flex; flex-direction: column; gap: 24px;
            box-shadow: 0 20px 50px rgba(0,0,0,0.4);
        }
        .sidebar-card h3 { font-size: 18px; font-weight: 800; display: flex; align-items: center; gap: 12px; }

        .analytics-box {
            background: rgba(7, 9, 19, 0.7); border: 1px solid var(--glass-border);
            border-radius: 18px; padding: 20px; display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; text-align: center;
        }
        .stat-num { font-size: 22px; font-weight: 800; color: var(--neon-cyan); font-family: 'JetBrains Mono', monospace; }
        .stat-label { font-size: 10px; color: var(--text-dim); text-transform: uppercase; font-weight: 700; margin-top: 4px; letter-spacing: 0.5px; }

        .tier-item {
            display: flex; align-items: center; justify-content: space-between;
            padding: 16px 0; border-bottom: 1px solid rgba(255,255,255,0.05);
        }
        .tier-info { display: flex; align-items: center; gap: 14px; }
        .tier-icon {
            width: 38px; height: 38px; border-radius: 10px;
            background: rgba(56, 189, 248, 0.1); border: 1px solid rgba(56, 189, 248, 0.2);
            display: flex; align-items: center; justify-content: center;
            color: var(--neon-cyan); font-size: 16px;
        }
    </style>
</head>
<body>
    <div class="background-blobs">
        <div class="blob blob-1"></div>
        <div class="blob blob-2"></div>
    </div>

    <div class="container">
        <header>
            <div class="brand">
                <div class="brand-icon"><i class="fa-solid fa-shield-halved"></i></div>
                <div>
                    <h1>PhishShield Enterprise Glass SOC</h1>
                </div>
            </div>
            <div class="badge-live">
                <div class="pulse"></div>
                3-TIER ENGINE LIVE
            </div>
        </header>

        <div class="scan-card">
            <h2>Real-Time Zero-Day Threat Inspection</h2>
            <p>Analyze target links via Whitelist Gatekeeper, SHA-256 Redis Memory Cache, and Tri-Voting Ensemble NLP Engine.</p>
            
            <div class="input-group">
                <div class="input-wrapper">
                    <i class="fa-solid fa-globe"></i>
                    <input type="text" id="urlInput" placeholder="Paste target URL for analysis (e.g. http://paypa1-security-center.account-verification-dispatch.info)">
                </div>
                <button class="btn-scan" onclick="analyzeURL()">
                    <i class="fa-solid fa-bolt"></i> Inspect Threat
                </button>
            </div>

            <div class="result-panel" id="resultPanel">
                <div class="result-header">
                    <div>
                        <span style="font-size: 12px; color: var(--text-dim); text-transform: uppercase; font-weight: 700;">Target URL</span>
                        <div id="resURL" style="font-weight: 700; word-break: break-all; margin-top: 4px; font-family: 'JetBrains Mono', monospace;"></div>
                    </div>
                    <div id="resVerdict" class="verdict-tag"></div>
                </div>

                <div class="metrics-grid">
                    <div class="metric-box">
                        <label>Detection Source</label>
                        <span id="resSource">-</span>
                    </div>
                    <div class="metric-box">
                        <label>Threat Risk Score</label>
                        <span id="resScore">-</span>
                    </div>
                    <div class="metric-box">
                        <label>Execution Latency</label>
                        <span id="resLatency">-</span>
                    </div>
                </div>
            </div>
        </div>

        <div class="dashboard-grid">
            <div class="table-card">
                <h3><i class="fa-solid fa-list-check" style="color: var(--neon-purple);"></i> Real-Time Audit Log Feed</h3>
                <table>
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Target URL</th>
                            <th>Verdict</th>
                            <th>Source Tier</th>
                            <th>Latency</th>
                        </tr>
                    </thead>
                    <tbody id="logsBody">
                        <tr><td colspan="5" style="text-align: center; color: var(--text-muted); padding: 24px;">Loading live telemetry...</td></tr>
                    </tbody>
                </table>
            </div>

            <div class="sidebar-card">
                <h3><i class="fa-solid fa-chart-pie" style="color: var(--neon-cyan);"></i> SOC Telemetry</h3>
                
                <div class="analytics-box">
                    <div>
                        <div class="stat-num" id="statTotal">0</div>
                        <div class="stat-label">Total Scans</div>
                    </div>
                    <div>
                        <div class="stat-num" style="color: var(--neon-red);" id="statMalicious">0</div>
                        <div class="stat-label">Threats</div>
                    </div>
                    <div>
                        <div class="stat-num" style="color: var(--neon-green);" id="statLatency">0.0 ms</div>
                        <div class="stat-label">Avg Latency</div>
                    </div>
                </div>

                <h3 style="margin-top: 8px;"><i class="fa-solid fa-microchip" style="color: var(--neon-purple);"></i> Active Tiers</h3>
                
                <div class="tier-item">
                    <div class="tier-info">
                        <div class="tier-icon"><i class="fa-solid fa-bolt"></i></div>
                        <div>
                            <strong style="font-size: 14px; display: block;">Tier-3 Whitelist</strong>
                            <span style="font-size: 12px; color: var(--text-muted);">Enterprise Gatekeeper</span>
                        </div>
                    </div>
                    <span style="font-size: 12px; color: var(--neon-green); font-weight: 700; font-family: 'JetBrains Mono', monospace;">&lt; 0.1 ms</span>
                </div>

                <div class="tier-item">
                    <div class="tier-info">
                        <div class="tier-icon" style="color: var(--neon-purple); border-color: rgba(168, 85, 247, 0.2); background: rgba(168, 85, 247, 0.1);"><i class="fa-solid fa-database"></i></div>
                        <div>
                            <strong style="font-size: 14px; display: block;">Tier-1 Redis Cache</strong>
                            <span style="font-size: 12px; color: var(--text-muted);">SHA-256 Memory Lookup</span>
                        </div>
                    </div>
                    <span style="font-size: 12px; color: var(--neon-green); font-weight: 700; font-family: 'JetBrains Mono', monospace;">&lt; 0.5 ms</span>
                </div>

                <div class="tier-item">
                    <div class="tier-info">
                        <div class="tier-icon" style="color: var(--neon-pink); border-color: rgba(236, 72, 153, 0.2); background: rgba(236, 72, 153, 0.1);"><i class="fa-solid fa-brain"></i></div>
                        <div>
                            <strong style="font-size: 14px; display: block;">Tier-2 Ensemble NLP</strong>
                            <span style="font-size: 12px; color: var(--text-muted);">Tri-Voting Classifier</span>
                        </div>
                    </div>
                    <span style="font-size: 12px; color: var(--neon-cyan); font-weight: 700; font-family: 'JetBrains Mono', monospace;">~ 12 ms</span>
                </div>
            </div>
        </div>
    </div>

    <script>
        async function analyzeURL() {
            const url = document.getElementById("urlInput").value.trim();
            if(!url) return;

            const btn = document.querySelector(".btn-scan");
            btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Inspecting...';

            try {
                const response = await fetch("/api/v1/check-url", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ url: url })
                });
                const data = await response.json();

                document.getElementById("resURL").innerText = data.url;
                document.getElementById("resSource").innerText = data.source;
                document.getElementById("resScore").innerText = (data.risk_score * 100).toFixed(1) + "%";
                document.getElementById("resLatency").innerText = data.latency;

                const verdictElem = document.getElementById("resVerdict");
                verdictElem.innerText = data.verdict;
                
                if (data.verdict === "SAFE") {
                    verdictElem.className = "verdict-tag verdict-safe";
                } else if (data.verdict === "SUSPICIOUS") {
                    verdictElem.className = "verdict-tag verdict-suspicious";
                } else {
                    verdictElem.className = "verdict-tag verdict-malicious";
                }

                document.getElementById("resultPanel").style.display = "block";
                loadLogs();
            } catch (err) {
                alert("API Server Connection Error!");
            } finally {
                btn.innerHTML = '<i class="fa-solid fa-bolt"></i> Inspect Threat';
            }
        }

        async function loadLogs() {
            try {
                const response = await fetch("/api/v1/logs");
                const logs = await response.json();
                
                const tbody = document.getElementById("logsBody");
                tbody.innerHTML = "";

                logs.forEach(log => {
                    const row = document.createElement("tr");
                    let color = 'var(--neon-green)';
                    if (log.verdict === 'SUSPICIOUS') color = 'var(--neon-amber)';
                    if (log.verdict === 'MALICIOUS') color = 'var(--neon-red)';

                    row.innerHTML = `
                        <td style="font-family: 'JetBrains Mono', monospace; font-weight: 600; color: var(--text-dim);">#${log.id}</td>
                        <td class="url-cell">${log.url}</td>
                        <td><span style="color: ${color}; font-weight: 800; letter-spacing: 0.5px;">${log.verdict}</span></td>
                        <td style="color: var(--text-muted); font-size: 12px;">${log.source}</td>
                        <td style="font-family: 'JetBrains Mono', monospace; font-size: 12px; color: var(--neon-cyan);">${log.latency}</td>
                    `;
                    tbody.appendChild(row);
                });

                const analyticsRes = await fetch("/api/v1/stats");
                const stats = await analyticsRes.json();
                document.getElementById("statTotal").innerText = stats.total_scans || 0;
                document.getElementById("statMalicious").innerText = stats.malicious_detected || stats.malicious_count || 0;
                document.getElementById("statLatency").innerText = (stats.avg_latency_ms || stats.avg_latency || 0) + ' ms';
            } catch(e) {}
        }

        loadLogs();
        setInterval(loadLogs, 4000);
    </script>
</body>
</html>"""

os.makedirs("app/templates", exist_ok=True)
with open("app/templates/index.html", "w") as f:
    f.write(html_content)

print("[+] Successfully updated app/templates/index.html!")
