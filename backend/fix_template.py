import os

html_code = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PhishShield Enterprise Glass SOC</title>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;600;700;800&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        :root {
            --bg-gradient: linear-gradient(135deg, #0f172a 0%, #1e1b4b 50%, #311042 100%);
            --glass-bg: rgba(255, 255, 255, 0.05);
            --glass-border: rgba(255, 255, 255, 0.12);
            --glass-hover: rgba(255, 255, 255, 0.09);
            --neon-blue: #38bdf8;
            --neon-purple: #c084fc;
            --neon-red: #f43f5e;
            --neon-green: #34d399;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
        }

        * { margin: 0; padding: 0; box-sizing: border-box; font-family: "Plus Jakarta Sans", sans-serif; }
        body { background: var(--bg-gradient); color: var(--text-main); min-height: 100vh; overflow-x: hidden; padding: 24px; }
        
        .background-blobs { position: fixed; top: 0; left: 0; width: 100vw; height: 100vh; z-index: -1; overflow: hidden; pointer-events: none; }
        .blob { position: absolute; filter: blur(100px); opacity: 0.35; border-radius: 50%; }
        .blob-1 { width: 500px; height: 500px; background: #6366f1; top: -100px; left: -100px; }
        .blob-2 { width: 550px; height: 550px; background: #d946ef; bottom: -150px; right: -100px; }

        .container { max-width: 1400px; margin: 0 auto; display: grid; grid-template-columns: 1fr; gap: 24px; }
        
        header {
            background: var(--glass-bg); backdrop-filter: blur(16px); -webkit-backdrop-filter: blur(16px);
            border: 1px solid var(--glass-border); border-radius: 20px; padding: 20px 30px;
            display: flex; justify-content: space-between; align-items: center; box-shadow: 0 8px 32px rgba(0,0,0,0.37);
        }
        .brand { display: flex; align-items: center; gap: 14px; }
        .brand i { font-size: 28px; color: var(--neon-blue); }
        .brand h1 { font-size: 22px; font-weight: 800; letter-spacing: -0.5px; background: linear-gradient(to right, #38bdf8, #c084fc); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        
        .badge-live { display: flex; align-items: center; gap: 8px; background: rgba(52, 211, 153, 0.1); border: 1px solid rgba(52, 211, 153, 0.3); padding: 6px 14px; border-radius: 20px; color: var(--neon-green); font-size: 13px; font-weight: 600; }
        .pulse { width: 8px; height: 8px; background: var(--neon-green); border-radius: 50%; box-shadow: 0 0 10px var(--neon-green); animation: pulse 1.5s infinite; }

        @keyframes pulse { 0% { opacity: 0.4; } 50% { opacity: 1; } 100% { opacity: 0.4; } }

        .scan-card {
            background: var(--glass-bg); backdrop-filter: blur(20px); -webkit-backdrop-filter: blur(20px);
            border: 1px solid var(--glass-border); border-radius: 24px; padding: 36px; box-shadow: 0 8px 32px rgba(0,0,0,0.37);
        }
        .scan-card h2 { font-size: 20px; margin-bottom: 8px; font-weight: 700; }
        .scan-card p { color: var(--text-muted); font-size: 14px; margin-bottom: 24px; }

        .input-group { display: flex; gap: 12px; position: relative; }
        .input-group i { position: absolute; left: 18px; top: 50%; transform: translateY(-50%); color: var(--text-muted); font-size: 18px; }
        .input-group input {
            width: 100%; background: rgba(15, 23, 42, 0.6); border: 1px solid var(--glass-border);
            border-radius: 14px; padding: 16px 20px 16px 50px; color: #fff; font-size: 15px; outline: none; transition: all 0.3s ease;
        }
        .input-group input:focus { border-color: var(--neon-blue); box-shadow: 0 0 20px rgba(56, 189, 248, 0.2); }
        
        .btn-scan {
            background: linear-gradient(135deg, #38bdf8 0%, #6366f1 100%); color: #fff; border: none;
            padding: 16px 32px; border-radius: 14px; font-weight: 700; font-size: 15px; cursor: pointer;
            transition: all 0.3s ease; display: flex; align-items: center; gap: 10px; white-space: nowrap;
        }
        .btn-scan:hover { transform: translateY(-2px); box-shadow: 0 10px 25px rgba(99, 102, 241, 0.4); }

        .result-panel {
            display: none; margin-top: 24px; background: rgba(15, 23, 42, 0.7); border: 1px solid var(--glass-border);
            border-radius: 18px; padding: 24px; animation: fadeIn 0.4s ease;
        }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }

        .result-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 18px; }
        .verdict-tag { font-size: 18px; font-weight: 800; padding: 8px 18px; border-radius: 12px; letter-spacing: 0.5px; }
        .verdict-safe { background: rgba(52, 211, 153, 0.15); color: var(--neon-green); border: 1px solid var(--neon-green); }
        .verdict-suspicious { background: rgba(251, 191, 36, 0.15); color: #fbbf24; border: 1px solid #fbbf24; }
        .verdict-malicious { background: rgba(244, 63, 94, 0.15); color: var(--neon-red); border: 1px solid var(--neon-red); }
        
        .metrics-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-top: 16px; }
        .metric-box { background: var(--glass-bg); border: 1px solid var(--glass-border); border-radius: 12px; padding: 14px 18px; }
        .metric-box label { font-size: 12px; color: var(--text-muted); display: block; margin-bottom: 4px; text-transform: uppercase; font-weight: 600; }
        .metric-box span { font-size: 16px; font-weight: 700; color: #fff; }

        .dashboard-grid { display: grid; grid-template-columns: 2fr 1fr; gap: 24px; }
        @media (max-width: 1024px) { .dashboard-grid { grid-template-columns: 1fr; } }

        .table-card {
            background: var(--glass-bg); backdrop-filter: blur(20px); -webkit-backdrop-filter: blur(20px);
            border: 1px solid var(--glass-border); border-radius: 24px; padding: 28px; box-shadow: 0 8px 32px rgba(0,0,0,0.37);
        }
        .table-card h3 { font-size: 18px; margin-bottom: 18px; display: flex; align-items: center; gap: 10px; }
        
        table { width: 100%; border-collapse: collapse; }
        th { text-align: left; padding: 12px 16px; color: var(--text-muted); font-size: 12px; text-transform: uppercase; border-bottom: 1px solid var(--glass-border); }
        td { padding: 14px 16px; font-size: 13px; border-bottom: 1px solid rgba(255,255,255,0.05); }
        tr:hover { background: var(--glass-hover); }

        .sidebar-card {
            background: var(--glass-bg); backdrop-filter: blur(20px); -webkit-backdrop-filter: blur(20px);
            border: 1px solid var(--glass-border); border-radius: 24px; padding: 28px;
            display: flex; flex-direction: column; gap: 20px;
        }
        .tier-item { display: flex; align-items: center; justify-content: space-between; padding: 12px 0; border-bottom: 1px solid rgba(255,255,255,0.05); }
        .tier-info { display: flex; align-items: center; gap: 12px; }
        .tier-info i { font-size: 18px; color: var(--neon-blue); }

        .analytics-box {
            background: rgba(15, 23, 42, 0.4); border: 1px solid var(--glass-border);
            border-radius: 16px; padding: 16px; display: flex; justify-content: space-around; text-align: center;
        }
        .stat-num { font-size: 20px; font-weight: 800; color: var(--neon-blue); }
        .stat-label { font-size: 11px; color: var(--text-muted); text-transform: uppercase; margin-top: 2px; }
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
                <i class="fa-solid fa-shield-halved"></i>
                <h1>PhishShield Enterprise Glass SOC</h1>
            </div>
            <div class="badge-live">
                <div class="pulse"></div>
                3-TIER ENGINE ACTIVE
            </div>
        </header>

        <div class="scan-card">
            <h2>Real-Time Threat Intelligence Inspection</h2>
            <p>Analyze links through Whitelist Gatekeeper, SHA-256 Redis Cache, and Tri-Voting Ensemble NLP Engine.</p>
            
            <div class="input-group">
                <i class="fa-solid fa-globe"></i>
                <input type="text" id="urlInput" placeholder="Paste target URL for analysis (e.g. http://paypa1-security-center.account-verification-dispatch.info)">
                <button class="btn-scan" onclick="analyzeURL()">
                    <i class="fa-solid fa-bolt"></i> Inspect Threat
                </button>
            </div>

            <div class="result-panel" id="resultPanel">
                <div class="result-header">
                    <div>
                        <span style="font-size: 13px; color: var(--text-muted);">Target URL:</span>
                        <div id="resURL" style="font-weight: 700; word-break: break-all; margin-top: 2px;"></div>
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
                        <tr><td colspan="5" style="text-align: center; color: var(--text-muted);">Loading live logs...</td></tr>
                    </tbody>
                </table>
            </div>

            <div class="sidebar-card">
                <h3 style="font-size: 18px;"><i class="fa-solid fa-chart-pie" style="color: var(--neon-blue);"></i> SOC Metrics</h3>
                
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
                        <div class="stat-num" style="color: var(--neon-green);" id="statLatency">0 ms</div>
                        <div class="stat-label">Avg Latency</div>
                    </div>
                </div>

                <h3 style="font-size: 18px; margin-top: 10px;"><i class="fa-solid fa-microchip" style="color: var(--neon-purple);"></i> Detection Tiers</h3>
                
                <div class="tier-item">
                    <div class="tier-info">
                        <i class="fa-solid fa-bolt"></i>
                        <div>
                            <strong style="font-size: 14px; display: block;">Tier-3 Whitelist</strong>
                            <span style="font-size: 12px; color: var(--text-muted);">Enterprise Gatekeeper</span>
                        </div>
                    </div>
                    <span style="font-size: 12px; color: var(--neon-green); font-weight: 700;">&lt; 0.1 ms</span>
                </div>

                <div class="tier-item">
                    <div class="tier-info">
                        <i class="fa-solid fa-database"></i>
                        <div>
                            <strong style="font-size: 14px; display: block;">Tier-1 Redis Cache</strong>
                            <span style="font-size: 12px; color: var(--text-muted);">SHA-256 Memory Lookup</span>
                        </div>
                    </div>
                    <span style="font-size: 12px; color: var(--neon-green); font-weight: 700;">&lt; 0.5 ms</span>
                </div>

                <div class="tier-item">
                    <div class="tier-info">
                        <i class="fa-solid fa-brain"></i>
                        <div>
                            <strong style="font-size: 14px; display: block;">Tier-2 Ensemble NLP</strong>
                            <span style="font-size: 12px; color: var(--text-muted);">Tri-Voting Classifier</span>
                        </div>
                    </div>
                    <span style="font-size: 12px; color: var(--neon-blue); font-weight: 700;">~ 12 ms</span>
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
                    if (log.verdict === 'SUSPICIOUS') color = '#fbbf24';
                    if (log.verdict === 'MALICIOUS') color = 'var(--neon-red)';

                    row.innerHTML = `
                        <td>#${log.id}</td>
                        <td style="max-width: 280px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${log.url}</td>
                        <td><span style="color: ${color}; font-weight: 700;">${log.verdict}</span></td>
                        <td>${log.source}</td>
                        <td>${log.latency}</td>
                    `;
                    tbody.appendChild(row);
                });

                const analyticsRes = await fetch("/api/v1/stats");
                const stats = await analyticsRes.json();
                document.getElementById("statTotal").innerText = stats.total_scans;
                document.getElementById("statMalicious").innerText = stats.malicious_detected;
                document.getElementById("statLatency").innerText = typeof stats.avg_latency === 'number' ? stats.avg_latency + ' ms' : stats.avg_latency;
            } catch(e) {}
        }

        loadLogs();
        setInterval(loadLogs, 4000);
    </script>
</body>
</html>"""

os.makedirs("app/templates", exist_ok=True)
with open("app/templates/index.html", "w") as f:
    f.write(html_code)

print("[+] Successfully wrote app/templates/index.html without syntax errors!")
