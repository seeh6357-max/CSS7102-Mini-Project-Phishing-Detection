import os

os.makedirs("app", exist_ok=True)
os.makedirs("app/templates", exist_ok=True)
os.makedirs("app/static", exist_ok=True)

# 1. train_model.py (Voting Ensemble Trainer)
with open("train_model.py", "w") as f:
    f.write('''import os
import math
import numpy as np
import pandas as pd
from Levenshtein import distance as lev_distance
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, VotingClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.base import BaseEstimator, TransformerMixin
import joblib

class LexicalFeatureExtractor(BaseEstimator, TransformerMixin):
    def __init__(self):
        self.target_brands = ["paypal", "google", "microsoft", "apple", "amazon", "bankofamerica", "netflix", "presidencyuniversity", "facebook", "instagram", "linkedin"]

    def calculate_entropy(self, text: str) -> float:
        if not text:
            return 0.0
        prob = [float(text.count(c)) / len(text) for c in set(text)]
        return -sum([p * math.log(p, 2) for p in prob])

    def min_brand_distance(self, domain: str) -> int:
        if not domain:
            return 999
        distances = [lev_distance(domain, brand) for brand in self.target_brands]
        return min(distances) if distances else 999

    def fit(self, X, y=None):
        return self

    def transform(self, X):
        features = []
        for url in X:
            url_str = str(url).lower()
            url_length = len(url_str)
            num_digits = sum(c.isdigit() for c in url_str)
            digit_ratio = num_digits / url_length if url_length > 0 else 0
            
            num_special = sum(not c.isalnum() for c in url_str)
            special_ratio = num_special / url_length if url_length > 0 else 0
            
            num_subdomains = url_str.count(".") - 1
            has_ip = 1 if any(char.isdigit() for char in url_str.split("/")[0]) and url_str.count(".") == 3 else 0
            
            entropy = self.calculate_entropy(url_str)
            domain = url_str.split("://")[-1].split("/")[0]
            brand_dist = self.min_brand_distance(domain)

            suspicious_tlds = [".xyz", ".top", ".tk", ".site", ".online", ".info", ".club"]
            has_suspicious_tld = 1 if any(url_str.endswith(tld) or tld + "/" in url_str for tld in suspicious_tlds) else 0

            features.append([
                url_length, digit_ratio, special_ratio, num_subdomains, has_ip, entropy, brand_dist, has_suspicious_tld
            ])
        return np.array(features)

def train_and_export():
    print("[*] Training Tier-2 Voting Ensemble Model...")
    data = {
        "url": [
            "https://www.google.com", "https://www.github.com", "https://www.wikipedia.org",
            "https://www.microsoft.com", "https://www.amazon.com", "https://www.presidencyuniversity.in",
            "https://stackoverflow.com", "https://www.python.org", "https://fastapi.tiangolo.com",
            "https://redis.io", "https://scikit-learn.org", "https://www.linkedin.com",
            "https://portal.presidencyuniversity.in/student/dashboard", "https://docs.python.org/3/library/index.html",
            "http://login.paypal.com.account-verify.secure-update.xyz/login.php",
            "http://secure-bankofamerica.update-login-credential.com/auth",
            "http://account-google-security-verify.temp-web.net/signin",
            "http://appleid.apple.com.verify.account.info-security.top/id",
            "http://192.168.1.1/login.php?update=true&user=admin",
            "http://free-crypto-giveaway-claim-now.site/claim",
            "http://secure.signin.amazon.com-check.tk/auth",
            "http://verify-identity-netflix-payment.support-now.online/billing",
            "http://paypa1-security-center.account-verification-dispatch.info",
            "http://presidency-university-exam-fee-portal.pay-online.tk"
        ],
        "label": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]
    }

    df = pd.DataFrame(data)
    os.makedirs("dataset", exist_ok=True)
    df.to_csv("dataset/phishing_urls.csv", index=False)

    X = df["url"]
    y = df["label"]

    char_vec = TfidfVectorizer(analyzer="char", ngram_range=(3, 5), max_features=800)
    word_vec = TfidfVectorizer(analyzer="word", ngram_range=(1, 2), max_features=400)
    lexical_extractor = LexicalFeatureExtractor()

    X_char = char_vec.fit_transform(X).toarray()
    X_word = word_vec.fit_transform(X).toarray()
    X_lexical = lexical_extractor.transform(X)
    
    scaler = StandardScaler()
    X_lexical_scaled = scaler.fit_transform(X_lexical)
    X_combined = np.hstack((X_char, X_word, X_lexical_scaled))

    rf = RandomForestClassifier(n_estimators=100, random_state=42)
    gb = GradientBoostingClassifier(n_estimators=100, random_state=42)
    
    ensemble = VotingClassifier(estimators=[("rf", rf), ("gb", gb)], voting="soft")
    ensemble.fit(X_combined, y)

    os.makedirs("app", exist_ok=True)
    joblib.dump(char_vec, "app/char_vec.pkl")
    joblib.dump(word_vec, "app/word_vec.pkl")
    joblib.dump(scaler, "app/scaler.pkl")
    joblib.dump(ensemble, "app/model.pkl")
    print("[+] Advanced Ensemble Artifacts Exported Successfully!")

if __name__ == "__main__":
    train_and_export()
''')

# 2. app/nlp_engine.py
with open("app/nlp_engine.py", "w") as f:
    f.write('''import joblib
import os
import math
import numpy as np
from Levenshtein import distance as lev_distance

class AdvancedNLPEngine:
    def __init__(self):
        char_path = "app/char_vec.pkl"
        word_path = "app/word_vec.pkl"
        scaler_path = "app/scaler.pkl"
        model_path = "app/model.pkl"
        self.target_brands = ["paypal", "google", "microsoft", "apple", "amazon", "bankofamerica", "netflix", "presidencyuniversity", "facebook", "instagram", "linkedin"]
        
        if os.path.exists(char_path) and os.path.exists(word_path) and os.path.exists(scaler_path) and os.path.exists(model_path):
            self.char_vec = joblib.load(char_path)
            self.word_vec = joblib.load(word_path)
            self.scaler = joblib.load(scaler_path)
            self.model = joblib.load(model_path)
            self.ready = True
            print("[+] Tier-2 Advanced Voting Ensemble NLP Engine Online.")
        else:
            self.ready = False
            print("[-] NLP Engine Error: Missing Model Artifacts.")

    def _calculate_entropy(self, text: str) -> float:
        if not text:
            return 0.0
        prob = [float(text.count(c)) / len(text) for c in set(text)]
        return -sum([p * math.log(p, 2) for p in prob])

    def _extract_lexical_features(self, url: str):
        url_str = url.lower()
        url_length = len(url_str)
        num_digits = sum(c.isdigit() for c in url_str)
        digit_ratio = num_digits / url_length if url_length > 0 else 0
        
        num_special = sum(not c.isalnum() for c in url_str)
        special_ratio = num_special / url_length if url_length > 0 else 0
        
        num_subdomains = url_str.count(".") - 1
        has_ip = 1 if any(char.isdigit() for char in url_str.split("/")[0]) and url_str.count(".") == 3 else 0
        
        entropy = self._calculate_entropy(url_str)
        domain = url_str.split("://")[-1].split("/")[0]
        distances = [lev_distance(domain, brand) for brand in self.target_brands]
        brand_dist = min(distances) if distances else 999

        suspicious_tlds = [".xyz", ".top", ".tk", ".site", ".online", ".info", ".club"]
        has_suspicious_tld = 1 if any(url_str.endswith(tld) or tld + "/" in url_str for tld in suspicious_tlds) else 0

        return np.array([[
            url_length, digit_ratio, special_ratio, num_subdomains, has_ip, entropy, brand_dist, has_suspicious_tld
        ]])

    def predict(self, url: str):
        if not self.ready:
            return "UNKNOWN", 0.0

        char_feat = self.char_vec.transform([url]).toarray()
        word_feat = self.word_vec.transform([url]).toarray()
        lex_feat = self._extract_lexical_features(url)
        lex_scaled = self.scaler.transform(lex_feat)

        combined_features = np.hstack((char_feat, word_feat, lex_scaled))
        prob = self.model.predict_proba(combined_features)[0][1]
        
        if prob >= 0.75:
            verdict = "MALICIOUS"
        elif prob >= 0.45:
            verdict = "SUSPICIOUS"
        else:
            verdict = "SAFE"

        return verdict, round(float(prob), 4)
''')

# 3. app/database.py
with open("app/database.py", "w") as f:
    f.write('''import sqlite3
import os
from datetime import datetime

class AuditLogger:
    def __init__(self, db_path="app/audit_logs.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                verdict TEXT NOT NULL,
                source TEXT NOT NULL,
                risk_score REAL NOT NULL,
                latency_ms REAL NOT NULL,
                timestamp TEXT NOT NULL
            )
        """)
        conn.commit()
        conn.close()

    def log_scan(self, url: str, verdict: str, source: str, risk_score: float, latency_ms: float):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO scan_logs (url, verdict, source, risk_score, latency_ms, timestamp)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (url, verdict, source, risk_score, latency_ms, datetime.utcnow().isoformat()))
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[-] Database Error: {e}")

    def get_recent_logs(self, limit=15):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT id, url, verdict, source, risk_score, latency_ms, timestamp FROM scan_logs ORDER BY id DESC LIMIT ?", (limit,))
            rows = cursor.fetchall()
            conn.close()
            return rows
        except Exception:
            return []
''')

# 4. Glassmorphic UI (app/templates/index.html)
with open("app/templates/index.html", "w") as f:
    f.write('''<!DOCTYPE html>
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
        body { background: var(--bg-gradient); color: var(--text-main); min-height: 100vh; overflow-x: hidden; padding: 20px; }
        
        .background-blobs { position: fixed; top: 0; left: 0; width: 100vw; height: 100vh; z-index: -1; overflow: hidden; }
        .blob { position: absolute; filter: blur(90px); opacity: 0.4; border-radius: 50%; }
        .blob-1 { width: 450px; height: 450px; background: #6366f1; top: -100px; left: -100px; }
        .blob-2 { width: 500px; height: 500px; background: #d946ef; bottom: -150px; right: -100px; }

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
        }
        .tier-item { display: flex; align-items: center; justify-content: space-between; padding: 14px 0; border-bottom: 1px solid rgba(255,255,255,0.05); }
        .tier-info { display: flex; align-items: center; gap: 12px; }
        .tier-info i { font-size: 18px; color: var(--neon-blue); }
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
                3-TIER ENGINE LIVE
            </div>
        </header>

        <div class="scan-card">
            <h2>Real-Time Zero-Day URL Threat Inspection</h2>
            <p>Analyze incoming links via Enterprise Whitelist, SHA-256 Redis Cache, and Composite Voting Ensemble NLP.</p>
            
            <div class="input-group">
                <i class="fa-solid fa-globe"></i>
                <input type="text" id="urlInput" placeholder="Paste target URL for analysis (e.g. http://paypa1-security-update.xyz)">
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
                <h3><i class="fa-solid fa-list-check" style="color: var(--neon-purple);"></i> Real-Time Audit Log Database</h3>
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
                <h3 style="font-size: 18px; margin-bottom: 18px;"><i class="fa-solid fa-microchip" style="color: var(--neon-blue);"></i> Active Intelligence Tiers</h3>
                
                <div class="tier-item">
                    <div class="tier-info">
                        <i class="fa-solid fa-bolt"></i>
                        <div>
                            <strong style="font-size: 14px; display: block;">Tier-3 Whitelist</strong>
                            <span style="font-size: 12px; color: var(--text-muted);">Top 1M & Corporate Domains</span>
                        </div>
                    </div>
                    <span style="font-size: 12px; color: var(--neon-green); font-weight: 700;">< 0.1 ms</span>
                </div>

                <div class="tier-item">
                    <div class="tier-info">
                        <i class="fa-solid fa-database"></i>
                        <div>
                            <strong style="font-size: 14px; display: block;">Tier-1 Redis Cache</strong>
                            <span style="font-size: 12px; color: var(--text-muted);">SHA-256 Memory Lookup</span>
                        </div>
                    </div>
                    <span style="font-size: 12px; color: var(--neon-green); font-weight: 700;">< 0.5 ms</span>
                </div>

                <div class="tier-item">
                    <div class="tier-info">
                        <i class="fa-solid fa-brain"></i>
                        <div>
                            <strong style="font-size: 14px; display: block;">Tier-2 Ensemble NLP</strong>
                            <span style="font-size: 12px; color: var(--text-muted);">Voting RF + Gradient Boosting</span>
                        </div>
                    </div>
                    <span style="font-size: 12px; color: var(--neon-blue); font-weight: 700;">~ 15 ms</span>
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
                verdictElem.className = "verdict-tag " + (data.verdict === "SAFE" ? "verdict-safe" : "verdict-malicious");

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
                    const isSafe = log.verdict === "SAFE";
                    row.innerHTML = `
                        <td>#${log.id}</td>
                        <td style="max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${log.url}</td>
                        <td><span style="color: ${isSafe ? 'var(--neon-green)' : 'var(--neon-red)'}; font-weight: 700;">${log.verdict}</span></td>
                        <td>${log.source}</td>
                        <td>${log.latency}</td>
                    `;
                    tbody.appendChild(row);
                });
            } catch(e) {}
        }

        loadLogs();
        setInterval(loadLogs, 5000);
    </script>
</body>
</html>
''')

# 5. app/main.py (FastAPI Server with Web UI)
with open("app/main.py", "w") as f:
    f.write('''import time
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from app.redis_cache import RedisCacheManager
from app.nlp_engine import AdvancedNLPEngine
from app.whitelist import EnterpriseWhitelistGatekeeper
from app.database import AuditLogger

app = FastAPI(
    title="Real-Time Phishing Detection Engine",
    version="3.0",
    description="Multi-Tier Glassmorphic Threat Intelligence Framework"
)

templates = Jinja2Templates(directory="app/templates")

cache = RedisCacheManager()
nlp = AdvancedNLPEngine()
whitelist = EnterpriseWhitelistGatekeeper()
logger = AuditLogger()

class URLRequest(BaseModel):
    url: str

@app.get("/", response_class=HTMLResponse)
def serve_ui(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/api/v1/logs")
def get_audit_logs():
    raw_logs = logger.get_recent_logs(10)
    formatted = []
    for r in raw_logs:
        formatted.append({
            "id": r[0],
            "url": r[1],
            "verdict": r[2],
            "source": r[3],
            "risk_score": r[4],
            "latency": f"{r[5]} ms",
            "timestamp": r[6]
        })
    return formatted

@app.post("/api/v1/check-url")
def analyze_url(payload: URLRequest):
    start_time = time.time()
    url = payload.url.strip()

    if not url:
        raise HTTPException(status_code=400, detail="Invalid URL payload")

    if whitelist.is_whitelisted(url):
        execution_time = round((time.time() - start_time) * 1000, 3)
        logger.log_scan(url, "SAFE", "Tier-3 Enterprise Whitelist", 0.0, execution_time)
        return {
            "url": url,
            "verdict": "SAFE",
            "source": "Tier-3 Enterprise Whitelist",
            "risk_score": 0.0,
            "latency": f"{execution_time} ms"
        }

    cached = cache.get_verdict(url)
    if cached:
        execution_time = round((time.time() - start_time) * 1000, 3)
        risk_score = float(cached.get("risk_score", 1.0 if cached.get("verdict") == "MALICIOUS" else 0.0))
        logger.log_scan(url, cached.get("verdict"), "Tier-1 Redis Threat Cache", risk_score, execution_time)
        return {
            "url": url,
            "verdict": cached.get("verdict"),
            "source": "Tier-1 Redis Threat Cache",
            "risk_score": risk_score,
            "latency": f"{execution_time} ms"
        }

    verdict, risk_score = nlp.predict(url)
    execution_time = round((time.time() - start_time) * 1000, 3)

    ttl = 86400 if verdict == "MALICIOUS" else (3600 if verdict == "SUSPICIOUS" else 43200)
    cache.set_verdict(url, verdict, risk_score, ttl=ttl)
    logger.log_scan(url, verdict, "Tier-2 Advanced NLP Engine", risk_score, execution_time)

    return {
        "url": url,
        "verdict": verdict,
        "source": "Tier-2 Advanced Lexical-NLP Engine",
        "risk_score": risk_score,
        "latency": f"{execution_time} ms"
    }
''')

print("[+] setup_3.py created successfully inside backend!")
