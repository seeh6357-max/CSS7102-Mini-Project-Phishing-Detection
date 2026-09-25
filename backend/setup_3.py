import os

# ==============================================================================
# Enterprise Phishing Threat Intelligence Framework - Master Setup Script
# Creates complete multi-tiered detection system architecture
# ==============================================================================

os.makedirs("app", exist_ok=True)
os.makedirs("app/templates", exist_ok=True)
os.makedirs("app/static", exist_ok=True)
os.makedirs("dataset", exist_ok=True)
os.makedirs("artifacts", exist_ok=True)

# ------------------------------------------------------------------------------
# 1. Configuration Module (app/config.py)
# ------------------------------------------------------------------------------
with open("app/config.py", "w") as f:
    f.write('''import os

class Settings:
    PROJECT_NAME: str = "PhishShield Enterprise Glass SOC"
    VERSION: str = "3.5.0"
    API_V1_PREFIX: str = "/api/v1"
    
    # Model & Artifact Paths
    ARTIFACTS_DIR: str = "artifacts"
    CHAR_VEC_PATH: str = os.path.join(ARTIFACTS_DIR, "char_vec.pkl")
    WORD_VEC_PATH: str = os.path.join(ARTIFACTS_DIR, "word_vec.pkl")
    SCALER_PATH: str = os.path.join(ARTIFACTS_DIR, "scaler.pkl")
    MODEL_PATH: str = os.path.join(ARTIFACTS_DIR, "model.pkl")
    
    # Cache Settings
    REDIS_HOST: str = os.getenv("REDIS_HOST", "localhost")
    REDIS_PORT: int = int(os.getenv("REDIS_PORT", 6379))
    REDIS_DB: int = int(os.getenv("REDIS_DB", 0))
    REDIS_PASSWORD: str = os.getenv("REDIS_PASSWORD", "")
    DEFAULT_CACHE_TTL: int = 86400  # 24 Hours
    
    # Database Settings
    DB_PATH: str = "app/audit_logs.db"
    
    # Detection Thresholds
    HIGH_RISK_THRESHOLD: float = 0.75
    MEDIUM_RISK_THRESHOLD: float = 0.45

settings = Settings()
''')

# ------------------------------------------------------------------------------
# 2. Advanced Feature Extractor (app/lexical_extractor.py)
# ------------------------------------------------------------------------------
with open("app/lexical_extractor.py", "w") as f:
    f.write('''import math
import re
import numpy as np
from urllib.parse import urlparse
from Levenshtein import distance as lev_distance
from sklearn.base import BaseEstimator, TransformerMixin

TARGET_BRANDS = [
    "paypal", "google", "microsoft", "apple", "amazon", "bankofamerica", 
    "netflix", "facebook", "instagram", "linkedin", "presidencyuniversity",
    "chase", "wellsfargo", "dropbox", "github", "twitter", "binance", 
    "coinbase", "adobe", "steam", "spotify", "standardchartered", "hdfcbank"
]

SUSPICIOUS_TLDS = [
    ".xyz", ".top", ".tk", ".site", ".online", ".info", ".club", 
    ".work", ".click", ".buzz", ".cc", ".cf", ".ga", ".gq", ".ml", ".icu"
]

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "account", "secure", "banking", "confirm",
    "signin", "support", "service", "billing", "credential", "security", "free",
    "bonus", "claim", "wallet", "dispatched", "suspended", "action-required"
]

class LexicalFeatureExtractor(BaseEstimator, TransformerMixin):
    def __init__(self):
        self.target_brands = TARGET_BRANDS
        self.suspicious_tlds = SUSPICIOUS_TLDS
        self.suspicious_keywords = SUSPICIOUS_KEYWORDS

    def calculate_entropy(self, text: str) -> float:
        if not text:
            return 0.0
        prob = [float(text.count(c)) / len(text) for c in set(text)]
        return -sum([p * math.log(p, 2) for p in prob])

    def min_brand_distance(self, domain: str) -> int:
        if not domain:
            return 999
        clean_domain = domain.split(".")[0]
        distances = [lev_distance(clean_domain, brand) for brand in self.target_brands]
        return min(distances) if distances else 999

    def has_ip_address(self, netloc: str) -> int:
        ip_pattern = r'^(\\d{1,3}\\.){3}\\d{1,3}(:\\d+)?$'
        return 1 if re.match(ip_pattern, netloc) else 0

    def detect_homoglyphs(self, domain: str) -> int:
        return 1 if "xn--" in domain.lower() else 0

    def extract_features_single(self, url: str) -> list:
        url_str = str(url).lower().strip()
        parsed = urlparse(url_str if "://" in url_str else "http://" + url_str)
        
        domain = parsed.netloc
        path = parsed.path
        query = parsed.query
        
        url_length = len(url_str)
        domain_length = len(domain)
        path_length = len(path)
        
        num_digits = sum(c.isdigit() for c in url_str)
        digit_ratio = num_digits / url_length if url_length > 0 else 0
        
        num_special = sum(not c.isalnum() for c in url_str)
        special_ratio = num_special / url_length if url_length > 0 else 0
        
        num_subdomains = max(0, domain.count(".") - 1)
        has_ip = self.has_ip_address(domain)
        has_punycode = self.detect_homoglyphs(domain)
        
        overall_entropy = self.calculate_entropy(url_str)
        domain_entropy = self.calculate_entropy(domain)
        
        brand_dist = self.min_brand_distance(domain)
        has_suspicious_tld = 1 if any(domain.endswith(tld) for tld in self.suspicious_tlds) else 0
        
        keyword_matches = sum(1 for kw in self.suspicious_keywords if kw in url_str)
        has_at_symbol = 1 if "@" in url_str else 0
        is_https = 1 if parsed.scheme == "https" else 0
        has_double_slash = 1 if "//" in path else 0
        query_param_count = len(query.split("&")) if query else 0

        return [
            url_length, domain_length, path_length, digit_ratio, special_ratio,
            num_subdomains, has_ip, has_punycode, overall_entropy, domain_entropy,
            brand_dist, has_suspicious_tld, keyword_matches, has_at_symbol,
            is_https, has_double_slash, query_param_count
        ]

    def fit(self, X, y=None):
        return self

    def transform(self, X):
        features = [self.extract_features_single(url) for url in X]
        return np.array(features)
''')

# ------------------------------------------------------------------------------
# 3. Model Trainer & Artifact Generator (train_model.py)
# ------------------------------------------------------------------------------
with open("train_model.py", "w") as f:
    f.write('''import os
import joblib
import numpy as np
import pandas as pd
from scipy.sparse import hstack
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, ExtraTreesClassifier, VotingClassifier
from sklearn.preprocessing import StandardScaler
from app.lexical_extractor import LexicalFeatureExtractor
from app.config import settings

def generate_synthetic_dataset():
    benign_urls = [
        "https://www.google.com", "https://www.github.com", "https://www.wikipedia.org",
        "https://www.microsoft.com", "https://www.amazon.com", "https://www.presidencyuniversity.in",
        "https://stackoverflow.com", "https://www.python.org", "https://fastapi.tiangolo.com",
        "https://redis.io", "https://scikit-learn.org", "https://www.linkedin.com",
        "https://portal.presidencyuniversity.in/student/dashboard", "https://docs.python.org/3/library/index.html",
        "https://aws.amazon.com/console/", "https://drive.google.com/drive/my-drive",
        "https://developer.mozilla.org/en-US/docs/Web", "https://pypi.org/project/joblib/",
        "https://www.cloudflare.com/network/", "https://www.sciencedirect.com/journal/cybersecurity",
        "https://arxiv.org/abs/2301.00001", "https://www.nytimes.com/section/technology",
        "https://medium.com/topic/cybersecurity", "https://chat.openai.com/",
        "https://hub.docker.com/_/redis", "https://www.postman.com/product/api-platform/",
        "https://git-scm.com/doc", "https://news.ycombinator.com/", "https://www.reddit.com/r/netsec/"
    ]
    
    phishing_urls = [
        "http://login.paypal.com.account-verify.secure-update.xyz/login.php",
        "http://secure-bankofamerica.update-login-credential.com/auth",
        "http://account-google-security-verify.temp-web.net/signin",
        "http://appleid.apple.com.verify.account.info-security.top/id",
        "http://192.168.1.1/login.php?update=true&user=admin",
        "http://free-crypto-giveaway-claim-now.site/claim",
        "http://secure.signin.amazon.com-check.tk/auth",
        "http://verify-identity-netflix-payment.support-now.online/billing",
        "http://paypa1-security-center.account-verification-dispatch.info",
        "http://presidency-university-exam-fee-portal.pay-online.tk",
        "http://xn--gogl-0ra.com/login-verification-security",
        "http://microsoft-office365-password-reset.action-required.club",
        "http://chase-online-banking-alert.suspended-account.work",
        "http://wellsfargo-verify-identity-billing-update.buzz/login",
        "http://facebook-security-appeal-center.account-support.cc",
        "http://instagram-copyright-infringement-claim.site/verify",
        "http://binance-wallet-recovery-passphrase.claim-airdrop.top",
        "http://coinbase-auth-mfa-token-sync.info-verification.online",
        "http://adobe-account-renewal-payment.discount-offer.click",
        "http://hdfc-netbanking-otp-auth.secure-update.gq/login",
        "http://10.0.0.1/admin/config.php?session=stolen",
        "http://spotify-premium-annual-free-pass.buzz/claim",
        "http://dropbox-shared-confidential-document.xyz/download"
    ]
    
    urls = benign_urls + phishing_urls
    labels = [0] * len(benign_urls) + [1] * len(phishing_urls)
    return pd.DataFrame({"url": urls, "label": labels})

def train_and_export():
    print("[*] Initiating PhishShield Model Training Pipeline...")
    df = generate_synthetic_dataset()
    df.to_csv("dataset/phishing_urls.csv", index=False)

    X = df["url"]
    y = df["label"]

    char_vec = TfidfVectorizer(analyzer="char", ngram_range=(3, 5), max_features=1200)
    word_vec = TfidfVectorizer(analyzer="word", ngram_range=(1, 3), max_features=600)
    lexical_extractor = LexicalFeatureExtractor()

    X_char = char_vec.fit_transform(X)
    X_word = word_vec.fit_transform(X)
    X_lexical = lexical_extractor.transform(X)

    scaler = StandardScaler()
    X_lexical_scaled = scaler.fit_transform(X_lexical)

    X_combined = hstack([X_char, X_word, X_lexical_scaled]).tocsr()

    rf = RandomForestClassifier(n_estimators=150, max_depth=12, random_state=42)
    gb = GradientBoostingClassifier(n_estimators=150, learning_rate=0.1, random_state=42)
    et = ExtraTreesClassifier(n_estimators=100, random_state=42)

    ensemble = VotingClassifier(
        estimators=[("rf", rf), ("gb", gb), ("et", et)],
        voting="soft"
    )
    ensemble.fit(X_combined, y)

    os.makedirs(settings.ARTIFACTS_DIR, exist_ok=True)
    joblib.dump(char_vec, settings.CHAR_VEC_PATH)
    joblib.dump(word_vec, settings.WORD_VEC_PATH)
    joblib.dump(scaler, settings.SCALER_PATH)
    joblib.dump(ensemble, settings.MODEL_PATH)

    print("[+] Advanced Tri-Voting Ensemble Artifacts Exported Successfully!")

if __name__ == "__main__":
    train_and_export()
''')

# ------------------------------------------------------------------------------
# 4. Redis Cache Manager with In-Memory Fallback (app/redis_cache.py)
# ------------------------------------------------------------------------------
with open("app/redis_cache.py", "w") as f:
    f.write('''import hashlib
import json
import time
from app.config import settings

try:
    import redis
    redis_client = redis.Redis(
        host=settings.REDIS_HOST,
        port=settings.REDIS_PORT,
        db=settings.REDIS_DB,
        password=settings.REDIS_PASSWORD if settings.REDIS_PASSWORD else None,
        socket_timeout=1.0
    )
    redis_client.ping()
    REDIS_AVAILABLE = True
    print("[+] Connected to Redis Cache Server.")
except Exception:
    REDIS_AVAILABLE = False
    print("[-] Redis Server unavailable. Falling back to High-Speed In-Memory LRU Cache.")

class MemoryCache:
    def __init__(self):
        self.store = {}

    def get(self, key: str):
        item = self.store.get(key)
        if not item:
            return None
        if time.time() > item["expires"]:
            del self.store[key]
            return None
        return item["value"]

    def set(self, key: str, value: str, ex: int):
        self.store[key] = {
            "value": value,
            "expires": time.time() + ex
        }

local_cache = MemoryCache()

class RedisCacheManager:
    def __init__(self):
        self.use_redis = REDIS_AVAILABLE

    def _hash_url(self, url: str) -> str:
        return hashlib.sha256(url.strip().lower().encode("utf-8")).hexdigest()

    def get_verdict(self, url: str):
        key = f"phish_cache:{self._hash_url(url)}"
        try:
            if self.use_redis:
                data = redis_client.get(key)
                return json.loads(data) if data else None
            else:
                data = local_cache.get(key)
                return json.loads(data) if data else None
        except Exception:
            return None

    def set_verdict(self, url: str, verdict: str, risk_score: float, ttl: int = settings.DEFAULT_CACHE_TTL):
        key = f"phish_cache:{self._hash_url(url)}"
        payload = json.dumps({"verdict": verdict, "risk_score": risk_score, "cached_at": time.time()})
        try:
            if self.use_redis:
                redis_client.setex(key, ttl, payload)
            else:
                local_cache.set(key, payload, ex=ttl)
        except Exception as e:
            print(f"[-] Cache Write Error: {e}")
''')

# ------------------------------------------------------------------------------
# 5. Whitelist Gatekeeper (app/whitelist.py)
# ------------------------------------------------------------------------------
with open("app/whitelist.py", "w") as f:
    f.write('''import re
from urllib.parse import urlparse

WHITELISTED_DOMAINS = {
    "google.com", "github.com", "wikipedia.org", "microsoft.com", 
    "amazon.com", "presidencyuniversity.in", "stackoverflow.com", 
    "python.org", "tiangolo.com", "redis.io", "scikit-learn.org", 
    "linkedin.com", "cloudflare.com", "openai.com", "docker.com",
    "apple.com", "facebook.com", "youtube.com", "twitter.com"
}

class EnterpriseWhitelistGatekeeper:
    def __init__(self):
        self.domains = WHITELISTED_DOMAINS

    def is_whitelisted(self, url: str) -> bool:
        try:
            url_str = url.strip().lower()
            if not url_str.startswith(("http://", "https://")):
                url_str = "http://" + url_str
                
            parsed = urlparse(url_str)
            domain = parsed.netloc.split(":")[0]
            
            if domain in self.domains:
                return True
                
            parts = domain.split(".")
            if len(parts) >= 2:
                root_domain = f"{parts[-2]}.{parts[-1]}"
                if root_domain in self.domains:
                    return True
            return False
        except Exception:
            return False
''')

# ------------------------------------------------------------------------------
# 6. SQLite Audit Database Engine (app/database.py)
# ------------------------------------------------------------------------------
with open("app/database.py", "w") as f:
    f.write('''import sqlite3
from datetime import datetime
from app.config import settings

class AuditLogger:
    def __init__(self, db_path=settings.DB_PATH):
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
            print(f"[-] Audit DB Insert Error: {e}")

    def get_recent_logs(self, limit=15):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, url, verdict, source, risk_score, latency_ms, timestamp 
                FROM scan_logs ORDER BY id DESC LIMIT ?
            """, (limit,))
            rows = cursor.fetchall()
            conn.close()
            return rows
        except Exception:
            return []

    def get_analytics(self):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM scan_logs")
            total_scans = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM scan_logs WHERE verdict = 'MALICIOUS'")
            malicious_count = cursor.fetchone()[0]
            
            cursor.execute("SELECT AVG(latency_ms) FROM scan_logs")
            avg_latency = cursor.fetchone()[0] or 0.0
            
            conn.close()
            return {
                "total_scans": total_scans,
                "malicious_detected": malicious_count,
                "avg_latency_ms": round(avg_latency, 2)
            }
        except Exception:
            return {"total_scans": 0, "malicious_detected": 0, "avg_latency_ms": 0.0}
''')

# ------------------------------------------------------------------------------
# 7. Advanced Inference Engine (app/nlp_engine.py)
# ------------------------------------------------------------------------------
with open("app/nlp_engine.py", "w") as f:
    f.write('''import os
import joblib
import numpy as np
from scipy.sparse import hstack
from app.lexical_extractor import LexicalFeatureExtractor
from app.config import settings

class AdvancedNLPEngine:
    def __init__(self):
        self.ready = False
        self.lexical_extractor = LexicalFeatureExtractor()
        self._load_artifacts()

    def _load_artifacts(self):
        try:
            if (os.path.exists(settings.CHAR_VEC_PATH) and 
                os.path.exists(settings.WORD_VEC_PATH) and 
                os.path.exists(settings.SCALER_PATH) and 
                os.path.exists(settings.MODEL_PATH)):
                
                self.char_vec = joblib.load(settings.CHAR_VEC_PATH)
                self.word_vec = joblib.load(settings.WORD_VEC_PATH)
                self.scaler = joblib.load(settings.SCALER_PATH)
                self.model = joblib.load(settings.MODEL_PATH)
                self.ready = True
                print("[+] Tri-Voting Ensemble Engine Engine Online.")
            else:
                print("[-] NLP Engine Notice: Model artifacts missing. Run train_model.py first.")
        except Exception as e:
            print(f"[-] NLP Engine Initialization Failed: {e}")

    def predict(self, url: str):
        if not self.ready:
            return "UNKNOWN", 0.0

        try:
            char_feat = self.char_vec.transform([url])
            word_feat = self.word_vec.transform([url])
            
            lex_feat = self.lexical_extractor.transform([url])
            lex_scaled = self.scaler.transform(lex_feat)

            combined_features = hstack([char_feat, word_feat, lex_scaled]).tocsr()
            prob = self.model.predict_proba(combined_features)[0][1]

            if prob >= settings.HIGH_RISK_THRESHOLD:
                verdict = "MALICIOUS"
            elif prob >= settings.MEDIUM_RISK_THRESHOLD:
                verdict = "SUSPICIOUS"
            else:
                verdict = "SAFE"

            return verdict, round(float(prob), 4)
        except Exception as e:
            print(f"[-] Inference Error: {e}")
            return "UNKNOWN", 0.0
''')

# ------------------------------------------------------------------------------
# 8. Glassmorphic UI Dashboard (app/templates/index.html)
# ------------------------------------------------------------------------------
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
                <input type="text" id="urlInput" placeholder="Paste target URL for analysis (e.g. http://login.paypal.com.account-verify.secure-update.xyz)">
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

                const analyticsRes = await fetch("/api/v1/analytics");
                const stats = await analyticsRes.json();
                document.getElementById("statTotal").innerText = stats.total_scans;
                document.getElementById("statMalicious").innerText = stats.malicious_detected;
                document.getElementById("statLatency").innerText = stats.avg_latency_ms + " ms";
            } catch(e) {}
        }

        loadLogs();
        setInterval(loadLogs, 4000);
    </script>
</body>
</html>
''')

# ------------------------------------------------------------------------------
# 9. Main FastAPI Backend Server (app/main.py)
# ------------------------------------------------------------------------------
with open("app/main.py", "w") as f:
    f.write('''import time
from fastapi import FastAPI, HTTPException, Request, BackgroundTasks
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, HttpUrl
from app.config import settings
from app.redis_cache import RedisCacheManager
from app.nlp_engine import AdvancedNLPEngine
from app.whitelist import EnterpriseWhitelistGatekeeper
from app.database import AuditLogger

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Multi-Tier Enterprise Threat Intelligence Framework"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

templates = Jinja2Templates(directory="app/templates")

cache = RedisCacheManager()
nlp = AdvancedNLPEngine()
whitelist = EnterpriseWhitelistGatekeeper()
logger = AuditLogger()

class URLRequest(BaseModel):
    url: str

@app.get("/", response_class=HTMLResponse)
def serve_dashboard(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/health")
def health_check():
    return {"status": "ONLINE", "engine_ready": nlp.ready, "version": settings.VERSION}

@app.get(f"{settings.API_V1_PREFIX}/logs")
def get_audit_logs():
    raw_logs = logger.get_recent_logs(12)
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

@app.get(f"{settings.API_V1_PREFIX}/analytics")
def get_soc_analytics():
    return logger.get_analytics()

@app.post(f"{settings.API_V1_PREFIX}/check-url")
def analyze_url(payload: URLRequest, background_tasks: BackgroundTasks):
    start_time = time.time()
    url = payload.url.strip()

    if not url:
        raise HTTPException(status_code=400, detail="Invalid URL payload")

    # Tier-3 Whitelist Check
    if whitelist.is_whitelisted(url):
        execution_time = round((time.time() - start_time) * 1000, 3)
        background_tasks.add_task(logger.log_scan, url, "SAFE", "Tier-3 Whitelist", 0.0, execution_time)
        return {
            "url": url,
            "verdict": "SAFE",
            "source": "Tier-3 Whitelist",
            "risk_score": 0.0,
            "latency": f"{execution_time} ms"
        }

    # Tier-1 Cache Lookup
    cached = cache.get_verdict(url)
    if cached:
        execution_time = round((time.time() - start_time) * 1000, 3)
        risk_score = float(cached.get("risk_score", 0.0))
        verdict = cached.get("verdict", "SAFE")
        background_tasks.add_task(logger.log_scan, url, verdict, "Tier-1 Redis Cache", risk_score, execution_time)
        return {
            "url": url,
            "verdict": verdict,
            "source": "Tier-1 Redis Cache",
            "risk_score": risk_score,
            "latency": f"{execution_time} ms"
        }

    # Tier-2 Tri-Voting Ensemble NLP Inspection
    verdict, risk_score = nlp.predict(url)
    execution_time = round((time.time() - start_time) * 1000, 3)

    ttl = 86400 if verdict == "MALICIOUS" else (3600 if verdict == "SUSPICIOUS" else 43200)
    cache.set_verdict(url, verdict, risk_score, ttl=ttl)
    background_tasks.add_task(logger.log_scan, url, verdict, "Tier-2 Ensemble NLP", risk_score, execution_time)

    return {
        "url": url,
        "verdict": verdict,
        "source": "Tier-2 Ensemble NLP Engine",
        "risk_score": risk_score,
        "latency": f"{execution_time} ms"
    }
''')

print("[+] Master setup script written successfully! Generating initial ML artifacts...")

# Execute model training upon setup creation
import train_model
train_model.train_and_export()

print("\n==========================================================================")
print("[+] PhishShield Enterprise SOC Architecture Setup Complete!")
print("==========================================================================")
print("Run the server using:")
print("    uvicorn app.main:app --reload --port 8000")
print("==========================================================================")