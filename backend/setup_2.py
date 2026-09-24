import os

os.makedirs("app", exist_ok=True)

# 1. train_model.py
with open("train_model.py", "w") as f:
    f.write('''import os
import math
import numpy as np
import pandas as pd
from Levenshtein import distance as lev_distance
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.base import BaseEstimator, TransformerMixin
import joblib

class LexicalFeatureExtractor(BaseEstimator, TransformerMixin):
    def __init__(self):
        self.target_brands = ["paypal", "google", "microsoft", "apple", "amazon", "bankofamerica", "netflix", "presidencyuniversity"]

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

            features.append([
                url_length, digit_ratio, special_ratio, num_subdomains, has_ip, entropy, brand_dist
            ])
        return np.array(features)

def train_and_export():
    print("[*] Generating Comprehensive Training Dataset...")
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

    vectorizer = TfidfVectorizer(analyzer="char", ngram_range=(3, 5), max_features=1000)
    lexical_extractor = LexicalFeatureExtractor()

    X_tfidf = vectorizer.fit_transform(X).toarray()
    X_lexical = lexical_extractor.transform(X)
    
    scaler = StandardScaler()
    X_lexical_scaled = scaler.fit_transform(X_lexical)
    X_combined = np.hstack((X_tfidf, X_lexical_scaled))

    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X_combined, y)

    os.makedirs("app", exist_ok=True)
    joblib.dump(vectorizer, "app/vectorizer.pkl")
    joblib.dump(scaler, "app/scaler.pkl")
    joblib.dump(clf, "app/model.pkl")
    print("[+] Advanced Model Artifacts Exported Successfully!")

if __name__ == "__main__":
    train_and_export()
''')

# 2. app/redis_cache.py
with open("app/redis_cache.py", "w") as f:
    f.write('''import redis
import os
import hashlib

class RedisCacheManager:
    def __init__(self):
        self.host = os.getenv("REDIS_HOST", "localhost")
        self.port = int(os.getenv("REDIS_PORT", 6379))
        try:
            self.client = redis.Redis(host=self.host, port=self.port, decode_responses=True)
            self.client.ping()
            print("[+] Tier-1 Redis Threat Cache Initialized.")
        except Exception as e:
            print(f"[-] Redis Cache Warning: {e}")
            self.client = None

    def _hash_url(self, url: str) -> str:
        return hashlib.sha256(url.strip().lower().encode("utf-8")).hexdigest()

    def get_verdict(self, url: str):
        if not self.client:
            return None
        url_hash = self._hash_url(url)
        data = self.client.hgetall(f"url:{url_hash}")
        if data:
            return data
        return None

    def set_verdict(self, url: str, verdict: str, risk_score: float, ttl: int = 3600):
        if not self.client:
            return
        url_hash = self._hash_url(url)
        key = f"url:{url_hash}"
        self.client.hset(key, mapping={
            "verdict": verdict,
            "risk_score": str(risk_score),
            "raw_url": url
        })
        self.client.expire(key, ttl)
''')

# 3. app/nlp_engine.py
with open("app/nlp_engine.py", "w") as f:
    f.write('''import joblib
import os
import math
import numpy as np
from Levenshtein import distance as lev_distance

class AdvancedNLPEngine:
    def __init__(self):
        vec_path = "app/vectorizer.pkl"
        scaler_path = "app/scaler.pkl"
        model_path = "app/model.pkl"
        self.target_brands = ["paypal", "google", "microsoft", "apple", "amazon", "bankofamerica", "netflix", "presidencyuniversity"]
        
        if os.path.exists(vec_path) and os.path.exists(scaler_path) and os.path.exists(model_path):
            self.vectorizer = joblib.load(vec_path)
            self.scaler = joblib.load(scaler_path)
            self.model = joblib.load(model_path)
            self.ready = True
            print("[+] Tier-2 Advanced NLP Engine Online.")
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

        return np.array([[
            url_length, digit_ratio, special_ratio, num_subdomains, has_ip, entropy, brand_dist
        ]])

    def predict(self, url: str):
        if not self.ready:
            return "UNKNOWN", 0.0

        tfidf_feat = self.vectorizer.transform([url]).toarray()
        lex_feat = self._extract_lexical_features(url)
        lex_scaled = self.scaler.transform(lex_feat)

        combined_features = np.hstack((tfidf_feat, lex_scaled))
        prob = self.model.predict_proba(combined_features)[0][1]
        
        if prob >= 0.80:
            verdict = "MALICIOUS"
        elif prob >= 0.50:
            verdict = "SUSPICIOUS"
        else:
            verdict = "SAFE"

        return verdict, round(float(prob), 4)
''')

# 4. app/whitelist.py
with open("app/whitelist.py", "w") as f:
    f.write('''from urllib.parse import urlparse

class EnterpriseWhitelistGatekeeper:
    def __init__(self):
        self.whitelisted_domains = {
            "presidencyuniversity.in",
            "google.com",
            "github.com",
            "microsoft.com",
            "wikipedia.org",
            "amazon.com",
            "python.org",
            "stackoverflow.com"
        }

    def is_whitelisted(self, url: str) -> bool:
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower() or parsed.path.split("/")[0].lower()
            domain = domain.split(":")[0]
            
            if domain in self.whitelisted_domains:
                return True
                
            for trusted in self.whitelisted_domains:
                if domain.endswith("." + trusted):
                    return True
            return False
        except Exception:
            return False
''')

# 5. app/database.py
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
            print(f"[-] Database Logging Error: {e}")
''')

# 6. app/main.py
with open("app/main.py", "w") as f:
    f.write('''import time
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from app.redis_cache import RedisCacheManager
from app.nlp_engine import AdvancedNLPEngine
from app.whitelist import EnterpriseWhitelistGatekeeper
from app.database import AuditLogger

app = FastAPI(
    title="Real-Time Phishing Detection Engine",
    version="2.0",
    description="Multi-Tier Threat Intelligence Framework"
)

cache = RedisCacheManager()
nlp = AdvancedNLPEngine()
whitelist = EnterpriseWhitelistGatekeeper()
logger = AuditLogger()

class URLRequest(BaseModel):
    url: str

@app.get("/")
def health_check():
    return {
        "status": "ONLINE",
        "system": "Hybrid Phishing Detection Framework",
        "version": "2.0",
        "tiers": ["Tier-1 Redis Cache", "Tier-2 NLP Engine", "Tier-3 Enterprise Whitelist"]
    }

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

print("[+] All 2.0 backend engine files written successfully!")