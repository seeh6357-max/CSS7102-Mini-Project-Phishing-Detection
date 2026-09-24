import time
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
