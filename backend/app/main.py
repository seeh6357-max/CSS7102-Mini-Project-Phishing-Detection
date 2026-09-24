from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from app.redis_cache import RedisCacheManager
from app.nlp_engine import NLPEngine
from app.whitelist import WhitelistEngine

app = FastAPI(title="Hybrid Phishing URL Detection API", version="1.0")

cache_manager = RedisCacheManager()
nlp_engine = NLPEngine()
whitelist_engine = WhitelistEngine()

class URLCheckRequest(BaseModel):
    url: str

@app.get("/")
def root():
    return {"status": "Active", "review": "Review-3 Implementation"}

@app.post("/api/v1/check-url")
def check_url(payload: URLCheckRequest):
    url = payload.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL cannot be empty")

    if whitelist_engine.is_whitelisted(url):
        return {
            "url": url,
            "verdict": "SAFE",
            "source": "Tier-3 Enterprise Whitelist",
            "risk_score": 0.0,
            "latency": "< 0.5 ms"
        }

    cached_verdict = cache_manager.get_verdict(url)
    if cached_verdict:
        return {
            "url": url,
            "verdict": cached_verdict,
            "source": "Tier-1 Redis Threat Cache",
            "risk_score": 1.0 if cached_verdict == "MALICIOUS" else 0.0,
            "latency": "< 1 ms"
        }

    verdict, probability = nlp_engine.predict(url)
    cache_manager.set_verdict(url, verdict)

    return {
        "url": url,
        "verdict": verdict,
        "source": "Tier-2 TF-IDF NLP Engine (Zero-Day)",
        "risk_score": probability,
        "latency": "~ 15 ms"
    }
