import time
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
    return templates.TemplateResponse(request=request, name="index.html")

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
