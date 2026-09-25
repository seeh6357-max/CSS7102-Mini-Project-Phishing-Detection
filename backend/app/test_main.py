import sys
from pathlib import Path

# Add backend root directory to system search path
sys.path.insert(0, str(Path(__file__).parent.resolve()))

import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_system_health():
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "OPERATIONAL"

def test_serve_dashboard():
    response = client.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]

def test_check_url_whitelist_tier3():
    payload = {"url": "https://www.presidencyuniversity.in"}
    response = client.post("/api/v1/check-url", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "SAFE"
    assert data["source"] == "Tier-3 Enterprise Whitelist"

def test_check_url_phishing_tier2():
    payload = {"url": "http://paypa1-security-center.account-verification-dispatch.info"}
    response = client.post("/api/v1/check-url", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] in ["MALICIOUS", "SUSPICIOUS"]

def test_check_url_cache_tier1():
    url = "http://paypa1-security-center.account-verification-dispatch.info"
    client.post("/api/v1/check-url", json={"url": url})
    response = client.post("/api/v1/check-url", json={"url": url})
    assert response.status_code == 200
    data = response.json()
    assert data["source"] == "Tier-1 Redis Threat Cache"

def test_check_url_invalid_payload():
    response = client.post("/api/v1/check-url", json={"url": ""})
    assert response.status_code == 400

def test_batch_analyze_urls():
    payload = {
        "urls": [
            "https://www.google.com",
            "http://free-crypto-giveaway-claim-now.site/claim"
        ]
    }
    response = client.post("/api/v1/batch-check", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["processed_count"] == 2

def test_batch_analyze_empty():
    response = client.post("/api/v1/batch-check", json={"urls": []})
    assert response.status_code == 400

def test_get_telemetry_stats():
    response = client.get("/api/v1/stats")
    assert response.status_code == 200
    data = response.json()
    assert "total_scans" in data

def test_get_audit_logs():
    response = client.get("/api/v1/logs?limit=5")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)

def test_get_log_by_id_not_found():
    response = client.get("/api/v1/logs/999999")
    assert response.status_code == 404

def test_clear_cache():
    payload = {"purge_all": True}
    response = client.post("/api/v1/clear-cache", json=payload)
    assert response.status_code == 200