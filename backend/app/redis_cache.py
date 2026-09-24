import redis
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
