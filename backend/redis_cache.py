import redis
import os

class RedisCacheManager:
    def __init__(self):
        self.host = os.getenv("REDIS_HOST", "localhost")
        self.port = int(os.getenv("REDIS_PORT", 6379))
        try:
            self.client = redis.Redis(host=self.host, port=self.port, decode_responses=True)
            self.client.ping()
            # Seed initial cache values
            self.client.set("https://www.google.com", "SAFE")
            self.client.set("https://www.presidencyuniversity.in", "SAFE")
            self.client.set("http://malicious-phishing-test.com", "MALICIOUS")
            print("[+] Tier-1 Redis Threat Cache Connected (100% Functional).")
        except Exception as e:
            print(f"[-] Redis Cache Warning: {e}")
            self.client = None

    def get_verdict(self, url: str):
        if self.client:
            return self.client.get(url)
        return None

    def set_verdict(self, url: str, verdict: str, ttl: int = 3600):
        if self.client:
            self.client.setex(url, ttl, verdict)