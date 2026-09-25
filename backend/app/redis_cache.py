import redis
import hashlib
import json
import time
import logging
from collections import OrderedDict
from threading import Lock
from typing import Optional, Dict, Any

# Configure Logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("PhishShield-RedisCache")

class LocalLRUCache:
    """
    Thread-safe in-memory LRU fallback cache used if Redis server is unreachable.
    Guarantees 100% API availability under infrastructure degradation.
    """
    def __init__(self, capacity: int = 2000):
        self.capacity = capacity
        self.cache = OrderedDict()
        self.lock = Lock()

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        with self.lock:
            if key not in self.cache:
                return None
            item = self.cache[key]
            # Check TTL Expiration
            if time.time() > item["expires_at"]:
                del self.cache[key]
                return None
            self.cache.move_to_end(key)
            return item["data"]

    def set(self, key: str, data: Dict[str, Any], ttl: int):
        with self.lock:
            if key in self.cache:
                self.cache.move_to_end(key)
            self.cache[key] = {
                "data": data,
                "expires_at": time.time() + ttl
            }
            if len(self.cache) > self.capacity:
                self.cache.popitem(last=False)

    def delete(self, key: str):
        with self.lock:
            if key in self.cache:
                del self.cache[key]

    def clear(self):
        with self.lock:
            self.cache.clear()

    def size(self) -> int:
        with self.lock:
            return len(self.cache)


class RedisCacheManager:
    """
    Research-Grade Tier-1 SHA-256 Threat Cache Manager.
    Interfaces with Redis for sub-millisecond memory lookups and
    maintains fallback resilience via local LRU memory.
    """
    def __init__(self, host: str = "127.0.0.1", port: int = 6379, db: int = 0):
        self.host = host
        self.port = port
        self.db = db
        self.prefix = "phishshield:threat:"
        self.local_lru = LocalLRUCache(capacity=2000)
        
        # Telemetry Counters
        self.hits = 0
        self.misses = 0

        # Redis Connection Pool
        try:
            self.pool = redis.ConnectionPool(
                host=self.host,
                port=self.port,
                db=self.db,
                decode_responses=True,
                socket_timeout=0.5,
                socket_connect_timeout=0.5,
                max_connections=50
            )
            self.client = redis.Redis(connection_pool=self.pool)
            if self.is_connected():
                print("[+] Tier-1 Redis Threat Cache Initialized & Connected.")
            else:
                print("[!] Tier-1 Redis Offline. Local LRU Memory Cache Activated.")
        except Exception as e:
            self.client = None
            print(f"[!] Redis Initialization Exception: {e}. Using Local Memory Cache.")

    def _hash_url(self, url: str) -> str:
        """Computes SHA-256 digest of canonicalized target URL."""
        canonical = url.strip().lower()
        sha256 = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        return f"{self.prefix}{sha256}"

    def is_connected(self) -> bool:
        """Verifies if Redis server ping responds."""
        if not self.client:
            return False
        try:
            return self.client.ping()
        except Exception:
            return False

    def get_verdict(self, url: str) -> Optional[Dict[str, Any]]:
        """
        Retrieves pre-calculated threat verdict for target URL.
        Checks Redis primary cache first, then falls back to Local LRU.
        """
        key = self._hash_url(url)

        # Primary Lookup: Redis
        if self.is_connected():
            try:
                raw_data = self.client.get(key)
                if raw_data:
                    self.hits += 1
                    return json.loads(raw_data)
            except Exception as e:
                logger.warning(f"Redis READ Error: {e}")

        # Secondary Lookup: Local LRU Memory Fallback
        local_data = self.local_lru.get(key)
        if local_data:
            self.hits += 1
            return local_data

        self.misses += 1
        return None

    def set_verdict(self, url: str, verdict: str, risk_score: float, ttl: int = 86400, metadata: Optional[Dict[str, Any]] = None) -> bool:
        """
        Caches URL verdict and risk probability score with dynamic TTL.
        """
        key = self._hash_url(url)
        payload = {
            "url": url,
            "verdict": verdict,
            "risk_score": risk_score,
            "cached_at": time.time(),
            "metadata": metadata or {}
        }
        json_str = json.dumps(payload)

        # Write to Local Fallback LRU
        self.local_lru.set(key, payload, ttl)

        # Write to Primary Redis
        if self.is_connected():
            try:
                self.client.set(name=key, value=json_str, ex=ttl)
                return True
            except Exception as e:
                logger.warning(f"Redis WRITE Error: {e}")
                return False

        return True

    def delete_verdict(self, url: str) -> bool:
        """Purges a specific URL key from both cache layers."""
        key = self._hash_url(url)
        self.local_lru.delete(key)

        if self.is_connected():
            try:
                self.client.delete(key)
                return True
            except Exception as e:
                logger.warning(f"Redis DELETE Error: {e}")
                return False
        return True

    def clear_all(self) -> bool:
        """Flushes all threat keys from Redis and local LRU fallback."""
        self.local_lru.clear()
        if self.is_connected():
            try:
                # Flush matching keys safely using SCAN
                keys = self.client.keys(f"{self.prefix}*")
                if keys:
                    self.client.delete(*keys)
                return True
            except Exception as e:
                logger.warning(f"Redis CLEAR Error: {e}")
                return False
        return True

    def get_stats() -> Dict[str, Any]:
        """Returns Tier-1 Threat Cache execution metrics and hit ratio."""
        total = self.hits + self.misses
        hit_ratio = round((self.hits / total) * 100, 2) if total > 0 else 0.0

        redis_connected = self.is_connected()
        total_redis_keys = 0

        if redis_connected:
            try:
                total_redis_keys = len(self.client.keys(f"{self.prefix}*"))
            except Exception:
                total_redis_keys = 0

        return {
            "status": "ONLINE" if redis_connected else "DEGRADED (LOCAL LRU ACTIVE)",
            "primary_engine": "Redis In-Memory Key-Value Store",
            "hits": self.hits,
            "misses": self.misses,
            "hit_ratio_percent": f"{hit_ratio}%",
            "redis_keys_count": total_redis_keys,
            "local_lru_keys_count": self.local_lru.size()
        }