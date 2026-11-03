"""
Redis-backed Distributed Rate Limiting & Response Caching for API-Hub-Pro.
Uses Redis sliding-window / token-bucket counters when a Redis server is reachable,
and transparently falls back to a thread-safe Redis-compatible in-memory store
when running in standalone, CI, or Termux environments.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

from apihub.config import settings


class RedisCompatibleStore:
    """
    Unified Redis client wrapper that connects to `REDIS_URL` if `redis` is installed
    and reachable, and provides a thread-safe atomic fallback with identical semantics.
    """

    def __init__(self, redis_url: Optional[str] = None) -> None:
        self.redis_url = redis_url or settings.redis_url
        self._lock = threading.RLock()
        self._kv: Dict[str, Tuple[Any, Optional[float]]] = {}
        self._zsets: Dict[str, List[Tuple[float, str]]] = {}
        self._redis_client: Any = None
        self.backend_mode = "redis-memory-emulated"
        self._try_connect_redis()

    def _try_connect_redis(self) -> None:
        if not settings.redis_enabled:
            return
        try:
            import redis  # type: ignore

            client = redis.Redis.from_url(
                self.redis_url,
                socket_connect_timeout=0.3,
                socket_timeout=0.3,
                decode_responses=True,
            )
            client.ping()
            self._redis_client = client
            self.backend_mode = "redis-live"
        except Exception:
            self._redis_client = None
            self.backend_mode = "redis-memory-emulated"

    def get(self, key: str) -> Optional[str]:
        full_key = f"{settings.redis_key_prefix}{key}"
        if self._redis_client is not None:
            try:
                return self._redis_client.get(full_key)
            except Exception:
                pass
        with self._lock:
            entry = self._kv.get(full_key)
            if not entry:
                return None
            val, expires_at = entry
            if expires_at is not None and time.time() >= expires_at:
                del self._kv[full_key]
                return None
            return str(val)

    def setex(self, key: str, ttl_seconds: int, value: str) -> None:
        full_key = f"{settings.redis_key_prefix}{key}"
        if self._redis_client is not None:
            try:
                self._redis_client.setex(full_key, max(1, int(ttl_seconds)), value)
                return
            except Exception:
                pass
        with self._lock:
            self._kv[full_key] = (value, time.time() + max(1, ttl_seconds))

    def delete(self, key: str) -> None:
        full_key = f"{settings.redis_key_prefix}{key}"
        if self._redis_client is not None:
            try:
                self._redis_client.delete(full_key)
            except Exception:
                pass
        with self._lock:
            self._kv.pop(full_key, None)
            self._zsets.pop(full_key, None)

    def flush_all(self) -> None:
        with self._lock:
            self._kv.clear()
            self._zsets.clear()

    def sliding_window_check(
        self,
        bucket_key: str,
        limit: int,
        window_seconds: int = 60,
        now: Optional[float] = None,
    ) -> Dict[str, Any]:
        """
        Distributed sliding-window rate limiter.
        Returns dict with: allowed (bool), limit (int), remaining (int),
        reset_epoch (int), retry_after (int), current_count (int), backend (str).
        """
        current_time = now if now is not None else time.time()
        window_start = current_time - window_seconds
        full_key = f"{settings.redis_key_prefix}rl:{bucket_key}"
        effective_limit = max(1, int(limit))

        if self._redis_client is not None:
            try:
                pipe = self._redis_client.pipeline()
                member = f"{current_time:.6f}"
                pipe.zremrangebyscore(full_key, "-inf", window_start)
                pipe.zcard(full_key)
                results = pipe.execute()
                count_before = int(results[1])
                if count_before >= effective_limit:
                    reset_epoch = int(current_time + window_seconds)
                    return {
                        "allowed": False,
                        "limit": effective_limit,
                        "remaining": 0,
                        "current_count": count_before,
                        "reset_epoch": reset_epoch,
                        "retry_after": max(1, int(window_seconds)),
                        "backend": self.backend_mode,
                    }
                pipe2 = self._redis_client.pipeline()
                pipe2.zadd(full_key, {member: current_time})
                pipe2.expire(full_key, int(window_seconds) + 5)
                pipe2.execute()
                remaining = max(0, effective_limit - (count_before + 1))
                return {
                    "allowed": True,
                    "limit": effective_limit,
                    "remaining": remaining,
                    "current_count": count_before + 1,
                    "reset_epoch": int(current_time + window_seconds),
                    "retry_after": 0,
                    "backend": self.backend_mode,
                }
            except Exception:
                pass

        with self._lock:
            entries = self._zsets.get(full_key, [])
            entries = [(ts, m) for (ts, m) in entries if ts > window_start]
            if len(entries) >= effective_limit:
                oldest_ts = entries[0][0] if entries else current_time
                retry_after = max(1, int(round((oldest_ts + window_seconds) - current_time)))
                self._zsets[full_key] = entries
                return {
                    "allowed": False,
                    "limit": effective_limit,
                    "remaining": 0,
                    "current_count": len(entries),
                    "reset_epoch": int(oldest_ts + window_seconds),
                    "retry_after": retry_after,
                    "backend": self.backend_mode,
                }
            entries.append((current_time, f"{current_time:.6f}:{len(entries)}"))
            self._zsets[full_key] = entries
            remaining = max(0, effective_limit - len(entries))
            oldest_ts = entries[0][0]
            return {
                "allowed": True,
                "limit": effective_limit,
                "remaining": remaining,
                "current_count": len(entries),
                "reset_epoch": int(oldest_ts + window_seconds),
                "retry_after": 0,
                "backend": self.backend_mode,
            }

    @staticmethod
    def build_rate_limit_headers(decision: Dict[str, Any]) -> Dict[str, str]:
        headers = {
            "X-RateLimit-Limit": str(decision["limit"]),
            "X-RateLimit-Remaining": str(decision["remaining"]),
            "X-RateLimit-Reset": str(decision["reset_epoch"]),
            "X-RateLimit-Backend": str(decision.get("backend", "redis")),
        }
        if not decision["allowed"]:
            headers["Retry-After"] = str(decision.get("retry_after", 60))
        return headers


class ResponseCache:
    """Gateway response cache backed by RedisCompatibleStore."""

    def __init__(self, store: RedisCompatibleStore) -> None:
        self.store = store
        self.hits = 0
        self.misses = 0

    @staticmethod
    def make_cache_key(
        project_id: str,
        version: str,
        method: str,
        path: str,
        query_params: Dict[str, Any],
    ) -> str:
        raw = json.dumps(
            {
                "p": project_id,
                "v": version,
                "m": method.upper(),
                "path": path,
                "q": sorted(query_params.items()),
            },
            sort_keys=True,
        )
        digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]
        return f"cache:{project_id}:{version}:{digest}"

    def get_cached_response(self, cache_key: str) -> Optional[Dict[str, Any]]:
        raw = self.store.get(cache_key)
        if raw is None:
            self.misses += 1
            return None
        try:
            self.hits += 1
            return json.loads(raw)
        except Exception:
            self.misses += 1
            return None

    def set_cached_response(
        self, cache_key: str, payload: Dict[str, Any], ttl_seconds: int
    ) -> None:
        if ttl_seconds <= 0:
            return
        self.store.setex(cache_key, ttl_seconds, json.dumps(payload))

    def stats(self) -> Dict[str, Any]:
        total = self.hits + self.misses
        hit_rate = round((self.hits / total) * 100.0, 2) if total > 0 else 0.0
        return {
            "backend": self.store.backend_mode,
            "redis_url": self.store.redis_url,
            "hits": self.hits,
            "misses": self.misses,
            "hit_rate_percent": hit_rate,
        }


redis_store = RedisCompatibleStore()
response_cache = ResponseCache(redis_store)
