"""
server/api/cache.py
-------------------
Enterprise Speed & Caching Layer for InsiEDR.

Architecture & Design:
======================
This module provides a production-grade multi-tiered caching architecture:
  - L1 Cache: In-memory thread-safe LRU cache with sub-millisecond lookups.
  - L2 Cache: Distributed Redis 7 cache shared across all backend replicas,
              supporting TTLs, atomic operations, and pattern-based invalidations.
  - Graceful Resilience: If Redis is unavailable or unconfigured, the system
                         automatically falls back to L1 in-memory caching with
                         zero disruption to API queries or dashboard polling.

Team Usage Example:
-------------------
    from server.api.cache import api_cache, cached

    # Direct cache usage:
    api_cache.set("user_status:alice", {"status": "active"}, ttl=30.0)
    user_status = api_cache.get("user_status:alice")

    # Invalidate by pattern across all replicas:
    api_cache.clear_pattern("user_status:*")

    # Function decorator usage:
    @cached(ttl=10.0, key_prefix="fleet_analytics")
    def calculate_fleet_summary(org_id: str):
        ...
"""
from __future__ import annotations

import collections
import functools
import json
import logging
import os
import threading
import time
from datetime import date, datetime
from typing import Any, Callable, Optional, Protocol, Union
from uuid import UUID

logger = logging.getLogger("insiedr.cache")


# ==============================================================================
# Domain Serializer Helper
# ==============================================================================

class _EnhancedJSONEncoder(json.JSONEncoder):
    """Custom JSON encoder supporting Datetime, Date, UUID, and dataclasses."""
    def default(self, o: Any) -> Any:
        if isinstance(o, (datetime, date)):
            return o.isoformat()
        if isinstance(o, UUID):
            return str(o)
        if hasattr(o, "__dataclass_fields__"):
            import dataclasses
            return dataclasses.asdict(o)
        if hasattr(o, "dict") and callable(o.dict):
            return o.dict()
        if hasattr(o, "model_dump") and callable(o.model_dump):
            return o.model_dump()
        return super().default(o)


def _serialize(value: Any) -> str:
    return json.dumps(value, cls=_EnhancedJSONEncoder, separators=(",", ":"))


def _deserialize(payload: Union[str, bytes]) -> Any:
    if isinstance(payload, bytes):
        payload = payload.decode("utf-8")
    return json.loads(payload)


# ==============================================================================
# Cache Provider Interface
# ==============================================================================

class ICacheProvider(Protocol):
    """Protocol contract for all InsiEDR cache backends."""

    def get(self, key: str) -> Any | None:
        """Retrieve an item from cache by key, returning None on miss or expiry."""
        ...

    def set(self, key: str, value: Any, ttl: float | None = None) -> None:
        """Store an item in cache with an optional TTL in seconds."""
        ...

    def invalidate(self, key: str) -> None:
        """Evict a specific key from cache."""
        ...

    def clear(self) -> None:
        """Evict all keys managed by this cache."""
        ...

    def clear_pattern(self, pattern: str) -> int:
        """Evict all keys matching a glob pattern (e.g. 'fleet:*'). Returns count removed."""
        ...

    def is_alive(self) -> bool:
        """Check if the cache backend is healthy and responding."""
        ...


# ==============================================================================
# L1: In-Memory LRU Cache with TTL
# ==============================================================================

class InMemoryCacheProvider:
    """
    Thread-safe in-memory cache with TTL and LRU bounded size.
    Used as L1 local cache and as standalone fallback when Redis is absent.
    """

    def __init__(self, default_ttl: float = 5.0, max_items: int = 2048) -> None:
        self.default_ttl = default_ttl
        self.max_items = max_items
        self._store: collections.OrderedDict[str, tuple[float, Any]] = collections.OrderedDict()
        self._lock = threading.RLock()

    def get(self, key: str) -> Any | None:
        with self._lock:
            if key not in self._store:
                return None
            expiry, value = self._store[key]
            if time.time() > expiry:
                del self._store[key]
                return None
            # Move to end for LRU
            self._store.move_to_end(key)
            return value

    def set(self, key: str, value: Any, ttl: float | None = None) -> None:
        expiry = time.time() + (ttl if ttl is not None else self.default_ttl)
        with self._lock:
            if key in self._store:
                del self._store[key]
            elif len(self._store) >= self.max_items:
                # Evict oldest entry (FIFO / LRU)
                self._store.popitem(last=False)
            self._store[key] = (expiry, value)

    def invalidate(self, key: str) -> None:
        with self._lock:
            self._store.pop(key, None)

    def clear(self) -> None:
        with self._lock:
            self._store.clear()

    def clear_pattern(self, pattern: str) -> int:
        import fnmatch
        with self._lock:
            matched_keys = [k for k in self._store if fnmatch.fnmatch(k, pattern)]
            for k in matched_keys:
                del self._store[k]
            return len(matched_keys)

    def is_alive(self) -> bool:
        return True


# ==============================================================================
# L2: Redis 7 Cache Provider
# ==============================================================================

class Redis7CacheProvider:
    """
    High-performance Redis 7 caching engine with connection pooling,
    key namespacing, and non-blocking SCAN pattern invalidation.
    """

    def __init__(
        self,
        redis_url: str,
        namespace: str = "insiedr:cache:",
        default_ttl: float = 5.0,
        socket_timeout: float = 0.25,
        socket_connect_timeout: float = 0.25,
    ) -> None:
        self.redis_url = redis_url
        self.namespace = namespace
        self.default_ttl = default_ttl
        self._client: Any = None
        self._lock = threading.Lock()
        self._is_connected = False
        self.socket_timeout = socket_timeout
        self.socket_connect_timeout = socket_connect_timeout
        self._init_client()

    def _init_client(self) -> None:
        try:
            import redis
            pool = redis.ConnectionPool.from_url(
                self.redis_url,
                max_connections=32,
                socket_timeout=self.socket_timeout,
                socket_connect_timeout=self.socket_connect_timeout,
                retry_on_timeout=False,
                decode_responses=False,
            )
            self._client = redis.Redis(connection_pool=pool)
            self._client.ping()
            self._is_connected = True
            logger.info("Connected to Redis 7 cache at %s", self.redis_url.split("@")[-1])
        except Exception as exc:
            self._is_connected = False
            # Retain the client/pool so a temporary startup outage can recover.
            logger.warning("Redis 7 cache unavailable (%s). Operating in local fallback mode.", exc)

    def _prefixed_key(self, key: str) -> str:
        if key.startswith(self.namespace):
            return key
        return f"{self.namespace}{key}"

    def get(self, key: str) -> Any | None:
        if not self._is_connected or self._client is None:
            return None
        try:
            raw = self._client.get(self._prefixed_key(key))
            if raw is None:
                return None
            return _deserialize(raw)
        except Exception as exc:
            logger.debug("Redis GET error for key '%s': %s", key, exc)
            return None

    def set(self, key: str, value: Any, ttl: float | None = None) -> None:
        if not self._is_connected or self._client is None:
            return
        try:
            serialized = _serialize(value)
            expire_seconds = int(ttl if ttl is not None else self.default_ttl)
            expire_seconds = max(1, expire_seconds)
            self._client.set(self._prefixed_key(key), serialized, ex=expire_seconds)
        except Exception as exc:
            logger.debug("Redis SET error for key '%s': %s", key, exc)

    def invalidate(self, key: str) -> None:
        if not self._is_connected or self._client is None:
            return
        try:
            self._client.delete(self._prefixed_key(key))
        except Exception as exc:
            logger.debug("Redis DEL error for key '%s': %s", key, exc)

    def clear(self) -> None:
        self.clear_pattern("*")

    def clear_pattern(self, pattern: str) -> int:
        if not self._is_connected or self._client is None:
            return 0
        try:
            full_pattern = self._prefixed_key(pattern)
            cursor = 0
            total_deleted = 0
            while True:
                cursor, keys = self._client.scan(cursor=cursor, match=full_pattern, count=100)
                if keys:
                    self._client.unlink(*keys)
                    total_deleted += len(keys)
                if cursor == 0:
                    break
            return total_deleted
        except Exception as exc:
            logger.debug("Redis SCAN/UNLINK error for pattern '%s': %s", pattern, exc)
            return 0

    def is_alive(self) -> bool:
        if not self._client:
            return False
        try:
            self._is_connected = bool(self._client.ping())
            return self._is_connected
        except Exception:
            return False


# ==============================================================================
# Tiered Hybrid Cache Manager (L1 Memory + L2 Redis 7)
# ==============================================================================

class TieredCache:
    """
    Two-tier cache combining ultra-fast local L1 (in-memory) and distributed
    L2 (Redis 7). Offers seamless failover when Redis is unavailable.
    """

    def __init__(
        self,
        redis_url: str | None = None,
        default_ttl: float = 5.0,
        l1_max_items: int = 2048,
    ) -> None:
        self.default_ttl = default_ttl
        self.l1 = InMemoryCacheProvider(default_ttl=default_ttl, max_items=l1_max_items)
        self.l2: Optional[Redis7CacheProvider] = None
        if redis_url:
            self.l2 = Redis7CacheProvider(redis_url=redis_url, default_ttl=default_ttl)

    def get(self, key: str) -> Any | None:
        # 1. Try L1 (in-memory, sub-millisecond)
        val = self.l1.get(key)
        if val is not None:
            return val

        # 2. Try L2 (Redis 7 across replicas)
        if self.l2 and self.l2.is_alive():
            val = self.l2.get(key)
            if val is not None:
                # Backfill L1 with a short slice of TTL for micro-caching
                self.l1.set(key, val, ttl=min(self.default_ttl, 3.0))
                return val

        return None

    def set(self, key: str, value: Any, ttl: float | None = None) -> None:
        actual_ttl = ttl if ttl is not None else self.default_ttl
        # Write to L1
        self.l1.set(key, value, ttl=actual_ttl)
        # Write to L2
        if self.l2 and self.l2.is_alive():
            self.l2.set(key, value, ttl=actual_ttl)

    def invalidate(self, key: str) -> None:
        self.l1.invalidate(key)
        if self.l2 and self.l2.is_alive():
            self.l2.invalidate(key)

    def clear(self) -> None:
        self.l1.clear()
        if self.l2 and self.l2.is_alive():
            self.l2.clear()

    def clear_pattern(self, pattern: str) -> int:
        c1 = self.l1.clear_pattern(pattern)
        c2 = 0
        if self.l2 and self.l2.is_alive():
            c2 = self.l2.clear_pattern(pattern)
        return max(c1, c2)

    def is_alive(self) -> bool:
        return True


# Backward-compatible alias for existing imports
TTLCache = TieredCache


# ==============================================================================
# Global Cache Instance Factory
# ==============================================================================

def get_redis_url_from_env() -> str | None:
    return (
        os.environ.get("INSIEDR_REDIS_URL")
        or os.environ.get("REDIS_URL")
    )


# Singleton instance matching the application's configuration
api_cache = TieredCache(
    redis_url=get_redis_url_from_env(),
    default_ttl=5.0,
)


# ==============================================================================
# Function Decorator
# ==============================================================================

def cached(ttl: float = 5.0, key_prefix: str = ""):
    """Decorator to cache sync or async function results with a TTL."""
    def decorator(fn: Callable):
        import inspect
        is_coroutine = inspect.iscoroutinefunction(fn)

        if is_coroutine:
            @functools.wraps(fn)
            async def async_wrapper(*args, **kwargs):
                key = f"{key_prefix}:{fn.__name__}:{str(args)}:{str(sorted(kwargs.items()))}"
                hit = api_cache.get(key)
                if hit is not None:
                    return hit
                result = await fn(*args, **kwargs)
                api_cache.set(key, result, ttl=ttl)
                return result
            return async_wrapper
        else:
            @functools.wraps(fn)
            def sync_wrapper(*args, **kwargs):
                key = f"{key_prefix}:{fn.__name__}:{str(args)}:{str(sorted(kwargs.items()))}"
                hit = api_cache.get(key)
                if hit is not None:
                    return hit
                result = fn(*args, **kwargs)
                api_cache.set(key, result, ttl=ttl)
                return result
            return sync_wrapper

    return decorator
