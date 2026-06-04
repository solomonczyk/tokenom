"""Performance guardrails and SHA256 cache primitives for Tokenom."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import time
from typing import Any

from .redactor import PayloadDecision, guard_payload


@dataclass(frozen=True)
class PerformancePolicy:
    skip_below_bytes: int = 2048
    enable_cache: bool = True
    cache_ttl_hours: int = 24
    max_payload_mb: int = 5
    max_latency_ms: int = 300

    @property
    def max_payload_bytes(self) -> int:
        return self.max_payload_mb * 1024 * 1024


def should_skip_payload(payload: bytes | str, policy: PerformancePolicy | None = None) -> bool:
    """Return True when a payload is below the compression threshold."""

    active_policy = policy or PerformancePolicy()
    size = len(payload.encode("utf-8") if isinstance(payload, str) else payload)
    return size < active_policy.skip_below_bytes


class SHA256PayloadCache:
    """Small in-memory SHA256 cache interface for layer-001 integration."""

    def __init__(self, ttl_hours: int = 24) -> None:
        self.ttl_seconds = ttl_hours * 60 * 60
        self._items: dict[str, tuple[float, Any]] = {}

    @staticmethod
    def digest(payload: bytes | str) -> str:
        data = payload.encode("utf-8") if isinstance(payload, str) else payload
        return hashlib.sha256(data).hexdigest()

    def get(self, payload: bytes | str) -> Any | None:
        key = self.digest(payload)
        item = self._items.get(key)
        if item is None:
            return None
        created_at, value = item
        if time.time() - created_at > self.ttl_seconds:
            self._items.pop(key, None)
            return None
        return value

    def set(self, payload: bytes | str, value: Any) -> str:
        key = self.digest(payload)
        self._items[key] = (time.time(), value)
        return key

    def __len__(self) -> int:
        return len(self._items)


@dataclass(frozen=True)
class PayloadSecurityCacheStats:
    """Runtime counters for cached Tokenom payload guard decisions."""

    hits: int = 0
    misses: int = 0
    stores: int = 0
    entries: int = 0

    @property
    def hit_rate(self) -> float:
        total = self.hits + self.misses
        return self.hits / total if total else 0.0


class CachedPayloadGuard:
    """Cache identical payload guard decisions without skipping security policy.

    The cache key includes the raw payload hash material plus the path, mode,
    and production-key policy flags, so a decision for one security context is
    never reused for a different context.
    """

    def __init__(
        self,
        policy: PerformancePolicy | None = None,
        *,
        ttl_hours: int | None = None,
    ) -> None:
        self.policy = policy or PerformancePolicy()
        self._cache = SHA256PayloadCache(ttl_hours=ttl_hours or self.policy.cache_ttl_hours)
        self._hits = 0
        self._misses = 0
        self._stores = 0

    def guard(
        self,
        payload: str,
        *,
        mode: str = "redact",
        path: str | None = None,
        block_production_keys: bool = True,
    ) -> PayloadDecision:
        """Apply Tokenom payload guardrails with per-context memoization."""

        use_cache = self.policy.enable_cache and self._cacheable(payload)
        cache_material = ""
        if use_cache:
            cache_material = self._cache_material(
                payload,
                mode=mode,
                path=path,
                block_production_keys=block_production_keys,
            )
            cached = self._cache.get(cache_material)
            if cached is not None:
                self._hits += 1
                return cached

        self._misses += 1
        decision = guard_payload(
            payload,
            mode=mode,
            path=path,
            block_production_keys=block_production_keys,
        )
        if use_cache:
            self._cache.set(cache_material, decision)
            self._stores += 1
        return decision

    def stats(self) -> PayloadSecurityCacheStats:
        return PayloadSecurityCacheStats(
            hits=self._hits,
            misses=self._misses,
            stores=self._stores,
            entries=len(self._cache),
        )

    def _cacheable(self, payload: str) -> bool:
        return len(payload.encode("utf-8")) <= self.policy.max_payload_bytes

    @staticmethod
    def _cache_material(
        payload: str,
        *,
        mode: str,
        path: str | None,
        block_production_keys: bool,
    ) -> str:
        return json.dumps(
            {
                "payload": payload,
                "mode": mode,
                "path": path,
                "block_production_keys": block_production_keys,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
