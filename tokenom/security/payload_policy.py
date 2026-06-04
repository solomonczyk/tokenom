"""Performance guardrails and SHA256 cache primitives for Tokenom."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import time
from typing import Any


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
