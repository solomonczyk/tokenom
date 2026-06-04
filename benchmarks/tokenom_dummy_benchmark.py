"""Dummy-data benchmark scaffold for Tokenom layer-001 guardrails."""

from __future__ import annotations

import time
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tokenom.security.payload_policy import SHA256PayloadCache, should_skip_payload
from tokenom.security.redactor import redact_text


def run_dummy_benchmark() -> dict[str, float | int | bool]:
    payload = "hello from tokenom " * 256
    started = time.perf_counter()
    redacted = redact_text(payload)
    cache = SHA256PayloadCache()
    cache.set(payload, redacted)
    duration_ms = (time.perf_counter() - started) * 1000
    return {
        "dummy_only": True,
        "payload_bytes": len(payload.encode("utf-8")),
        "skipped_small_payload": should_skip_payload("tiny"),
        "cache_hit": cache.get(payload) == redacted,
        "duration_ms": round(duration_ms, 3),
    }


if __name__ == "__main__":
    print(run_dummy_benchmark())
