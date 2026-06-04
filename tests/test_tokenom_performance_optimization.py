from __future__ import annotations

from tokenom.security.payload_policy import CachedPayloadGuard, PerformancePolicy
from tokenom.security.redactor import guard_payload


def _openai_key() -> str:
    return "sk-" + "A" * 32


def _openai_key_assignment() -> str:
    return "OPENAI" + "_API_KEY=" + _openai_key()


def test_guard_payload_scans_once_for_redaction(monkeypatch) -> None:
    from tokenom.security import redactor

    calls = 0
    original_scan_text = redactor.scan_text

    def counted_scan_text(*args, **kwargs):
        nonlocal calls
        calls += 1
        return original_scan_text(*args, **kwargs)

    monkeypatch.setattr(redactor, "scan_text", counted_scan_text)

    decision = guard_payload(_openai_key_assignment())

    assert decision.allowed is True
    assert _openai_key() not in decision.payload
    assert "[REDACTED_OPENAI_API_KEY]" in decision.payload
    assert calls == 1


def test_cached_payload_guard_reuses_identical_decision(monkeypatch) -> None:
    from tokenom.security import redactor

    calls = 0
    original_scan_text = redactor.scan_text

    def counted_scan_text(*args, **kwargs):
        nonlocal calls
        calls += 1
        return original_scan_text(*args, **kwargs)

    monkeypatch.setattr(redactor, "scan_text", counted_scan_text)
    cached_guard = CachedPayloadGuard()
    payload = _openai_key_assignment()

    first = cached_guard.guard(payload)
    second = cached_guard.guard(payload)
    stats = cached_guard.stats()

    assert first == second
    assert calls == 1
    assert stats.hits == 1
    assert stats.misses == 1
    assert stats.stores == 1
    assert stats.entries == 1
    assert stats.hit_rate == 0.5


def test_cached_payload_guard_keys_path_and_mode() -> None:
    cached_guard = CachedPayloadGuard()
    payload = "plain dummy payload"

    allowed = cached_guard.guard(payload)
    forbidden = cached_guard.guard(payload, path=".env")
    blocked_mode = cached_guard.guard(payload, mode="block")

    assert allowed.allowed is True
    assert forbidden.allowed is False
    assert any("forbidden path" in reason for reason in forbidden.reasons)
    assert blocked_mode.allowed is True
    assert cached_guard.stats().misses == 3


def test_cached_payload_guard_can_be_disabled() -> None:
    cached_guard = CachedPayloadGuard(PerformancePolicy(enable_cache=False))
    payload = _openai_key_assignment()

    cached_guard.guard(payload)
    cached_guard.guard(payload)

    stats = cached_guard.stats()
    assert stats.hits == 0
    assert stats.misses == 2
    assert stats.stores == 0
    assert stats.entries == 0
