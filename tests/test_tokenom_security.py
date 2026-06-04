from __future__ import annotations

import json
from pathlib import Path

from tokenom.security.audit_logger import AuditLogger
from tokenom.security.path_policy import is_forbidden_path
from tokenom.security.payload_policy import PerformancePolicy, SHA256PayloadCache, should_skip_payload
from tokenom.security.proxy_policy import DEFAULT_PROXY_HOST, validate_proxy_host
from tokenom.security.redactor import guard_payload, redact_text


ROOT = Path(__file__).resolve().parents[1]


def _openai_key() -> str:
    return "sk-" + "A" * 32


def _github_token() -> str:
    return "ghp_" + "b" * 36


def _private_key_block() -> str:
    return "-----BEGIN " + "PRIVATE KEY-----\nabc123\n-----END " + "PRIVATE KEY-----"


def test_openai_key_redaction() -> None:
    redacted = redact_text("OPENAI_API_KEY=" + _openai_key())
    assert _openai_key() not in redacted
    assert "[REDACTED_OPENAI_API_KEY]" in redacted


def test_github_token_redaction() -> None:
    redacted = redact_text("token=" + _github_token())
    assert _github_token() not in redacted
    assert "[REDACTED_GITHUB_TOKEN]" in redacted


def test_bearer_token_redaction() -> None:
    bearer = "Bearer " + "c" * 32
    redacted = redact_text("Authorization: " + bearer)
    assert bearer not in redacted
    assert "[REDACTED_BEARER_TOKEN]" in redacted


def test_private_key_blocking() -> None:
    decision = guard_payload(_private_key_block())
    assert decision.allowed is False
    assert any("PRIVATE_KEY" in reason for reason in decision.reasons)


def test_env_path_blocking() -> None:
    decision = guard_payload("OPENAI_API_KEY=" + _openai_key(), path=".env")
    assert decision.allowed is False
    assert any("forbidden path" in reason for reason in decision.reasons)


def test_forbidden_path_blocking() -> None:
    assert is_forbidden_path("credentials/service-account.json")
    assert is_forbidden_path("local.pem")
    assert is_forbidden_path("app/node_modules/pkg/index.js")


def test_proxy_default_host_is_localhost_ip() -> None:
    decision = validate_proxy_host()
    assert DEFAULT_PROXY_HOST == "127.0.0.1"
    assert decision.allowed is True
    assert decision.host == "127.0.0.1"


def test_proxy_rejects_public_bind_by_default() -> None:
    decision = validate_proxy_host("0.0.0.0")
    assert decision.allowed is False
    assert decision.audit_event is not None


def test_raw_logs_are_not_written(tmp_path: Path) -> None:
    key = _openai_key()
    audit_path = tmp_path / "audit.jsonl"
    logger = AuditLogger(audit_path)
    logger.record_event("request", {"prompt": "key=" + key})
    content = audit_path.read_text(encoding="utf-8")
    assert key not in content
    assert "[REDACTED_OPENAI_API_KEY]" in content
    assert '"raw_payload_written": false' in content


def test_audit_json_schema_is_valid() -> None:
    audit_path = ROOT / "artifacts" / "session_audit" / "example_session_audit.json"
    payload = json.loads(audit_path.read_text(encoding="utf-8"))
    required = {
        "project",
        "based_on",
        "license_preserved",
        "proxy_local_only",
        "raw_logs_written",
        "requests_total",
        "blocked_requests",
        "secrets_detected",
        "secrets_redacted",
        "forbidden_paths_blocked",
        "production_keys_sent",
        "compression_enabled",
        "token_reduction_percent",
        "cache_hit_rate",
        "safe_to_continue",
    }
    assert required <= payload.keys()
    assert payload["project"] == "Tokenom"
    assert payload["raw_logs_written"] is False


def test_small_payload_skip_policy_exists() -> None:
    assert should_skip_payload("small", PerformancePolicy(skip_below_bytes=2048))


def test_cache_policy_exists() -> None:
    policy_path = ROOT / "config" / "performance_policy.yaml"
    policy_text = policy_path.read_text(encoding="utf-8")
    assert "enable_cache: true" in policy_text
    cache = SHA256PayloadCache()
    digest = cache.set("payload", {"ok": True})
    assert len(digest) == 64
    assert cache.get("payload") == {"ok": True}
