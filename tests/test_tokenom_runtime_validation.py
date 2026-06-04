from __future__ import annotations

from pathlib import Path

from tokenom.runtime_validation import (
    import_validation,
    path_policy_runtime_validation,
    proxy_runtime_validation,
    security_before_compression_validation,
)


def test_import_validation_records_core_blocker_honestly() -> None:
    result = import_validation()
    assert result["headroom_import_ok"] is True
    assert result["tokenom_security_import_ok"] is True
    assert result["security_guard_callable"] is True
    assert "compiled_core_import_ok" in result


def test_security_runs_before_compression_without_raw_secret_leaks(tmp_path: Path) -> None:
    result = security_before_compression_validation(tmp_path / "audit.jsonl")
    assert result["dummy_only"] is True
    assert result["network_provider_called"] is False
    assert result["security_scan_before_compression"] is True
    assert result["secrets_detected"] is True
    assert result["secrets_redacted"] is True
    assert result["private_key_blocked"] is True
    assert result["raw_secret_in_redacted_payload"] is False
    assert result["raw_secret_in_compressed_payload"] is False
    assert result["raw_secret_in_audit"] is False


def test_proxy_runtime_policy_is_local_only_and_audits_override(tmp_path: Path) -> None:
    result = proxy_runtime_validation(tmp_path / "proxy_audit.jsonl")
    assert result["proxy_default_host"] == "127.0.0.1"
    assert result["localhost_only_default"] is True
    assert result["zero_zero_zero_zero_blocked_by_default"] is True
    assert result["unsafe_override_required"] is True
    assert result["unsafe_override_audited"] is True
    assert result["raw_request_logging_default"] is False
    assert result["raw_response_logging_default"] is False


def test_path_policy_runtime_blocks_forbidden_paths() -> None:
    result = path_policy_runtime_validation()
    assert result["allowed_paths_passed"] is True
    assert result["env_file_blocked"] is True
    assert result["secrets_dir_blocked"] is True
    assert result["private_key_blocked"] is True
    assert result["git_config_blocked"] is True
    assert result["forbidden_contents_read"] is False
