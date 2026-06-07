from __future__ import annotations

import json
import socket
from pathlib import Path

from click.testing import CliRunner

from headroom.cli.main import main
from tokenom.sandbox_agent.config import FEATURE_FLAG, default_allowed_sandbox_root
from tokenom.sandbox_agent.orchestrator import SandboxAgentOrchestrator
from tokenom.sandbox_agent.provider import MockSandboxProvider

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "sandbox_agent"

RAW_DUMMY_VALUES = (
    "sk-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "tester@example.invalid",
    "Bearer CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
    "C:\\Users\\dummy-user\\sandbox",
    "DUMMY_SECRET=notarealsecretvalue",
    "password=dummyPassword123",
    "-----BEGIN PRIVATE KEY-----\nabc123\n-----END PRIVATE KEY-----",
)


def _fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _enabled_env() -> dict[str, str]:
    return {FEATURE_FLAG: "1"}


def _orchestrator(tmp_path: Path, provider: MockSandboxProvider | None = None) -> SandboxAgentOrchestrator:
    return SandboxAgentOrchestrator(
        provider=provider,
        audit_path=tmp_path / "audit.jsonl",
        allowed_roots=(default_allowed_sandbox_root(),),
        env=_enabled_env(),
    )


def test_feature_flag_default_disabled_blocks_execution(tmp_path: Path) -> None:
    provider = MockSandboxProvider()
    orchestrator = SandboxAgentOrchestrator(
        provider=provider,
        audit_path=tmp_path / "audit.jsonl",
        env={},
    )

    result = orchestrator.run(_fixture("disabled_feature_request.json"))

    assert result["status"] == "blocked"
    assert result["error"]["category"] == "sandbox_integration_disabled"
    assert result["security"]["provider_called"] is False
    assert result["runtime"]["tokenom_runtime_invoked"] is False
    assert provider.calls == 0


def test_valid_request_accepted_and_calls_runtime_provider_and_audit(tmp_path: Path) -> None:
    provider = MockSandboxProvider()
    orchestrator = _orchestrator(tmp_path, provider)

    result = orchestrator.run(_fixture("valid_sandbox_request.json"))

    assert result["status"] == "completed"
    assert result["mode"] == "sandbox"
    assert result["provider"] == "mock"
    assert result["output"]["content"] == "Mocked sandbox result"
    assert result["security"]["path_policy_passed"] is True
    assert result["security"]["external_network_used"] is False
    assert result["security"]["real_provider_used"] is False
    assert result["runtime"]["tokenom_runtime_invoked"] is True
    assert result["runtime"]["optimization_layer_invoked"] is True
    assert result["runtime"]["cache_checked"] is True
    assert provider.calls == 1
    assert (tmp_path / "audit.jsonl").exists()


def test_malformed_and_dangerous_extra_fields_are_blocked(tmp_path: Path) -> None:
    orchestrator = _orchestrator(tmp_path)

    malformed = orchestrator.run(_fixture("malformed_request.json"))
    assert malformed["status"] == "blocked"
    assert malformed["security"]["provider_called"] is False

    request = _fixture("valid_sandbox_request.json")
    request["production"] = True
    dangerous = orchestrator.run(request)
    assert dangerous["status"] == "blocked"
    assert dangerous["error"]["category"] == "dangerous_extra_field"
    assert dangerous["security"]["provider_called"] is False


def test_production_mode_and_real_provider_are_blocked_before_provider(tmp_path: Path) -> None:
    provider = MockSandboxProvider()
    orchestrator = _orchestrator(tmp_path, provider)

    production = orchestrator.run(_fixture("production_mode_request.json"))
    real_provider = orchestrator.run(_fixture("real_provider_request.json"))

    assert production["error"]["category"] == "production_mode_forbidden"
    assert real_provider["error"]["category"] == "real_provider_forbidden"
    assert production["security"]["provider_called"] is False
    assert real_provider["security"]["provider_called"] is False
    assert provider.calls == 0


def test_path_traversal_absolute_external_and_env_paths_are_blocked(tmp_path: Path) -> None:
    provider = MockSandboxProvider()
    orchestrator = _orchestrator(tmp_path, provider)

    traversal = orchestrator.run(_fixture("path_traversal_request.json"))
    assert traversal["error"]["category"] == "path_policy_violation"

    absolute = _fixture("valid_sandbox_request.json")
    absolute["workspace"]["root"] = "C:\\"
    absolute_result = orchestrator.run(absolute)
    assert absolute_result["error"]["category"] == "path_policy_violation"

    env_path = _fixture("valid_sandbox_request.json")
    env_path["workspace"]["root"] = "<repo>/tests/fixtures/sandbox_agent/workspace/.env"
    env_result = orchestrator.run(env_path)
    assert env_result["error"]["category"] == "path_policy_violation"
    assert provider.calls == 0


def test_redaction_prevents_raw_dummy_values_in_result_audit_and_logs(tmp_path: Path, caplog) -> None:
    orchestrator = _orchestrator(tmp_path)

    result = orchestrator.run(_fixture("request_with_dummy_api_key.json"))
    serialized_result = json.dumps(result, sort_keys=True)
    audit_text = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
    log_text = "\n".join(record.getMessage() for record in caplog.records)

    assert result["status"] == "completed"
    assert result["security"]["redaction_applied"] is True
    assert result["security"]["redaction_count"] >= 7
    for raw in RAW_DUMMY_VALUES:
        assert raw not in serialized_result
        assert raw not in audit_text
        assert raw not in log_text
    assert "raw_prompt_written" in audit_text
    assert "raw_response_written" in audit_text


def test_outbound_network_call_is_not_used(monkeypatch, tmp_path: Path) -> None:
    def blocked_socket(*args, **kwargs):
        raise AssertionError("sandbox integration attempted outbound network")

    monkeypatch.setattr(socket, "socket", blocked_socket)
    monkeypatch.setattr(socket, "create_connection", blocked_socket)

    result = _orchestrator(tmp_path).run(_fixture("valid_sandbox_request.json"))

    assert result["status"] == "completed"
    assert result["security"]["external_network_used"] is False


def test_repeated_identical_request_exercises_cache_consistently(tmp_path: Path) -> None:
    provider = MockSandboxProvider()
    orchestrator = _orchestrator(tmp_path, provider)
    request = _fixture("repeated_identical_request.json")

    first = orchestrator.run(request)
    second = orchestrator.run(request)

    assert first["status"] == "completed"
    assert second["status"] == "completed"
    assert first["output"] == second["output"]
    assert first["runtime"]["cache_misses"] == 1
    assert second["runtime"]["cache_hits"] == 1
    assert provider.calls == 2


def test_mock_provider_failure_is_audited_without_retry_or_leaks(tmp_path: Path) -> None:
    provider = MockSandboxProvider()
    orchestrator = _orchestrator(tmp_path, provider)

    result = orchestrator.run(_fixture("mock_provider_failure_request.json"))
    audit_text = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")

    assert result["status"] == "failed"
    assert result["error"]["category"] == "mock_provider_error"
    assert result["security"]["provider_called"] is True
    assert provider.calls == 1
    assert "mock_provider_error" in audit_text
    for raw in RAW_DUMMY_VALUES:
        assert raw not in audit_text


def test_disabling_again_restores_blocked_state(tmp_path: Path) -> None:
    enabled = _orchestrator(tmp_path)
    assert enabled.run(_fixture("valid_sandbox_request.json"))["status"] == "completed"

    disabled = SandboxAgentOrchestrator(audit_path=tmp_path / "disabled.jsonl", env={})
    result = disabled.run(_fixture("valid_sandbox_request.json"))

    assert result["status"] == "blocked"
    assert result["error"]["category"] == "sandbox_integration_disabled"
    assert result["runtime"]["tokenom_runtime_invoked"] is False


def test_cli_smoke_valid_and_blocked_modes(tmp_path: Path, monkeypatch) -> None:
    runner = CliRunner()
    monkeypatch.setenv(FEATURE_FLAG, "1")

    valid = runner.invoke(
        main,
        [
            "sandbox-agent-run",
            "--fixture",
            str(FIXTURES / "valid_sandbox_request.json"),
            "--audit-path",
            str(tmp_path / "cli-audit.jsonl"),
        ],
    )
    assert valid.exit_code == 0
    valid_payload = json.loads(valid.output)
    assert valid_payload["status"] == "completed"
    assert valid_payload["provider"] == "mock"
    assert valid_payload["security"]["provider_called_count"] == 1

    production = runner.invoke(
        main,
        [
            "sandbox-agent-run",
            "--fixture",
            str(FIXTURES / "production_mode_request.json"),
            "--audit-path",
            str(tmp_path / "cli-prod-audit.jsonl"),
        ],
    )
    assert production.exit_code == 2
    assert json.loads(production.output)["error"]["category"] == "production_mode_forbidden"

    real_provider = runner.invoke(
        main,
        [
            "sandbox-agent-run",
            "--fixture",
            str(FIXTURES / "real_provider_request.json"),
            "--audit-path",
            str(tmp_path / "cli-real-audit.jsonl"),
        ],
    )
    assert real_provider.exit_code == 2
    assert json.loads(real_provider.output)["error"]["category"] == "real_provider_forbidden"

    monkeypatch.delenv(FEATURE_FLAG)
    disabled = runner.invoke(
        main,
        [
            "sandbox-agent-run",
            "--fixture",
            str(FIXTURES / "disabled_feature_request.json"),
            "--audit-path",
            str(tmp_path / "cli-disabled-audit.jsonl"),
        ],
    )
    assert disabled.exit_code == 2
    assert json.loads(disabled.output)["error"]["category"] == "sandbox_integration_disabled"
