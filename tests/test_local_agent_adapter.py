from __future__ import annotations

import json
import socket
from pathlib import Path

from click.testing import CliRunner

from headroom.cli.main import main
from tokenom.local_agent_adapter.adapter import LocalAgentAdapter
from tokenom.local_agent_adapter.config import FEATURE_FLAG, local_agent_default_workspace_root
from tokenom.local_agent_adapter.operations import ALLOWLISTED_OPERATIONS, get_operation_spec
from tokenom.sandbox_agent.config import FEATURE_FLAG as SANDBOX_FEATURE_FLAG
from tokenom.sandbox_agent.orchestrator import SandboxAgentOrchestrator
from tokenom.sandbox_agent.provider import MockSandboxProvider

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "local_agent_adapter"

RAW_DUMMY_VALUES = (
    "sk-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "tester@example.invalid",
    "Bearer CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
    "C:\\Users\\dummy-user\\sandbox",
    "password=dummyPassword123",
)


def _fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _enabled_env() -> dict[str, str]:
    return {FEATURE_FLAG: "1", SANDBOX_FEATURE_FLAG: "1"}


def _adapter(
    tmp_path: Path,
    provider: MockSandboxProvider | None = None,
    env: dict[str, str] | None = None,
) -> tuple[LocalAgentAdapter, SandboxAgentOrchestrator, MockSandboxProvider]:
    active_provider = provider or MockSandboxProvider()
    orchestrator = SandboxAgentOrchestrator(
        provider=active_provider,
        audit_path=tmp_path / "audit.jsonl",
        allowed_roots=(local_agent_default_workspace_root(),),
        env=env if env is not None else _enabled_env(),
    )
    adapter = LocalAgentAdapter(
        orchestrator=orchestrator,
        audit_path=tmp_path / "audit.jsonl",
        allowed_roots=(local_agent_default_workspace_root(),),
        env=env if env is not None else _enabled_env(),
    )
    return adapter, orchestrator, active_provider


def test_adapter_default_disabled_blocks_before_runtime(tmp_path: Path) -> None:
    adapter, orchestrator, provider = _adapter(tmp_path, env={})

    result = adapter.execute(_fixture("adapter_disabled_request.json"))

    assert result["status"] == "blocked"
    assert result["error"]["category"] == "local_adapter_disabled"
    assert result["execution"]["sandbox_runtime_invoked"] is False
    assert result["security"]["external_network_used"] is False
    assert orchestrator.runtime_calls == 0
    assert provider.calls == 0


def test_sandbox_dependency_required_before_runtime(tmp_path: Path) -> None:
    adapter, orchestrator, provider = _adapter(tmp_path, env={FEATURE_FLAG: "1"})

    result = adapter.execute(_fixture("sandbox_dependency_disabled_request.json"))

    assert result["status"] == "blocked"
    assert result["error"]["category"] == "sandbox_dependency_disabled"
    assert result["execution"]["attempts"] == 0
    assert orchestrator.runtime_calls == 0
    assert provider.calls == 0


def test_valid_request_accepts_and_preserves_ids(tmp_path: Path) -> None:
    adapter, orchestrator, provider = _adapter(tmp_path)

    result = adapter.execute(_fixture("valid_compress_request.json"))

    assert result["status"] == "completed"
    assert result["adapter_request_id"] == "adapter-001"
    assert result["correlation_id"] == "corr-001"
    assert result["operation"] == "compress_context"
    assert result["result"]["content"] == "Mocked sandbox result"
    assert result["security"]["sandbox_enforced"] is True
    assert result["security"]["path_policy_passed"] is True
    assert result["security"]["external_network_used"] is False
    assert result["security"]["real_provider_used"] is False
    assert result["execution"]["attempts"] == 1
    assert result["execution"]["retry_executed"] is False
    assert result["execution"]["sandbox_runtime_invoked"] is True
    assert result["security"]["downstream_sandbox_audit_id"]
    assert orchestrator.runtime_calls == 1
    assert orchestrator.optimization_calls == 1
    assert provider.calls == 1


def test_malformed_unknown_fields_and_dangerous_fields_blocked(tmp_path: Path) -> None:
    adapter, orchestrator, provider = _adapter(tmp_path)

    malformed = adapter.execute(_fixture("malformed_request.json"))
    dynamic = adapter.execute(_fixture("dangerous_dynamic_execution_request.json"))
    unknown_field = _fixture("valid_compress_request.json")
    unknown_field["unexpected"] = True

    assert malformed["error"]["category"] == "malformed_request"
    assert dynamic["error"]["category"] == "dangerous_extra_field"
    assert adapter.execute(unknown_field)["error"]["category"] == "dangerous_extra_field"
    assert orchestrator.runtime_calls == 0
    assert provider.calls == 0


def test_contract_rejects_production_provider_retry_and_timeout_bounds(tmp_path: Path) -> None:
    adapter, orchestrator, provider = _adapter(tmp_path)

    production = adapter.execute(_fixture("production_mode_request.json"))
    provider_override = adapter.execute(_fixture("real_provider_override_request.json"))
    retry = _fixture("valid_compress_request.json")
    retry["execution"]["allow_retry"] = True
    too_short = _fixture("valid_compress_request.json")
    too_short["execution"]["timeout_ms"] = 99
    too_long = _fixture("valid_compress_request.json")
    too_long["execution"]["timeout_ms"] = 30001

    assert production["error"]["category"] == "production_mode_forbidden"
    assert provider_override["error"]["category"] == "private_or_production_flag_forbidden"
    assert adapter.execute(retry)["error"]["category"] == "retry_forbidden"
    assert adapter.execute(too_short)["error"]["category"] == "timeout_policy_violation"
    assert adapter.execute(too_long)["error"]["category"] == "timeout_policy_violation"
    assert orchestrator.runtime_calls == 0
    assert provider.calls == 0


def test_operation_registry_blocks_arbitrary_execution_before_runtime(tmp_path: Path) -> None:
    adapter, orchestrator, provider = _adapter(tmp_path)

    assert sorted(ALLOWLISTED_OPERATIONS) == [
        "compress_context",
        "inspect_payload_safely",
        "sandbox_health",
    ]
    assert get_operation_spec("compress_context").invokes_tokenom_runtime is True
    assert get_operation_spec("sandbox_health").invokes_tokenom_runtime is False
    assert get_operation_spec("__import__") is None
    assert get_operation_spec("os.system") is None

    unknown = adapter.execute(_fixture("unknown_operation_request.json"))
    arbitrary = _fixture("valid_compress_request.json")
    arbitrary["operation"] = "os.system"

    assert unknown["error"]["category"] == "unsupported_operation"
    assert adapter.execute(arbitrary)["error"]["category"] == "unsupported_operation"
    assert orchestrator.runtime_calls == 0
    assert provider.calls == 0


def test_inspect_operation_uses_same_sandbox_boundary(tmp_path: Path) -> None:
    adapter, orchestrator, provider = _adapter(tmp_path)

    result = adapter.execute(_fixture("valid_inspect_request.json"))

    assert result["status"] == "completed"
    assert result["operation"] == "inspect_payload_safely"
    assert result["execution"]["sandbox_runtime_invoked"] is True
    assert orchestrator.runtime_calls == 1
    assert provider.calls == 1


def test_health_operation_is_read_only_without_runtime(tmp_path: Path) -> None:
    adapter, orchestrator, provider = _adapter(tmp_path)

    result = adapter.execute(_fixture("valid_health_request.json"))

    assert result["status"] == "completed"
    assert result["operation"] == "sandbox_health"
    assert result["result"]["content"] == "sandbox adapter health ok"
    assert result["execution"]["attempts"] == 0
    assert result["execution"]["sandbox_runtime_invoked"] is False
    assert orchestrator.runtime_calls == 0
    assert provider.calls == 0


def test_path_policy_blocks_traversal_external_and_env_paths(tmp_path: Path) -> None:
    adapter, orchestrator, provider = _adapter(tmp_path)

    traversal = adapter.execute(_fixture("path_traversal_request.json"))
    external = _fixture("valid_compress_request.json")
    external["workspace"]["root"] = "C:\\"
    env_path = _fixture("valid_compress_request.json")
    env_path["workspace"]["root"] = "<repo>/tests/fixtures/local_agent_adapter/workspace/.env"

    assert traversal["error"]["category"] == "path_policy_violation"
    assert adapter.execute(external)["error"]["category"] == "path_policy_violation"
    assert adapter.execute(env_path)["error"]["category"] == "path_policy_violation"
    assert orchestrator.runtime_calls == 0
    assert provider.calls == 0


def test_dummy_secrets_absent_from_result_audit_and_logs(tmp_path: Path, caplog) -> None:
    adapter, _, _ = _adapter(tmp_path)

    result = adapter.execute(_fixture("request_with_dummy_secrets.json"))
    serialized_result = json.dumps(result, sort_keys=True)
    audit_text = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
    log_text = "\n".join(record.getMessage() for record in caplog.records)

    assert result["status"] == "completed"
    assert result["security"]["redaction_applied"] is True
    for raw in RAW_DUMMY_VALUES:
        assert raw not in serialized_result
        assert raw not in audit_text
        assert raw not in log_text
    assert "payload_sha256" in audit_text
    assert "raw_payload_written" in audit_text
    assert "raw_output_written" in audit_text


def test_oversized_payload_blocks_before_runtime_and_audits_hash_only(tmp_path: Path) -> None:
    adapter, orchestrator, provider = _adapter(tmp_path)
    request = _fixture("oversized_payload_request.json")
    request["payload"]["content"] = "x" * 263000

    result = adapter.execute(request)
    audit_text = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")

    assert result["status"] == "blocked"
    assert result["error"]["category"] == "payload_too_large"
    assert result["execution"]["attempts"] == 0
    assert orchestrator.runtime_calls == 0
    assert provider.calls == 0
    assert "payload_sha256" in audit_text
    assert "x" * 128 not in audit_text


def test_timeout_is_controlled_single_attempt_without_retry(tmp_path: Path) -> None:
    adapter, orchestrator, provider = _adapter(tmp_path)

    result = adapter.execute(_fixture("timeout_simulation_request.json"))
    audit_text = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")

    assert result["status"] == "timeout"
    assert result["error"]["category"] == "mock_provider_timeout"
    assert result["execution"]["attempts"] == 1
    assert result["execution"]["timed_out"] is True
    assert result["execution"]["automatic_retry"] is False
    assert result["execution"]["blind_retry"] is False
    assert result["execution"]["execution_after_timeout"] is False
    assert orchestrator.runtime_calls == 1
    assert provider.calls == 1
    assert "controlled_timeout" in audit_text


def test_cancellation_stops_before_downstream_execution(tmp_path: Path) -> None:
    adapter, orchestrator, provider = _adapter(tmp_path)

    result = adapter.execute(_fixture("cancellation_simulation_request.json"))
    audit_text = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")

    assert result["status"] == "cancelled"
    assert result["error"]["category"] == "request_cancelled"
    assert result["execution"]["attempts"] == 0
    assert result["execution"]["cancelled"] is True
    assert result["execution"]["sandbox_runtime_invoked"] is False
    assert orchestrator.runtime_calls == 0
    assert provider.calls == 0
    assert "request_cancelled_before_downstream_execution" in audit_text


def test_no_outbound_network_or_listener_created(monkeypatch, tmp_path: Path) -> None:
    def blocked_socket(*args, **kwargs):
        raise AssertionError("local agent adapter attempted network I/O")

    monkeypatch.setattr(socket, "socket", blocked_socket)
    monkeypatch.setattr(socket, "create_connection", blocked_socket)

    adapter, _, _ = _adapter(tmp_path)
    result = adapter.execute(_fixture("valid_compress_request.json"))

    assert result["status"] == "completed"
    assert result["transport"]["public_listener_created"] is False
    assert result["transport"]["remote_transport_available"] is False
    assert result["transport"]["outbound_network_requests"] == 0
    assert result["transport"]["localhost_http_server_started"] is False
    assert result["transport"]["background_daemon_started"] is False


def test_rollback_disables_execution_after_enabled_flow(tmp_path: Path) -> None:
    enabled_adapter, _, _ = _adapter(tmp_path)
    assert enabled_adapter.execute(_fixture("valid_compress_request.json"))["status"] == "completed"

    disabled_adapter, disabled_orchestrator, disabled_provider = _adapter(
        tmp_path / "disabled",
        env={SANDBOX_FEATURE_FLAG: "1"},
    )
    result = disabled_adapter.execute(_fixture("valid_compress_request.json"))

    assert result["status"] == "blocked"
    assert result["error"]["category"] == "local_adapter_disabled"
    assert disabled_orchestrator.runtime_calls == 0
    assert disabled_provider.calls == 0


def test_cli_smoke_valid_blocked_and_disabled(tmp_path: Path, monkeypatch) -> None:
    runner = CliRunner()
    monkeypatch.setenv(FEATURE_FLAG, "1")
    monkeypatch.setenv(SANDBOX_FEATURE_FLAG, "1")

    valid = runner.invoke(
        main,
        [
            "local-agent-run",
            "--fixture",
            str(FIXTURES / "valid_compress_request.json"),
            "--audit-path",
            str(tmp_path / "cli-audit.jsonl"),
        ],
    )
    assert valid.exit_code == 0
    assert json.loads(valid.output)["status"] == "completed"

    blocked = runner.invoke(
        main,
        [
            "local-agent-run",
            "--fixture",
            str(FIXTURES / "unknown_operation_request.json"),
            "--audit-path",
            str(tmp_path / "cli-blocked-audit.jsonl"),
        ],
    )
    assert blocked.exit_code == 2
    assert json.loads(blocked.output)["error"]["category"] == "unsupported_operation"

    monkeypatch.delenv(FEATURE_FLAG)
    disabled = runner.invoke(
        main,
        [
            "local-agent-run",
            "--fixture",
            str(FIXTURES / "adapter_disabled_request.json"),
            "--audit-path",
            str(tmp_path / "cli-disabled-audit.jsonl"),
        ],
    )
    assert disabled.exit_code == 2
    disabled_payload = json.loads(disabled.output)
    assert disabled_payload["error"]["category"] == "local_adapter_disabled"
    assert "sk-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" not in disabled.output


def test_cli_uses_shared_adapter_service(monkeypatch, tmp_path: Path) -> None:
    import headroom.cli.local_agent_adapter as cli_module

    calls: list[dict] = []

    class StubAdapter:
        def __init__(self, *, audit_path):
            self.audit_path = audit_path

        def execute(self, request):
            calls.append(request)
            return {
                "adapter_request_id": "stub",
                "correlation_id": "stub",
                "status": "completed",
                "operation": "sandbox_health",
                "result": {"content": "stub"},
                "security": {},
                "execution": {},
                "audit_id": None,
            }

    monkeypatch.setattr(cli_module, "LocalAgentAdapter", StubAdapter)
    result = CliRunner().invoke(
        main,
        [
            "local-agent-run",
            "--fixture",
            str(FIXTURES / "valid_health_request.json"),
            "--audit-path",
            str(tmp_path / "stub-audit.jsonl"),
        ],
    )

    assert result.exit_code == 0
    assert calls and calls[0]["operation"] == "sandbox_health"
