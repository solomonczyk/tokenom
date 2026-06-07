from __future__ import annotations

import json
import shutil
import socket
import subprocess
from pathlib import Path

import pytest
from click.testing import CliRunner

from headroom.cli.main import main
from tokenom.local_agent_adapter.config import FEATURE_FLAG as LOCAL_ADAPTER_FEATURE_FLAG
from tokenom.local_developer_tool.config import FEATURE_FLAG, default_fixture_repository_root
from tokenom.local_developer_tool.operations import ALLOWLISTED_OPERATIONS, get_operation_spec
from tokenom.local_developer_tool.service import LocalDeveloperToolService
from tokenom.sandbox_agent.config import FEATURE_FLAG as SANDBOX_FEATURE_FLAG

ROOT = Path(__file__).resolve().parents[1]
REQUESTS = ROOT / "tests" / "fixtures" / "local_developer_tool" / "requests"
FIXTURE_REPO = ROOT / "tests" / "fixtures" / "local_developer_tool" / "repository"

RAW_DUMMY_VALUES = (
    "sk-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "Bearer CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
    "dummyPassword123",
    "DUMMY_SECRET=notarealsecretvalue",
    "-----BEGIN PRIVATE KEY-----",
)


def _fixture(name: str) -> dict:
    return json.loads((REQUESTS / name).read_text(encoding="utf-8"))


def _enabled_env() -> dict[str, str]:
    return {
        FEATURE_FLAG: "1",
        LOCAL_ADAPTER_FEATURE_FLAG: "1",
        SANDBOX_FEATURE_FLAG: "1",
    }


def _service(tmp_path: Path, *, env: dict[str, str] | None = None, allowed_roots: tuple[Path, ...] | None = None) -> LocalDeveloperToolService:
    return LocalDeveloperToolService(
        audit_path=tmp_path / "audit.jsonl",
        manifest_dir=tmp_path / "manifests",
        allowed_roots=allowed_roots or (default_fixture_repository_root(),),
        env=env if env is not None else _enabled_env(),
    )


def _request_for(root: Path, *, operation: str = "build_context_bundle") -> dict:
    request = _fixture("valid_request.json")
    request["operation"] = operation
    request["repository"]["root"] = str(root)
    return request


def _copy_fixture_repo(tmp_path: Path) -> Path:
    target = tmp_path / "repo"
    shutil.copytree(FIXTURE_REPO, target)
    return target


def _init_git_repo(repo: Path) -> None:
    subprocess.run(["git", "init", "-b", "main"], cwd=repo, check=True, capture_output=True, text=True)
    subprocess.run(["git", "config", "user.email", "dummy@example.invalid"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "Dummy User"], cwd=repo, check=True)
    subprocess.run(["git", "add", "-A", "-f"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-m", "fixture"], cwd=repo, check=True, capture_output=True, text=True)


def test_operation_registry_is_closed() -> None:
    assert sorted(ALLOWLISTED_OPERATIONS) == [
        "build_context_bundle",
        "developer_tool_health",
        "inspect_repository_safely",
    ]
    assert get_operation_spec("build_context_bundle").invokes_local_agent_adapter is True
    assert get_operation_spec("inspect_repository_safely").invokes_local_agent_adapter is False
    assert get_operation_spec("os.system") is None


def test_feature_flag_default_disabled_blocks_before_scan(tmp_path: Path) -> None:
    service = _service(tmp_path, env={LOCAL_ADAPTER_FEATURE_FLAG: "1", SANDBOX_FEATURE_FLAG: "1"})

    result = service.execute(_fixture("disabled_request.json"))

    assert result["status"] == "blocked"
    assert result["error"]["category"] == "local_developer_tool_disabled"
    assert result["proof"]["repository_scan_executed"] is False
    assert result["proof"]["adapter_invocations"] == 0
    assert result["execution"]["attempts"] == 0


def test_dependency_gates_block_before_repository_scan(tmp_path: Path) -> None:
    missing_adapter = _service(tmp_path / "adapter", env={FEATURE_FLAG: "1", SANDBOX_FEATURE_FLAG: "1"})
    missing_sandbox = _service(tmp_path / "sandbox", env={FEATURE_FLAG: "1", LOCAL_ADAPTER_FEATURE_FLAG: "1"})

    adapter_result = missing_adapter.execute(_fixture("valid_request.json"))
    sandbox_result = missing_sandbox.execute(_fixture("valid_request.json"))

    assert adapter_result["error"]["category"] == "local_agent_adapter_disabled"
    assert sandbox_result["error"]["category"] == "sandbox_dependency_disabled"
    assert adapter_result["proof"]["repository_scan_executed"] is False
    assert sandbox_result["proof"]["repository_scan_executed"] is False


def test_valid_context_build_delegates_to_adapter_sandbox_and_runtime(tmp_path: Path) -> None:
    service = _service(tmp_path)

    result = service.execute(_fixture("valid_request.json"))

    assert result["status"] == "completed"
    assert result["operation"] == "build_context_bundle"
    assert result["bundle"]["selected_files"] >= 4
    assert result["bundle"]["compression_applied"] is True
    assert result["security"]["repository_boundary_passed"] is True
    assert result["security"]["secret_scan_passed"] is True
    assert result["security"]["external_network_used"] is False
    assert result["security"]["real_provider_used"] is False
    assert result["execution"]["attempts"] == 1
    assert result["execution"]["retry_executed"] is False
    assert result["downstream_adapter_audit_id"]
    assert result["proof"]["local_adapter_invocations"] == 1
    assert result["proof"]["sandbox_orchestrator_invocations"] == 1
    assert result["proof"]["runtime_invocations"] == 1
    assert result["proof"]["real_provider_requests"] == 0
    assert result["proof"]["external_network_requests"] == 0


def test_result_manifest_and_audit_do_not_leak_raw_source_or_secrets(tmp_path: Path, caplog) -> None:
    service = _service(tmp_path)

    result = service.execute(_fixture("valid_request.json"))
    manifest = tmp_path / "manifests" / f"{result['bundle']['bundle_id']}.json"
    manifest_text = manifest.read_text(encoding="utf-8")
    audit_text = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
    serialized_result = json.dumps(result, sort_keys=True)
    log_text = "\n".join(record.getMessage() for record in caplog.records)

    assert manifest.exists()
    assert result["manifest_path"].startswith("artifacts/local_developer_tool_runtime/manifests/")
    assert '"raw_source_written": false' in manifest_text.lower()
    assert '"raw_secret_written": false' in manifest_text.lower()
    for raw in RAW_DUMMY_VALUES:
        assert raw not in serialized_result
        assert raw not in manifest_text
        assert raw not in audit_text
        assert raw not in log_text
    assert "src/app.py" in manifest_text
    assert "content" not in json.loads(manifest_text)["selected_files"][0]


def test_inspect_repository_returns_safe_metadata_without_adapter(tmp_path: Path) -> None:
    service = _service(tmp_path)

    result = service.execute(_fixture("inspect_request.json"))

    assert result["status"] == "completed"
    assert result["operation"] == "inspect_repository_safely"
    assert result["inspection"]["file_categories"]["selected_text"] >= 4
    assert result["proof"]["local_adapter_invocations"] == 0
    assert result["proof"]["runtime_invocations"] == 0
    assert "inspection" in result
    for raw in RAW_DUMMY_VALUES:
        assert raw not in json.dumps(result, sort_keys=True)


def test_health_does_not_scan_or_invoke_dependencies(tmp_path: Path) -> None:
    request = _fixture("valid_request.json")
    request["operation"] = "developer_tool_health"
    service = _service(tmp_path, env={})

    result = service.execute(request)

    assert result["status"] == "completed"
    assert result["proof"]["repository_scan_executed"] is False
    assert result["proof"]["adapter_invocations"] == 0
    assert result["proof"]["runtime_invocations"] == 0


@pytest.mark.parametrize(
    ("mutate", "reason"),
    [
        (lambda r: r.update({"unexpected": True}), "dangerous_extra_field"),
        (lambda r: r.__setitem__("mode", "production"), "production_mode_forbidden"),
        (lambda r: r.__setitem__("operation", "os.system"), "unsupported_operation"),
        (lambda r: r["execution"].__setitem__("allow_retry", True), "retry_forbidden"),
        (lambda r: r["repository"]["include"].__setitem__(0, "../secret.py"), "invalid_include_patterns"),
        (lambda r: r["repository"]["include"].__setitem__(0, "C:/secret.py"), "invalid_include_patterns"),
        (lambda r: r["context"].__setitem__("max_files", 201), "context_limit_violation"),
    ],
)
def test_contract_rejects_invalid_requests_before_runtime(tmp_path: Path, mutate, reason: str) -> None:
    request = _fixture("valid_request.json")
    mutate(request)
    service = _service(tmp_path)

    result = service.execute(request)

    assert result["status"] == "blocked"
    assert result["error"]["category"] == reason
    assert result["proof"]["adapter_invocations"] == 0
    assert result["proof"]["runtime_invocations"] == 0


def test_repository_boundary_blocks_parent_sibling_drive_user_and_unc(tmp_path: Path) -> None:
    repo = _copy_fixture_repo(tmp_path)
    service = _service(tmp_path / "audit", allowed_roots=(repo,))

    parent = _request_for(repo.parent)
    sibling = _request_for(tmp_path / "sibling")
    drive = _request_for(Path(repo.anchor))
    unc = _request_for(repo)
    unc["repository"]["root"] = "\\\\server\\share\\repo"

    assert service.execute(parent)["error"]["category"] == "repository_boundary_violation"
    assert service.execute(sibling)["error"]["category"] == "repository_boundary_violation"
    assert service.execute(drive)["error"]["category"] == "repository_boundary_violation"
    assert service.execute(unc)["error"]["category"] == "repository_boundary_violation"


def test_mandatory_exclusions_binary_and_limits_are_enforced(tmp_path: Path) -> None:
    repo = _copy_fixture_repo(tmp_path)
    (repo / "many").mkdir()
    for index in range(4):
        (repo / "many" / f"{index}.py").write_text(f"VALUE = {index}\n", encoding="utf-8")
    (repo / "nul.txt").write_bytes(b"abc\x00def")
    request = _request_for(repo)
    request["repository"]["include"] = ["**/*", "*.txt", "many/*.py"]
    request["context"]["max_files"] = 2
    request["context"]["max_bundle_bytes"] = 80
    service = _service(tmp_path / "audit", allowed_roots=(repo,))

    result = service.execute(request)
    manifest = json.loads((tmp_path / "audit" / "manifests" / f"{result['bundle']['bundle_id']}.json").read_text(encoding="utf-8"))
    reasons = {item["reason"] for item in manifest["excluded_files"]}

    assert result["status"] == "completed"
    assert result["bundle"]["selected_files"] <= 2
    assert any(reason.startswith("mandatory_exclusion:.env") for reason in reasons)
    assert any(reason.startswith("mandatory_exclusion:*.key") for reason in reasons)
    assert any(reason.startswith("mandatory_exclusion:*.bin") for reason in reasons)
    assert "max_files_truncated" in reasons or "max_bundle_bytes_truncated" in reasons


def test_max_file_bytes_excludes_oversized_file_before_full_read(tmp_path: Path) -> None:
    repo = _copy_fixture_repo(tmp_path)
    (repo / "src" / "oversized.py").write_text("x" * 2048, encoding="utf-8")
    request = _request_for(repo)
    request["repository"]["include"] = ["src/*.py"]
    request["context"]["max_file_bytes"] = 128
    service = _service(tmp_path / "audit", allowed_roots=(repo,))

    result = service.execute(request)
    manifest = json.loads((tmp_path / "audit" / "manifests" / f"{result['bundle']['bundle_id']}.json").read_text(encoding="utf-8"))

    assert any(item["path"] == "src/oversized.py" and item["reason"] == "max_file_bytes_exceeded" for item in manifest["excluded_files"])


def test_symlink_escape_is_blocked_where_supported(tmp_path: Path) -> None:
    repo = _copy_fixture_repo(tmp_path)
    outside = tmp_path / "outside.txt"
    outside.write_text("outside secret", encoding="utf-8")
    link = repo / "src" / "escape.txt"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("symlink creation is unavailable in this Windows environment")
    request = _request_for(repo)
    request["repository"]["include"] = ["src/*.txt", "src/**/*.txt"]
    service = _service(tmp_path / "audit", allowed_roots=(repo,))

    result = service.execute(request)
    manifest = json.loads((tmp_path / "audit" / "manifests" / f"{result['bundle']['bundle_id']}.json").read_text(encoding="utf-8"))

    assert any(item["path"] == "src/escape.txt" and item["reason"] == "symlink_or_junction_escape" for item in manifest["excluded_files"])


def test_git_metadata_is_read_only_and_dirty_status_detected(tmp_path: Path) -> None:
    repo = _copy_fixture_repo(tmp_path)
    _init_git_repo(repo)
    (repo / "untracked.txt").write_text("untracked", encoding="utf-8")
    service = _service(tmp_path / "audit", allowed_roots=(repo,))

    result = service.execute(_request_for(repo, operation="inspect_repository_safely"))

    assert result["repository"]["branch"] == "main"
    assert result["repository"]["head"] != "unknown"
    assert result["repository"]["dirty"] is True
    assert result["inspection"]["git"]["untracked_count"] == 1
    assert result["inspection"]["git"]["git_mutation_commands_executed"] is False
    assert result["inspection"]["git"]["git_network_commands_executed"] is False


def test_cancellation_stops_before_scan_and_downstream(tmp_path: Path) -> None:
    request = _fixture("valid_request.json")
    request["execution"]["cancelled"] = True
    service = _service(tmp_path)

    result = service.execute(request)

    assert result["status"] == "cancelled"
    assert result["error"]["category"] == "request_cancelled"
    assert result["proof"]["repository_scan_executed"] is False
    assert result["execution"]["attempts"] == 0


def test_no_network_or_listener_created(monkeypatch, tmp_path: Path) -> None:
    def blocked_socket(*args, **kwargs):
        raise AssertionError("local developer tool attempted network I/O")

    monkeypatch.setattr(socket, "socket", blocked_socket)
    monkeypatch.setattr(socket, "create_connection", blocked_socket)
    service = _service(tmp_path)

    result = service.execute(_fixture("valid_request.json"))

    assert result["status"] == "completed"
    assert result["security"]["external_network_used"] is False
    assert result["security"]["real_provider_used"] is False


def test_rollback_disables_execution_after_enabled_flow(tmp_path: Path) -> None:
    enabled = _service(tmp_path / "enabled")
    assert enabled.execute(_fixture("valid_request.json"))["status"] == "completed"

    disabled = _service(tmp_path / "disabled", env={LOCAL_ADAPTER_FEATURE_FLAG: "1", SANDBOX_FEATURE_FLAG: "1"})
    result = disabled.execute(_fixture("valid_request.json"))

    assert result["status"] == "blocked"
    assert result["error"]["category"] == "local_developer_tool_disabled"
    assert result["proof"]["repository_scan_executed"] is False
    assert result["proof"]["adapter_invocations"] == 0
    assert result["proof"]["runtime_invocations"] == 0


def test_cli_smoke_valid_traversal_secret_disabled_and_health(tmp_path: Path, monkeypatch) -> None:
    runner = CliRunner()
    monkeypatch.setenv(FEATURE_FLAG, "1")
    monkeypatch.setenv(LOCAL_ADAPTER_FEATURE_FLAG, "1")
    monkeypatch.setenv(SANDBOX_FEATURE_FLAG, "1")

    valid = runner.invoke(
        main,
        [
            "local-dev-tool",
            "run",
            "--request",
            str(REQUESTS / "valid_request.json"),
            "--audit-path",
            str(tmp_path / "cli-audit.jsonl"),
            "--manifest-dir",
            str(tmp_path / "cli-manifests"),
        ],
    )
    assert valid.exit_code == 0
    valid_payload = json.loads(valid.output)
    assert valid_payload["status"] == "completed"
    assert valid_payload["proof"]["local_adapter_invocations"] == 1
    for raw in RAW_DUMMY_VALUES:
        assert raw not in valid.output

    traversal = runner.invoke(
        main,
        [
            "local-dev-tool",
            "run",
            "--request",
            str(REQUESTS / "traversal_request.json"),
            "--audit-path",
            str(tmp_path / "cli-traversal-audit.jsonl"),
            "--manifest-dir",
            str(tmp_path / "cli-traversal-manifests"),
        ],
    )
    assert traversal.exit_code == 2
    assert json.loads(traversal.output)["error"]["category"] == "repository_boundary_violation"

    monkeypatch.delenv(FEATURE_FLAG)
    disabled = runner.invoke(
        main,
        [
            "local-dev-tool",
            "run",
            "--request",
            str(REQUESTS / "disabled_request.json"),
            "--audit-path",
            str(tmp_path / "cli-disabled-audit.jsonl"),
            "--manifest-dir",
            str(tmp_path / "cli-disabled-manifests"),
        ],
    )
    assert disabled.exit_code == 2
    assert json.loads(disabled.output)["error"]["category"] == "local_developer_tool_disabled"

    health = runner.invoke(main, ["local-dev-tool", "health", "--audit-path", str(tmp_path / "health.jsonl")])
    assert health.exit_code == 0
    assert json.loads(health.output)["proof"]["repository_scan_executed"] is False


def test_cli_uses_shared_service(monkeypatch, tmp_path: Path) -> None:
    import headroom.cli.local_developer_tool as cli_module

    calls: list[dict] = []

    class StubService:
        def __init__(self, *, audit_path, manifest_dir=None):
            self.audit_path = audit_path
            self.manifest_dir = manifest_dir

        def execute(self, request):
            calls.append(request)
            return {
                "tool_request_id": "stub",
                "correlation_id": "stub",
                "status": "completed",
                "operation": "developer_tool_health",
                "repository": {},
                "bundle": {},
                "security": {},
                "execution": {},
                "audit_id": None,
            }

    monkeypatch.setattr(cli_module, "LocalDeveloperToolService", StubService)
    result = CliRunner().invoke(
        main,
        [
            "local-dev-tool",
            "run",
            "--request",
            str(REQUESTS / "valid_request.json"),
            "--audit-path",
            str(tmp_path / "stub-audit.jsonl"),
        ],
    )

    assert result.exit_code == 0
    assert calls and calls[0]["operation"] == "build_context_bundle"
