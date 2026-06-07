from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from click.testing import CliRunner

from headroom.cli.main import main
from tokenom.local_agent_adapter.config import FEATURE_FLAG as LOCAL_ADAPTER_FEATURE_FLAG
from tokenom.local_daily_workflow.config import FEATURE_FLAG, WORKFLOW_HOME_ENV, default_profile
from tokenom.local_daily_workflow.history import HistoryStore
from tokenom.local_daily_workflow.profile_registry import (
    ProfileRegistry,
    ProfileValidationError,
    RegistryCorruptionError,
)
from tokenom.local_daily_workflow.service import DailyWorkflowService
from tokenom.local_developer_tool.config import FEATURE_FLAG as LOCAL_DEVELOPER_TOOL_FEATURE_FLAG
from tokenom.sandbox_agent.config import FEATURE_FLAG as SANDBOX_FEATURE_FLAG

ROOT = Path(__file__).resolve().parents[1]
FIXTURE_REPO = ROOT / "tests" / "fixtures" / "local_developer_tool" / "repository"
RAW_DUMMY_VALUES = (
    "sk-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "Bearer CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
    "dummyPassword123",
    "DUMMY_SECRET=notarealsecretvalue",
    "-----BEGIN PRIVATE KEY-----",
)


def _enabled_env(home: Path) -> dict[str, str]:
    return {
        WORKFLOW_HOME_ENV: str(home),
        FEATURE_FLAG: "1",
        LOCAL_DEVELOPER_TOOL_FEATURE_FLAG: "1",
        LOCAL_ADAPTER_FEATURE_FLAG: "1",
        SANDBOX_FEATURE_FLAG: "1",
    }


def _copy_git_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    shutil.copytree(FIXTURE_REPO, repo)
    subprocess.run(["git", "init", "-b", "main"], cwd=repo, check=True, capture_output=True, text=True)
    subprocess.run(["git", "config", "user.email", "daily@example.invalid"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "Daily Workflow"], cwd=repo, check=True)
    subprocess.run(["git", "add", "-A", "-f"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-m", "fixture"], cwd=repo, check=True, capture_output=True, text=True)
    return repo


def _profile(root: Path, *, enabled: bool = False) -> dict:
    profile = default_profile()
    profile["enabled"] = enabled
    profile["repository"] = {
        "root": str(root),
        "approved": True,
        "include": ["src/*.py", "src/**/*.json", "src/**/*.txt", "README.md"],
        "exclude": ["tests/generated/**"],
    }
    return profile


def _write_registry(path: Path, profiles: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"version": 1, "profiles": profiles}, indent=2), encoding="utf-8")


def _service(tmp_path: Path, repo: Path, *, enabled: bool = False, env: dict[str, str] | None = None) -> DailyWorkflowService:
    home = tmp_path / "home"
    registry_path = home / "profiles.json"
    _write_registry(registry_path, [_profile(repo, enabled=enabled)])
    active_env = env if env is not None else ({WORKFLOW_HOME_ENV: str(home)} if not enabled else _enabled_env(home))
    return DailyWorkflowService(
        registry=ProfileRegistry(registry_path, env=active_env),
        history=HistoryStore(home / "history", env=active_env),
        env=active_env,
        manifest_dir=tmp_path / "manifests",
    )


def test_profile_registry_validates_default_disabled_and_safe_schema(tmp_path: Path) -> None:
    registry = ProfileRegistry(tmp_path / "profiles.json", env={WORKFLOW_HOME_ENV: str(tmp_path)})

    profiles = registry.list_profiles()

    assert len(profiles) == 1
    assert profiles[0].profile_id == "tokenom-safe"
    assert profiles[0].enabled is False
    assert "root" not in profiles[0].to_safe_dict()["repository"]
    assert registry.validate()["valid"] is True


def test_profile_registry_blocks_duplicate_unknown_dangerous_limits_and_invalid_root(tmp_path: Path) -> None:
    repo = _copy_git_repo(tmp_path)
    registry_path = tmp_path / "home" / "profiles.json"
    duplicate = [_profile(repo), _profile(repo)]
    _write_registry(registry_path, duplicate)
    registry = ProfileRegistry(registry_path)

    try:
        registry.list_profiles()
        raise AssertionError("duplicate profile was accepted")
    except ProfileValidationError as exc:
        assert str(exc) == "duplicate_profile_id"

    bad = _profile(repo)
    bad["unexpected"] = True
    _write_registry(registry_path, [bad])
    try:
        registry.list_profiles()
        raise AssertionError("unknown field was accepted")
    except ProfileValidationError as exc:
        assert str(exc) == "unknown_profile_field"

    bad = _profile(repo)
    bad["provider"] = "real"
    _write_registry(registry_path, [bad])
    try:
        registry.list_profiles()
        raise AssertionError("provider field was accepted")
    except ProfileValidationError as exc:
        assert str(exc) in {"unknown_profile_field", "production_provider_or_shell_field_forbidden"}

    bad = _profile(repo)
    bad["limits"]["max_files"] = 999
    _write_registry(registry_path, [bad])
    try:
        registry.list_profiles()
        raise AssertionError("excessive limits were accepted")
    except ProfileValidationError as exc:
        assert str(exc) == "limits_exceed_policy"

    bad = _profile(tmp_path / "missing")
    _write_registry(registry_path, [bad])
    try:
        registry.list_profiles()
        raise AssertionError("missing root was accepted")
    except ProfileValidationError as exc:
        assert str(exc) == "invalid_repository_root"


def test_corrupted_registry_detected_and_atomic_update(tmp_path: Path) -> None:
    repo = _copy_git_repo(tmp_path)
    registry_path = tmp_path / "home" / "profiles.json"
    registry_path.parent.mkdir(parents=True)
    registry_path.write_text("{bad json", encoding="utf-8")
    registry = ProfileRegistry(registry_path)

    try:
        registry.list_profiles()
        raise AssertionError("corrupted registry was accepted")
    except RegistryCorruptionError as exc:
        assert str(exc) == "registry_corrupted"

    _write_registry(registry_path, [_profile(repo)])
    enabled = registry.enable("tokenom-safe")

    assert enabled.enabled is True
    assert not list(registry_path.parent.glob("*.tmp"))
    assert json.loads(registry_path.read_text(encoding="utf-8"))["profiles"][0]["enabled"] is True


def test_preflight_gates_and_no_repository_scan_before_gates_pass(tmp_path: Path) -> None:
    repo = _copy_git_repo(tmp_path)
    home = tmp_path / "home"
    env = _enabled_env(home)
    service = _service(tmp_path, repo, enabled=True, env=env)

    ready = service.preflight("tokenom-safe")
    assert ready["ready"] is True

    disabled_workflow = _service(
        tmp_path / "disabled",
        repo,
        enabled=True,
        env={
            WORKFLOW_HOME_ENV: str(tmp_path / "disabled" / "home"),
            LOCAL_DEVELOPER_TOOL_FEATURE_FLAG: "1",
            LOCAL_ADAPTER_FEATURE_FLAG: "1",
            SANDBOX_FEATURE_FLAG: "1",
        },
    )
    blocked = disabled_workflow.run("tokenom-safe")
    assert blocked["status"] == "blocked"
    assert blocked["error"]["category"] == "daily_workflow_feature_enabled"
    assert blocked["proof"]["repository_scan_executed"] is False
    assert blocked["proof"]["adapter_invocations"] == 0
    assert blocked["proof"]["runtime_invocations"] == 0


def test_preflight_blocks_profile_dependency_missing_repository_and_invalid_git(tmp_path: Path) -> None:
    repo = _copy_git_repo(tmp_path)
    home = tmp_path / "home"

    profile_disabled = _service(tmp_path / "profile-disabled", repo, enabled=False, env=_enabled_env(home))
    assert profile_disabled.preflight("tokenom-safe")["ready"] is False

    missing_dev_env = {
        WORKFLOW_HOME_ENV: str(tmp_path / "missing-dev" / "home"),
        FEATURE_FLAG: "1",
        LOCAL_ADAPTER_FEATURE_FLAG: "1",
        SANDBOX_FEATURE_FLAG: "1",
    }
    missing_dev = _service(tmp_path / "missing-dev", repo, enabled=True, env=missing_dev_env)
    assert missing_dev.preflight("tokenom-safe")["blockers"][0]["category"] == "local_developer_tool_flag_enabled"

    missing_adapter_env = {
        WORKFLOW_HOME_ENV: str(tmp_path / "missing-adapter" / "home"),
        FEATURE_FLAG: "1",
        LOCAL_DEVELOPER_TOOL_FEATURE_FLAG: "1",
        SANDBOX_FEATURE_FLAG: "1",
    }
    missing_adapter = _service(tmp_path / "missing-adapter", repo, enabled=True, env=missing_adapter_env)
    assert missing_adapter.preflight("tokenom-safe")["ready"] is False

    missing_sandbox_env = {
        WORKFLOW_HOME_ENV: str(tmp_path / "missing-sandbox" / "home"),
        FEATURE_FLAG: "1",
        LOCAL_DEVELOPER_TOOL_FEATURE_FLAG: "1",
        LOCAL_ADAPTER_FEATURE_FLAG: "1",
    }
    missing_sandbox = _service(tmp_path / "missing-sandbox", repo, enabled=True, env=missing_sandbox_env)
    assert missing_sandbox.preflight("tokenom-safe")["ready"] is False

    plain = tmp_path / "plain"
    plain.mkdir()
    invalid_git = _service(tmp_path / "invalid-git", plain, enabled=True, env=_enabled_env(tmp_path / "invalid-git-home"))
    assert any(item["category"] == "repository_is_git" for item in invalid_git.preflight("tokenom-safe")["blockers"])


def test_completed_run_manifest_history_and_safety(tmp_path: Path) -> None:
    repo = _copy_git_repo(tmp_path)
    service = _service(tmp_path, repo, enabled=True, env=_enabled_env(tmp_path / "home"))

    result = service.run("tokenom-safe")
    history = result["history_record"]
    serialized = json.dumps(result, sort_keys=True)

    assert result["status"] == "completed"
    assert result["execution"]["attempts"] == 1
    assert result["execution"]["retry_executed"] is False
    assert result["proof"]["adapter_invocations"] == 1
    assert result["proof"]["runtime_invocations"] == 1
    assert result["developer_tool"]["manifest_path"].startswith("artifacts/local_developer_tool_runtime/manifests/")
    assert history["status"] == "completed"
    assert history["selected_files"] >= 3
    assert history["raw_source_written"] is False
    assert history["raw_output_written"] is False
    assert history["raw_secret_written"] is False
    assert history["absolute_paths_written"] is False
    assert str(repo) not in serialized
    for raw in RAW_DUMMY_VALUES:
        assert raw not in serialized


def test_history_retention_corruption_and_lookup_are_safe(tmp_path: Path) -> None:
    store = HistoryStore(tmp_path / "history", retention=2)
    for index in range(3):
        store.append(
            {
                "run_id": f"run-{index}",
                "profile_id": "tokenom-safe",
                "status": "completed",
                "raw_source": "secret",
                "absolute_path": "C:/Users/example/project",
            }
        )

    assert len(store.list(limit=10)) == 2
    latest = store.latest()
    assert latest is not None
    assert "raw_source" not in latest
    assert "absolute_path" not in latest

    corrupted = tmp_path / "history" / "corrupt.json"
    corrupted.write_text("{bad", encoding="utf-8")
    assert store.get("corrupt")["status"] == "corrupted"


def test_rollback_disables_profile_and_blocks_without_downstream(tmp_path: Path) -> None:
    repo = _copy_git_repo(tmp_path)
    home = tmp_path / "home"
    service = _service(tmp_path, repo, enabled=True, env=_enabled_env(home))

    assert service.run("tokenom-safe")["status"] == "completed"
    disabled = service.disable_profile("tokenom-safe")
    blocked = service.run("tokenom-safe")

    assert disabled["enabled"] is False
    assert blocked["status"] == "blocked"
    assert blocked["proof"]["repository_scan_executed"] is False
    assert blocked["proof"]["adapter_invocations"] == 0
    assert blocked["proof"]["runtime_invocations"] == 0


def test_service_uses_local_developer_tool_once_without_runtime_bypass(monkeypatch, tmp_path: Path) -> None:
    repo = _copy_git_repo(tmp_path)
    calls = []

    class StubDeveloperTool:
        repository_scan_executed = True
        local_adapter_invocations = 1
        runtime_invocations = 1
        external_network_requests = 0
        real_provider_requests = 0

        def __init__(self, **kwargs):
            self.kwargs = kwargs

        def execute(self, request):
            calls.append(request)
            return {
                "tool_request_id": request["tool_request_id"],
                "correlation_id": request["correlation_id"],
                "status": "completed",
                "operation": "build_context_bundle",
                "repository": {"repository_id": "repo123", "branch": "main", "head": "abc"},
                "bundle": {
                    "bundle_id": "bundle123",
                    "selected_files": 1,
                    "excluded_files": 0,
                    "source_bytes": 10,
                    "optimized_bytes": 5,
                },
                "security": {"external_network_used": False, "real_provider_used": False},
                "execution": {"attempts": 1, "retry_executed": False},
                "manifest_path": "artifacts/local_developer_tool_runtime/manifests/bundle123.json",
                "audit_id": "audit123",
                "downstream_adapter_audit_id": "adapter123",
                "proof": {},
            }

    import tokenom.local_daily_workflow.service as service_module

    monkeypatch.setattr(service_module, "LocalDeveloperToolService", StubDeveloperTool)
    service = _service(tmp_path, repo, enabled=True, env=_enabled_env(tmp_path / "home"))

    result = service.run("tokenom-safe")

    assert result["status"] == "completed"
    assert len(calls) == 1
    assert calls[0]["execution"]["allow_retry"] is False


def test_cli_status_profiles_preflight_run_history_and_disabled_run(tmp_path: Path) -> None:
    repo = _copy_git_repo(tmp_path)
    home = tmp_path / "home"
    _write_registry(home / "profiles.json", [_profile(repo, enabled=False)])
    env = _enabled_env(home)
    runner = CliRunner()

    status = runner.invoke(main, ["local-workflow", "status"], env=env)
    assert status.exit_code == 0
    assert json.loads(status.output)["real_provider_disabled"] is True

    profiles = runner.invoke(main, ["local-workflow", "profiles"], env=env)
    assert profiles.exit_code == 0
    assert "root" not in profiles.output

    preflight_blocked = runner.invoke(main, ["local-workflow", "preflight", "--profile", "tokenom-safe"], env=env)
    assert preflight_blocked.exit_code == 2

    enabled = runner.invoke(main, ["local-workflow", "profile-enable", "--profile", "tokenom-safe"], env=env)
    assert enabled.exit_code == 0

    preflight_ready = runner.invoke(main, ["local-workflow", "preflight", "--profile", "tokenom-safe"], env=env)
    assert preflight_ready.exit_code == 0

    run = runner.invoke(main, ["local-workflow", "run", "--profile", "tokenom-safe"], env=env)
    assert run.exit_code == 0
    run_payload = json.loads(run.output)
    assert run_payload["status"] == "completed"
    assert run_payload["execution"]["attempts"] == 1
    for raw in RAW_DUMMY_VALUES:
        assert raw not in run.output

    history = runner.invoke(main, ["local-workflow", "history", "--limit", "10"], env=env)
    assert history.exit_code == 0
    assert json.loads(history.output)["history"][0]["status"] == "completed"

    disabled = runner.invoke(main, ["local-workflow", "disable", "--profile", "tokenom-safe"], env=env)
    assert disabled.exit_code == 0

    blocked = runner.invoke(main, ["local-workflow", "run", "--profile", "tokenom-safe"], env=env)
    assert blocked.exit_code == 2
    assert json.loads(blocked.output)["proof"]["runtime_invocations"] == 0
