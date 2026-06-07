"""Daily workflow service layered over the existing local developer tool."""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from tokenom.local_agent_adapter.config import is_local_agent_adapter_enabled
from tokenom.local_developer_tool.config import (
    default_manifest_dir,
    is_local_developer_tool_enabled,
)
from tokenom.local_developer_tool.service import LocalDeveloperToolService
from tokenom.sandbox_agent.config import is_sandbox_agent_enabled

from .config import is_local_daily_workflow_enabled
from .history import HistoryStore
from .profile_registry import ProfileRegistry
from .readiness import ReadinessChecker


class DailyWorkflowService:
    """Operator-triggered, single-attempt local daily workflow."""

    def __init__(
        self,
        *,
        registry: ProfileRegistry | None = None,
        history: HistoryStore | None = None,
        developer_tool: LocalDeveloperToolService | None = None,
        env: dict[str, str] | None = None,
        manifest_dir: Path | None = None,
    ) -> None:
        self.env = env
        self.registry = registry or ProfileRegistry(env=env)
        self.history = history or HistoryStore(env=env)
        self.developer_tool = developer_tool
        self.manifest_dir = manifest_dir or default_manifest_dir()

    def status(self) -> dict[str, Any]:
        profiles = self.registry.list_profiles()
        latest = self.history.latest()
        return {
            "daily_workflow_feature_enabled": is_local_daily_workflow_enabled(self.env),
            "dependency_flags": {
                "local_developer_tool": is_local_developer_tool_enabled(self.env),
                "local_agent_adapter": is_local_agent_adapter_enabled(self.env),
                "sandbox_agent_integration": is_sandbox_agent_enabled(self.env),
            },
            "profile_count": len(profiles),
            "enabled_profiles": [profile.profile_id for profile in profiles if profile.enabled],
            "runtime_available": True,
            "native_core_available": self._native_core_available(),
            "latest_run_status": None if latest is None else latest.get("status"),
            "real_provider_disabled": True,
            "network_disabled": True,
            "autonomous_editing_disabled": True,
            "production_accepted": False,
            "real_provider_allowed": False,
            "autonomous_editing_allowed": False,
        }

    def health(self) -> dict[str, Any]:
        return {
            "status": "ok",
            "daily_workflow_feature_enabled": is_local_daily_workflow_enabled(self.env),
            "profile_registry_available": True,
            "history_available": True,
            "runtime_import_available": True,
            "native_core_available": self._native_core_available(),
            "repository_scan_executed": False,
            "adapter_invocations": 0,
            "runtime_invocations": 0,
            "real_provider_disabled": True,
            "network_disabled": True,
            "autonomous_editing_disabled": True,
        }

    def list_profiles(self) -> dict[str, Any]:
        return {
            "profiles": [profile.to_safe_dict() for profile in self.registry.list_profiles()],
            "registry_path": self.registry.safe_registry_path(),
        }

    def show_profile(self, profile_id: str) -> dict[str, Any]:
        return self.registry.get(profile_id).to_safe_dict()

    def enable_profile(self, profile_id: str) -> dict[str, Any]:
        profile = self.registry.enable(profile_id)
        return {
            "profile_id": profile.profile_id,
            "enabled": profile.enabled,
            "workflow_started": False,
        }

    def disable_profile(self, profile_id: str) -> dict[str, Any]:
        profile = self.registry.disable(profile_id)
        return {
            "profile_id": profile.profile_id,
            "enabled": profile.enabled,
            "workflow_started": False,
        }

    def preflight(self, profile_id: str) -> dict[str, Any]:
        checker = ReadinessChecker(self.registry, env=self.env, manifest_dir=self.manifest_dir)
        return checker.check(profile_id).to_dict()

    def run(self, profile_id: str) -> dict[str, Any]:
        run_id = f"daily-{uuid4().hex[:16]}"
        started = time.monotonic()
        preflight = self.preflight(profile_id)
        if not preflight["ready"]:
            category = self._first_blocker(preflight)
            record = self.history.append(
                {
                    "run_id": run_id,
                    "profile_id": profile_id,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "status": "blocked",
                    "safe_repository_id": None,
                    "duration_ms": self._duration_ms(started),
                    "attempts": 0,
                    "retry_executed": False,
                    "automatic_retry": False,
                    "error_category": category,
                    "repository_scan_executed": False,
                    "adapter_invocations": 0,
                    "runtime_invocations": 0,
                    "external_network_requests": 0,
                    "real_provider_requests": 0,
                }
            )
            return {
                "run_id": run_id,
                "profile_id": profile_id,
                "status": "blocked",
                "preflight": preflight,
                "history_record": record,
                "execution": {"attempts": 0, "retry_executed": False, "automatic_retry": False},
                "proof": {
                    "repository_scan_executed": False,
                    "adapter_invocations": 0,
                    "runtime_invocations": 0,
                    "external_network_requests": 0,
                    "real_provider_requests": 0,
                },
                "error": {"category": category},
            }

        profile = self.registry.get(profile_id)
        request = self._developer_tool_request(profile, run_id)
        tool = self.developer_tool or LocalDeveloperToolService(
            allowed_roots=(profile.repository.root,),
            env=self.env,
            manifest_dir=self.manifest_dir,
        )
        result = self._preserve_run_manifest(run_id, tool.execute(request))
        record = self.history.append(self._history_record(run_id, profile_id, result, tool, started))
        return {
            "run_id": run_id,
            "profile_id": profile_id,
            "status": result.get("status"),
            "preflight": preflight,
            "developer_tool": self._safe_developer_result(result),
            "history_record": record,
            "execution": {
                "attempts": result.get("execution", {}).get("attempts", 0),
                "retry_executed": False,
                "automatic_retry": False,
            },
            "proof": {
                "repository_scan_executed": bool(getattr(tool, "repository_scan_executed", False)),
                "adapter_invocations": int(getattr(tool, "local_adapter_invocations", 0)),
                "runtime_invocations": int(getattr(tool, "runtime_invocations", 0)),
                "external_network_requests": int(getattr(tool, "external_network_requests", 0)),
                "real_provider_requests": int(getattr(tool, "real_provider_requests", 0)),
            },
        }

    def history_list(self, *, limit: int = 10, run_id: str | None = None) -> dict[str, Any]:
        if run_id:
            return {"history": [] if self.history.get(run_id) is None else [self.history.get(run_id)]}
        return {"history": self.history.list(limit=limit)}

    def _preserve_run_manifest(self, run_id: str, result: dict[str, Any]) -> dict[str, Any]:
        bundle = result.get("bundle") if isinstance(result.get("bundle"), dict) else {}
        bundle_id = bundle.get("bundle_id")
        if result.get("status") != "completed" or not isinstance(bundle_id, str) or not bundle_id:
            return result

        source = self.manifest_dir / f"{bundle_id}.json"
        if not source.exists():
            return result
        try:
            manifest = json.loads(source.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return result

        workflow_manifest_id = f"{run_id}-{bundle_id}"
        manifest["workflow_run_id"] = run_id
        manifest["workflow_manifest_id"] = workflow_manifest_id
        destination = self.manifest_dir / "workflow-runs" / f"{workflow_manifest_id}.json"
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")

        updated = dict(result)
        updated["manifest_path"] = (
            Path("artifacts")
            / "local_developer_tool_runtime"
            / "manifests"
            / "workflow-runs"
            / f"{workflow_manifest_id}.json"
        ).as_posix()
        return updated

    @staticmethod
    def _developer_tool_request(profile: Any, run_id: str) -> dict[str, Any]:
        return {
            "tool_request_id": run_id,
            "correlation_id": run_id,
            "mode": "sandbox",
            "operation": profile.operation,
            "repository": {
                "root": str(profile.repository.root),
                "include": list(profile.repository.include),
                "exclude": list(profile.repository.exclude),
            },
            "context": {
                "max_files": profile.limits.max_files,
                "max_file_bytes": profile.limits.max_file_bytes,
                "max_bundle_bytes": profile.limits.max_bundle_bytes,
                "include_git_metadata": True,
            },
            "execution": {
                "timeout_ms": profile.limits.timeout_ms,
                "allow_retry": False,
            },
        }

    def _history_record(
        self,
        run_id: str,
        profile_id: str,
        result: dict[str, Any],
        tool: LocalDeveloperToolService,
        started: float,
    ) -> dict[str, Any]:
        bundle = result.get("bundle") if isinstance(result.get("bundle"), dict) else {}
        repository = result.get("repository") if isinstance(result.get("repository"), dict) else {}
        execution = result.get("execution") if isinstance(result.get("execution"), dict) else {}
        error = result.get("error") if isinstance(result.get("error"), dict) else None
        return {
            "run_id": run_id,
            "profile_id": profile_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "status": result.get("status"),
            "safe_repository_id": repository.get("repository_id"),
            "branch": repository.get("branch"),
            "head": repository.get("head"),
            "selected_files": bundle.get("selected_files", 0),
            "excluded_files": bundle.get("excluded_files", 0),
            "source_bytes": bundle.get("source_bytes", 0),
            "optimized_bytes": bundle.get("optimized_bytes", 0),
            "bundle_id": bundle.get("bundle_id"),
            "manifest_id": bundle.get("bundle_id"),
            "manifest_path": result.get("manifest_path"),
            "audit_id": result.get("audit_id"),
            "adapter_audit_id": result.get("downstream_adapter_audit_id"),
            "sandbox_audit_id": None,
            "duration_ms": self._duration_ms(started),
            "attempts": execution.get("attempts", 0),
            "retry_executed": False,
            "automatic_retry": False,
            "error_category": None if error is None else error.get("category"),
            "repository_scan_executed": bool(getattr(tool, "repository_scan_executed", False)),
            "adapter_invocations": int(getattr(tool, "local_adapter_invocations", 0)),
            "runtime_invocations": int(getattr(tool, "runtime_invocations", 0)),
            "external_network_requests": int(getattr(tool, "external_network_requests", 0)),
            "real_provider_requests": int(getattr(tool, "real_provider_requests", 0)),
            "raw_source_written": False,
            "raw_output_written": False,
            "raw_secret_written": False,
            "absolute_paths_written": False,
        }

    @staticmethod
    def _safe_developer_result(result: dict[str, Any]) -> dict[str, Any]:
        allowed = {
            "tool_request_id",
            "correlation_id",
            "status",
            "operation",
            "repository",
            "bundle",
            "security",
            "execution",
            "manifest_path",
            "audit_id",
            "downstream_adapter_audit_id",
            "error",
            "proof",
        }
        return {key: value for key, value in result.items() if key in allowed}

    @staticmethod
    def _first_blocker(preflight: dict[str, Any]) -> str:
        blockers = preflight.get("blockers")
        if isinstance(blockers, list) and blockers:
            first = blockers[0]
            if isinstance(first, dict):
                return str(first.get("category") or "preflight_blocked")
        return "preflight_blocked"

    @staticmethod
    def _duration_ms(started: float) -> int:
        return max(0, int((time.monotonic() - started) * 1000))

    @staticmethod
    def _native_core_available() -> bool:
        try:
            import headroom._core  # noqa: F401
        except ImportError:
            return False
        return True
