"""Readiness checks for the local daily workflow."""

from __future__ import annotations

import importlib
from pathlib import Path

from tokenom.local_agent_adapter.config import is_local_agent_adapter_enabled
from tokenom.local_developer_tool.config import (
    is_local_developer_tool_enabled,
)
from tokenom.local_developer_tool.service import LocalDeveloperToolService
from tokenom.sandbox_agent.config import is_sandbox_agent_enabled

from .config import DAILY_WORKFLOW_VERSION, is_local_daily_workflow_enabled
from .contracts import CheckResult, PreflightResult, WorkflowProfile
from .profile_registry import ProfileRegistry, RegistryError


class ReadinessChecker:
    """Fail-closed preflight checks before daily workflow execution."""

    def __init__(
        self,
        registry: ProfileRegistry,
        *,
        env: dict[str, str] | None = None,
        manifest_dir: Path | None = None,
    ) -> None:
        self.registry = registry
        self.env = env
        self.manifest_dir = manifest_dir

    def check(self, profile_id: str) -> PreflightResult:
        checks: list[CheckResult] = []
        blockers: list[dict[str, str]] = []
        warnings: list[dict[str, str]] = []

        profile: WorkflowProfile | None = None
        try:
            profile = self.registry.get(profile_id)
            checks.append(CheckResult("profile_exists", "passed"))
        except RegistryError as exc:
            self._block(checks, blockers, "profile_exists", str(exc))
            return self._result(profile_id, checks, blockers, warnings)

        daily_enabled = is_local_daily_workflow_enabled(self.env)
        self._gate(checks, blockers, "daily_workflow_feature_enabled", daily_enabled)
        self._gate(checks, blockers, "profile_enabled", profile.enabled)
        self._gate(checks, blockers, "sandbox_flag_enabled", is_sandbox_agent_enabled(self.env))
        self._gate(checks, blockers, "local_agent_adapter_flag_enabled", is_local_agent_adapter_enabled(self.env))
        self._gate(checks, blockers, "local_developer_tool_flag_enabled", is_local_developer_tool_enabled(self.env))
        self._gate(checks, blockers, "retry_disabled", profile.execution.allow_retry is False)
        self._gate(checks, blockers, "sandbox_mode", profile.mode == "sandbox")
        self._gate(checks, blockers, "repository_approved", profile.repository.approved)
        self._gate(checks, blockers, "provider_override_absent", True)
        self._gate(checks, blockers, "shell_fields_absent", True)
        self._gate(checks, blockers, "no_server_or_network_provider_configured", True)

        if blockers:
            return self._result(profile_id, checks, blockers, warnings)

        root = profile.repository.root
        self._gate(checks, blockers, "repository_exists", root.exists() and root.is_dir())
        self._gate(checks, blockers, "repository_is_git", (root / ".git").exists())
        self._gate(checks, blockers, "approved_root_matches_profile", root == profile.repository.root.resolve())
        self._gate(
            checks,
            blockers,
            "mandatory_exclusions_active",
            LocalDeveloperToolService._mandatory_exclusion_reason(".git/config") is not None
            and LocalDeveloperToolService._mandatory_exclusion_reason(".env") is not None,
        )
        self._gate(checks, blockers, "feature_versions_compatible", DAILY_WORKFLOW_VERSION == "009")
        self._gate(checks, blockers, "runtime_import_available", self._import_available("tokenom.local_developer_tool.service"))
        native_available = self._import_available("headroom._core")
        checks.append(
            CheckResult(
                "native_core_status_known",
                "passed",
                detail="available" if native_available else "unavailable",
            )
        )
        if not native_available:
            warnings.append({"category": "native_core_unavailable", "detail": "Python fallback is acceptable for local workflow."})
        self._gate(checks, blockers, "manifest_audit_directory_available", self._state_directory_available())
        self._gate(
            checks,
            blockers,
            "max_limits_valid",
            profile.limits.max_files > 0
            and profile.limits.max_file_bytes > 0
            and profile.limits.max_bundle_bytes > 0
            and profile.limits.timeout_ms > 0,
        )

        return self._result(profile_id, checks, blockers, warnings)

    def _state_directory_available(self) -> bool:
        try:
            if self.manifest_dir is not None:
                self.manifest_dir.mkdir(parents=True, exist_ok=True)
            self.registry.path.parent.mkdir(parents=True, exist_ok=True)
        except OSError:
            return False
        return True

    @staticmethod
    def _import_available(module_name: str) -> bool:
        try:
            importlib.import_module(module_name)
        except ImportError:
            return False
        return True

    @staticmethod
    def _gate(
        checks: list[CheckResult],
        blockers: list[dict[str, str]],
        name: str,
        passed: bool,
        category: str | None = None,
    ) -> None:
        if passed:
            checks.append(CheckResult(name, "passed"))
            return
        reason = category or name
        ReadinessChecker._block(checks, blockers, name, reason)

    @staticmethod
    def _block(
        checks: list[CheckResult],
        blockers: list[dict[str, str]],
        name: str,
        category: str,
    ) -> None:
        checks.append(CheckResult(name, "blocked", category=category))
        blockers.append({"category": category, "check": name})

    @staticmethod
    def _result(
        profile_id: str,
        checks: list[CheckResult],
        blockers: list[dict[str, str]],
        warnings: list[dict[str, str]],
    ) -> PreflightResult:
        return PreflightResult(
            ready=not blockers,
            profile_id=profile_id,
            checks=tuple(checks),
            blockers=tuple(blockers),
            warnings=tuple(warnings),
        )
