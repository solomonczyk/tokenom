"""Contracts for local daily workflow profiles and results."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class RepositoryProfile:
    root: Path
    approved: bool
    include: tuple[str, ...]
    exclude: tuple[str, ...]

    @property
    def repository_id(self) -> str:
        from tokenom.local_developer_tool.audit import safe_hash

        return safe_hash(str(self.root))[:16]


@dataclass(frozen=True)
class WorkflowLimits:
    max_files: int
    max_file_bytes: int
    max_bundle_bytes: int
    timeout_ms: int


@dataclass(frozen=True)
class WorkflowExecutionPolicy:
    allow_retry: bool


@dataclass(frozen=True)
class WorkflowProfile:
    profile_id: str
    enabled: bool
    mode: str
    repository: RepositoryProfile
    operation: str
    limits: WorkflowLimits
    execution: WorkflowExecutionPolicy

    def to_safe_dict(self) -> dict[str, Any]:
        return {
            "profile_id": self.profile_id,
            "enabled": self.enabled,
            "mode": self.mode,
            "repository": {
                "repository_id": self.repository.repository_id,
                "approved": self.repository.approved,
                "include": list(self.repository.include),
                "exclude": list(self.repository.exclude),
            },
            "operation": self.operation,
            "limits": {
                "max_files": self.limits.max_files,
                "max_file_bytes": self.limits.max_file_bytes,
                "max_bundle_bytes": self.limits.max_bundle_bytes,
                "timeout_ms": self.limits.timeout_ms,
            },
            "execution": {"allow_retry": self.execution.allow_retry},
        }


@dataclass(frozen=True)
class CheckResult:
    name: str
    status: str
    category: str | None = None
    detail: str | None = None

    def to_dict(self) -> dict[str, Any]:
        payload = {"name": self.name, "status": self.status}
        if self.category:
            payload["category"] = self.category
        if self.detail:
            payload["detail"] = self.detail
        return payload


@dataclass(frozen=True)
class PreflightResult:
    ready: bool
    profile_id: str
    checks: tuple[CheckResult, ...]
    blockers: tuple[dict[str, str], ...]
    warnings: tuple[dict[str, str], ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "ready": self.ready,
            "profile_id": self.profile_id,
            "checks": [check.to_dict() for check in self.checks],
            "blockers": list(self.blockers),
            "warnings": list(self.warnings),
        }
