"""Request and result contracts for the local developer tool layer."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class RepositoryRequest:
    root: str
    include: tuple[str, ...]
    exclude: tuple[str, ...] = ()


@dataclass(frozen=True)
class ContextBudget:
    max_files: int
    max_file_bytes: int
    max_bundle_bytes: int
    include_git_metadata: bool = True


@dataclass(frozen=True)
class ExecutionPolicy:
    timeout_ms: int
    allow_retry: bool
    cancelled: bool = False


@dataclass(frozen=True)
class DeveloperToolRequest:
    tool_request_id: str
    correlation_id: str
    mode: str
    operation: str
    repository: RepositoryRequest
    context: ContextBudget
    execution: ExecutionPolicy


@dataclass(frozen=True)
class DeveloperToolResult:
    tool_request_id: str
    correlation_id: str
    status: str
    operation: str
    repository: dict[str, Any] = field(default_factory=dict)
    bundle: dict[str, Any] = field(default_factory=dict)
    security: dict[str, Any] = field(default_factory=dict)
    execution: dict[str, Any] = field(default_factory=dict)
    manifest_path: str | None = None
    audit_id: str | None = None
    downstream_adapter_audit_id: str | None = None
    error: dict[str, Any] | None = None
    inspection: dict[str, Any] = field(default_factory=dict)
    proof: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "tool_request_id": self.tool_request_id,
            "correlation_id": self.correlation_id,
            "status": self.status,
            "operation": self.operation,
            "repository": self.repository,
            "bundle": self.bundle,
            "security": self.security,
            "execution": self.execution,
            "manifest_path": self.manifest_path,
            "audit_id": self.audit_id,
            "downstream_adapter_audit_id": self.downstream_adapter_audit_id,
        }
        if self.inspection:
            payload["inspection"] = self.inspection
        if self.proof:
            payload["proof"] = self.proof
        if self.error is not None:
            payload["error"] = self.error
        return payload
