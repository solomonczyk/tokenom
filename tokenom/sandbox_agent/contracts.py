"""Request and result contracts for the sandbox agent layer."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class SandboxAgentRequest:
    request_id: str
    mode: str
    task_type: str
    input: dict[str, Any]
    workspace: dict[str, Any]
    provider: str
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_mapping(cls, payload: dict[str, Any]) -> SandboxAgentRequest:
        return cls(
            request_id=str(payload["request_id"]),
            mode=str(payload["mode"]),
            task_type=str(payload["task_type"]),
            input=dict(payload["input"]),
            workspace=dict(payload["workspace"]),
            provider=str(payload["provider"]),
            metadata=dict(payload.get("metadata") or {}),
        )


@dataclass(frozen=True)
class SandboxAgentResult:
    request_id: str
    status: str
    mode: str
    provider: str
    output: dict[str, Any]
    security: dict[str, Any]
    runtime: dict[str, Any]
    audit_id: str | None
    error: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "request_id": self.request_id,
            "status": self.status,
            "mode": self.mode,
            "provider": self.provider,
            "output": self.output,
            "security": self.security,
            "runtime": self.runtime,
            "audit_id": self.audit_id,
        }
        if self.error is not None:
            payload["error"] = self.error
        return payload
