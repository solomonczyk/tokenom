"""Request and result contracts for the controlled local agent adapter."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class LocalAgentRequest:
    adapter_request_id: str
    correlation_id: str
    mode: str
    operation: str
    payload: dict[str, Any]
    workspace: dict[str, Any]
    execution: dict[str, Any]


@dataclass(frozen=True)
class LocalAgentResult:
    adapter_request_id: str
    correlation_id: str
    status: str
    operation: str
    result: dict[str, Any]
    security: dict[str, Any]
    execution: dict[str, Any]
    audit_id: str | None
    error: dict[str, Any] | None = None
    transport: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "adapter_request_id": self.adapter_request_id,
            "correlation_id": self.correlation_id,
            "status": self.status,
            "operation": self.operation,
            "result": self.result,
            "security": self.security,
            "execution": self.execution,
            "audit_id": self.audit_id,
        }
        if self.transport:
            payload["transport"] = self.transport
        if self.error is not None:
            payload["error"] = self.error
        return payload
