"""In-process, local-only adapter that delegates to the sandbox orchestrator."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from tokenom.sandbox_agent.config import is_sandbox_agent_enabled
from tokenom.sandbox_agent.orchestrator import SandboxAgentOrchestrator

from .audit import build_adapter_audit_payload, payload_hash, record_adapter_audit
from .config import (
    DEFAULT_TIMEOUT_MS,
    MAX_PAYLOAD_BYTES,
    MAX_TIMEOUT_MS,
    MIN_TIMEOUT_MS,
    is_local_agent_adapter_enabled,
    local_agent_default_workspace_root,
)
from .contracts import LocalAgentRequest, LocalAgentResult
from .operations import get_operation_spec

_ALLOWED_TOP_LEVEL = {
    "adapter_request_id",
    "correlation_id",
    "mode",
    "operation",
    "payload",
    "workspace",
    "execution",
}
_ALLOWED_PAYLOAD = {"content", "metadata"}
_ALLOWED_WORKSPACE = {"root"}
_ALLOWED_EXECUTION = {"timeout_ms", "allow_retry", "cancelled"}
_DANGEROUS_KEYS = {
    "__import__",
    "api_key",
    "apiKey",
    "args",
    "callable",
    "cmd",
    "command",
    "credential",
    "credentials",
    "dynamic_import",
    "exec",
    "execute",
    "filesystem_path",
    "function",
    "module",
    "private",
    "private_project",
    "production",
    "production_mode",
    "provider",
    "provider_config",
    "real_provider",
    "remote_transport",
    "secret",
    "secrets",
    "shell",
    "socket",
    "url",
    "websocket",
}
_SECRET_ID_MARKERS = (
    "sk-",
    "sk-ant-",
    "bearer ",
    "github_pat_",
    "ghp_",
    "password=",
    "token=",
    "secret=",
)


class LocalAgentAdapter:
    """Run one local agent request through adapter gates and the sandbox layer."""

    def __init__(
        self,
        *,
        orchestrator: SandboxAgentOrchestrator | None = None,
        audit_path: Path | None = None,
        allowed_roots: tuple[Path, ...] | None = None,
        env: dict[str, str] | None = None,
        max_payload_bytes: int = MAX_PAYLOAD_BYTES,
    ) -> None:
        self.env = env
        self.audit_path = audit_path
        self.max_payload_bytes = max_payload_bytes
        self.allowed_roots = allowed_roots or (local_agent_default_workspace_root(),)
        self.orchestrator = orchestrator or SandboxAgentOrchestrator(
            audit_path=audit_path,
            allowed_roots=self.allowed_roots,
            env=env,
        )

    def execute(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        """Execute one request with no automatic retry or remote transport."""

        serialized_payload = self._stable_json(payload)
        payload_size = len(serialized_payload.encode("utf-8"))
        payload_sha256 = payload_hash(serialized_payload)
        request_id = self._safe_id(payload.get("adapter_request_id"), "unknown")
        correlation_id = self._safe_id(payload.get("correlation_id"), "unknown")
        operation = str(payload.get("operation") or "unknown") if isinstance(payload, Mapping) else "unknown"

        local_enabled = is_local_agent_adapter_enabled(self.env)
        sandbox_enabled = is_sandbox_agent_enabled(self.env)
        base_gates = {
            "local_adapter_enabled": local_enabled,
            "sandbox_integration_enabled": sandbox_enabled,
            "local_only_transport": True,
            "payload_limit_active": True,
            "operation_allowlist_active": True,
            "public_listener_created": False,
            "remote_transport_available": False,
            "outbound_network_requests": 0,
            "localhost_http_server_started": False,
            "background_daemon_started": False,
        }
        if not local_enabled:
            return self._blocked(
                "local_adapter_disabled",
                request_id,
                correlation_id,
                operation,
                payload_size,
                payload_sha256,
                base_gates,
            )
        if not sandbox_enabled:
            return self._blocked(
                "sandbox_dependency_disabled",
                request_id,
                correlation_id,
                operation,
                payload_size,
                payload_sha256,
                base_gates,
            )
        if payload_size > self.max_payload_bytes:
            return self._blocked(
                "payload_too_large",
                request_id,
                correlation_id,
                operation,
                payload_size,
                payload_sha256,
                base_gates,
            )

        validation = self._validate(payload)
        if isinstance(validation, str):
            return self._blocked(
                validation,
                request_id,
                correlation_id,
                operation,
                payload_size,
                payload_sha256,
                base_gates,
            )
        request = validation
        operation_spec = get_operation_spec(request.operation)
        if operation_spec is None:
            return self._blocked(
                "unsupported_operation",
                request.adapter_request_id,
                request.correlation_id,
                request.operation,
                payload_size,
                payload_sha256,
                base_gates,
            )
        if request.execution.get("cancelled") is True:
            return self._cancelled(request, payload_size, payload_sha256, base_gates)
        if request.operation == "sandbox_health":
            return self._health(request, payload_size, payload_sha256, base_gates)

        sandbox_request = self._to_sandbox_request(request)
        sandbox_result = self.orchestrator.run(sandbox_request)
        return self._from_sandbox_result(
            request,
            sandbox_result,
            payload_size,
            payload_sha256,
            base_gates,
        )

    def _validate(self, payload: Mapping[str, Any]) -> LocalAgentRequest | str:
        if not isinstance(payload, Mapping):
            return "malformed_request"
        if set(payload) - _ALLOWED_TOP_LEVEL:
            return "dangerous_extra_field"
        if self._contains_dangerous_key(payload):
            return "private_or_production_flag_forbidden"
        for required in _ALLOWED_TOP_LEVEL:
            if required not in payload:
                return "malformed_request"
        adapter_request_id = self._validate_id(payload.get("adapter_request_id"))
        if adapter_request_id is None:
            return "invalid_adapter_request_id"
        correlation_id = self._validate_id(payload.get("correlation_id"))
        if correlation_id is None:
            return "invalid_correlation_id"
        if payload.get("mode") != "sandbox":
            return "production_mode_forbidden"
        if not isinstance(payload.get("operation"), str):
            return "unsupported_operation"
        if get_operation_spec(str(payload["operation"])) is None:
            return "unsupported_operation"
        if not isinstance(payload.get("payload"), dict) or set(payload["payload"]) - _ALLOWED_PAYLOAD:
            return "invalid_payload_contract"
        if "content" in payload["payload"] and not isinstance(payload["payload"]["content"], str):
            return "invalid_payload_contract"
        if "metadata" in payload["payload"] and not isinstance(payload["payload"]["metadata"], dict):
            return "invalid_payload_contract"
        if not isinstance(payload.get("workspace"), dict) or set(payload["workspace"]) - _ALLOWED_WORKSPACE:
            return "invalid_workspace_contract"
        if not isinstance(payload.get("execution"), dict) or set(payload["execution"]) - _ALLOWED_EXECUTION:
            return "invalid_execution_contract"
        if payload["execution"].get("allow_retry") is not False:
            return "retry_forbidden"
        timeout_ms = payload["execution"].get("timeout_ms", DEFAULT_TIMEOUT_MS)
        if not isinstance(timeout_ms, int) or timeout_ms < MIN_TIMEOUT_MS or timeout_ms > MAX_TIMEOUT_MS:
            return "timeout_policy_violation"
        if "cancelled" in payload["execution"] and not isinstance(payload["execution"]["cancelled"], bool):
            return "invalid_execution_contract"
        operation = str(payload["operation"])
        if operation != "sandbox_health" and "content" not in payload["payload"]:
            return "invalid_payload_contract"
        if operation == "sandbox_health" and "content" in payload["payload"]:
            return "invalid_payload_contract"
        return LocalAgentRequest(
            adapter_request_id=adapter_request_id,
            correlation_id=correlation_id,
            mode="sandbox",
            operation=operation,
            payload=dict(payload["payload"]),
            workspace=dict(payload["workspace"]),
            execution=dict(payload["execution"]),
        )

    def _to_sandbox_request(self, request: LocalAgentRequest) -> dict[str, Any]:
        metadata = dict(request.payload.get("metadata") or {})
        mock_behavior = metadata.get("mock_behavior", "success")
        sandbox_context = {
            "adapter_request_id": request.adapter_request_id,
            "correlation_id": request.correlation_id,
            "operation": request.operation,
            "metadata": metadata,
        }
        return {
            "request_id": request.adapter_request_id,
            "mode": "sandbox",
            "task_type": request.operation,
            "input": {
                "prompt": str(request.payload.get("content", "")),
                "context": sandbox_context,
            },
            "workspace": {"root": str(request.workspace.get("root"))},
            "provider": "mock",
            "metadata": {
                "source": "tokenom_local_agent_adapter",
                "mock_behavior": str(mock_behavior),
            },
        }

    def _from_sandbox_result(
        self,
        request: LocalAgentRequest,
        sandbox_result: dict[str, Any],
        payload_size: int,
        payload_sha256: str,
        gate_decisions: dict[str, Any],
    ) -> dict[str, Any]:
        status = str(sandbox_result.get("status") or "failed")
        sandbox_security = dict(sandbox_result.get("security") or {})
        sandbox_runtime = dict(sandbox_result.get("runtime") or {})
        sandbox_error = sandbox_result.get("error") if isinstance(sandbox_result.get("error"), dict) else None
        timed_out = bool(sandbox_error and sandbox_error.get("category") == "mock_provider_timeout")
        adapter_status = "timeout" if timed_out else status
        attempts = 1 if sandbox_security.get("provider_called") or sandbox_runtime.get("tokenom_runtime_invoked") else 0
        audit_id = self._record(
            request.adapter_request_id,
            request.correlation_id,
            request.operation,
            payload_size,
            payload_sha256,
            {**gate_decisions, "sandbox_orchestrator_reused": True},
            adapter_status,
            attempts,
            "controlled_timeout" if timed_out else None,
            None,
            sandbox_result.get("audit_id"),
        )
        result_content = ""
        if isinstance(sandbox_result.get("output"), dict):
            result_content = str(sandbox_result["output"].get("content") or "")
        result = LocalAgentResult(
            adapter_request_id=request.adapter_request_id,
            correlation_id=request.correlation_id,
            status=adapter_status,
            operation=request.operation,
            result={"content": result_content} if adapter_status == "completed" else {},
            security={
                "sandbox_enforced": True,
                "redaction_applied": bool(sandbox_security.get("redaction_applied")),
                "path_policy_passed": bool(sandbox_security.get("path_policy_passed")),
                "external_network_used": False,
                "real_provider_used": False,
                "public_server_created": False,
                "remote_transport_available": False,
                "background_daemon_started": False,
                "downstream_sandbox_audit_id": sandbox_result.get("audit_id"),
            },
            execution={
                "attempts": attempts,
                "retry_executed": False,
                "automatic_retry": False,
                "blind_retry": False,
                "timed_out": timed_out,
                "cancelled": False,
                "execution_after_timeout": False,
                "sandbox_runtime_invoked": bool(sandbox_runtime.get("tokenom_runtime_invoked")),
            },
            audit_id=audit_id,
            error=sandbox_error,
            transport=self._transport_proof(),
        )
        return result.to_dict()

    def _health(
        self,
        request: LocalAgentRequest,
        payload_size: int,
        payload_sha256: str,
        gate_decisions: dict[str, Any],
    ) -> dict[str, Any]:
        audit_id = self._record(
            request.adapter_request_id,
            request.correlation_id,
            request.operation,
            payload_size,
            payload_sha256,
            {**gate_decisions, "sandbox_orchestrator_reused": False},
            "completed",
            0,
            None,
            None,
            None,
        )
        return LocalAgentResult(
            adapter_request_id=request.adapter_request_id,
            correlation_id=request.correlation_id,
            status="completed",
            operation=request.operation,
            result={"content": "sandbox adapter health ok"},
            security={
                "sandbox_enforced": True,
                "redaction_applied": False,
                "path_policy_passed": True,
                "external_network_used": False,
                "real_provider_used": False,
                "public_server_created": False,
                "remote_transport_available": False,
                "background_daemon_started": False,
                "downstream_sandbox_audit_id": None,
            },
            execution={
                "attempts": 0,
                "retry_executed": False,
                "automatic_retry": False,
                "blind_retry": False,
                "timed_out": False,
                "cancelled": False,
                "execution_after_timeout": False,
                "sandbox_runtime_invoked": False,
            },
            audit_id=audit_id,
            transport=self._transport_proof(),
        ).to_dict()

    def _cancelled(
        self,
        request: LocalAgentRequest,
        payload_size: int,
        payload_sha256: str,
        gate_decisions: dict[str, Any],
    ) -> dict[str, Any]:
        audit_id = self._record(
            request.adapter_request_id,
            request.correlation_id,
            request.operation,
            payload_size,
            payload_sha256,
            gate_decisions,
            "cancelled",
            0,
            None,
            "request_cancelled_before_downstream_execution",
            None,
        )
        return LocalAgentResult(
            adapter_request_id=request.adapter_request_id,
            correlation_id=request.correlation_id,
            status="cancelled",
            operation=request.operation,
            result={},
            security=self._blocked_security(None),
            execution=self._blocked_execution(cancelled=True),
            audit_id=audit_id,
            error={"category": "request_cancelled"},
            transport=self._transport_proof(),
        ).to_dict()

    def _blocked(
        self,
        reason: str,
        adapter_request_id: str,
        correlation_id: str,
        operation: str,
        payload_size: int,
        payload_sha256: str,
        gate_decisions: dict[str, Any],
    ) -> dict[str, Any]:
        audit_id = self._record(
            adapter_request_id,
            correlation_id,
            operation,
            payload_size,
            payload_sha256,
            gate_decisions,
            "blocked",
            0,
            None,
            None,
            None,
        )
        return LocalAgentResult(
            adapter_request_id=adapter_request_id,
            correlation_id=correlation_id,
            status="blocked",
            operation=operation,
            result={},
            security=self._blocked_security(reason),
            execution=self._blocked_execution(),
            audit_id=audit_id,
            error={"category": reason},
            transport=self._transport_proof(),
        ).to_dict()

    def _record(
        self,
        adapter_request_id: str,
        correlation_id: str,
        operation: str,
        payload_size: int,
        payload_sha256: str,
        gate_decisions: dict[str, Any],
        execution_status: str,
        attempts: int,
        timeout_category: str | None,
        cancellation_category: str | None,
        downstream_sandbox_audit_id: str | None,
    ) -> str | None:
        audit_payload = build_adapter_audit_payload(
            adapter_request_id=adapter_request_id,
            correlation_id=correlation_id,
            operation=operation,
            payload_size_bytes=payload_size,
            payload_sha256=payload_sha256,
            gate_decisions=gate_decisions,
            execution_status=execution_status,
            attempts=attempts,
            timeout_category=timeout_category,
            cancellation_category=cancellation_category,
            downstream_sandbox_audit_id=downstream_sandbox_audit_id,
        )
        return record_adapter_audit(self.audit_path, audit_payload)

    @staticmethod
    def _blocked_security(reason: str | None) -> dict[str, Any]:
        return {
            "sandbox_enforced": False,
            "redaction_applied": False,
            "path_policy_passed": reason != "path_policy_violation",
            "external_network_used": False,
            "real_provider_used": False,
            "public_server_created": False,
            "remote_transport_available": False,
            "background_daemon_started": False,
            "downstream_sandbox_audit_id": None,
        }

    @staticmethod
    def _blocked_execution(*, cancelled: bool = False) -> dict[str, Any]:
        return {
            "attempts": 0,
            "retry_executed": False,
            "automatic_retry": False,
            "blind_retry": False,
            "timed_out": False,
            "cancelled": cancelled,
            "execution_after_timeout": False,
            "sandbox_runtime_invoked": False,
        }

    @staticmethod
    def _transport_proof() -> dict[str, Any]:
        return {
            "local_only": True,
            "public_listener_created": False,
            "remote_transport_available": False,
            "outbound_network_requests": 0,
            "localhost_http_server_started": False,
            "background_daemon_started": False,
        }

    @staticmethod
    def _contains_dangerous_key(value: Any) -> bool:
        if isinstance(value, Mapping):
            return any(
                str(key) in _DANGEROUS_KEYS or LocalAgentAdapter._contains_dangerous_key(child)
                for key, child in value.items()
            )
        if isinstance(value, list):
            return any(LocalAgentAdapter._contains_dangerous_key(item) for item in value)
        return False

    @staticmethod
    def _validate_id(value: Any) -> str | None:
        if not isinstance(value, str) or not value or len(value) > 128:
            return None
        lowered = value.lower()
        if any(marker in lowered for marker in _SECRET_ID_MARKERS):
            return None
        return value

    @staticmethod
    def _safe_id(value: Any, default: str) -> str:
        if isinstance(value, str) and value and len(value) <= 128:
            lowered = value.lower()
            if not any(marker in lowered for marker in _SECRET_ID_MARKERS):
                return value
        return default

    @staticmethod
    def _stable_json(payload: Any) -> str:
        return json.dumps(payload, sort_keys=True, ensure_ascii=False, default=str, separators=(",", ":"))
