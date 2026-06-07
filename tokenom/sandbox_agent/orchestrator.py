"""Fail-closed orchestration for Tokenom's sandbox agent integration."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from headroom import CompressConfig, compress
from tokenom.security.path_policy import PathPolicy
from tokenom.security.payload_policy import CachedPayloadGuard
from tokenom.security.redactor import redact_text
from tokenom.security.scanner import scan_text

from .audit import build_audit_payload, prompt_hash, record_audit
from .config import default_allowed_sandbox_root, is_sandbox_agent_enabled, repository_root
from .contracts import SandboxAgentRequest, SandboxAgentResult
from .provider import MockSandboxProvider, MockSandboxProviderError, MockSandboxProviderTimeout

_ALLOWED_TOP_LEVEL = {"request_id", "mode", "task_type", "input", "workspace", "provider", "metadata"}
_ALLOWED_INPUT = {"prompt", "context"}
_ALLOWED_WORKSPACE = {"root"}
_ALLOWED_METADATA = {"source", "mock_behavior"}
_DANGEROUS_KEYS = {
    "api_key",
    "apiKey",
    "secret",
    "secrets",
    "credential",
    "credentials",
    "private",
    "private_project",
    "production",
    "production_mode",
    "real_provider",
    "provider_config",
}
_BLOCKED_ROOT_FRAGMENTS = (".env", ".git", "%USERPROFILE%", "secrets", "credentials")


class SandboxAgentOrchestrator:
    """Run a sandbox request through Tokenom security, runtime, provider, and audit."""

    def __init__(
        self,
        *,
        provider: MockSandboxProvider | None = None,
        audit_path: Path | None = None,
        allowed_roots: tuple[Path, ...] | None = None,
        payload_guard: CachedPayloadGuard | None = None,
        env: dict[str, str] | None = None,
    ) -> None:
        self.provider = provider or MockSandboxProvider()
        self.audit_path = audit_path
        self.allowed_roots = tuple(
            root.resolve() for root in (allowed_roots or (default_allowed_sandbox_root(),))
        )
        self.payload_guard = payload_guard or CachedPayloadGuard()
        self.env = env
        self.path_policy = PathPolicy()
        self.real_provider_calls = 0
        self.external_network_requests = 0
        self.runtime_calls = 0
        self.optimization_calls = 0

    def run(self, payload: dict[str, Any]) -> dict[str, Any]:
        if not is_sandbox_agent_enabled(self.env):
            return self._blocked_result("sandbox_integration_disabled", "unknown", "unknown", audit=False)

        request_id = str(payload.get("request_id") or "unknown") if isinstance(payload, dict) else "unknown"
        provider = str(payload.get("provider") or "unknown") if isinstance(payload, dict) else "unknown"

        request = self._validate_contract(payload)
        if isinstance(request, str):
            return self._blocked_result(request, request_id, provider)

        workspace_decision = self._validate_workspace(request.workspace.get("root"))
        if workspace_decision is not None:
            return self._blocked_result(workspace_decision, request.request_id, request.provider)

        prompt = request.input.get("prompt", "")
        context = request.input.get("context", {})
        if not isinstance(prompt, str) or not isinstance(context, dict):
            return self._blocked_result("invalid_input_contract", request.request_id, request.provider)

        redacted_object, findings_count = self._redact_value({"prompt": prompt, "context": context})
        redacted_input = json.dumps(redacted_object, sort_keys=True, ensure_ascii=False)
        redaction_applied = findings_count > 0
        guard_decision = self.payload_guard.guard(redacted_input, mode="redact")
        cache_stats = self.payload_guard.stats()

        runtime = self._invoke_runtime(redacted_input, cache_stats)
        provider_payload = {
            "request_id": request.request_id,
            "task_type": request.task_type,
            "redacted_input": guard_decision.payload,
            "mock_behavior": request.metadata.get("mock_behavior", "success"),
            "runtime_tokens_saved": runtime.get("tokens_saved", 0),
        }

        try:
            provider_response = self.provider.invoke(provider_payload)
        except MockSandboxProviderTimeout:
            return self._failure_result(
                request=request,
                reason="mock_provider_timeout",
                runtime=runtime,
                redaction_applied=redaction_applied,
                redaction_count=findings_count,
                prompt_sha256=prompt_hash(prompt),
            )
        except MockSandboxProviderError:
            return self._failure_result(
                request=request,
                reason="mock_provider_error",
                runtime=runtime,
                redaction_applied=redaction_applied,
                redaction_count=findings_count,
                prompt_sha256=prompt_hash(prompt),
            )

        audit_id = self._record(
            request_id=request.request_id,
            mode=request.mode,
            provider=request.provider,
            status="completed",
            error_category=None,
            policy_decisions=self._policy_decisions(True, True, True),
            redaction_applied=redaction_applied,
            redaction_count=findings_count,
            runtime=runtime,
            prompt_sha256=prompt_hash(prompt),
        )
        result = SandboxAgentResult(
            request_id=request.request_id,
            status="completed",
            mode=request.mode,
            provider=request.provider,
            output={"content": provider_response["content"]},
            security={
                "redaction_applied": redaction_applied,
                "redaction_count": findings_count,
                "path_policy_passed": True,
                "external_network_used": False,
                "real_provider_used": False,
                "provider_called": True,
                "provider_called_count": self.provider.calls,
            },
            runtime=runtime,
            audit_id=audit_id,
        )
        return result.to_dict()

    def _validate_contract(self, payload: dict[str, Any]) -> SandboxAgentRequest | str:
        if not isinstance(payload, dict):
            return "malformed_request"
        if set(payload) - _ALLOWED_TOP_LEVEL:
            return "dangerous_extra_field"
        if any(key in payload for key in _DANGEROUS_KEYS):
            return "private_or_production_flag_forbidden"
        for required in ("request_id", "mode", "task_type", "input", "workspace", "provider"):
            if required not in payload:
                return "malformed_request"
        if payload.get("mode") != "sandbox":
            return "production_mode_forbidden"
        if payload.get("provider") != "mock":
            return "real_provider_forbidden"
        if not payload.get("request_id"):
            return "missing_request_id"
        if not isinstance(payload.get("input"), dict) or set(payload["input"]) - _ALLOWED_INPUT:
            return "invalid_input_contract"
        if not isinstance(payload.get("workspace"), dict) or set(payload["workspace"]) - _ALLOWED_WORKSPACE:
            return "invalid_workspace_contract"
        metadata = payload.get("metadata") or {}
        if not isinstance(metadata, dict) or set(metadata) - _ALLOWED_METADATA:
            return "invalid_metadata_contract"
        if self._contains_dangerous_key(payload):
            return "private_or_production_flag_forbidden"
        return SandboxAgentRequest.from_mapping(payload)

    def _validate_workspace(self, root_value: Any) -> str | None:
        if not isinstance(root_value, str) or not root_value:
            return "invalid_workspace_root"
        root_value = root_value.replace("<repo>", str(repository_root()))
        normalized = root_value.replace("\\", "/")
        if ".." in Path(normalized).parts or any(fragment.lower() in normalized.lower() for fragment in _BLOCKED_ROOT_FRAGMENTS):
            return "path_policy_violation"
        try:
            root = Path(root_value).expanduser().resolve()
        except (OSError, RuntimeError):
            return "path_policy_violation"
        if not any(root == allowed or root.is_relative_to(allowed) for allowed in self.allowed_roots):
            return "path_policy_violation"
        relative = root.relative_to(next(allowed for allowed in self.allowed_roots if root == allowed or root.is_relative_to(allowed)))
        if not self.path_policy.check(str(relative) or ".").allowed:
            return "path_policy_violation"
        return None

    def _invoke_runtime(self, redacted_input: str, cache_stats: Any) -> dict[str, Any]:
        self.runtime_calls += 1
        self.optimization_calls += 1
        result = compress(
            [{"role": "user", "content": redacted_input}],
            optimize=False,
            config=CompressConfig(
                compress_user_messages=True,
                protect_recent=0,
                min_tokens_to_compress=1,
                kompress_model="disabled",
            ),
        )
        native_core_available = self._native_core_available()
        return {
            "tokenom_runtime_used": True,
            "tokenom_runtime_invoked": True,
            "optimization_layer_used": True,
            "optimization_layer_invoked": True,
            "cache_checked": True,
            "cache_hits": cache_stats.hits,
            "cache_misses": cache_stats.misses,
            "cache_stores": cache_stats.stores,
            "native_core_available": native_core_available,
            "tokens_saved": result.tokens_saved,
            "transforms_applied": list(result.transforms_applied),
        }

    def _failure_result(
        self,
        *,
        request: SandboxAgentRequest,
        reason: str,
        runtime: dict[str, Any],
        redaction_applied: bool,
        redaction_count: int,
        prompt_sha256: str,
    ) -> dict[str, Any]:
        audit_id = self._record(
            request_id=request.request_id,
            mode=request.mode,
            provider=request.provider,
            status="failed",
            error_category=reason,
            policy_decisions=self._policy_decisions(True, True, True),
            redaction_applied=redaction_applied,
            redaction_count=redaction_count,
            runtime=runtime,
            prompt_sha256=prompt_sha256,
        )
        return SandboxAgentResult(
            request_id=request.request_id,
            status="failed",
            mode=request.mode,
            provider=request.provider,
            output={},
            security={
                "redaction_applied": redaction_applied,
                "redaction_count": redaction_count,
                "path_policy_passed": True,
                "external_network_used": False,
                "real_provider_used": False,
                "provider_called": True,
                "provider_called_count": self.provider.calls,
            },
            runtime=runtime,
            audit_id=audit_id,
            error={"category": reason},
        ).to_dict()

    def _blocked_result(
        self,
        reason: str,
        request_id: str,
        provider: str,
        *,
        audit: bool = True,
    ) -> dict[str, Any]:
        runtime = {
            "tokenom_runtime_used": False,
            "tokenom_runtime_invoked": False,
            "optimization_layer_used": False,
            "optimization_layer_invoked": False,
            "cache_checked": False,
            "native_core_available": self._native_core_available(),
        }
        audit_id = None
        if audit:
            audit_id = self._record(
                request_id=request_id,
                mode="sandbox" if reason != "production_mode_forbidden" else "blocked",
                provider=provider,
                status="blocked",
                error_category=reason,
                policy_decisions=self._policy_decisions(
                    reason != "production_mode_forbidden",
                    reason != "real_provider_forbidden",
                    reason != "path_policy_violation",
                ),
                redaction_applied=False,
                redaction_count=0,
                runtime=runtime,
                prompt_sha256="unavailable",
            )
        return SandboxAgentResult(
            request_id=request_id,
            status="blocked",
            mode="sandbox",
            provider=provider,
            output={},
            security={
                "redaction_applied": False,
                "path_policy_passed": reason != "path_policy_violation",
                "external_network_used": False,
                "real_provider_used": False,
                "provider_called": False,
                "provider_called_count": self.provider.calls,
            },
            runtime=runtime,
            audit_id=audit_id,
            error={"category": reason},
        ).to_dict()

    def _record(self, **kwargs: Any) -> str | None:
        if self.audit_path is None:
            return None
        payload = build_audit_payload(**kwargs)
        return record_audit(self.audit_path, payload)

    @staticmethod
    def _policy_decisions(
        sandbox_mode: bool,
        mock_provider: bool,
        path_policy: bool,
    ) -> dict[str, bool]:
        return {
            "sandbox_mode_required": True,
            "sandbox_mode_passed": sandbox_mode,
            "production_mode_blocked": True,
            "mock_provider_required": True,
            "mock_provider_passed": mock_provider,
            "real_provider_blocked": True,
            "path_policy_passed": path_policy,
            "external_network_blocked": True,
        }

    @staticmethod
    def _contains_dangerous_key(value: Any) -> bool:
        if isinstance(value, dict):
            return any(key in _DANGEROUS_KEYS or SandboxAgentOrchestrator._contains_dangerous_key(child) for key, child in value.items())
        if isinstance(value, list):
            return any(SandboxAgentOrchestrator._contains_dangerous_key(item) for item in value)
        return False

    @staticmethod
    def _redact_value(value: Any) -> tuple[Any, int]:
        if isinstance(value, str):
            findings = tuple(scan_text(value))
            return redact_text(value, findings), len(findings)
        if isinstance(value, dict):
            redacted: dict[str, Any] = {}
            total = 0
            for key, child in value.items():
                redacted_child, child_count = SandboxAgentOrchestrator._redact_value(child)
                redacted[key] = redacted_child
                total += child_count
            return redacted, total
        if isinstance(value, list):
            items = []
            total = 0
            for item in value:
                redacted_item, item_count = SandboxAgentOrchestrator._redact_value(item)
                items.append(redacted_item)
                total += item_count
            return items, total
        return value, 0

    @staticmethod
    def _native_core_available() -> bool:
        try:
            import headroom._core  # noqa: F401
        except Exception:
            return False
        return True
