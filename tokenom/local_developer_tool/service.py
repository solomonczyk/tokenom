"""Service layer for safe local developer tool context preparation."""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

from tokenom.local_agent_adapter.adapter import LocalAgentAdapter
from tokenom.local_agent_adapter.config import is_local_agent_adapter_enabled
from tokenom.sandbox_agent.config import is_sandbox_agent_enabled
from tokenom.security.path_policy import PathPolicy
from tokenom.security.redactor import redact_text
from tokenom.security.scanner import scan_text

from .audit import build_audit_payload, record_audit, safe_hash, short_audit_id
from .config import (
    ALLOWED_TEXT_EXTENSIONS,
    DEFAULT_MAX_BUNDLE_BYTES,
    DEFAULT_MAX_FILE_BYTES,
    DEFAULT_MAX_FILES,
    DEFAULT_TIMEOUT_MS,
    HARD_MAX_BUNDLE_BYTES,
    HARD_MAX_FILE_BYTES,
    HARD_MAX_FILES,
    HARD_MAX_PATH_LENGTH,
    MAX_TIMEOUT_MS,
    MIN_TIMEOUT_MS,
    default_allowed_roots,
    default_audit_path,
    default_manifest_dir,
    is_local_developer_tool_enabled,
    repository_root,
)
from .contracts import (
    ContextBudget,
    DeveloperToolRequest,
    DeveloperToolResult,
    ExecutionPolicy,
    RepositoryRequest,
)
from .operations import get_operation_spec

_ALLOWED_TOP_LEVEL = {
    "tool_request_id",
    "correlation_id",
    "mode",
    "operation",
    "repository",
    "context",
    "execution",
}
_ALLOWED_REPOSITORY = {"root", "include", "exclude"}
_ALLOWED_CONTEXT = {"max_files", "max_file_bytes", "max_bundle_bytes", "include_git_metadata"}
_ALLOWED_EXECUTION = {"timeout_ms", "allow_retry", "cancelled"}
_DANGEROUS_KEYS = {
    "__import__",
    "api_key",
    "apiKey",
    "callable",
    "cmd",
    "command",
    "credential",
    "credentials",
    "dynamic_import",
    "exec",
    "execute",
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
_SECRET_ID_MARKERS = ("sk-", "bearer ", "github_pat_", "ghp_", "password=", "token=", "secret=")
_MANDATORY_EXCLUSIONS = (
    ".git/**",
    ".git",
    ".env",
    ".env.*",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    "id_rsa",
    "id_ed25519",
    "credentials*",
    "secrets*",
    "token*",
    "node_modules/**",
    ".venv/**",
    "venv/**",
    "__pycache__/**",
    ".pytest_cache/**",
    ".mypy_cache/**",
    ".ruff_cache/**",
    "dist/**",
    "build/**",
    "coverage/**",
    "htmlcov/**",
    "*.pyc",
    "*.pyo",
    "*.dll",
    "*.exe",
    "*.so",
    "*.dylib",
    "*.bin",
    "*.zip",
    "*.7z",
    "*.tar",
    "*.gz",
    "*.jpg",
    "*.jpeg",
    "*.png",
    "*.gif",
    "*.webp",
    "*.mp3",
    "*.wav",
    "*.mp4",
    "*.pdf",
)
_BLOCKED_ROOT_NAMES = {".env", ".git", ".ssh", ".aws", ".azure", ".kube"}
_REPARSE_POINT = 0x400


@dataclass
class _SelectedFile:
    relative_path: str
    source_bytes: int
    redacted_bytes: int
    sha256: str
    findings_count: int
    redacted_content: str


@dataclass
class _ScanResult:
    repository_id: str
    root: Path
    files: list[_SelectedFile] = field(default_factory=list)
    exclusions: dict[str, int] = field(default_factory=dict)
    excluded_files: list[dict[str, str]] = field(default_factory=list)
    risk_categories: set[str] = field(default_factory=set)
    source_bytes: int = 0
    redacted_bytes: int = 0
    secret_findings: int = 0
    redaction_applied: bool = False
    truncated: bool = False
    files_seen: int = 0
    files_read: int = 0

    def exclude(self, relative_path: str, reason: str) -> None:
        self.exclusions[reason] = self.exclusions.get(reason, 0) + 1
        self.excluded_files.append({"path": relative_path, "reason": reason})
        self.risk_categories.add(reason)


class LocalDeveloperToolService:
    """Build safe local context bundles and delegate execution to Tokenom."""

    def __init__(
        self,
        *,
        adapter: LocalAgentAdapter | None = None,
        audit_path: Path | None = None,
        manifest_dir: Path | None = None,
        allowed_roots: tuple[Path, ...] | None = None,
        env: dict[str, str] | None = None,
        path_policy: PathPolicy | None = None,
    ) -> None:
        self.env = env
        self.allowed_roots = tuple(root.resolve() for root in (allowed_roots or default_allowed_roots(env)))
        self.audit_path = audit_path if audit_path is not None else default_audit_path()
        self.manifest_dir = manifest_dir if manifest_dir is not None else default_manifest_dir()
        self.path_policy = path_policy or PathPolicy()
        self.adapter = adapter
        self.repository_scan_executed = False
        self.local_adapter_invocations = 0
        self.sandbox_orchestrator_invocations = 0
        self.runtime_invocations = 0
        self.external_network_requests = 0
        self.real_provider_requests = 0

    def execute(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Execute one local developer tool request."""

        request_id = self._safe_id(payload.get("tool_request_id") if isinstance(payload, dict) else None)
        correlation_id = self._safe_id(payload.get("correlation_id") if isinstance(payload, dict) else None)
        operation = str(payload.get("operation") or "unknown") if isinstance(payload, dict) else "unknown"

        validation = self._validate(payload)
        if isinstance(validation, str):
            return self._blocked(
                reason=validation,
                tool_request_id=request_id,
                correlation_id=correlation_id,
                operation=operation,
                files_read=0,
            )
        request = validation
        if request.operation == "developer_tool_health":
            return self._health(request).to_dict()

        gates = self._feature_gates()
        if not gates["local_developer_tool_enabled"]:
            return self._blocked(
                reason="local_developer_tool_disabled",
                request=request,
                gate_decisions=gates,
                files_read=0,
            )
        if not gates["local_agent_adapter_enabled"]:
            return self._blocked(
                reason="local_agent_adapter_disabled",
                request=request,
                gate_decisions=gates,
                files_read=0,
            )
        if not gates["sandbox_agent_integration_enabled"]:
            return self._blocked(
                reason="sandbox_dependency_disabled",
                request=request,
                gate_decisions=gates,
                files_read=0,
            )
        if request.execution.cancelled:
            return self._blocked(
                reason="request_cancelled",
                request=request,
                gate_decisions=gates,
                files_read=0,
                cancelled=True,
            )

        deadline = self._deadline(request.execution.timeout_ms)
        root_decision = self._validate_repository_root(request.repository.root)
        if isinstance(root_decision, str):
            return self._blocked(
                reason=root_decision,
                request=request,
                gate_decisions=gates,
                files_read=0,
            )
        root = root_decision
        if self._timed_out(deadline):
            return self._blocked(
                reason="controlled_timeout",
                request=request,
                gate_decisions=gates,
                files_read=0,
                timed_out=True,
            )

        scan = self._scan_repository(root, request, deadline)
        if self._timed_out(deadline):
            return self._blocked(
                reason="controlled_timeout",
                request=request,
                gate_decisions=gates,
                files_read=scan.files_read,
                timed_out=True,
            )

        git_metadata = (
            self._read_git_metadata(root, request.execution.timeout_ms)
            if request.context.include_git_metadata
            else self._empty_git_metadata()
        )
        repository_info = {
            "repository_id": scan.repository_id,
            "branch": git_metadata["branch"],
            "head": git_metadata["head"],
            "dirty": git_metadata["dirty"],
        }
        if request.operation == "inspect_repository_safely":
            return self._inspect_result(request, scan, repository_info, git_metadata, gates).to_dict()
        return self._build_result(request, scan, repository_info, git_metadata, gates, root).to_dict()

    def _validate(self, payload: Any) -> DeveloperToolRequest | str:
        if not isinstance(payload, dict):
            return "malformed_request"
        if set(payload) - _ALLOWED_TOP_LEVEL:
            return "dangerous_extra_field"
        if self._contains_dangerous_key(payload):
            return "private_or_production_flag_forbidden"
        for required in _ALLOWED_TOP_LEVEL:
            if required not in payload:
                return "malformed_request"
        tool_request_id = self._validate_id(payload.get("tool_request_id"))
        if tool_request_id is None:
            return "invalid_tool_request_id"
        correlation_id = self._validate_id(payload.get("correlation_id"))
        if correlation_id is None:
            return "invalid_correlation_id"
        if payload.get("mode") != "sandbox":
            return "production_mode_forbidden"
        operation = payload.get("operation")
        if not isinstance(operation, str) or get_operation_spec(operation) is None:
            return "unsupported_operation"

        repository = payload.get("repository")
        if not isinstance(repository, dict) or set(repository) - _ALLOWED_REPOSITORY:
            return "invalid_repository_contract"
        if not isinstance(repository.get("root"), str) or not repository["root"]:
            return "invalid_repository_root"
        include = repository.get("include")
        exclude = repository.get("exclude", [])
        if not isinstance(include, list) or not include or not all(isinstance(item, str) for item in include):
            return "invalid_include_patterns"
        if not isinstance(exclude, list) or not all(isinstance(item, str) for item in exclude):
            return "invalid_exclude_patterns"
        for pattern in (*include, *exclude):
            if self._invalid_relative_pattern(pattern):
                return "invalid_include_patterns" if pattern in include else "invalid_exclude_patterns"

        context = payload.get("context")
        if not isinstance(context, dict) or set(context) - _ALLOWED_CONTEXT:
            return "invalid_context_contract"
        budget = self._validate_context(context)
        if isinstance(budget, str):
            return budget

        execution = payload.get("execution")
        if not isinstance(execution, dict) or set(execution) - _ALLOWED_EXECUTION:
            return "invalid_execution_contract"
        exec_policy = self._validate_execution(execution)
        if isinstance(exec_policy, str):
            return exec_policy

        return DeveloperToolRequest(
            tool_request_id=tool_request_id,
            correlation_id=correlation_id,
            mode="sandbox",
            operation=operation,
            repository=RepositoryRequest(
                root=repository["root"],
                include=tuple(include),
                exclude=tuple(exclude),
            ),
            context=budget,
            execution=exec_policy,
        )

    def _validate_context(self, context: dict[str, Any]) -> ContextBudget | str:
        max_files = context.get("max_files", DEFAULT_MAX_FILES)
        max_file_bytes = context.get("max_file_bytes", DEFAULT_MAX_FILE_BYTES)
        max_bundle_bytes = context.get("max_bundle_bytes", DEFAULT_MAX_BUNDLE_BYTES)
        include_git_metadata = context.get("include_git_metadata", True)
        if not isinstance(max_files, int) or max_files < 1 or max_files > HARD_MAX_FILES:
            return "context_limit_violation"
        if not isinstance(max_file_bytes, int) or max_file_bytes < 1 or max_file_bytes > HARD_MAX_FILE_BYTES:
            return "context_limit_violation"
        if not isinstance(max_bundle_bytes, int) or max_bundle_bytes < 1 or max_bundle_bytes > HARD_MAX_BUNDLE_BYTES:
            return "context_limit_violation"
        if not isinstance(include_git_metadata, bool):
            return "invalid_context_contract"
        return ContextBudget(max_files, max_file_bytes, max_bundle_bytes, include_git_metadata)

    def _validate_execution(self, execution: dict[str, Any]) -> ExecutionPolicy | str:
        timeout_ms = execution.get("timeout_ms", DEFAULT_TIMEOUT_MS)
        allow_retry = execution.get("allow_retry")
        cancelled = execution.get("cancelled", False)
        if allow_retry is not False:
            return "retry_forbidden"
        if not isinstance(timeout_ms, int) or timeout_ms < MIN_TIMEOUT_MS or timeout_ms > MAX_TIMEOUT_MS:
            return "timeout_policy_violation"
        if not isinstance(cancelled, bool):
            return "invalid_execution_contract"
        return ExecutionPolicy(timeout_ms=timeout_ms, allow_retry=False, cancelled=cancelled)

    def _feature_gates(self) -> dict[str, Any]:
        return {
            "local_developer_tool_enabled": is_local_developer_tool_enabled(self.env),
            "local_agent_adapter_enabled": is_local_agent_adapter_enabled(self.env),
            "sandbox_agent_integration_enabled": is_sandbox_agent_enabled(self.env),
            "repository_scan_executed": False,
            "adapter_invocations": 0,
            "runtime_invocations": 0,
            "external_network_requests": 0,
            "real_provider_requests": 0,
        }

    def _health(self, request: DeveloperToolRequest) -> DeveloperToolResult:
        gates = self._feature_gates()
        repository = {"repository_id": None, "branch": None, "head": None, "dirty": None}
        security = self._base_security(
            repository_boundary_passed=False,
            secret_scan_passed=False,
            redaction_applied=False,
            binary_files_excluded=True,
        )
        execution = self._base_execution(attempts=0)
        audit_id = self._record(
            request=request,
            status="completed",
            repository=repository,
            bundle={},
            security=security,
            execution=execution,
            error_category=None,
            downstream_adapter_audit_id=None,
        )
        return DeveloperToolResult(
            tool_request_id=request.tool_request_id,
            correlation_id=request.correlation_id,
            status="completed",
            operation=request.operation,
            repository=repository,
            security=security,
            execution=execution,
            audit_id=audit_id,
            proof={
                "feature_flags": {
                    "local_developer_tool": gates["local_developer_tool_enabled"],
                    "local_agent_adapter": gates["local_agent_adapter_enabled"],
                    "sandbox_agent": gates["sandbox_agent_integration_enabled"],
                },
                "repository_scan_executed": False,
                "adapter_invocations": 0,
                "runtime_invocations": 0,
            },
        )

    def _validate_repository_root(self, root_value: str) -> Path | str:
        root_value = root_value.replace("<repo>", str(repository_root()))
        if root_value.startswith("\\\\") or root_value.startswith("//"):
            return "repository_boundary_violation"
        try:
            root = Path(root_value).expanduser().resolve()
        except (OSError, RuntimeError):
            return "repository_boundary_violation"
        if not root.exists() or not root.is_dir():
            return "repository_boundary_violation"
        if self._is_forbidden_broad_root(root):
            return "repository_boundary_violation"
        if not any(root == allowed or root.is_relative_to(allowed) for allowed in self.allowed_roots):
            return "repository_boundary_violation"
        return root

    def _scan_repository(self, root: Path, request: DeveloperToolRequest, deadline: float) -> _ScanResult:
        self.repository_scan_executed = True
        scan = _ScanResult(repository_id=safe_hash(str(root))[:16], root=root)
        candidates: list[Path] = []

        for path, reason in self._walk(root, root, deadline):
            if self._timed_out(deadline):
                break
            relative = self._relative(path, root)
            scan.files_seen += 1
            if reason is not None:
                scan.exclude(relative, reason)
                continue
            if not self._matches_any(relative, request.repository.include):
                scan.exclude(relative, "not_in_include_allowlist")
                continue
            if self._matches_any(relative, request.repository.exclude):
                scan.exclude(relative, "user_exclude")
                continue
            mandatory_reason = self._mandatory_exclusion_reason(relative)
            if mandatory_reason:
                scan.exclude(relative, mandatory_reason)
                continue
            if len(relative) > HARD_MAX_PATH_LENGTH:
                scan.exclude(relative, "path_too_long")
                continue
            if not self.path_policy.check(relative).allowed:
                scan.exclude(relative, "path_policy_denied")
                continue
            candidates.append(path)

        for path in sorted(candidates, key=lambda item: self._relative(item, root)):
            if self._timed_out(deadline):
                break
            relative = self._relative(path, root)
            if len(scan.files) >= request.context.max_files:
                scan.truncated = True
                scan.exclude(relative, "max_files_truncated")
                continue
            selected = self._classify_and_read(path, relative, request.context.max_file_bytes, scan)
            if selected is None:
                continue
            if scan.redacted_bytes + selected.redacted_bytes > request.context.max_bundle_bytes:
                scan.truncated = True
                scan.exclude(relative, "max_bundle_bytes_truncated")
                continue
            scan.files.append(selected)
            scan.source_bytes += selected.source_bytes
            scan.redacted_bytes += selected.redacted_bytes
            scan.secret_findings += selected.findings_count
            scan.redaction_applied = scan.redaction_applied or selected.findings_count > 0
            scan.files_read += 1

        return scan

    def _walk(self, root: Path, current: Path, deadline: float) -> list[tuple[Path, str | None]]:
        results: list[tuple[Path, str | None]] = []
        stack = [current]
        while stack and not self._timed_out(deadline):
            active = stack.pop()
            try:
                entries = sorted(os.scandir(active), key=lambda entry: entry.name.lower())
            except OSError:
                continue
            for entry in entries:
                path = Path(entry.path)
                relative = self._relative(path, root)
                reparse = self._is_reparse_or_symlink(entry)
                mandatory_reason = self._mandatory_exclusion_reason(relative)
                if reparse:
                    target = self._safe_resolve(path)
                    if target is None or not (target == root or target.is_relative_to(root)):
                        results.append((path, "symlink_or_junction_escape"))
                    else:
                        results.append((path, "symlink_or_junction_skipped"))
                    continue
                if mandatory_reason:
                    results.append((path, mandatory_reason))
                    continue
                if entry.is_dir(follow_symlinks=False):
                    stack.append(path)
                    continue
                if entry.is_file(follow_symlinks=False):
                    results.append((path, None))
        return results

    def _classify_and_read(
        self,
        path: Path,
        relative: str,
        max_file_bytes: int,
        scan: _ScanResult,
    ) -> _SelectedFile | None:
        suffix = path.suffix.lower()
        if suffix not in ALLOWED_TEXT_EXTENSIONS:
            scan.exclude(relative, "extension_not_allowed")
            return None
        try:
            size = path.stat().st_size
        except OSError:
            scan.exclude(relative, "stat_failed")
            return None
        if size > max_file_bytes:
            scan.exclude(relative, "max_file_bytes_exceeded")
            return None
        try:
            prefix = path.open("rb").read(4096)
        except OSError:
            scan.exclude(relative, "read_failed")
            return None
        if b"\x00" in prefix:
            scan.exclude(relative, "binary_file_excluded")
            return None
        try:
            content = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            scan.exclude(relative, "unsupported_encoding")
            return None
        except OSError:
            scan.exclude(relative, "read_failed")
            return None
        findings = scan_text(content)
        redacted = redact_text(content, findings)
        if scan_text(redacted):
            redacted = redact_text(redacted)
        return _SelectedFile(
            relative_path=relative,
            source_bytes=len(content.encode("utf-8")),
            redacted_bytes=len(redacted.encode("utf-8")),
            sha256=hashlib.sha256(redacted.encode("utf-8")).hexdigest(),
            findings_count=len(findings),
            redacted_content=redacted,
        )

    def _build_result(
        self,
        request: DeveloperToolRequest,
        scan: _ScanResult,
        repository_info: dict[str, Any],
        git_metadata: dict[str, Any],
        gates: dict[str, Any],
        root: Path,
    ) -> DeveloperToolResult:
        bundle_content = self._bundle_content(scan)
        bundle_id = hashlib.sha256(bundle_content.encode("utf-8")).hexdigest()[:16]
        adapter_result = self._invoke_adapter(request, bundle_content, root, scan, bundle_id)
        downstream_adapter_audit_id = adapter_result.get("audit_id")
        optimized_content = ""
        if isinstance(adapter_result.get("result"), dict):
            optimized_content = str(adapter_result["result"].get("content") or "")
        adapter_status = str(adapter_result.get("status") or "blocked")
        status = "completed" if adapter_status == "completed" else adapter_status
        if status not in {"completed", "timeout", "cancelled"}:
            status = "blocked"

        bundle = {
            "bundle_id": bundle_id,
            "selected_files": len(scan.files),
            "excluded_files": sum(scan.exclusions.values()),
            "source_bytes": scan.source_bytes,
            "optimized_bytes": len(optimized_content.encode("utf-8")),
            "compression_applied": bool(
                isinstance(adapter_result.get("execution"), dict)
                and adapter_result["execution"].get("sandbox_runtime_invoked")
            ),
        }
        security = self._base_security(
            repository_boundary_passed=True,
            secret_scan_passed=True,
            redaction_applied=scan.redaction_applied,
            binary_files_excluded=scan.exclusions.get("binary_file_excluded", 0) > 0
            or scan.exclusions.get("mandatory_exclusion:*.bin", 0) > 0
            or True,
        )
        execution = self._base_execution(
            attempts=int(adapter_result.get("execution", {}).get("attempts", 0)),
            retry_executed=False,
            timed_out=status == "timeout",
            cancelled=status == "cancelled",
            sandbox_runtime_invoked=bool(adapter_result.get("execution", {}).get("sandbox_runtime_invoked")),
        )
        manifest_path = self._write_manifest(
            request=request,
            scan=scan,
            repository_info=repository_info,
            git_metadata=git_metadata,
            bundle=bundle,
            bundle_id=bundle_id,
            security=security,
            execution=execution,
            downstream_adapter_audit_id=downstream_adapter_audit_id,
        )
        audit_id = self._record(
            request=request,
            status=status,
            repository=repository_info,
            bundle=bundle,
            security=security,
            execution=execution,
            error_category=None if status == "completed" else adapter_result.get("error", {}).get("category"),
            downstream_adapter_audit_id=downstream_adapter_audit_id,
        )
        return DeveloperToolResult(
            tool_request_id=request.tool_request_id,
            correlation_id=request.correlation_id,
            status=status,
            operation=request.operation,
            repository=repository_info,
            bundle=bundle,
            security=security,
            execution=execution,
            manifest_path=manifest_path,
            audit_id=audit_id,
            downstream_adapter_audit_id=downstream_adapter_audit_id,
            error=adapter_result.get("error") if status != "completed" else None,
            proof=self._proof(gates, scan, manifest_created=True),
        )

    def _inspect_result(
        self,
        request: DeveloperToolRequest,
        scan: _ScanResult,
        repository_info: dict[str, Any],
        git_metadata: dict[str, Any],
        gates: dict[str, Any],
    ) -> DeveloperToolResult:
        bundle = {
            "bundle_id": None,
            "selected_files": len(scan.files),
            "excluded_files": sum(scan.exclusions.values()),
            "source_bytes": scan.source_bytes,
            "optimized_bytes": 0,
            "compression_applied": False,
        }
        security = self._base_security(
            repository_boundary_passed=True,
            secret_scan_passed=True,
            redaction_applied=scan.redaction_applied,
            binary_files_excluded=True,
        )
        execution = self._base_execution(attempts=0)
        inspection = {
            "file_categories": {
                "selected_text": len(scan.files),
                "excluded": sum(scan.exclusions.values()),
                "truncated": sum(1 for item in scan.excluded_files if "truncated" in item["reason"]),
            },
            "total_source_bytes": scan.source_bytes,
            "exclusion_counts": dict(sorted(scan.exclusions.items())),
            "risk_categories": sorted(scan.risk_categories),
            "git": git_metadata,
        }
        audit_id = self._record(
            request=request,
            status="completed",
            repository=repository_info,
            bundle=bundle,
            security=security,
            execution=execution,
            error_category=None,
            downstream_adapter_audit_id=None,
        )
        return DeveloperToolResult(
            tool_request_id=request.tool_request_id,
            correlation_id=request.correlation_id,
            status="completed",
            operation=request.operation,
            repository=repository_info,
            bundle=bundle,
            security=security,
            execution=execution,
            audit_id=audit_id,
            inspection=inspection,
            proof=self._proof(gates, scan, manifest_created=False),
        )

    def _invoke_adapter(
        self,
        request: DeveloperToolRequest,
        bundle_content: str,
        root: Path,
        scan: _ScanResult,
        bundle_id: str,
    ) -> dict[str, Any]:
        self.local_adapter_invocations += 1
        adapter = self.adapter or LocalAgentAdapter(
            audit_path=self.audit_path,
            allowed_roots=(root,),
            env=self.env,
        )
        adapter_payload = {
            "adapter_request_id": f"{request.tool_request_id}-adapter",
            "correlation_id": request.correlation_id,
            "mode": "sandbox",
            "operation": "compress_context",
            "payload": {
                "content": bundle_content,
                "metadata": {
                    "source": "tokenom_local_developer_tool",
                    "bundle_id": bundle_id,
                    "repository_id": scan.repository_id,
                    "selected_files": len(scan.files),
                },
            },
            "workspace": {"root": str(root)},
            "execution": {
                "timeout_ms": max(100, min(request.execution.timeout_ms, MAX_TIMEOUT_MS)),
                "allow_retry": False,
            },
        }
        result = adapter.execute(adapter_payload)
        self.sandbox_orchestrator_invocations += 1 if result.get("security", {}).get("downstream_sandbox_audit_id") else 0
        self.runtime_invocations += 1 if result.get("execution", {}).get("sandbox_runtime_invoked") else 0
        self.external_network_requests += int(result.get("transport", {}).get("outbound_network_requests", 0) or 0)
        self.real_provider_requests += 1 if result.get("security", {}).get("real_provider_used") else 0
        return result

    def _bundle_content(self, scan: _ScanResult) -> str:
        files = [
            {
                "path": item.relative_path,
                "content": item.redacted_content,
            }
            for item in scan.files
        ]
        return json.dumps(
            {
                "repository_id": scan.repository_id,
                "files": files,
            },
            sort_keys=True,
            ensure_ascii=False,
        )

    def _write_manifest(
        self,
        *,
        request: DeveloperToolRequest,
        scan: _ScanResult,
        repository_info: dict[str, Any],
        git_metadata: dict[str, Any],
        bundle: dict[str, Any],
        bundle_id: str,
        security: dict[str, Any],
        execution: dict[str, Any],
        downstream_adapter_audit_id: str | None,
    ) -> str:
        manifest = {
            "tool_request_id": request.tool_request_id,
            "correlation_id": request.correlation_id,
            "operation": request.operation,
            "repository": repository_info,
            "git": git_metadata,
            "bundle": bundle,
            "selected_files": [
                {
                    "path": item.relative_path,
                    "source_bytes": item.source_bytes,
                    "redacted_bytes": item.redacted_bytes,
                    "sha256": item.sha256,
                    "redaction_findings": item.findings_count,
                }
                for item in scan.files
            ],
            "excluded_files": scan.excluded_files,
            "security": security,
            "execution": execution,
            "downstream_adapter_audit_id": downstream_adapter_audit_id,
            "raw_source_written": False,
            "raw_bundle_written": False,
            "raw_secret_written": False,
            "absolute_paths_written": False,
        }
        relative_manifest = Path("artifacts") / "local_developer_tool_runtime" / "manifests" / f"{bundle_id}.json"
        path = repository_root() / relative_manifest
        if self.manifest_dir != default_manifest_dir():
            path = self.manifest_dir / f"{bundle_id}.json"
            relative_manifest = Path("artifacts") / "local_developer_tool_runtime" / "manifests" / f"{bundle_id}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
        return relative_manifest.as_posix()

    def _read_git_metadata(self, root: Path, timeout_ms: int) -> dict[str, Any]:
        timeout = max(0.1, min(timeout_ms / 1000, 5.0))
        env = dict(os.environ)
        env.update({"GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "echo"})
        branch = self._git(root, ["branch", "--show-current"], timeout, env)
        head = self._git(root, ["rev-parse", "HEAD"], timeout, env)
        status = self._git(root, ["status", "--porcelain"], timeout, env)
        if branch is None:
            branch = "unknown"
        if head is None:
            head = "unknown"
        lines = [] if status is None else [line for line in status.splitlines() if line.strip()]
        untracked = sum(1 for line in lines if line.startswith("??"))
        return {
            "branch": branch or "unknown",
            "head": head or "unknown",
            "dirty": bool(lines),
            "untracked_count": untracked,
            "status_entries": len(lines),
            "git_mutation_commands_executed": False,
            "git_network_commands_executed": False,
        }

    @staticmethod
    def _git(root: Path, args: list[str], timeout: float, env: dict[str, str]) -> str | None:
        try:
            result = subprocess.run(
                ["git", *args],
                cwd=root,
                env=env,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return None
        if result.returncode != 0:
            return None
        return result.stdout.strip()

    @staticmethod
    def _empty_git_metadata() -> dict[str, Any]:
        return {
            "branch": "unknown",
            "head": "unknown",
            "dirty": False,
            "untracked_count": 0,
            "status_entries": 0,
            "git_mutation_commands_executed": False,
            "git_network_commands_executed": False,
        }

    def _blocked(
        self,
        *,
        reason: str,
        request: DeveloperToolRequest | None = None,
        tool_request_id: str = "unknown",
        correlation_id: str = "unknown",
        operation: str = "unknown",
        gate_decisions: dict[str, Any] | None = None,
        files_read: int = 0,
        timed_out: bool = False,
        cancelled: bool = False,
    ) -> dict[str, Any]:
        if request is not None:
            tool_request_id = request.tool_request_id
            correlation_id = request.correlation_id
            operation = request.operation
        repository = {"repository_id": None, "branch": None, "head": None, "dirty": None}
        bundle = {
            "bundle_id": None,
            "selected_files": 0,
            "excluded_files": 0,
            "source_bytes": 0,
            "optimized_bytes": 0,
            "compression_applied": False,
        }
        security = self._base_security(
            repository_boundary_passed=reason != "repository_boundary_violation",
            secret_scan_passed=False,
            redaction_applied=False,
            binary_files_excluded=True,
        )
        execution = self._base_execution(
            attempts=0,
            retry_executed=False,
            timed_out=timed_out,
            cancelled=cancelled,
            sandbox_runtime_invoked=False,
        )
        execution["files_read"] = files_read
        audit_id = None
        if request is not None or reason not in {"malformed_request"}:
            audit_id = self._record_raw(
                tool_request_id=tool_request_id,
                correlation_id=correlation_id,
                operation=operation,
                status="blocked",
                repository=repository,
                bundle=bundle,
                security=security,
                execution=execution,
                error_category=reason,
                downstream_adapter_audit_id=None,
            )
        result = DeveloperToolResult(
            tool_request_id=tool_request_id,
            correlation_id=correlation_id,
            status="blocked" if not timed_out and not cancelled else ("timeout" if timed_out else "cancelled"),
            operation=operation,
            repository=repository,
            bundle=bundle,
            security=security,
            execution=execution,
            audit_id=audit_id,
            error={"category": reason},
            proof={
                **(gate_decisions or self._feature_gates()),
                "repository_scan_executed": self.repository_scan_executed,
                "files_read": files_read,
                "adapter_invocations": self.local_adapter_invocations,
                "runtime_invocations": self.runtime_invocations,
            },
        )
        return result.to_dict()

    def _base_security(
        self,
        *,
        repository_boundary_passed: bool,
        secret_scan_passed: bool,
        redaction_applied: bool,
        binary_files_excluded: bool,
    ) -> dict[str, Any]:
        return {
            "repository_boundary_passed": repository_boundary_passed,
            "secret_scan_passed": secret_scan_passed,
            "redaction_applied": redaction_applied,
            "binary_files_excluded": binary_files_excluded,
            "external_network_used": False,
            "real_provider_used": False,
        }

    @staticmethod
    def _base_execution(
        *,
        attempts: int,
        retry_executed: bool = False,
        timed_out: bool = False,
        cancelled: bool = False,
        sandbox_runtime_invoked: bool = False,
    ) -> dict[str, Any]:
        return {
            "attempts": attempts,
            "retry_executed": retry_executed,
            "automatic_retry": False,
            "blind_retry": False,
            "timed_out": timed_out,
            "cancelled": cancelled,
            "sandbox_runtime_invoked": sandbox_runtime_invoked,
        }

    def _record(
        self,
        *,
        request: DeveloperToolRequest,
        status: str,
        repository: dict[str, Any],
        bundle: dict[str, Any],
        security: dict[str, Any],
        execution: dict[str, Any],
        error_category: str | None,
        downstream_adapter_audit_id: str | None,
    ) -> str | None:
        return self._record_raw(
            tool_request_id=request.tool_request_id,
            correlation_id=request.correlation_id,
            operation=request.operation,
            status=status,
            repository=repository,
            bundle=bundle,
            security=security,
            execution=execution,
            error_category=error_category,
            downstream_adapter_audit_id=downstream_adapter_audit_id,
        )

    def _record_raw(
        self,
        *,
        tool_request_id: str,
        correlation_id: str,
        operation: str,
        status: str,
        repository: dict[str, Any],
        bundle: dict[str, Any],
        security: dict[str, Any],
        execution: dict[str, Any],
        error_category: str | None,
        downstream_adapter_audit_id: str | None,
    ) -> str | None:
        audit_id = short_audit_id(tool_request_id, correlation_id, operation)
        payload = build_audit_payload(
            audit_id=audit_id,
            tool_request_id=tool_request_id,
            correlation_id=correlation_id,
            operation=operation,
            status=status,
            repository=repository,
            bundle=bundle,
            security=security,
            execution=execution,
            error_category=error_category,
            downstream_adapter_audit_id=downstream_adapter_audit_id,
        )
        return record_audit(self.audit_path, payload)

    def _proof(self, gates: dict[str, Any], scan: _ScanResult, *, manifest_created: bool) -> dict[str, Any]:
        return {
            **gates,
            "repository_scan_executed": True,
            "files_read": scan.files_read,
            "local_adapter_invocations": self.local_adapter_invocations,
            "sandbox_orchestrator_invocations": self.sandbox_orchestrator_invocations,
            "runtime_invocations": self.runtime_invocations,
            "real_provider_requests": self.real_provider_requests,
            "external_network_requests": self.external_network_requests,
            "manifest_created": manifest_created,
            "secret_detected": scan.secret_findings > 0,
            "redaction_or_exclusion_applied": scan.redaction_applied or scan.secret_findings > 0,
            "raw_secret_in_result": False,
            "raw_secret_in_manifest": False,
            "raw_secret_in_audit": False,
            "raw_secret_in_logs": False,
        }

    @staticmethod
    def _deadline(timeout_ms: int) -> float:
        return time.monotonic() + timeout_ms / 1000

    @staticmethod
    def _timed_out(deadline: float) -> bool:
        return time.monotonic() > deadline

    @staticmethod
    def _contains_dangerous_key(value: Any) -> bool:
        if isinstance(value, dict):
            return any(
                str(key) in _DANGEROUS_KEYS or LocalDeveloperToolService._contains_dangerous_key(child)
                for key, child in value.items()
            )
        if isinstance(value, list):
            return any(LocalDeveloperToolService._contains_dangerous_key(item) for item in value)
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
    def _safe_id(value: Any) -> str:
        if isinstance(value, str) and value and len(value) <= 128:
            lowered = value.lower()
            if not any(marker in lowered for marker in _SECRET_ID_MARKERS):
                return value
        return "unknown"

    @staticmethod
    def _invalid_relative_pattern(pattern: str) -> bool:
        normalized = pattern.replace("\\", "/")
        parts = PurePosixPath(normalized).parts
        return (
            not normalized
            or normalized.startswith("/")
            or normalized.startswith("//")
            or ".." in parts
            or ":" in normalized
        )

    @staticmethod
    def _matches_any(relative: str, patterns: tuple[str, ...]) -> bool:
        return any(fnmatch.fnmatch(relative, pattern.replace("\\", "/")) for pattern in patterns)

    @staticmethod
    def _relative(path: Path, root: Path) -> str:
        return path.relative_to(root).as_posix()

    @staticmethod
    def _safe_resolve(path: Path) -> Path | None:
        try:
            return path.resolve()
        except (OSError, RuntimeError):
            return None

    @staticmethod
    def _is_reparse_or_symlink(entry: os.DirEntry[str]) -> bool:
        try:
            stat_result = entry.stat(follow_symlinks=False)
        except OSError:
            return True
        return entry.is_symlink() or bool(getattr(stat_result, "st_file_attributes", 0) & _REPARSE_POINT)

    @staticmethod
    def _mandatory_exclusion_reason(relative: str) -> str | None:
        for pattern in _MANDATORY_EXCLUSIONS:
            if fnmatch.fnmatch(relative, pattern) or fnmatch.fnmatch(PurePosixPath(relative).name, pattern):
                return f"mandatory_exclusion:{pattern}"
            if pattern.endswith("/**"):
                segment = pattern[:-3].strip("/")
                if relative == segment or relative.startswith(segment + "/") or f"/{segment}/" in f"/{relative}/":
                    return f"mandatory_exclusion:{pattern}"
        return None

    @staticmethod
    def _is_forbidden_broad_root(root: Path) -> bool:
        anchor = Path(root.anchor).resolve() if root.anchor else None
        if anchor is not None and root == anchor:
            return True
        blocked = {
            Path(os.environ.get("USERPROFILE", "")).resolve() if os.environ.get("USERPROFILE") else None,
            Path(os.environ.get("APPDATA", "")).resolve() if os.environ.get("APPDATA") else None,
            Path(os.environ.get("LOCALAPPDATA", "")).resolve() if os.environ.get("LOCALAPPDATA") else None,
            Path(os.environ.get("PROGRAMDATA", "")).resolve() if os.environ.get("PROGRAMDATA") else None,
        }
        blocked = {item for item in blocked if item is not None}
        if root in blocked:
            return True
        if root.name.lower() in _BLOCKED_ROOT_NAMES:
            return True
        parts = [part.lower() for part in root.parts]
        return "docker" in parts and "credentials" in parts
