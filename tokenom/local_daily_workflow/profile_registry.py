"""Local profile registry for daily workflow operations."""

from __future__ import annotations

import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any

from tokenom.local_developer_tool.config import (
    HARD_MAX_BUNDLE_BYTES,
    HARD_MAX_FILE_BYTES,
    HARD_MAX_FILES,
    MAX_TIMEOUT_MS,
    MIN_TIMEOUT_MS,
)
from tokenom.local_developer_tool.service import LocalDeveloperToolService

from .config import DEFAULT_OPERATION, default_profile, default_registry_path
from .contracts import (
    RepositoryProfile,
    WorkflowExecutionPolicy,
    WorkflowLimits,
    WorkflowProfile,
)

_REGISTRY_TOP_LEVEL = {"version", "profiles"}
_PROFILE_KEYS = {"profile_id", "enabled", "mode", "repository", "operation", "limits", "execution"}
_REPOSITORY_KEYS = {"root", "approved", "include", "exclude"}
_LIMIT_KEYS = {"max_files", "max_file_bytes", "max_bundle_bytes", "timeout_ms"}
_EXECUTION_KEYS = {"allow_retry"}
_DANGEROUS_KEYS = {
    "api_key",
    "apiKey",
    "cmd",
    "command",
    "credential",
    "credentials",
    "exec",
    "execute",
    "private",
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


class RegistryError(ValueError):
    """Base error for local daily workflow registry issues."""


class RegistryCorruptionError(RegistryError):
    """Raised when the registry cannot be parsed safely."""


class ProfileValidationError(RegistryError):
    """Raised when a profile violates the local daily workflow contract."""


class ProfileRegistry:
    """Load, validate, and update local daily workflow profiles."""

    def __init__(self, path: Path | None = None, *, env: dict[str, str] | None = None) -> None:
        self.env = env
        self.path = path or default_registry_path(env)

    def ensure_default_registry(self) -> None:
        if self.path.exists():
            return
        self._write_payload({"version": 1, "profiles": [default_profile()]})

    def list_profiles(self) -> list[WorkflowProfile]:
        payload = self._load_payload()
        return self._profiles_from_payload(payload)

    def get(self, profile_id: str) -> WorkflowProfile:
        for profile in self.list_profiles():
            if profile.profile_id == profile_id:
                return profile
        raise ProfileValidationError("profile_not_found")

    def validate(self) -> dict[str, Any]:
        profiles = self.list_profiles()
        return {
            "valid": True,
            "profile_count": len(profiles),
            "profiles": [profile.to_safe_dict() for profile in profiles],
            "registry_path": self.safe_registry_path(),
        }

    def enable(self, profile_id: str) -> WorkflowProfile:
        return self._set_enabled(profile_id, True)

    def disable(self, profile_id: str) -> WorkflowProfile:
        return self._set_enabled(profile_id, False)

    def safe_registry_path(self) -> str:
        return self._redact_path(self.path)

    def _set_enabled(self, profile_id: str, enabled: bool) -> WorkflowProfile:
        payload = self._load_payload()
        found = False
        for profile in payload["profiles"]:
            if profile.get("profile_id") == profile_id:
                profile["enabled"] = enabled
                found = True
                break
        if not found:
            raise ProfileValidationError("profile_not_found")
        self._profiles_from_payload(payload)
        self._write_payload(payload)
        return self.get(profile_id)

    def _load_payload(self) -> dict[str, Any]:
        self.ensure_default_registry()
        last_error: OSError | None = None
        for _ in range(3):
            try:
                payload = json.loads(self.path.read_text(encoding="utf-8"))
                break
            except json.JSONDecodeError as exc:
                raise RegistryCorruptionError("registry_corrupted") from exc
            except OSError as exc:
                last_error = exc
                time.sleep(0.02)
        else:
            raise RegistryCorruptionError("registry_unreadable") from last_error
        if not isinstance(payload, dict) or set(payload) - _REGISTRY_TOP_LEVEL:
            raise RegistryCorruptionError("registry_schema_invalid")
        if payload.get("version") != 1 or not isinstance(payload.get("profiles"), list):
            raise RegistryCorruptionError("registry_schema_invalid")
        return payload

    def _profiles_from_payload(self, payload: dict[str, Any]) -> list[WorkflowProfile]:
        seen: set[str] = set()
        profiles = []
        for raw_profile in payload["profiles"]:
            profile = self._parse_profile(raw_profile)
            if profile.profile_id in seen:
                raise ProfileValidationError("duplicate_profile_id")
            seen.add(profile.profile_id)
            profiles.append(profile)
        return profiles

    def _parse_profile(self, raw: Any) -> WorkflowProfile:
        if not isinstance(raw, dict) or set(raw) - _PROFILE_KEYS:
            raise ProfileValidationError("unknown_profile_field")
        if self._contains_dangerous_key(raw):
            raise ProfileValidationError("production_provider_or_shell_field_forbidden")
        profile_id = raw.get("profile_id")
        if not isinstance(profile_id, str) or not profile_id or len(profile_id) > 64:
            raise ProfileValidationError("invalid_profile_id")
        if not isinstance(raw.get("enabled"), bool):
            raise ProfileValidationError("invalid_profile_enabled")
        if raw.get("mode") != "sandbox":
            raise ProfileValidationError("production_mode_forbidden")
        if raw.get("operation") != DEFAULT_OPERATION:
            raise ProfileValidationError("unsupported_operation")

        repository = self._parse_repository(raw.get("repository"))
        limits = self._parse_limits(raw.get("limits"))
        execution = self._parse_execution(raw.get("execution"))
        return WorkflowProfile(
            profile_id=profile_id,
            enabled=raw["enabled"],
            mode="sandbox",
            repository=repository,
            operation=DEFAULT_OPERATION,
            limits=limits,
            execution=execution,
        )

    def _parse_repository(self, raw: Any) -> RepositoryProfile:
        if not isinstance(raw, dict) or set(raw) - _REPOSITORY_KEYS:
            raise ProfileValidationError("invalid_repository_contract")
        root_value = raw.get("root")
        if not isinstance(root_value, str) or not root_value:
            raise ProfileValidationError("invalid_repository_root")
        if root_value.startswith("\\\\") or root_value.startswith("//"):
            raise ProfileValidationError("invalid_repository_root")
        try:
            root = Path(root_value).expanduser().resolve()
        except (OSError, RuntimeError) as exc:
            raise ProfileValidationError("invalid_repository_root") from exc
        if not root.exists() or not root.is_dir() or LocalDeveloperToolService._is_forbidden_broad_root(root):
            raise ProfileValidationError("invalid_repository_root")
        if raw.get("approved") is not True:
            raise ProfileValidationError("repository_not_approved")
        include = raw.get("include")
        exclude = raw.get("exclude")
        if not isinstance(include, list) or not include or not all(isinstance(item, str) for item in include):
            raise ProfileValidationError("invalid_include_patterns")
        if not isinstance(exclude, list) or not all(isinstance(item, str) for item in exclude):
            raise ProfileValidationError("invalid_exclude_patterns")
        for pattern in include:
            if LocalDeveloperToolService._invalid_relative_pattern(pattern):
                raise ProfileValidationError("invalid_include_patterns")
        for pattern in exclude:
            if LocalDeveloperToolService._invalid_relative_pattern(pattern):
                raise ProfileValidationError("invalid_exclude_patterns")
        return RepositoryProfile(
            root=root,
            approved=True,
            include=tuple(include),
            exclude=tuple(exclude),
        )

    @staticmethod
    def _parse_limits(raw: Any) -> WorkflowLimits:
        if not isinstance(raw, dict) or set(raw) - _LIMIT_KEYS:
            raise ProfileValidationError("invalid_limits_contract")
        max_files = raw.get("max_files")
        max_file_bytes = raw.get("max_file_bytes")
        max_bundle_bytes = raw.get("max_bundle_bytes")
        timeout_ms = raw.get("timeout_ms")
        if not isinstance(max_files, int) or max_files < 1 or max_files > HARD_MAX_FILES:
            raise ProfileValidationError("limits_exceed_policy")
        if not isinstance(max_file_bytes, int) or max_file_bytes < 1 or max_file_bytes > HARD_MAX_FILE_BYTES:
            raise ProfileValidationError("limits_exceed_policy")
        if not isinstance(max_bundle_bytes, int) or max_bundle_bytes < 1 or max_bundle_bytes > HARD_MAX_BUNDLE_BYTES:
            raise ProfileValidationError("limits_exceed_policy")
        if not isinstance(timeout_ms, int) or timeout_ms < MIN_TIMEOUT_MS or timeout_ms > MAX_TIMEOUT_MS:
            raise ProfileValidationError("limits_exceed_policy")
        return WorkflowLimits(max_files, max_file_bytes, max_bundle_bytes, timeout_ms)

    @staticmethod
    def _parse_execution(raw: Any) -> WorkflowExecutionPolicy:
        if not isinstance(raw, dict) or set(raw) - _EXECUTION_KEYS:
            raise ProfileValidationError("invalid_execution_contract")
        if raw.get("allow_retry") is not False:
            raise ProfileValidationError("retry_forbidden")
        return WorkflowExecutionPolicy(allow_retry=False)

    def _write_payload(self, payload: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(
            prefix=f".{self.path.name}.",
            suffix=".tmp",
            dir=str(self.path.parent),
            text=True,
        )
        tmp_path = Path(tmp_name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
                json.dump(payload, handle, indent=2, sort_keys=True)
                handle.write("\n")
            try:
                tmp_path.chmod(0o600)
            except OSError:
                pass
            os.replace(tmp_path, self.path)
            try:
                self.path.chmod(0o600)
            except OSError:
                pass
        finally:
            if tmp_path.exists():
                try:
                    tmp_path.unlink()
                except OSError:
                    pass

    @staticmethod
    def _contains_dangerous_key(value: Any) -> bool:
        if isinstance(value, dict):
            return any(
                str(key) in _DANGEROUS_KEYS or ProfileRegistry._contains_dangerous_key(child)
                for key, child in value.items()
            )
        if isinstance(value, list):
            return any(ProfileRegistry._contains_dangerous_key(item) for item in value)
        return False

    @staticmethod
    def _redact_path(path: Path) -> str:
        parts = path.parts
        if len(parts) <= 2:
            return "<local-state>"
        return str(Path("<local-state>", *parts[-2:]))
