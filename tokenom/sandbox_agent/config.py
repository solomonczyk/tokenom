"""Configuration helpers for the sandbox agent integration."""

from __future__ import annotations

import os
from pathlib import Path

FEATURE_FLAG = "TOKENOM_SANDBOX_AGENT_INTEGRATION_ENABLED"


def is_sandbox_agent_enabled(env: dict[str, str] | None = None) -> bool:
    """Return True only when the sandbox integration is explicitly enabled."""

    value = (env or os.environ).get(FEATURE_FLAG, "")
    return value.strip().lower() in {"1", "true", "yes", "on", "enabled"}


def repository_root() -> Path:
    """Return the repository root for the installed source tree."""

    return Path(__file__).resolve().parents[2]


def default_allowed_sandbox_root() -> Path:
    """Return the committed dummy workspace root allowed by default."""

    return repository_root() / "tests" / "fixtures" / "sandbox_agent" / "workspace"


def default_audit_path() -> Path:
    """Return the local runtime audit path for CLI executions."""

    return repository_root() / "artifacts" / "sandbox_agent_runtime" / "audit.jsonl"
