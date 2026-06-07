"""Configuration helpers for the controlled local agent adapter."""

from __future__ import annotations

import os
from pathlib import Path

FEATURE_FLAG = "TOKENOM_LOCAL_AGENT_ADAPTER_ENABLED"
MAX_PAYLOAD_BYTES = 262_144
MIN_TIMEOUT_MS = 100
MAX_TIMEOUT_MS = 30_000
DEFAULT_TIMEOUT_MS = 5_000


def is_local_agent_adapter_enabled(env: dict[str, str] | None = None) -> bool:
    """Return True only when the local adapter is explicitly enabled."""

    value = (env or os.environ).get(FEATURE_FLAG, "")
    return value.strip().lower() in {"1", "true", "yes", "on", "enabled"}


def repository_root() -> Path:
    """Return the repository root for the installed source tree."""

    return Path(__file__).resolve().parents[2]


def local_agent_default_workspace_root() -> Path:
    """Return the committed dummy workspace accepted by the local adapter."""

    return repository_root() / "tests" / "fixtures" / "local_agent_adapter" / "workspace"


def local_agent_default_audit_path() -> Path:
    """Return the local adapter JSONL audit path for CLI executions."""

    return repository_root() / "artifacts" / "local_agent_adapter_runtime" / "audit.jsonl"
