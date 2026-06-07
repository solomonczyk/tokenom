"""Configuration for the operator-controlled local daily workflow."""

from __future__ import annotations

import os
from pathlib import Path

from tokenom.local_developer_tool.config import repository_root

FEATURE_FLAG = "TOKENOM_LOCAL_DAILY_WORKFLOW_ENABLED"
WORKFLOW_HOME_ENV = "TOKENOM_LOCAL_DAILY_WORKFLOW_HOME"

DEFAULT_PROFILE_ID = "tokenom-safe"
DEFAULT_OPERATION = "build_context_bundle"
DEFAULT_MAX_FILES = 30
DEFAULT_MAX_FILE_BYTES = 131_072
DEFAULT_MAX_BUNDLE_BYTES = 524_288
DEFAULT_TIMEOUT_MS = 10_000
HISTORY_RETENTION = 100

DAILY_WORKFLOW_VERSION = "009"


def is_enabled_value(value: str | None) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes", "on", "enabled"}


def is_local_daily_workflow_enabled(env: dict[str, str] | None = None) -> bool:
    """Return True only when the daily workflow gate is explicitly enabled."""

    return is_enabled_value((env or os.environ).get(FEATURE_FLAG))


def runtime_home(env: dict[str, str] | None = None) -> Path:
    """Return the user-local daily workflow state directory."""

    active_env = env or os.environ
    configured = active_env.get(WORKFLOW_HOME_ENV)
    if configured:
        return Path(configured).expanduser().resolve()
    local_appdata = active_env.get("LOCALAPPDATA")
    if local_appdata:
        return Path(local_appdata).expanduser().resolve() / "Tokenom" / "local_daily_workflow"
    return Path.home().resolve() / ".tokenom" / "local_daily_workflow"


def default_registry_path(env: dict[str, str] | None = None) -> Path:
    return runtime_home(env) / "profiles.json"


def default_history_dir(env: dict[str, str] | None = None) -> Path:
    return runtime_home(env) / "history"


def default_profile() -> dict:
    """Return the built-in disabled tokenom-safe profile."""

    return {
        "profile_id": DEFAULT_PROFILE_ID,
        "enabled": False,
        "mode": "sandbox",
        "repository": {
            "root": str(repository_root().resolve()),
            "approved": True,
            "include": [
                "README.md",
                "docs/integrations/**/*.md",
                "tokenom/**/*.py",
            ],
            "exclude": [],
        },
        "operation": DEFAULT_OPERATION,
        "limits": {
            "max_files": DEFAULT_MAX_FILES,
            "max_file_bytes": DEFAULT_MAX_FILE_BYTES,
            "max_bundle_bytes": DEFAULT_MAX_BUNDLE_BYTES,
            "timeout_ms": DEFAULT_TIMEOUT_MS,
        },
        "execution": {
            "allow_retry": False,
        },
    }
