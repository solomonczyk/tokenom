"""Configuration for the sandbox-only local developer tool integration."""

from __future__ import annotations

import os
from pathlib import Path

FEATURE_FLAG = "TOKENOM_LOCAL_DEVELOPER_TOOL_ENABLED"

DEFAULT_MAX_FILES = 50
DEFAULT_MAX_FILE_BYTES = 131_072
DEFAULT_MAX_BUNDLE_BYTES = 524_288
DEFAULT_MAX_PATH_LENGTH = 240

HARD_MAX_FILES = 200
HARD_MAX_FILE_BYTES = 262_144
HARD_MAX_BUNDLE_BYTES = 1_048_576
HARD_MAX_PATH_LENGTH = 260

MIN_TIMEOUT_MS = 1
MAX_TIMEOUT_MS = 30_000
DEFAULT_TIMEOUT_MS = 5_000

ALLOWED_TEXT_EXTENSIONS = frozenset(
    {
        ".py",
        ".js",
        ".ts",
        ".tsx",
        ".jsx",
        ".json",
        ".yaml",
        ".yml",
        ".toml",
        ".md",
        ".txt",
        ".rst",
        ".html",
        ".css",
        ".sql",
    }
)


def is_local_developer_tool_enabled(env: dict[str, str] | None = None) -> bool:
    """Return True only when the developer tool layer is explicitly enabled."""

    value = (env or os.environ).get(FEATURE_FLAG, "")
    return value.strip().lower() in {"1", "true", "yes", "on", "enabled"}


def repository_root() -> Path:
    """Return the Tokenom repository root for this source tree."""

    return Path(__file__).resolve().parents[2]


def default_fixture_repository_root() -> Path:
    """Return the committed dummy repository root accepted by default."""

    return repository_root() / "tests" / "fixtures" / "local_developer_tool" / "repository"


def configured_allowed_roots(env: dict[str, str] | None = None) -> tuple[Path, ...]:
    """Return explicitly configured local developer tool roots."""

    value = (env or os.environ).get("TOKENOM_LOCAL_DEVELOPER_TOOL_ALLOWED_ROOTS", "")
    roots = []
    for item in value.split(os.pathsep):
        if item.strip():
            roots.append(Path(item.strip()))
    return tuple(roots)


def default_allowed_roots(env: dict[str, str] | None = None) -> tuple[Path, ...]:
    """Return default approved roots without granting parent directory access."""

    return (default_fixture_repository_root(), *configured_allowed_roots(env))


def default_audit_path() -> Path:
    """Return the local developer tool JSONL audit path for CLI executions."""

    return repository_root() / "artifacts" / "local_developer_tool_runtime" / "audit.jsonl"


def default_manifest_dir() -> Path:
    """Return the local developer tool manifest directory for CLI executions."""

    return repository_root() / "artifacts" / "local_developer_tool_runtime" / "manifests"
