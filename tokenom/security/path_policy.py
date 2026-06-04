"""Path allow/deny policy for Tokenom guardrails."""

from __future__ import annotations

from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import PurePosixPath


DEFAULT_DENYLIST = (
    ".env",
    ".env.*",
    "secrets/",
    "credentials/",
    ".vercel/",
    ".git/config",
    "*.pem",
    "*.key",
    "*.p12",
    "*.sqlite",
    "*.db",
    "node_modules/",
    ".venv/",
    "__pycache__/",
)

DEFAULT_ALLOWLIST_EXAMPLES = (
    "src/",
    "app/",
    "tests/",
    "docs/",
    "README.md",
    "package.json",
    "pyproject.toml",
    "requirements.txt",
)


@dataclass(frozen=True)
class PathDecision:
    allowed: bool
    path: str
    reason: str | None = None


@dataclass(frozen=True)
class PathPolicy:
    denylist: tuple[str, ...] = field(default_factory=lambda: DEFAULT_DENYLIST)
    allowlist_examples: tuple[str, ...] = field(default_factory=lambda: DEFAULT_ALLOWLIST_EXAMPLES)

    def check(self, path: str) -> PathDecision:
        normalized = _normalize(path)
        for pattern in self.denylist:
            if _matches(normalized, pattern):
                return PathDecision(False, normalized, f"matched denylist pattern {pattern}")
        return PathDecision(True, normalized, None)


def is_forbidden_path(path: str, policy: PathPolicy | None = None) -> bool:
    """Return True if *path* is denied by the Tokenom path policy."""

    return not (policy or PathPolicy()).check(path).allowed


def _normalize(path: str) -> str:
    cleaned = path.replace("\\", "/")
    while cleaned.startswith("./"):
        cleaned = cleaned[2:]
    return str(PurePosixPath(cleaned))


def _matches(path: str, pattern: str) -> bool:
    pattern = pattern.replace("\\", "/")
    basename = PurePosixPath(path).name
    if pattern.endswith("/"):
        segment = pattern.strip("/")
        return path == segment or path.startswith(segment + "/") or f"/{segment}/" in f"/{path}/"
    return fnmatch(path, pattern) or fnmatch(basename, pattern)
