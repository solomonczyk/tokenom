"""Secret scanner used by Tokenom guardrails.

The scanner is intentionally conservative and dependency-free. It detects the
credential shapes Tokenom must never forward or persist raw.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Iterable


@dataclass(frozen=True)
class SecretFinding:
    """A detected secret-like span."""

    secret_type: str
    start: int
    end: int
    value: str
    high_risk: bool = False

    @property
    def redaction_label(self) -> str:
        return f"[REDACTED_{self.secret_type}]"


@dataclass(frozen=True)
class _PatternSpec:
    secret_type: str
    regex: re.Pattern[str]
    high_risk: bool = False


_PATTERNS: tuple[_PatternSpec, ...] = (
    _PatternSpec(
        "PRIVATE_KEY",
        re.compile(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z0-9 ]*PRIVATE KEY-----",
            re.MULTILINE,
        ),
        True,
    ),
    _PatternSpec("OPENAI_API_KEY", re.compile(r"\bsk-(?:proj-|live-)?[A-Za-z0-9_-]{24,}\b"), True),
    _PatternSpec("ANTHROPIC_API_KEY", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"), True),
    _PatternSpec(
        "GITHUB_TOKEN",
        re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}\b|\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
        True,
    ),
    _PatternSpec("VERCEL_TOKEN", re.compile(r"\bvercel_[A-Za-z0-9_-]{20,}\b"), True),
    _PatternSpec("OPERATOR_KEY", re.compile(r"\bopk_[A-Za-z0-9_-]{20,}\b"), True),
    _PatternSpec("BEARER_TOKEN", re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{16,}\b"), True),
    _PatternSpec(
        "JWT",
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
        True,
    ),
    _PatternSpec(
        "COOKIE_OR_SESSION",
        re.compile(r"(?i)\b(?:cookie|session(?:id)?|connect\.sid|sid)\s*[:=]\s*[A-Za-z0-9%._~+/=-]{12,}"),
    ),
    _PatternSpec(
        "DATABASE_URL",
        re.compile(r"(?i)\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis)://[^\s'\"<>]+"),
        True,
    ),
    _PatternSpec(
        "ENV_SECRET",
        re.compile(
            r"(?im)^\s*(?:export\s+)?[A-Z0-9_]*(?:API[_-]?KEY|TOKEN|SECRET|PASSWORD|PASSWD|PRIVATE[_-]?KEY|DATABASE_URL|SESSION[_-]?ID)[A-Z0-9_]*\s*=\s*[^\s#'\"]{8,}\s*$"
        ),
        True,
    ),
)


def scan_text(text: str, *, include_overlaps: bool = False) -> list[SecretFinding]:
    """Return secret-like findings in *text*.

    By default overlapping spans are collapsed in favor of the first, broader
    match. This keeps redaction deterministic for values such as env-style API
    keys that also match a provider-specific token pattern.
    """

    findings: list[SecretFinding] = []
    for spec in _PATTERNS:
        for match in spec.regex.finditer(text):
            findings.append(
                SecretFinding(
                    secret_type=spec.secret_type,
                    start=match.start(),
                    end=match.end(),
                    value=match.group(0),
                    high_risk=spec.high_risk,
                )
            )

    findings = _drop_generic_env_overlaps(findings)
    findings.sort(key=lambda item: (item.start, -(item.end - item.start), item.secret_type))
    if include_overlaps:
        return findings

    collapsed: list[SecretFinding] = []
    occupied_until = -1
    for finding in findings:
        if finding.start < occupied_until:
            continue
        collapsed.append(finding)
        occupied_until = finding.end
    return collapsed


def contains_high_risk_secret(text: str, secret_types: Iterable[str] | None = None) -> bool:
    """Return True when text contains a high-risk secret finding."""

    allowed_types = set(secret_types) if secret_types is not None else None
    return any(
        finding.high_risk and (allowed_types is None or finding.secret_type in allowed_types)
        for finding in scan_text(text)
    )


def _drop_generic_env_overlaps(findings: list[SecretFinding]) -> list[SecretFinding]:
    specific = [finding for finding in findings if finding.secret_type != "ENV_SECRET"]
    result = list(specific)
    for env_finding in (finding for finding in findings if finding.secret_type == "ENV_SECRET"):
        overlaps_specific = any(
            env_finding.start <= finding.start < env_finding.end
            or finding.start <= env_finding.start < finding.end
            for finding in specific
        )
        if not overlaps_specific:
            result.append(env_finding)
    return result
