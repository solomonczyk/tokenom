"""Redaction and blocking decisions for Tokenom payloads."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from .path_policy import is_forbidden_path
from .scanner import SecretFinding, scan_text


BLOCKED_SECRET_TYPES = {
    "PRIVATE_KEY",
}

PRODUCTION_KEY_TYPES = {
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "GITHUB_TOKEN",
    "VERCEL_TOKEN",
    "OPERATOR_KEY",
    "DATABASE_URL",
}


@dataclass(frozen=True)
class PayloadDecision:
    """Result of applying Tokenom payload guardrails."""

    allowed: bool
    payload: str
    findings: tuple[SecretFinding, ...] = field(default_factory=tuple)
    reasons: tuple[str, ...] = field(default_factory=tuple)


def redact_text(text: str, findings: Iterable[SecretFinding] | None = None) -> str:
    """Replace detected secrets with typed redaction markers."""

    active_findings = tuple(scan_text(text) if findings is None else findings)
    redacted = text
    for finding in sorted(active_findings, key=lambda item: item.start, reverse=True):
        redacted = redacted[: finding.start] + finding.redaction_label + redacted[finding.end :]
    return redacted


def guard_payload(
    payload: str,
    *,
    mode: str = "redact",
    path: str | None = None,
    block_production_keys: bool = True,
) -> PayloadDecision:
    """Apply Tokenom's redact/block policy to a payload.

    ``mode="redact"`` returns a sanitized payload unless hard-blocking content
    is found. ``mode="block"`` rejects any detected secret or forbidden path.
    """

    findings = tuple(scan_text(payload))
    reasons: list[str] = []

    if path is not None and is_forbidden_path(path):
        reasons.append(f"forbidden path: {path}")

    blocked_types = {finding.secret_type for finding in findings if finding.secret_type in BLOCKED_SECRET_TYPES}
    if blocked_types:
        reasons.append("blocked secret type: " + ", ".join(sorted(blocked_types)))

    if block_production_keys and mode == "block":
        production_types = {finding.secret_type for finding in findings if finding.secret_type in PRODUCTION_KEY_TYPES}
        if production_types:
            reasons.append("production key payload: " + ", ".join(sorted(production_types)))

    if mode == "block" and findings and not reasons:
        reasons.append("secret detected")

    if reasons:
        return PayloadDecision(False, "", findings, tuple(reasons))

    return PayloadDecision(True, redact_text(payload, findings), findings, ())
