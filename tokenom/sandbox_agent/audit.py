"""Safe audit helpers for sandbox agent executions."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tokenom.security.audit_logger import AuditLogger


def prompt_hash(prompt: str) -> str:
    return hashlib.sha256(prompt.encode("utf-8")).hexdigest()


def build_audit_payload(
    *,
    request_id: str,
    mode: str,
    provider: str,
    status: str,
    policy_decisions: dict[str, Any],
    redaction_applied: bool,
    redaction_count: int,
    runtime: dict[str, Any],
    error_category: str | None,
    prompt_sha256: str,
) -> dict[str, Any]:
    timestamp = datetime.now(timezone.utc).isoformat()
    audit_id = hashlib.sha256(f"{request_id}:{timestamp}".encode()).hexdigest()[:16]
    return {
        "audit_id": audit_id,
        "timestamp": timestamp,
        "request_id": request_id,
        "mode": mode,
        "provider": provider,
        "status": status,
        "policy_decisions": policy_decisions,
        "redaction_applied": redaction_applied,
        "redaction_count": redaction_count,
        "runtime": runtime,
        "error_category": error_category,
        "prompt_sha256": prompt_sha256,
        "raw_prompt_written": False,
        "raw_response_written": False,
    }


def record_audit(path: Path, payload: dict[str, Any]) -> str:
    AuditLogger(path).record_event("sandbox_agent_execution", payload)
    return str(payload["audit_id"])


def read_audit_records(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    records = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            records.append(json.loads(line))
    return records
