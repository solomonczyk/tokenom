"""Safe audit helpers for local developer tool executions."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tokenom.security.audit_logger import AuditLogger


def safe_hash(value: str) -> str:
    """Return a stable SHA256 hex digest."""

    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def short_audit_id(*parts: str) -> str:
    timestamp = datetime.now(timezone.utc).isoformat()
    return safe_hash(":".join((*parts, timestamp)))[:16]


def build_audit_payload(
    *,
    audit_id: str,
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
) -> dict[str, Any]:
    return {
        "audit_id": audit_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tool_request_id": tool_request_id,
        "correlation_id": correlation_id,
        "operation": operation,
        "status": status,
        "repository": repository,
        "bundle": bundle,
        "security": security,
        "execution": execution,
        "error_category": error_category,
        "downstream_adapter_audit_id": downstream_adapter_audit_id,
        "raw_source_written": False,
        "raw_bundle_written": False,
        "raw_secret_written": False,
        "absolute_paths_written": False,
    }


def record_audit(path: Path | None, payload: dict[str, Any]) -> str | None:
    if path is None:
        return str(payload["audit_id"])
    AuditLogger(path).record_event("local_developer_tool_execution", payload)
    return str(payload["audit_id"])


def read_audit_records(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
