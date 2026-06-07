"""Safe audit helpers for local adapter executions."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tokenom.security.audit_logger import AuditLogger


def payload_hash(serialized_payload: str) -> str:
    return hashlib.sha256(serialized_payload.encode("utf-8")).hexdigest()


def build_adapter_audit_payload(
    *,
    adapter_request_id: str,
    correlation_id: str,
    operation: str,
    payload_size_bytes: int,
    payload_sha256: str,
    gate_decisions: dict[str, Any],
    execution_status: str,
    attempts: int,
    timeout_category: str | None,
    cancellation_category: str | None,
    downstream_sandbox_audit_id: str | None,
) -> dict[str, Any]:
    timestamp = datetime.now(timezone.utc).isoformat()
    audit_id = hashlib.sha256(
        f"{adapter_request_id}:{correlation_id}:{operation}:{timestamp}".encode()
    ).hexdigest()[:16]
    return {
        "audit_id": audit_id,
        "timestamp": timestamp,
        "adapter_request_id": adapter_request_id,
        "correlation_id": correlation_id,
        "operation": operation,
        "payload_size_bytes": payload_size_bytes,
        "payload_sha256": payload_sha256,
        "gate_decisions": gate_decisions,
        "execution_status": execution_status,
        "attempts": attempts,
        "timeout_category": timeout_category,
        "cancellation_category": cancellation_category,
        "downstream_sandbox_audit_id": downstream_sandbox_audit_id,
        "raw_payload_written": False,
        "raw_prompt_written": False,
        "raw_output_written": False,
    }


def record_adapter_audit(path: Path | None, payload: dict[str, Any]) -> str | None:
    if path is None:
        return None
    AuditLogger(path).record_event("local_agent_adapter_execution", payload)
    return str(payload["audit_id"])


def read_adapter_audit_records(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    records = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            records.append(json.loads(line))
    return records
