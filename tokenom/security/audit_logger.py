"""Audit proof helpers that never persist raw prompts or responses by default."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any

from .redactor import redact_text


@dataclass
class AuditLogger:
    """Append-only JSONL audit logger.

    Raw payload fields are not written unless explicitly enabled, and the
    default remains redacted-only for prompts, tool outputs, and responses.
    """

    path: Path
    log_raw_prompts: bool = False
    log_raw_tool_outputs: bool = False
    log_raw_responses: bool = False
    log_redacted_payload_only: bool = True

    def record_event(self, event_type: str, payload: Any | None = None) -> dict[str, Any]:
        safe_payload = self._sanitize_payload(payload)
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "redacted_payload": safe_payload,
            "raw_payload_written": False,
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, sort_keys=True) + "\n")
        return entry

    def _sanitize_payload(self, payload: Any | None) -> Any:
        if payload is None:
            return None
        if isinstance(payload, str):
            return redact_text(payload)
        serialized = json.dumps(payload, sort_keys=True, default=str)
        return json.loads(redact_text(serialized))


def build_session_audit(**overrides: Any) -> dict[str, Any]:
    """Build the baseline Tokenom session audit proof payload."""

    audit = {
        "project": "Tokenom",
        "based_on": "chopratejas/headroom",
        "license_preserved": True,
        "proxy_local_only": True,
        "raw_logs_written": False,
        "requests_total": 0,
        "blocked_requests": 0,
        "secrets_detected": 0,
        "secrets_redacted": 0,
        "forbidden_paths_blocked": True,
        "production_keys_sent": False,
        "compression_enabled": True,
        "token_reduction_percent": None,
        "cache_hit_rate": None,
        "safe_to_continue": True,
    }
    audit.update(overrides)
    return audit
