"""Safe bounded history store for local daily workflow runs."""

from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import HISTORY_RETENTION, default_history_dir


class HistoryStore:
    """Persist safe run records without raw source, output, secrets, or paths."""

    def __init__(
        self,
        history_dir: Path | None = None,
        *,
        env: dict[str, str] | None = None,
        retention: int = HISTORY_RETENTION,
    ) -> None:
        self.history_dir = history_dir or default_history_dir(env)
        self.retention = retention

    def append(self, record: dict[str, Any]) -> dict[str, Any]:
        safe_record = self._safe_record(record)
        self.history_dir.mkdir(parents=True, exist_ok=True)
        path = self._path_for(str(safe_record["run_id"]))
        self._atomic_write(path, safe_record)
        self._enforce_retention()
        return safe_record

    def latest(self) -> dict[str, Any] | None:
        records = self.list(limit=1)
        return records[0] if records else None

    def list(self, *, limit: int = 10) -> list[dict[str, Any]]:
        records = self._read_all()
        records.sort(key=lambda item: str(item.get("timestamp", "")), reverse=True)
        return records[: max(0, limit)]

    def get(self, run_id: str) -> dict[str, Any] | None:
        path = self._path_for(run_id)
        if not path.exists():
            return None
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return {
                "run_id": run_id,
                "status": "corrupted",
                "error_category": "history_record_corrupted",
                "raw_source_written": False,
                "raw_output_written": False,
                "raw_secret_written": False,
                "absolute_paths_written": False,
            }
        return self._safe_record(payload)

    def _read_all(self) -> list[dict[str, Any]]:
        if not self.history_dir.exists():
            return []
        records = []
        for path in self.history_dir.glob("*.json"):
            try:
                records.append(self._safe_record(json.loads(path.read_text(encoding="utf-8"))))
            except (json.JSONDecodeError, OSError):
                records.append(
                    {
                        "run_id": path.stem,
                        "timestamp": datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat(),
                        "status": "corrupted",
                        "error_category": "history_record_corrupted",
                        "raw_source_written": False,
                        "raw_output_written": False,
                        "raw_secret_written": False,
                        "absolute_paths_written": False,
                    }
                )
        return records

    def _enforce_retention(self) -> None:
        records = sorted(
            self.history_dir.glob("*.json"),
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        )
        for stale in records[self.retention :]:
            try:
                stale.unlink()
            except OSError:
                pass

    def _path_for(self, run_id: str) -> Path:
        safe = "".join(ch if ch.isalnum() or ch in {"-", "_"} else "-" for ch in run_id)[:96]
        return self.history_dir / f"{safe}.json"

    @staticmethod
    def _atomic_write(path: Path, payload: dict[str, Any]) -> None:
        fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent), text=True)
        tmp_path = Path(tmp_name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
                json.dump(payload, handle, indent=2, sort_keys=True)
                handle.write("\n")
            try:
                tmp_path.chmod(0o600)
            except OSError:
                pass
            os.replace(tmp_path, path)
        finally:
            if tmp_path.exists():
                try:
                    tmp_path.unlink()
                except OSError:
                    pass

    @staticmethod
    def _safe_record(record: dict[str, Any]) -> dict[str, Any]:
        allowed = {
            "run_id",
            "profile_id",
            "timestamp",
            "status",
            "safe_repository_id",
            "branch",
            "head",
            "selected_files",
            "excluded_files",
            "source_bytes",
            "optimized_bytes",
            "bundle_id",
            "manifest_path",
            "manifest_id",
            "audit_id",
            "adapter_audit_id",
            "sandbox_audit_id",
            "duration_ms",
            "attempts",
            "retry_executed",
            "automatic_retry",
            "error_category",
            "repository_scan_executed",
            "adapter_invocations",
            "runtime_invocations",
            "external_network_requests",
            "real_provider_requests",
            "raw_source_written",
            "raw_output_written",
            "raw_secret_written",
            "absolute_paths_written",
        }
        safe = {key: value for key, value in record.items() if key in allowed}
        safe.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
        safe.setdefault("raw_source_written", False)
        safe.setdefault("raw_output_written", False)
        safe.setdefault("raw_secret_written", False)
        safe.setdefault("absolute_paths_written", False)
        return safe
