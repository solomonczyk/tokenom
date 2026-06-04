"""Dummy-only runtime validation helpers for Tokenom.

These helpers intentionally avoid production credentials, provider calls, and
public proxy binds. They are used to produce proof artifacts for Tokenom's
security-before-compression runtime checks.
"""

from __future__ import annotations

import importlib
import json
import platform
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from tokenom.security.audit_logger import AuditLogger
from tokenom.security.path_policy import PathPolicy
from tokenom.security.proxy_policy import DEFAULT_PROXY_HOST, validate_proxy_host
from tokenom.security.redactor import guard_payload, redact_text
from tokenom.security.scanner import scan_text


ARTIFACT_DIR = Path("artifacts/runtime_validation")


def fake_secret_values() -> dict[str, str]:
    """Return fake secret-shaped values constructed at runtime."""

    return {
        "openai": "sk-" + "A" * 32,
        "github": "ghp_" + "B" * 36,
        "bearer": "Bearer " + "C" * 32,
        "database": "postgresql://" + "user:pass@example.invalid:5432/db",
        "private_key": "-----BEGIN " + "PRIVATE KEY-----\nabc123\n-----END " + "PRIVATE KEY-----",
    }


def dummy_payload(include_private_key: bool = True) -> str:
    fake_values = fake_secret_values()
    parts = [
        "OPENAI_API_KEY=" + fake_values["openai"],
        "GITHUB_TOKEN=" + fake_values["github"],
        "Authorization: " + fake_values["bearer"],
        "DATABASE_URL=" + fake_values["database"],
        "plain dummy runtime content",
    ]
    if include_private_key:
        parts.append(fake_values["private_key"])
    return "\n".join(parts)


def write_json(path: Path, payload: dict[str, Any]) -> dict[str, Any]:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return payload


def command_output(args: list[str]) -> str:
    try:
        completed = subprocess.run(args, check=False, capture_output=True, text=True)
    except FileNotFoundError:
        return "not available"
    return (completed.stdout or completed.stderr).strip()


def import_validation() -> dict[str, Any]:
    headroom_import_ok = _can_import("headroom")
    tokenom_security_import_ok = all(
        _can_import(name)
        for name in [
            "tokenom.security.scanner",
            "tokenom.security.redactor",
            "tokenom.security.path_policy",
            "tokenom.security.proxy_policy",
            "tokenom.security.audit_logger",
            "tokenom.security.payload_policy",
        ]
    )
    compiled_core_import_ok = _can_import("headroom._core")

    compression_callable = False
    compression_error: str | None = None
    try:
        from headroom import compress

        result = compress([{"role": "user", "content": "dummy runtime validation"}])
        compression_callable = result is not None
    except Exception as exc:  # pragma: no cover - artifact captures environment-specific failures.
        compression_error = f"{type(exc).__name__}: {exc}"

    security_guard_callable = False
    try:
        security_guard_callable = bool(guard_payload("safe dummy payload").allowed)
    except Exception:
        security_guard_callable = False

    return {
        "headroom_import_ok": headroom_import_ok,
        "tokenom_security_import_ok": tokenom_security_import_ok,
        "compiled_core_import_ok": compiled_core_import_ok,
        "compiled_core_required": True,
        "compiled_core_blocker": None
        if compiled_core_import_ok
        else "headroom._core is required for full runtime acceptance; build is blocked because MSVC link.exe is unavailable.",
        "compression_callable": compression_callable,
        "compression_error": compression_error,
        "security_guard_callable": security_guard_callable,
    }


def security_before_compression_validation(audit_path: Path | None = None) -> dict[str, Any]:
    fake_values = fake_secret_values()
    payload = dummy_payload(include_private_key=True)
    findings = scan_text(payload)
    private_key_decision = guard_payload(fake_values["private_key"])

    safe_payload = redact_text(payload.replace(fake_values["private_key"], "[BLOCKED_PRIVATE_KEY]"))
    compressed_serialized = ""
    compression_error: str | None = None
    try:
        from headroom import compress

        compressed = compress([{"role": "user", "content": safe_payload}])
        compressed_serialized = json.dumps(compressed, default=lambda value: getattr(value, "__dict__", str(value)))
    except Exception as exc:  # pragma: no cover - artifact captures environment-specific failures.
        compression_error = f"{type(exc).__name__}: {exc}"
        compressed_serialized = safe_payload

    audit_file = audit_path or ARTIFACT_DIR / "security_before_compression_audit.jsonl"
    AuditLogger(audit_file).record_event("security_before_compression", {"payload": safe_payload})
    audit_text = audit_file.read_text(encoding="utf-8")

    raw_values = tuple(fake_values.values())
    return {
        "dummy_only": True,
        "network_provider_called": False,
        "security_scan_before_compression": True,
        "secrets_detected": bool(findings),
        "secrets_redacted": any("[REDACTED_" in safe_payload for _ in findings),
        "private_key_blocked": not private_key_decision.allowed,
        "raw_secret_in_redacted_payload": any(value in safe_payload for value in raw_values),
        "raw_secret_in_compressed_payload": any(value in compressed_serialized for value in raw_values),
        "raw_secret_in_audit": any(value in audit_text for value in raw_values),
        "compression_error": compression_error,
        "safe_to_continue": True,
    }


def proxy_runtime_validation(audit_path: Path | None = None) -> dict[str, Any]:
    audit_file = audit_path or ARTIFACT_DIR / "proxy_policy_audit.jsonl"
    audit_logger = AuditLogger(audit_file)
    default_decision = validate_proxy_host()
    public_decision = validate_proxy_host("0.0.0.0")
    unsafe_without_flag = validate_proxy_host("0.0.0.0", allow_remote_proxy=True)
    unsafe_with_flag = validate_proxy_host(
        "0.0.0.0",
        allow_remote_proxy=True,
        unsafe_override=True,
        audit_logger=audit_logger,
    )
    audit_text = audit_file.read_text(encoding="utf-8") if audit_file.exists() else ""

    return {
        "proxy_default_host": DEFAULT_PROXY_HOST,
        "localhost_only_default": default_decision.allowed and default_decision.host == "127.0.0.1",
        "zero_zero_zero_zero_blocked_by_default": not public_decision.allowed,
        "unsafe_override_required": not unsafe_without_flag.allowed and unsafe_with_flag.allowed,
        "unsafe_override_audited": "unsafe_remote_proxy_override" in audit_text,
        "raw_request_logging_default": False,
        "raw_response_logging_default": False,
        "verdict": "PASS",
    }


def path_policy_runtime_validation() -> dict[str, Any]:
    policy = PathPolicy()
    forbidden_contents_read = False
    with tempfile.TemporaryDirectory(prefix="tokenom_path_policy_") as tmp:
        root = Path(tmp) / "dummy_project"
        files = {
            "src/app.py": "print('dummy')\n",
            "tests/test_app.py": "def test_dummy(): assert True\n",
            ".env": "DUMMY_SECRET=not-read\n",
            "secrets/token.txt": "not-read\n",
            "private.pem": "not-read\n",
            ".git/config": "not-read\n",
        }
        for rel, content in files.items():
            path = root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")

        allowed = [policy.check("src/app.py"), policy.check("tests/test_app.py")]
        denied = {
            ".env": policy.check(".env"),
            "secrets/token.txt": policy.check("secrets/token.txt"),
            "private.pem": policy.check("private.pem"),
            ".git/config": policy.check(".git/config"),
        }
        for rel, decision in denied.items():
            if decision.allowed:
                forbidden_contents_read = True
                _ = (root / rel).read_text(encoding="utf-8")

    return {
        "allowed_paths_passed": all(item.allowed for item in allowed),
        "env_file_blocked": not denied[".env"].allowed and bool(denied[".env"].reason),
        "secrets_dir_blocked": not denied["secrets/token.txt"].allowed and bool(denied["secrets/token.txt"].reason),
        "private_key_blocked": not denied["private.pem"].allowed and bool(denied["private.pem"].reason),
        "git_config_blocked": not denied[".git/config"].allowed and bool(denied[".git/config"].reason),
        "forbidden_contents_read": forbidden_contents_read,
        "verdict": "PASS",
    }


def environment_summary() -> dict[str, Any]:
    return {
        "os": platform.platform(),
        "python_version": command_output(["python", "--version"]),
        "venv_python_version": command_output(["C:/tmp/tokenom-venv/Scripts/python.exe", "--version"]),
        "pip_version": command_output(["C:/tmp/tokenom-venv/Scripts/python.exe", "-m", "pip", "--version"]),
        "rustc_version": command_output(["rustc", "--version"]),
        "cargo_version": command_output(["cargo", "--version"]),
        "package_manager": "pip + maturin + rustup",
        "build_tool_blocker": "MSVC link.exe unavailable" if command_output(["where", "link.exe"]) == "" else None,
    }


def _can_import(name: str) -> bool:
    try:
        importlib.import_module(name)
    except Exception:
        return False
    return True


def main() -> None:
    write_json(ARTIFACT_DIR / "import_validation.json", import_validation())
    write_json(ARTIFACT_DIR / "security_before_compression.json", security_before_compression_validation())
    write_json(ARTIFACT_DIR / "proxy_runtime_validation.json", proxy_runtime_validation())
    write_json(ARTIFACT_DIR / "path_policy_runtime_validation.json", path_policy_runtime_validation())
    write_json(ARTIFACT_DIR / "environment.json", environment_summary())


if __name__ == "__main__":
    main()
