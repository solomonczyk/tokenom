"""Local developer tool integration CLI commands."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from tokenom.local_developer_tool.config import (
    default_audit_path,
    default_fixture_repository_root,
)
from tokenom.local_developer_tool.service import LocalDeveloperToolService

from .main import main


@main.group("local-dev-tool")
def local_dev_tool() -> None:
    """Run sandbox-only local developer tool integration commands."""


@local_dev_tool.command("run")
@click.option(
    "--request",
    "request_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
    help="Path to a local developer tool request JSON fixture.",
)
@click.option(
    "--audit-path",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Optional local JSONL audit output path.",
)
@click.option(
    "--manifest-dir",
    type=click.Path(file_okay=False, path_type=Path),
    default=None,
    help="Optional safe manifest output directory.",
)
def run_request(request_path: Path, audit_path: Path | None, manifest_dir: Path | None) -> None:
    """Run one local developer tool request through Tokenom guardrails."""

    try:
        request = json.loads(request_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        click.echo(
            json.dumps(
                {
                    "tool_request_id": "unknown",
                    "correlation_id": "unknown",
                    "status": "blocked",
                    "operation": "unknown",
                    "repository": {},
                    "bundle": {},
                    "security": {"external_network_used": False, "real_provider_used": False},
                    "execution": {"attempts": 0, "retry_executed": False},
                    "error": {"category": "malformed_request", "detail": str(exc)},
                },
                sort_keys=True,
            )
        )
        sys.exit(2)

    service = LocalDeveloperToolService(
        audit_path=audit_path or default_audit_path(),
        manifest_dir=manifest_dir,
    )
    result = service.execute(request)
    click.echo(json.dumps(result, indent=2, sort_keys=True))
    sys.exit(0 if result.get("status") == "completed" else 2)


@local_dev_tool.command("health")
@click.option(
    "--audit-path",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Optional local JSONL audit output path.",
)
def health(audit_path: Path | None) -> None:
    """Return safe local developer tool health JSON without scanning a repository."""

    request = {
        "tool_request_id": "devtool-health",
        "correlation_id": "devtool-health",
        "mode": "sandbox",
        "operation": "developer_tool_health",
        "repository": {
            "root": str(default_fixture_repository_root()),
            "include": ["README.md"],
            "exclude": [],
        },
        "context": {
            "max_files": 1,
            "max_file_bytes": 1024,
            "max_bundle_bytes": 2048,
            "include_git_metadata": False,
        },
        "execution": {"timeout_ms": 1000, "allow_retry": False},
    }
    service = LocalDeveloperToolService(audit_path=audit_path or default_audit_path())
    result = service.execute(request)
    click.echo(json.dumps(result, indent=2, sort_keys=True))
    sys.exit(0 if result.get("status") == "completed" else 2)
