"""Controlled local agent adapter CLI command."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from tokenom.local_agent_adapter.adapter import LocalAgentAdapter
from tokenom.local_agent_adapter.config import local_agent_default_audit_path

from .main import main


@main.command("local-agent-run")
@click.option(
    "--fixture",
    "fixture_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
    help="Path to a local agent adapter request JSON fixture.",
)
@click.option(
    "--audit-path",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Optional local JSONL audit output path.",
)
def local_agent_run(fixture_path: Path, audit_path: Path | None) -> None:
    """Run one dummy local agent adapter request through Tokenom guardrails."""

    try:
        request = json.loads(fixture_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        click.echo(
            json.dumps(
                {
                    "adapter_request_id": "unknown",
                    "correlation_id": "unknown",
                    "status": "blocked",
                    "operation": "unknown",
                    "result": {},
                    "error": {"category": "malformed_request", "detail": str(exc)},
                    "security": {
                        "external_network_used": False,
                        "real_provider_used": False,
                    },
                    "execution": {
                        "attempts": 0,
                        "retry_executed": False,
                        "sandbox_runtime_invoked": False,
                    },
                },
                sort_keys=True,
            )
        )
        sys.exit(2)

    adapter = LocalAgentAdapter(audit_path=audit_path or local_agent_default_audit_path())
    result = adapter.execute(request)
    click.echo(json.dumps(result, indent=2, sort_keys=True))
    sys.exit(0 if result.get("status") == "completed" else 2)
