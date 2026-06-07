"""Sandbox agent integration CLI command."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from tokenom.sandbox_agent.config import default_audit_path
from tokenom.sandbox_agent.orchestrator import SandboxAgentOrchestrator

from .main import main


@main.command("sandbox-agent-run")
@click.option(
    "--fixture",
    "fixture_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
    help="Path to a sandbox request JSON fixture.",
)
@click.option(
    "--audit-path",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Optional local JSONL audit output path.",
)
def sandbox_agent_run(fixture_path: Path, audit_path: Path | None) -> None:
    """Run one dummy sandbox agent request through Tokenom guardrails."""

    try:
        request = json.loads(fixture_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        click.echo(
            json.dumps(
                {
                    "request_id": "unknown",
                    "status": "blocked",
                    "error": {"category": "malformed_request", "detail": str(exc)},
                    "security": {"provider_called": False},
                    "runtime": {"tokenom_runtime_invoked": False},
                },
                sort_keys=True,
            )
        )
        sys.exit(2)

    orchestrator = SandboxAgentOrchestrator(audit_path=audit_path or default_audit_path())
    result = orchestrator.run(request)
    click.echo(json.dumps(result, indent=2, sort_keys=True))
    sys.exit(0 if result.get("status") == "completed" else 2)
