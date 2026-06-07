"""Local daily workflow CLI commands."""

from __future__ import annotations

import json
import sys

import click

from tokenom.local_daily_workflow.profile_registry import RegistryError
from tokenom.local_daily_workflow.service import DailyWorkflowService

from .main import main


@main.group("local-workflow")
def local_workflow() -> None:
    """Run safe operator-controlled local daily workflow commands."""


@local_workflow.command("status")
def status() -> None:
    _emit(DailyWorkflowService().status())


@local_workflow.command("health")
def health() -> None:
    _emit(DailyWorkflowService().health())


@local_workflow.command("profiles")
def profiles() -> None:
    _run_registry(lambda service: service.list_profiles())


@local_workflow.command("profile-show")
@click.option("--profile", "profile_id", required=True)
def profile_show(profile_id: str) -> None:
    _run_registry(lambda service: service.show_profile(profile_id))


@local_workflow.command("profile-enable")
@click.option("--profile", "profile_id", required=True)
def profile_enable(profile_id: str) -> None:
    _run_registry(lambda service: service.enable_profile(profile_id))


@local_workflow.command("profile-disable")
@click.option("--profile", "profile_id", required=True)
def profile_disable(profile_id: str) -> None:
    _run_registry(lambda service: service.disable_profile(profile_id))


@local_workflow.command("disable")
@click.option("--profile", "profile_id", required=True)
def disable(profile_id: str) -> None:
    _run_registry(lambda service: service.disable_profile(profile_id))


@local_workflow.command("preflight")
@click.option("--profile", "profile_id", required=True)
def preflight(profile_id: str) -> None:
    _run_registry(
        lambda service: service.preflight(profile_id),
        exit_from=lambda payload: 0 if payload.get("ready") is True else 2,
    )


@local_workflow.command("run")
@click.option("--profile", "profile_id", required=True)
def run(profile_id: str) -> None:
    _run_registry(
        lambda service: service.run(profile_id),
        exit_from=lambda payload: 0 if payload.get("status") == "completed" else 2,
    )


@local_workflow.command("history")
@click.option("--limit", type=int, default=10, show_default=True)
@click.option("--run-id", default=None)
def history(limit: int, run_id: str | None) -> None:
    safe_limit = max(1, min(limit, 100))
    _run_registry(lambda service: service.history_list(limit=safe_limit, run_id=run_id))


def _run_registry(
    action,
    *,
    exit_from=None,
) -> None:
    try:
        payload = action(DailyWorkflowService())
    except RegistryError as exc:
        _emit({"status": "blocked", "error": {"category": str(exc)}}, exit_code=2)
        return
    _emit(payload, exit_code=0 if exit_from is None else exit_from(payload))


def _emit(payload: dict, *, exit_code: int = 0) -> None:
    click.echo(json.dumps(payload, indent=2, sort_keys=True))
    sys.exit(exit_code)
