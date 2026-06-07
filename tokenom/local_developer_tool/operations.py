"""Operation allowlist for the local developer tool integration."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class DeveloperToolOperation:
    name: str
    reads_repository: bool
    invokes_local_agent_adapter: bool


ALLOWLISTED_OPERATIONS: dict[str, DeveloperToolOperation] = {
    "build_context_bundle": DeveloperToolOperation(
        name="build_context_bundle",
        reads_repository=True,
        invokes_local_agent_adapter=True,
    ),
    "inspect_repository_safely": DeveloperToolOperation(
        name="inspect_repository_safely",
        reads_repository=True,
        invokes_local_agent_adapter=False,
    ),
    "developer_tool_health": DeveloperToolOperation(
        name="developer_tool_health",
        reads_repository=False,
        invokes_local_agent_adapter=False,
    ),
}


def get_operation_spec(operation: str) -> DeveloperToolOperation | None:
    """Return the allowlisted operation, if present."""

    return ALLOWLISTED_OPERATIONS.get(operation)
