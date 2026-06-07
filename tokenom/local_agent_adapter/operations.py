"""Central operation allowlist for the controlled local adapter."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class OperationSpec:
    name: str
    input_schema: dict[str, Any]
    output_schema: dict[str, Any]
    invokes_tokenom_runtime: bool


ALLOWLISTED_OPERATIONS: dict[str, OperationSpec] = {
    "compress_context": OperationSpec(
        name="compress_context",
        input_schema={
            "type": "object",
            "required": ["content"],
            "properties": {
                "content": {"type": "string"},
                "metadata": {"type": "object"},
            },
            "additionalProperties": False,
        },
        output_schema={
            "type": "object",
            "required": ["content"],
            "properties": {"content": {"type": "string"}},
            "additionalProperties": False,
        },
        invokes_tokenom_runtime=True,
    ),
    "inspect_payload_safely": OperationSpec(
        name="inspect_payload_safely",
        input_schema={
            "type": "object",
            "required": ["content"],
            "properties": {
                "content": {"type": "string"},
                "metadata": {"type": "object"},
            },
            "additionalProperties": False,
        },
        output_schema={
            "type": "object",
            "required": ["content"],
            "properties": {"content": {"type": "string"}},
            "additionalProperties": False,
        },
        invokes_tokenom_runtime=True,
    ),
    "sandbox_health": OperationSpec(
        name="sandbox_health",
        input_schema={
            "type": "object",
            "properties": {"metadata": {"type": "object"}},
            "additionalProperties": False,
        },
        output_schema={
            "type": "object",
            "required": ["content"],
            "properties": {"content": {"type": "string"}},
            "additionalProperties": False,
        },
        invokes_tokenom_runtime=False,
    ),
}


def get_operation_spec(operation: str) -> OperationSpec | None:
    """Return the allowlisted operation spec, if present."""

    return ALLOWLISTED_OPERATIONS.get(operation)
