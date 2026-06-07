"""Mock-only provider boundary for sandbox agent requests."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


class MockSandboxProviderError(RuntimeError):
    """Controlled mock provider failure."""


class MockSandboxProviderTimeout(MockSandboxProviderError):
    """Controlled mock provider timeout without sleeping."""


@dataclass
class MockSandboxProvider:
    """Deterministic provider adapter that never performs network I/O."""

    calls: int = 0

    def invoke(self, request: dict[str, Any]) -> dict[str, Any]:
        self.calls += 1
        behavior = str(request.get("mock_behavior") or "success")
        if behavior == "failure":
            raise MockSandboxProviderError("mock_provider_controlled_failure")
        if behavior == "timeout":
            raise MockSandboxProviderTimeout("mock_provider_controlled_timeout")
        if behavior == "error":
            raise MockSandboxProviderError("mock_provider_controlled_error")
        return {
            "content": "Mocked sandbox result",
            "mock_provider_invoked": True,
            "received_request_id": request.get("request_id"),
        }
