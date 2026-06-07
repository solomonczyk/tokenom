# Controlled Local Agent Adapter Security

The local agent adapter fails closed. A failed adapter gate returns `status: "blocked"` and prevents downstream sandbox/runtime/provider execution.

## Gates

```json
{
  "local_adapter_enabled": true,
  "sandbox_integration_enabled": true,
  "strict_contract": true,
  "operation_allowlist_active": true,
  "payload_limit_active": true,
  "path_policy_delegated": true,
  "redaction_delegated": true,
  "automatic_retry": false,
  "public_listener_created": false,
  "remote_transport_available": false
}
```

## Contract Controls

- `mode` must be `sandbox`.
- `allow_retry` must be `false`.
- Timeout must be between 100 ms and 30000 ms.
- Unknown contract fields are rejected.
- Production/private/provider override fields are rejected.
- Dynamic execution fields such as module/function/shell/command/import keys are rejected.
- Adapter and correlation IDs are bounded and cannot contain secret-like markers.

## Security Delegation

For runtime operations, the adapter delegates to:

```text
local adapter -> SandboxAgentOrchestrator -> PathPolicy/redaction/CachedPayloadGuard -> Tokenom runtime -> MockSandboxProvider
```

The adapter does not duplicate or weaken the sandbox security logic and does not bypass it by calling `headroom.compress()` directly.

## Path Policy

The default dummy workspace root is:

```text
tests/fixtures/local_agent_adapter/workspace
```

Traversal, external absolute roots, `.env`, `.git`, secrets, credentials, and user-profile markers are blocked by the sandbox path policy before runtime/provider execution.

## Audit Policy

Adapter audit records contain:

- adapter request ID
- correlation ID
- operation
- timestamp
- payload size
- payload hash
- gate decisions
- execution status
- attempts
- timeout or cancellation category
- downstream sandbox audit ID

Adapter audit records do not contain raw payload, raw prompt, raw output, raw secrets, or unredacted user paths.

## Local-Only Boundary

The adapter proves:

```json
{
  "public_listener_created": false,
  "remote_transport_available": false,
  "outbound_network_requests": 0,
  "localhost_http_server_started": false,
  "background_daemon_started": false
}
```

Tests monkeypatch socket creation during a valid execution to prove the path does not perform network I/O.

## Explicit Non-Production Statement

This integration is not approved for real providers, private project data, production agent workflows, production secrets, public APIs, remote sandboxes, or production readiness claims.
