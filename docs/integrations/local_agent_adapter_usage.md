# Controlled Local Agent Adapter Usage

This command is local-only and disabled by default.

## Enable Explicitly

PowerShell:

```powershell
$env:TOKENOM_LOCAL_AGENT_ADAPTER_ENABLED = "1"
$env:TOKENOM_SANDBOX_AGENT_INTEGRATION_ENABLED = "1"
```

Both flags must be enabled. If either flag is absent or disabled, the adapter returns a controlled blocked result and does not invoke the sandbox runtime/provider path.

## Run A Dummy Fixture

```powershell
python -m headroom.cli local-agent-run --fixture tests\fixtures\local_agent_adapter\valid_compress_request.json
```

The command prints sanitized JSON. Completed runtime operations include:

- `status: "completed"`
- `security.external_network_used: false`
- `security.real_provider_used: false`
- `execution.attempts: 1`
- `execution.retry_executed: false`
- `security.downstream_sandbox_audit_id: "..."`

Blocked, failed, timeout, and cancelled requests return a nonzero exit code.

## In-Process API

```python
from tokenom.local_agent_adapter import LocalAgentAdapter

result = LocalAgentAdapter().execute(request)
```

The in-process API is the primary transport. It does not open a listener, read a socket, start a daemon, or perform outbound network I/O.

## Supported Operations

- `compress_context`
- `inspect_payload_safely`
- `sandbox_health`

No request can select arbitrary modules, functions, shell commands, dynamic imports, or real providers.

## Payload And Timeout Limits

- Default payload limit: 262144 serialized bytes.
- Timeout range: 100 ms to 30000 ms.
- `execution.allow_retry` must be `false`.
- The adapter performs no automatic retry and no blind retry.

## Rollback

```powershell
Remove-Item Env:\TOKENOM_LOCAL_AGENT_ADAPTER_ENABLED
```

or set it to any non-enabled value. Rollback requires no code change.

## Not Allowed

Real provider traffic, production agent workflows, private repositories, remote transport, public servers, raw prompt logging, raw response logging, and production secrets are not allowed by this layer.
