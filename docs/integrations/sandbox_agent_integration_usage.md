# Safe Sandbox Agent Integration Usage

This command is sandbox-only and disabled by default.

## Enable Explicitly

```powershell
$env:TOKENOM_SANDBOX_AGENT_INTEGRATION_ENABLED = "1"
```

Disabling or unsetting the flag blocks execution and prevents runtime/provider invocation.

## Run A Dummy Fixture

```powershell
python -m headroom.cli sandbox-agent-run --fixture tests\fixtures\sandbox_agent\valid_sandbox_request.json
```

The command prints sanitized structured JSON. A completed result has:

- `mode: "sandbox"`
- `provider: "mock"`
- `security.external_network_used: false`
- `security.real_provider_used: false`
- `runtime.tokenom_runtime_invoked: true`
- `runtime.cache_checked: true`

Blocked or failed requests return a nonzero exit code.

## Supported Mock Behaviors

`metadata.mock_behavior` accepts:

- `success`: deterministic dummy response.
- `failure`: controlled provider failure.
- `timeout`: controlled timeout category without sleeping.
- `error`: controlled provider error.

No behavior performs network I/O or reads credentials.

## Rollback

```powershell
Remove-Item Env:\TOKENOM_SANDBOX_AGENT_INTEGRATION_ENABLED
```

or set it to any non-enabled value. Rollback requires no code change.

## Not Allowed

Real provider traffic, production agent workflows, private repositories, raw prompt logging, raw response logging, and production secrets are not allowed by this layer.
