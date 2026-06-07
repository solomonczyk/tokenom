# Controlled Local Agent Adapter Rollback

The rollback switch is:

```text
TOKENOM_LOCAL_AGENT_ADAPTER_ENABLED
```

Default state: disabled.

## Disable

PowerShell:

```powershell
Remove-Item Env:\TOKENOM_LOCAL_AGENT_ADAPTER_ENABLED
```

or:

```powershell
$env:TOKENOM_LOCAL_AGENT_ADAPTER_ENABLED = "0"
```

## Expected Disabled Behavior

When disabled:

- local adapter execution is blocked
- sandbox orchestrator is not called
- mock provider is not called
- Tokenom runtime is not called
- cache/optimization path is not called
- result status is `blocked`
- error category is `local_adapter_disabled`
- rollback requires no code change

## Sandbox Dependency

The adapter also requires:

```text
TOKENOM_SANDBOX_AGENT_INTEGRATION_ENABLED=true
```

If the sandbox dependency flag is disabled, the adapter returns `sandbox_dependency_disabled` and does not invoke the sandbox/runtime/provider path.

## Verification

```powershell
python -m pytest tests\test_local_agent_adapter.py -q --basetemp artifacts\pytest-tmp-local-agent
```

The focused tests verify enabled execution, default disabled state, sandbox dependency enforcement, and disabling after a successful enabled flow.

## Production Safety

Rollback does not affect production provider behavior because this layer never enables real providers, private projects, remote transport, public endpoints, or production agent workflows.
