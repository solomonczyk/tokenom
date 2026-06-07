# Safe Sandbox Agent Integration Rollback

The rollback switch is:

```text
TOKENOM_SANDBOX_AGENT_INTEGRATION_ENABLED
```

Default state: disabled.

## Disable

PowerShell:

```powershell
Remove-Item Env:\TOKENOM_SANDBOX_AGENT_INTEGRATION_ENABLED
```

or:

```powershell
$env:TOKENOM_SANDBOX_AGENT_INTEGRATION_ENABLED = "0"
```

## Expected Disabled Behavior

When disabled:

- sandbox execution is blocked
- mock provider is not called
- Tokenom runtime is not called
- cache/optimization path is not called
- result status is `blocked`
- error category is `sandbox_integration_disabled`

## Verification

```powershell
python -m pytest tests\test_sandbox_agent_integration.py -q --basetemp artifacts\pytest-tmp
```

The feature-flag tests verify default disabled state, enabled execution, and disabling again.

## Production Safety

Enabling the sandbox flag does not enable production mode, private project usage, real providers, remote sandboxes, telemetry, or outbound provider calls.
