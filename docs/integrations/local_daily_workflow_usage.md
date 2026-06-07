# Local Daily Workflow Usage

The daily workflow is disabled by default. Four process-local feature flags and an enabled profile are required before any repository scan or downstream invocation can happen:

```powershell
$env:TOKENOM_LOCAL_DAILY_WORKFLOW_ENABLED = "true"
$env:TOKENOM_LOCAL_DEVELOPER_TOOL_ENABLED = "true"
$env:TOKENOM_LOCAL_AGENT_ADAPTER_ENABLED = "true"
$env:TOKENOM_SANDBOX_AGENT_INTEGRATION_ENABLED = "true"
```

The default profile is `tokenom-safe`. It is created in the local profile registry on first use and remains disabled until the operator enables it.

```powershell
python -m headroom.cli local-workflow status
python -m headroom.cli local-workflow profiles
python -m headroom.cli local-workflow profile-show --profile tokenom-safe
python -m headroom.cli local-workflow profile-enable --profile tokenom-safe
python -m headroom.cli local-workflow preflight --profile tokenom-safe
python -m headroom.cli local-workflow run --profile tokenom-safe
python -m headroom.cli local-workflow history --limit 10
python -m headroom.cli local-workflow disable --profile tokenom-safe
```

`run` performs exactly one attempt. Failed or blocked executions are not retried automatically. A repeat run requires another explicit operator command after reviewing the previous result.

`status` and `health` do not scan repository contents, do not invoke compression, do not call a provider, and do not enable flags.
