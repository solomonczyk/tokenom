# Local Daily Workflow Rollback

Rollback requires no code change:

```powershell
python -m headroom.cli local-workflow disable --profile tokenom-safe
$env:TOKENOM_LOCAL_DAILY_WORKFLOW_ENABLED = "false"
```

After rollback, `run --profile tokenom-safe` is blocked during preflight. The blocked event records safe history only:

```json
{
  "profile_enabled": false,
  "workflow_feature_enabled": false,
  "repository_scan_executed": false,
  "adapter_invocations": 0,
  "runtime_invocations": 0
}
```

Disabling the profile does not start a workflow. Each execution remains a separate operator command. There is no retry gate, no production gate, no real provider gate, and no autonomous editing gate in Layer 009.
