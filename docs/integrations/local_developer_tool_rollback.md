# Local Developer Tool Rollback

Rollback is a feature flag change:

```powershell
$env:TOKENOM_LOCAL_DEVELOPER_TOOL_ENABLED = "false"
```

or remove the variable:

```powershell
Remove-Item Env:\TOKENOM_LOCAL_DEVELOPER_TOOL_ENABLED
```

When disabled:

1. Requests are blocked with `local_developer_tool_disabled`.
2. Repository files are not scanned or read.
3. Bundles and manifests are not created.
4. `LocalAgentAdapter` is not invoked.
5. `SandboxAgentOrchestrator`, runtime, provider, server, daemon, and network
   paths remain unused.

The focused tests verify an enabled flow first, then disable the flag and prove
the next request is blocked with zero scan, adapter, and runtime invocations.
