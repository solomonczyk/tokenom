# Local Daily Workflow Architecture

Layer 009 adds an operator-controlled daily workflow boundary around the accepted local-only Tokenom layers.

```text
operator command
  -> DailyWorkflowService
  -> ProfileRegistry
  -> ReadinessChecker
  -> LocalDeveloperToolService
  -> LocalAgentAdapter
  -> SandboxAgentOrchestrator
  -> Tokenom runtime/cache
  -> safe result + local developer manifest
  -> HistoryStore
```

The daily workflow does not read repository contents directly and does not call `headroom.compress` directly. Repository selection, scanning, redaction, path policy, adapter delegation, sandbox execution, and manifest creation remain owned by the existing local developer tool, local agent adapter, and sandbox agent layers.

The workflow adds only the operator layer: named profile selection, readiness checks, single-run orchestration, safe history, status/health UX, and rollback by disabling the profile and feature flag.

Production use remains out of scope. Real providers, autonomous editing, remote transport, public servers, background daemons, scheduling, retries, and production workflow gates are disabled.
