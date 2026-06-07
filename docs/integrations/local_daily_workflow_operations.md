# Local Daily Workflow Operations

The local profile registry is stored outside analyzed target repositories by default:

```text
%LOCALAPPDATA%\Tokenom\local_daily_workflow\profiles.json
```

If `LOCALAPPDATA` is unavailable, the fallback is:

```text
~/.tokenom/local_daily_workflow/profiles.json
```

Tests and isolated demos can use `TOKENOM_LOCAL_DAILY_WORKFLOW_HOME` to point the registry and history at a temporary local directory.

History is stored under the same local state root:

```text
history/*.json
```

History retention is bounded to 100 records. Corrupted history records are reported as safe corrupted entries and do not expose raw content.

The local developer tool continues to write its own safe manifest under its runtime artifact directory. Layer 009 history records only the redacted relative manifest path and bundle ID.

Known carryovers remain isolated from this layer: mypy availability, Windows symlink privilege limits, junction runtime fixture limits, existing compression timeout tests, broad suite litellm/timeout blockers, and unrelated Ruff import-order issues.
