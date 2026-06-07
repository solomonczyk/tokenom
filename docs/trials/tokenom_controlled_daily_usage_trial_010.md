# Tokenom Controlled Daily Usage Trial 010

Task: `TOKENOM-CONTROLLED-DAILY-USAGE-TRIAL-010`

Verdict: `ACCEPTED_WITH_CARRYOVERS`

The controlled daily usage trial was executed against `F:\Dev\Projects\tokenom` on branch `main` at baseline HEAD `9a206a8c213a069c6b9750fa201b0ae63ae2eeff`. The trial used the built-in `tokenom-safe` profile, four process-local feature flags, mock/sandbox execution only, and no real provider.

The final accepted evidence set is stored under the isolated local workflow home `.tokenom_runtime/trial010-final`. Runtime artifacts remain ignored by Git.

## Baseline

- branch: `main`
- HEAD before trial: `9a206a8c213a069c6b9750fa201b0ae63ae2eeff`
- `origin/main` before trial: `9a206a8c213a069c6b9750fa201b0ae63ae2eeff`
- origin: `git@github.com:solomonczyk/tokenom.git`
- upstream: `https://github.com/chopratejas/headroom`
- default daily workflow flag: disabled
- local developer tool flag: disabled
- local agent adapter flag: disabled
- sandbox agent flag: disabled
- default `tokenom-safe` profile: disabled

Known pre-existing modified files were preserved:

- `headroom/integrations/__init__.py`
- `tests/test_local_developer_tool.py`
- `tests/test_security_validations.py`
- `tokenom/local_developer_tool/service.py`

## Accepted Session Sequence

The accepted sequence used the recommended bounded plan:

1. Session A: successful controlled daily run.
2. Session C: intentionally blocked run with the profile disabled.
3. Recovery: separately operator-authorized successful run after review and re-enable.

Session B was not run as an additional success. The recovery run is the second successful operator run.

## Session A

- run ID: `daily-b562076a1a46421a`
- status: `completed`
- attempts: `1`
- retry executed: `false`
- automatic retry: `false`
- profile: `tokenom-safe`
- repository ID: `1a568e140d41717b`
- branch/head: `main` / `9a206a8c213a069c6b9750fa201b0ae63ae2eeff`
- selected files: `30`
- excluded files: `4723`
- source bytes: `101822`
- optimized bytes: `21`
- bundle ID: `76ca6f4ab618806e`
- manifest: `artifacts/local_developer_tool_runtime/manifests/workflow-runs/daily-b562076a1a46421a-76ca6f4ab618806e.json`
- developer-tool audit: `7892eb8dc3a19f7c`
- adapter audit: `ec7bb25923373321`
- sandbox audit: `e415a977397301e8`
- repository scans: `1`
- adapter invocations: `1`
- runtime invocations: `1`
- external network requests: `0`
- real provider requests: `0`

## Blocked Session

- run ID: `daily-b4983f0e67534943`
- status: `blocked`
- blocked reason: `profile_enabled`
- attempts: `0`
- retry executed: `false`
- automatic retry: `false`
- repository scan executed: `false`
- adapter invocations: `0`
- runtime invocations: `0`
- external network requests: `0`
- real provider requests: `0`

## Recovery

- run ID: `daily-2e10a258b2b94494`
- status: `completed`
- attempts: `1`
- retry executed: `false`
- automatic retry: `false`
- profile: `tokenom-safe`
- repository ID: `1a568e140d41717b`
- branch/head: `main` / `9a206a8c213a069c6b9750fa201b0ae63ae2eeff`
- selected files: `30`
- excluded files: `4726`
- source bytes: `101822`
- optimized bytes: `21`
- bundle ID: `76ca6f4ab618806e`
- manifest: `artifacts/local_developer_tool_runtime/manifests/workflow-runs/daily-2e10a258b2b94494-76ca6f4ab618806e.json`
- developer-tool audit: `5ff119ea02409326`
- adapter audit: `18d1e2385d54d822`
- sandbox audit: `4d4b295de6d0552e`
- repository scans: `1`
- adapter invocations: `1`
- runtime invocations: `1`
- external network requests: `0`
- real provider requests: `0`

## History

The accepted trial history before rollback contained three final records:

- `completed`: `daily-b562076a1a46421a`
- `blocked`: `daily-b4983f0e67534943`
- `completed`: `daily-2e10a258b2b94494`

History lookup by run ID worked, chronological ordering was correct, limit behavior returned the newest bounded records, and duplicate run IDs were `0`.

After rollback verification, one extra safe blocked history record was written for run `daily-d7e26b6aabc54298`. It is not counted as a controlled trial success or recovery run; it proves rollback blocking.

## Manifest And Audit Consistency

Both successful runs used the same deterministic bundle ID, `76ca6f4ab618806e`, because the selected content was unchanged. Layer 010 fixes preserve each run under a unique workflow manifest path so repeated deterministic bundles do not overwrite prior run evidence.

For each successful run:

- history run ID matched manifest `workflow_run_id` and `tool_request_id`
- history bundle ID matched manifest bundle ID
- history developer-tool audit ID matched a local developer-tool audit event
- history adapter audit ID matched a local adapter audit event
- adapter audit linked to the sandbox audit ID
- developer-tool, adapter, and sandbox audit statuses were `completed`
- retry and automatic retry flags were false
- real provider and external network usage were false or zero

## Rollback

Final rollback disabled the profile and removed all four feature flags from the process environment. `status` reported no enabled profiles and all dependency flags disabled. A post-rollback run was blocked with reason `daily_workflow_feature_enabled`, attempts `0`, repository scan `false`, adapter invocations `0`, and runtime invocations `0`.

## Tests

- `python -m pytest tests/test_local_daily_workflow.py -q --basetemp artifacts/pytest-tmp/layer010-daily-workflow`: 13 passed.
- `python -m pytest tests/test_local_developer_tool.py -q --basetemp artifacts/pytest-tmp/layer010-local-dev-tool`: 25 passed, 1 skipped.
- `python -m pytest tests/test_local_agent_adapter.py -q --basetemp artifacts/pytest-tmp/layer010-local-agent-adapter`: 17 passed.
- `python -m pytest tests/test_sandbox_agent_integration.py -q --basetemp artifacts/pytest-tmp/layer010-sandbox-agent`: 11 passed.
- `python -m pytest tests/test_tokenom_security.py tests/test_tokenom_runtime_validation.py -q --basetemp artifacts/pytest-tmp/layer010-security-runtime`: 16 passed.
- `python -m pytest tests/test_tokenom_performance_optimization.py tests/test_compression_cache.py -q --basetemp artifacts/pytest-tmp/layer010-performance-cache`: 35 passed.
- `python -m pytest tests/test_rust_core_smoke.py -q --basetemp artifacts/pytest-tmp/layer010-native-smoke`: 4 passed.
- `python -m pytest tests/test_local_developer_tool.py -k "valid_context_build or inspect_repository or rollback or git_metadata or no_network or mandatory_exclusions or symlink_escape" -q --basetemp artifacts/pytest-tmp/layer010-pilot008-focused`: 6 passed, 1 skipped.
- `python -m ruff check tokenom/local_daily_workflow headroom/cli/local_workflow.py tests/test_local_daily_workflow.py`: passed.
- import validation: passed.

## Carryovers

- Initial acceptance attempt discovered that repeated deterministic bundle IDs could overwrite prior daily workflow manifests. The accepted evidence set was restarted after the Layer 010 fix.
- The history record still stores the direct sandbox audit field as `null`; sandbox consistency is verified through the adapter audit linkage.
- Broad suites with known timeout or missing-dependency carryovers remain out of scope for this bounded trial.

## Decision

Limited regular local usage is allowed only as an operator-controlled, read-only, sandbox/mock workflow with the default state disabled. Real provider use, autonomous editing, production workflow mode, public servers, daemons, schedulers, and background workers remain forbidden.
