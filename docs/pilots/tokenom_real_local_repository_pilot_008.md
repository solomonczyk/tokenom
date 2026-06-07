# Tokenom Controlled Real Local Repository Pilot 008

Task: `TOKENOM-CONTROLLED-REAL-LOCAL-REPOSITORY-PILOT-008`

Verdict: `ACCEPTED_WITH_CARRYOVERS`

The controlled read-only pilot was executed against the operator-approved repository `F:\Dev\Projects\tokenom`. The pilot target was self-referential and limited to the approved include patterns only:

- `README.md`
- `docs/integrations/**/*.md`
- `tokenom/local_developer_tool/**/*.py`
- `tokenom/local_agent_adapter/**/*.py`
- `tokenom/sandbox_agent/**/*.py`

The configured context limits were `max_files=30`, `max_file_bytes=131072`, `max_bundle_bytes=524288`, `timeout_ms=10000`, and `allow_retry=false`.

## Baseline

Preflight confirmed:

- branch: `main`
- expected HEAD: `ecc79e1e65c828df0be8e8cd5f21545bff59e287`
- actual HEAD before pilot: `ecc79e1e65c828df0be8e8cd5f21545bff59e287`
- `git fsck --full`: passed
- origin: `git@github.com:solomonczyk/tokenom.git`
- upstream: `https://github.com/chopratejas/headroom`

The worktree was already dirty before the pilot. The pre-existing modified files were:

- `.gitignore`
- `headroom/integrations/__init__.py`
- `tests/test_local_developer_tool.py`
- `tests/test_security_validations.py`
- `tokenom/local_developer_tool/service.py`

Those files were treated as baseline operator/user changes and were not intentionally modified by this pilot.

## Execution

Phase 1, `inspect_repository_safely`, completed successfully. It returned safe metadata only, with no adapter or runtime invocation.

Phase 2, one primary `build_context_bundle`, completed successfully:

- bundle ID: `e040f68ccb9eadfd`
- selected files: 30
- excluded files: 4203
- source bytes: 148120
- optimized bytes: 21
- compression applied: true
- manifest: `.tokenom_runtime/pilots/008/manifests/e040f68ccb9eadfd.json`
- audit: `.tokenom_runtime/pilots/008/audit.jsonl`

Phase 3, one identical deterministic cache/idempotency check, completed successfully:

- repeated bundle ID: `e040f68ccb9eadfd`
- repeated selected files: 30
- repeated source bytes: 148120
- repeated optimized bytes: 21
- attempts per request: 1
- automatic retry: false

The identical check verified deterministic bundle identity and semantic equivalence. The developer-tool layer performed deterministic selection again; the runtime/cache boundary was exercised by the sandbox runtime audit.

Phase 4 rollback completed successfully. With all three feature flags disabled, the request was blocked before repository scan, adapter invocation, runtime invocation, provider call, or network use.

## Invocation Counts

- LocalAgentAdapter invocations: 2
- SandboxAgentOrchestrator invocations: 2
- runtime invocations: 2
- provider invocations: 0 real providers, mock provider only
- external network requests: 0
- git mutation commands during pilot: 0

## Immutability

HEAD, branch, remotes, tracked file hashes for sampled files, and the pre-existing dirty status were unchanged during the pilot. Runtime outputs were written under `.tokenom_runtime/pilots/008/`, which is ignored by `.gitignore`.

The pilot integration did not modify the selected repository content. The only source-tree additions made after the pilot are this sanitized report, the security report, and the proof JSON.

## Tests

Passed:

- focused pilot tests: 6 passed, 1 skipped
- local developer-tool tests: 25 passed, 1 skipped
- local agent adapter plus sandbox tests: 28 passed
- security/runtime/cache/policy tests: 71 passed
- native smoke tests: 44 passed
- Ruff: passed
- import validation: passed

Environment or pre-existing carryovers:

- `tests/test_compress_api.py` exceeded the 180 second bounded command window.
- `tests/test_compression_determinism.py` exceeded the 180 second bounded command window.
- broad feasible suite collection hit missing local dependency `litellm` in `tests/test_memory_eval.py`, and the rerun excluding that file and the two timeout files exceeded the 600 second bound.
- `python -m mypy ...` could not run because `mypy` is not installed.
- symlink creation was unavailable in this Windows session because the client lacks the required privilege.

## Closeout

Pilot 008 is accepted with carryovers. The runtime result is accepted as a controlled read-only pilot: one primary bundle execution and one deterministic cache/idempotency verification produced bundle `e040f68ccb9eadfd`, with 30 selected files, 4203 excluded files, 148120 source bytes, and 21 optimized bytes.

The `optimized_bytes=21` value is retained as runtime evidence. It is the real result emitted by the mock/sandbox optimization path during both accepted Pilot 008 executions. This pilot proves the repository boundary, cache/runtime path, audit safety, retry policy, and rollback behavior; it does not claim production compression quality from that 21-byte mock-provider result.

Closeout classification of the five pre-existing modified files:

- `.gitignore`: Pilot 008 closeout support; the single `.tokenom_runtime/` ignore rule is safe to commit so runtime manifest/audit artifacts remain outside Git.
- `headroom/integrations/__init__.py`: unrelated functional integration import-boundary change; left untouched.
- `tests/test_local_developer_tool.py`: Layer 007/local developer tool regression coverage; left untouched.
- `tests/test_security_validations.py`: unrelated security test fixture cleanup; left untouched.
- `tokenom/local_developer_tool/service.py`: Layer 007/local developer tool implementation change; left untouched.

Closeout regression results:

- focused Pilot 008 check: 6 passed, 1 skipped after creating the missing `.pytest-tmp` parent directory required by this Windows pytest invocation.
- local developer tool, local agent adapter, and sandbox integration check: 53 passed, 1 skipped.
- requested broad Ruff command failed on a pre-existing unrelated import-order issue in `tests/test_tokenom_security.py`.
- focused Pilot 008 Ruff slice passed.

Carryovers remain explicit: `mypy` is not installed, Windows symlink creation is environment-limited, the junction fixture is runtime-fixture limited, `tests/test_compress_api.py` and `tests/test_compression_determinism.py` remain 180-second timeout carryovers, the broad suite remains blocked by missing `litellm` or timeout, and the requested broad Ruff command has one unrelated pre-existing import-order issue.

The Pilot 008 closeout commit is limited to the Pilot 008 reports/proof plus the `.tokenom_runtime/` ignore rule. Real provider integration, autonomous editing, production workflows, and private-project general access remain disabled and out of scope. The next allowed layer is `TOKENOM-LOCAL-DAILY-WORKFLOW-READINESS-009`; Layer 009 was not started.
