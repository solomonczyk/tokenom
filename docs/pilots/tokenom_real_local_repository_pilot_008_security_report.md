# Tokenom Pilot 008 Security Report

Task: `TOKENOM-CONTROLLED-REAL-LOCAL-REPOSITORY-PILOT-008`

Verdict: `ACCEPTED_WITH_CARRYOVERS`

## Boundary

The approved pilot target was `F:\Dev\Projects\tokenom`. The executed request allowed only:

- `README.md`
- `docs/integrations/**/*.md`
- `tokenom/local_developer_tool/**/*.py`
- `tokenom/local_agent_adapter/**/*.py`
- `tokenom/sandbox_agent/**/*.py`

The primary build selected 30 files and excluded 4203 paths. Exclusion reasons included allowlist misses, cache directories, Git metadata, environment files, private-key patterns, token-name patterns, binaries, node modules, and max-file truncation.

## Security Proof

The current pilot result proves:

- repository boundary passed
- mandatory exclusions enforced
- secret scan executed
- redaction executed
- post-redaction verification passed
- raw source not written to manifest
- raw source not written to audit
- raw secrets not leaked
- absolute paths not written to manifest or audit
- `.git` directory contents not read
- `.env` files not read
- private key files not read
- binary files not read
- files outside the approved pilot repository not read by the primary pilot
- external network requests: 0
- real provider requests: 0
- git mutation commands during pilot: 0

The manifest and audit are operational evidence in the ignored runtime directory:

- manifest: `.tokenom_runtime/pilots/008/manifests/e040f68ccb9eadfd.json`
- audit: `.tokenom_runtime/pilots/008/audit.jsonl`
- structured pilot result: `.tokenom_runtime/pilots/008/pilot_results.json`

The runtime directory had pre-existing ignored material, so the audit path is append-only evidence. The current request IDs, bundle ID, and proof JSON identify the executed pilot evidence.

## Rollback

After the pilot, the three feature flags were set false for the rollback request:

- `TOKENOM_LOCAL_DEVELOPER_TOOL_ENABLED=false`
- `TOKENOM_LOCAL_AGENT_ADAPTER_ENABLED=false`
- `TOKENOM_SANDBOX_AGENT_INTEGRATION_ENABLED=false`

The rollback request was blocked with:

- status: `blocked`
- repository scan executed: false
- adapter invocations: 0
- runtime invocations: 0
- provider invocations: 0

## Reparse Points

The symlink capability check was environment-limited: Windows returned `A required privilege is not held by the client`.

The junction escape check passed using a temporary fixture outside the real pilot repository. The junction was excluded as `symlink_or_junction_escape`, selected files remained limited to the fixture `README.md`, and the fixture was removed.

## Residual Blockers

The primary security/read-only gates passed, so the pilot is accepted with explicit carryovers. Remaining carryovers are environment or pre-existing validation blockers:

- pre-existing dirty worktree before pilot
- two targeted compression timeout carryovers
- broad suite blocked by missing `litellm` and long runtime
- mypy unavailable in this Python environment
- symlink creation privilege unavailable
- requested broad Ruff command blocked by a pre-existing unrelated import-order issue in `tests/test_tokenom_security.py`

The Pilot 008 commit intentionally excludes unrelated Layer 007/code changes and runtime artifacts. The only tracked pre-existing change included in closeout is the `.tokenom_runtime/` ignore rule, which prevents the Pilot 008 manifest and audit from entering Git. No production readiness claim is made by this report.
