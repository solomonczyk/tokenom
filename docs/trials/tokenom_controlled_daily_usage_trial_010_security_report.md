# Tokenom Controlled Daily Usage Trial 010 Security Report

Task: `TOKENOM-CONTROLLED-DAILY-USAGE-TRIAL-010`

Verdict: `ACCEPTED_WITH_CARRYOVERS`

## Gates

- daily workflow feature flag default disabled: verified
- local developer tool flag default disabled: verified
- local agent adapter flag default disabled: verified
- sandbox agent integration flag default disabled: verified
- `tokenom-safe` profile default disabled: verified
- preflight blocked before gates: verified
- rollback blocked after gates removed: verified

## Runtime Isolation

The accepted trial used only local process environment flags and the `tokenom-safe` sandbox profile. It did not enable production mode, real provider mode, remote transport, shell execution, public listeners, daemons, schedulers, or autonomous editing.

Successful runs invoked:

- local developer-tool repository scan: `1` per successful run
- local adapter: `1` per successful run
- sandbox orchestrator/runtime: `1` per successful run
- real provider requests: `0`
- external network requests: `0`

The controlled blocked run and rollback blocked run both stopped before repository scan, adapter invocation, runtime invocation, provider use, and network use.

## Data Safety

History records store safe metadata only: run ID, profile ID, status, safe repository ID, branch, HEAD, counts, bytes, bundle ID, redacted manifest path, audit IDs, duration, attempts, retry flags, and safe error category.

The successful run manifests contain selected file names, byte counts, hashes, exclusion reasons, safe repository metadata, security flags, execution metadata, and audit linkage. They do not store raw source, raw optimized output, raw secrets, or absolute user paths.

Verified flags for both accepted successful runs:

- `raw_source_written=false`
- `raw_bundle_written=false`
- `raw_secret_written=false`
- `absolute_paths_written=false`
- audit `raw_payload_written=false`
- sandbox `raw_prompt_written=false`
- sandbox `raw_response_written=false`

## Audit Linkage

Session A:

- history run ID: `daily-b562076a1a46421a`
- manifest workflow run ID: `daily-b562076a1a46421a`
- developer-tool audit: `7892eb8dc3a19f7c`
- adapter audit: `ec7bb25923373321`
- sandbox audit via adapter: `e415a977397301e8`

Recovery:

- history run ID: `daily-2e10a258b2b94494`
- manifest workflow run ID: `daily-2e10a258b2b94494`
- developer-tool audit: `5ff119ea02409326`
- adapter audit: `18d1e2385d54d822`
- sandbox audit via adapter: `4d4b295de6d0552e`

## Repository Immutability

The workflow did not stage files, create commits, mutate remotes, or change Git config. Runtime artifacts were written under ignored runtime/artifact paths. The tracked-file changes after the trial are Layer 010 fixes, tests, and documentation/proof artifacts, plus the pre-existing unrelated dirty files preserved from baseline.

## Security Decision

No raw source, raw output, secrets, absolute user paths, real provider requests, or external network requests were found in the accepted trial evidence. Limited local use is allowed only in operator-controlled, read-only, sandbox/mock mode with default-disabled gates.
