# Local Developer Tool Security

The integration is a read-only sandbox layer for artificial local fixtures. It
does not enable private production repository usage, remote IDE access,
autonomous editing, real providers, shell execution, servers, daemons, or
network transport.

## Repository Boundary

Allowed roots are exact sandbox roots:

- `tests/fixtures/local_developer_tool/repository`
- test temporary roots passed explicitly by tests
- roots explicitly configured with `TOKENOM_LOCAL_DEVELOPER_TOOL_ALLOWED_ROOTS`

Drive roots, broad project parents, user profile roots, app data roots, system
directories, `.git`, `.env`, credential directories, Docker credentials, browser
profiles, and UNC/network paths are blocked unless a narrower sandbox root is
explicitly approved.

Parents of approved roots do not become approved.

## Symlinks And Junctions

Symlinks and Windows reparse points are detected before content reads. Escapes
outside the approved root are recorded only as metadata/risk categories. Their
contents are not read. Symlinks inside the root are also skipped rather than
followed.

## Exclusions

Mandatory exclusions include `.git/**`, `.env`, `.env.*`, private keys, token
and credential files, dependency caches, build/cache directories, bytecode,
executables, archives, images, audio/video, and PDFs. User excludes cannot
override mandatory exclusions.

## Text Classification And Limits

Allowed extensions are:

`.py`, `.js`, `.ts`, `.tsx`, `.jsx`, `.json`, `.yaml`, `.yml`, `.toml`, `.md`,
`.txt`, `.rst`, `.html`, `.css`, `.sql`.

Defaults:

```json
{
  "max_files": 50,
  "max_file_bytes": 131072,
  "max_bundle_bytes": 524288,
  "max_path_length": 240
}
```

Requests cannot exceed hard policy maximums. Oversized files are excluded before
full reads. Selection order is deterministic.

## Secret Handling

Each selected file is scanned with Tokenom's scanner and redacted before bundle
assembly. The manifest stores relative paths, hashes, byte counts, redaction
counts, and exclusion reasons only. Audits use `AuditLogger` and never store raw
source, raw bundles, raw secrets, full absolute target paths, or environment
values.

## Runtime Boundary

`build_context_bundle` calls `LocalAgentAdapter`, which calls
`SandboxAgentOrchestrator`, which reaches `CachedPayloadGuard` and the Tokenom
compression runtime. The developer tool service does not call
`headroom.compress` directly.
