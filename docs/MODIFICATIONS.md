# Tokenom Modifications

Tokenom adds a local AI-agent safety baseline to the Headroom-derived codebase.

Initial layer-001 changes:

- Added `tokenom.security` as an isolated Python guardrail package.
- Added secret scanning and typed redaction markers.
- Added path denylist handling for env files, credential folders, private keys,
  databases, virtual environments, caches, and dependency folders.
- Added local-only proxy policy with a blocked-by-default remote bind decision.
- Added redacted-only audit logging helpers.
- Added session audit proof schema and example artifact.
- Added performance guardrails for small-payload skipping, cache enablement,
  TTL, payload size, and latency budget.
- Added a SHA256 payload cache interface for future integration.
- Added dummy-data-only benchmark scaffold.
- Added focused tests proving the baseline safety gates.

The original Headroom compression, proxy, and memory modules remain intact.
