# Tokenom Security Protocol

Tokenom's baseline protocol is local-first and redacted-by-default.

## Secret Handling

Tokenom detects API keys, provider tokens, bearer tokens, JWT-like values,
cookies, session identifiers, database URLs, private key blocks, and env-style
secret assignments.

Default behavior:

- Common secrets are redacted as `[REDACTED_<TYPE>]`.
- Private key blocks are blocked.
- `.env` paths and credential paths are blocked.
- Production key payloads are blocked in strict block mode.

## Path Policy

The denylist in `config/path_policy.yaml` blocks private project data and local
runtime artifacts. The allowlist examples document ordinary safe project paths,
but allowlist examples do not override denylist entries.

## Proxy Policy

Tokenom's proxy guard defaults to `127.0.0.1`. Binding to public interfaces such
as `0.0.0.0` is blocked unless both an explicit remote-proxy allowance and an
unsafe override are provided. Unsafe override events must be visible and audited.

## Logging Policy

Raw prompts, raw tool outputs, and raw responses are disabled by default. Audit
events write redacted payloads only unless a caller deliberately opts out of the
baseline policy.

## Test Data

Tests must use dummy data only. Tests must not call external LLM providers and
must not require production API keys.
