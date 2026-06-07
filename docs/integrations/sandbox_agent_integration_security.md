# Safe Sandbox Agent Integration Security

This layer is fail-closed. A failed validation gate returns `status: "blocked"` and `security.provider_called: false`.

## Gates

```json
{
  "sandbox_mode_required": true,
  "production_mode_blocked": true,
  "mock_provider_required": true,
  "real_provider_blocked": true,
  "external_network_blocked": true,
  "path_policy_enforced": true,
  "redaction_enforced": true,
  "audit_safe": true
}
```

## Mode And Provider

- `mode` must be exactly `sandbox`.
- `provider` must be exactly `mock`.
- Unknown provider names are rejected as `real_provider_forbidden`.
- Production mode is rejected as `production_mode_forbidden`.

## Path Policy

The default allowed root is:

```text
tests/fixtures/sandbox_agent/workspace
```

The workspace gate blocks traversal, absolute external roots, `.env`, `.git`, credentials, secrets, system roots, and user-profile markers. The policy applies to actual workspace access, not to harmless string mentions inside dummy text.

## Redaction

Field-level redaction scans request prompt/context strings before runtime/provider invocation. It covers API-key-like strings, bearer tokens, emails, Windows user paths, environment secrets, dummy passwords, and private key markers.

Raw dummy sensitive values must not appear in:

- structured results
- audit records
- logs
- proof JSON

## Audit

Audit records are written through `AuditLogger`. They include request ID, timestamp, mode, provider, status, policy decisions, redaction count, runtime/cache flags, error category, and prompt hash. Raw prompt and raw provider response are not stored.

## Network

The mock provider contains no network client. Tests monkeypatch socket creation to prove the flow does not perform outbound network calls.

## Explicit Non-Production Statement

This integration is not approved for real private project data, production agent workflows, production secrets, public proxies, remote sandboxes, or real provider requests.
