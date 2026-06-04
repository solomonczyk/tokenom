# Tokenom performance optimization

This layer optimizes repeated token/context compression preparation without weakening Tokenom's safety gates.

## Changes

- `guard_payload` now scans once and passes the same findings into redaction.
- `CachedPayloadGuard` memoizes identical guard decisions with a SHA256-backed key.
- The guard cache key includes payload, mode, path, and production-key policy, so a safe decision is not reused for a different security context.
- The cache can be disabled with `PerformancePolicy(enable_cache=False)`.

## Safety invariants

- Security scanning and redaction still run before compression.
- Private-key payloads remain blocked.
- Proxy validation remains localhost-only by default.
- Raw request/response logging stays disabled.
- Validation uses dummy data only and does not call network providers.

## Benchmark proof

The dummy benchmark processes a repeated secret-shaped context payload using direct guarding and cached guarding. It records median runtime, cache hit rate, and leak checks under `artifacts/performance_optimization/`.
