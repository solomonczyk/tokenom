# Local Developer Tool Usage

The local developer tool integration is disabled by default.

Enable the full sandbox chain:

```powershell
$env:TOKENOM_LOCAL_DEVELOPER_TOOL_ENABLED = "true"
$env:TOKENOM_LOCAL_AGENT_ADAPTER_ENABLED = "true"
$env:TOKENOM_SANDBOX_AGENT_INTEGRATION_ENABLED = "true"
```

Run the dummy fixture request:

```powershell
python -m headroom.cli local-dev-tool run --request tests/fixtures/local_developer_tool/requests/valid_request.json
```

Run health without scanning repository contents:

```powershell
python -m headroom.cli local-dev-tool health
```

The CLI prints safe JSON. Completed requests exit `0`; blocked, cancelled, or
timeout results exit non-zero. Source content is not printed.

## Request Contract

Required fields:

- `tool_request_id`
- `correlation_id`
- `mode`: only `sandbox`
- `operation`: one of `build_context_bundle`, `inspect_repository_safely`,
  `developer_tool_health`
- `repository.root`
- `repository.include`
- `repository.exclude`
- `context.max_files`
- `context.max_file_bytes`
- `context.max_bundle_bytes`
- `context.include_git_metadata`
- `execution.timeout_ms`
- `execution.allow_retry`: must be `false`

Unknown fields are rejected. Absolute include paths, UNC paths, drive switching,
and `..` traversal are rejected.

## Result Contract

Completed `build_context_bundle` results include:

- request IDs and operation
- safe repository hash plus branch, head, and dirty state
- bundle ID, selected/excluded counts, source/optimized byte counts
- security proof flags
- execution proof with one attempt and no retry
- safe manifest path
- local adapter and sandbox audit linkage

Blocked/error results do not contain raw source content.
