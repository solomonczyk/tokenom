# Local Daily Workflow Security

The profile registry accepts only a closed schema. Unknown fields are rejected, duplicate profile IDs are blocked, profile roots are canonicalized, repository roots must be explicitly approved, `mode` must be `sandbox`, and retry must be `false`.

The `tokenom-safe` profile uses:

```json
{
  "profile_id": "tokenom-safe",
  "enabled": false,
  "mode": "sandbox",
  "operation": "build_context_bundle",
  "execution": {
    "allow_retry": false
  }
}
```

Shell, command, provider, real-provider, remote transport, production, credential, secret, socket, URL, and websocket fields are forbidden. The profile cannot expand the hard security limits enforced by the local developer tool.

History stores only safe metadata: run ID, profile ID, status, repository hash, branch, HEAD, counts, byte counts, bundle ID, redacted manifest path, audit IDs, duration, attempts, and error category. It does not store source content, optimized content, raw requests, secrets, environment variables, or absolute user paths.

External network requests, real provider calls, autonomous editing, Git mutation, public servers, background daemons, and scheduled tasks are prohibited for this layer.
