# Safe Usage

Use Tokenom for local AI-agent payload preparation and proxy safety checks.

Recommended defaults:

- Keep proxy binds on `127.0.0.1`.
- Keep raw logging disabled.
- Route payloads through redaction before audit logging.
- Run strict block mode before forwarding files or tool outputs from sensitive
  directories.
- Keep `.env`, private keys, local databases, dependency folders, virtual
  environments, and raw logs out of commits.

Do not use production credentials in tests. Use constructed dummy strings when
testing redaction behavior so real-looking secrets are not stored in the
repository.
