# M6.0 Authentication, RBAC and Audit Trail

Authentication is enabled by default for new deployments and uses local
SQLite users, salted versioned scrypt hashes, opaque server-side sessions and
instance-wide `admin`, `analyst`, and `viewer` roles. `OSINT_TOOLS_AUTH_ENABLED`
is an explicit development escape hatch. No default credentials are created.

Audit events are bounded and separate from analytical timelines; secrets,
passwords, session tokens, CSRF tokens and uploaded content are excluded.
External identity, MFA, API tokens, case ownership and per-case ACLs remain
deferred. TLS belongs at a trusted reverse proxy.
