# M6.2 Security Review

## Scope

M6.2 hardens the M6.1 multi-user authorization boundary. It does not add enterprise identity or broaden OSINT collection behavior.

## Authorization boundary

Case authorization remains centralized through the scoped HTTP/access helpers. Effective access intersects the instance-wide role with owner/direct-ACL/team-derived case access. Global viewers remain read-only, owners retain owner-only administration, and the administrator all-case override is explicit.

Protected mutations re-evaluate effective access at the mutation boundary. Deterministic concurrency tests cover ownership transfer, direct-grant revocation, team-membership removal and user disable before a stale authenticated actor attempts a protected mutation. The denied mutation is not persisted.

Inaccessible case resources remain non-disclosing where required: callers without case visibility receive `not_found`/404 behavior rather than evidence that the case exists. The browser ownership-transfer scenario explicitly verifies that the former owner loses visibility after a successful transfer.

## Browser security

The canonical CI installs Chromium only as a development/qualification dependency and runs the bounded Playwright security suite separately from the production OCI image. The suite covers login/logout, ownership, grants and revocation, ownership transfer, team-derived access/removal, global-viewer read-only behavior, CSRF/session behavior and hostile-name escaping.

Browser controls are not treated as the authorization boundary. Server-side checks remain authoritative for mutations and object visibility.

## Data interchange and audit

Imports establish local ownership and do not restore foreign owner, ACL or team authorization state. Exports omit local authorization policy. Audit records retain actor identity for security-relevant operations; credentials and session/CSRF secrets are not intended as audit payloads.

## Residual risks and deferred work

- Already-authorized analytical work is not cancelled merely because access is revoked after that work has begun.
- SQLite remains appropriate for the intended small self-hosted deployment model, not a high-contention enterprise authorization service.
- Administrator all-case access is intentional and must be protected operationally.
- `OSINT_TOOLS_AUTH_ENABLED=false` is for trusted, network-restricted deployments and provides no multi-user isolation.
- HTTPS/TLS termination remains an operator/deployment responsibility.
- Enterprise identity, MFA, API/service-account tokens, nested teams and policy-language/deny-rule systems remain deferred.
- Live commercial-provider and TAXII/MISP qualification still depends on operator credentials/endpoints.
- arm64 runtime qualification depends on an available arm64-capable CI builder/runner.
- Optional Podman ClamAV composition remains outside the current mandatory Podman harness.

No M6.2 result should be interpreted as cancellation-safe distributed authorization or enterprise IAM qualification.
