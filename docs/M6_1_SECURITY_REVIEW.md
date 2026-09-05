# M6.1 security review

This is a separate final review of the case authorization boundary, persistence model, route coverage, UI and qualification evidence. It does not claim external penetration testing or enterprise IAM features.

## A. RUNTIME-PROVEN

The canonical authenticated Docker HTTP driver exercises separate admin, analyst A, analyst B and viewer sessions. It proves creator ownership using stable user IDs even after multiple logins; inaccessible cases are absent from API/HTML listings; direct case and secondary target/file/analysis/candidate/detection/AV routes return non-disclosing 404s. Graph, timeline, reports and native/STIX/MISP exports are confined. Similarity results omit another user's private file; cross-case note references are rejected.

Direct viewer/editor ACLs, updates and revocation work. Team viewer/editor grants respond to membership removal/re-addition, team disable/re-enable and user disable/re-enable. Analysts with viewer grants cannot mutate; editors cannot manage ACLs or case metadata. Global viewers remain read-only with editor grants and even after a case owner is demoted. Administrative override is exercised explicitly. Ownership transfer removes the old implicit owner's access.

ACL creation/change/revocation, team creation/update/membership changes, ownership transfer and legacy adoption reject missing, wrong, cross-session and query-only CSRF tokens. Valid mutations succeed through the existing header mechanism. Session status returns safe identity fields rather than session hashes.

Native, STIX, controlled TAXII and MISP imports assign the local importer and ignore foreign authorization-like fields. Python tests additionally compare complete users, sessions, teams, memberships and ACL tables across imports, including password-hash state. Native/STIX/MISP/report exports omit local authorization internals. Hostile case, user and team names/descriptions are escaped in authenticated HTML; read-only workspaces have no mutation forms.

Security audit checks assert owner/ACL/team actions and stable actor IDs without fixture passwords, CSRF or source credentials. The real Docker ClamAV gate proves inaccessible users cannot inspect AV evidence, viewers cannot scan, and analyst owners/editors can scan with correct audit. Clean/EICAR, provenance, repeat/idempotency, persistence and configured local boundary remain exercised by the full harness. Provider dispatch is confined by case access; live commercial credentials remain unset.

Restart checks prove ACL/team access persists. A genuine schema-8 fixture generated from immutable M6.0 source is started under Docker: legacy evidence, users, session rows and audit survive; schema 9 appears; legacy ownership stays NULL until explicit admin adoption; another restart succeeds. The auth-disabled legacy workflow remains exercised. Podman runs its actual image, writable data directory, non-root UID, parser imports and authenticated ownership/ACL checks.

## B. CODE-REVIEW-ONLY

The review mapped all current case/target/file routes, including UI aliases, to the centralized request boundary and inspected the SQL listing predicate, foreign keys, uniqueness and strongest-grant/global-ceiling logic. Transactional rechecks and audit writes for owner/ACL/team administration were inspected. Deterministic concurrent transfer/revocation race tests were not run.

The browser JavaScript login/form flow, tab-local token storage, local assets and restrictive CSP were inspected. HTTP tests exercise returned HTML, escaping and the same mutation APIs; they are not a real-browser end-to-end interaction test. No frontend framework, remote asset, inline script or eval dependency was introduced.

Commercial provider network success is not exercised without live credentials. The controlled TAXII/MISP fixture proves request/response isolation and authorization behavior, not compatibility with every deployed upstream server. Arm64 execution is not inferred from amd64 success.

## C. RESIDUAL / DEFERRED

Authorization is checked before analytical dispatch. Revocation affects subsequent checks; it does not cancel already-authorized work in flight. Security administrative mutations serialize their own authorization/state/audit changes. SQLite and this application remain intended for a small self-hosted deployment, not distributed enterprise policy enforcement.

Admin access to all cases is intentional and explicit. Auth-disabled mode intentionally provides system-local administrative privileges and requires suitable deployment network restrictions. Disabled users cannot use sessions; re-enabling a user can make an existing unexpired session usable again, consistent with the retained M6.0 session model. Operators should use HTTPS; deployment transport security is outside this milestone.

Live IPinfo, VirusTotal, AbuseIPDB, Shodan, TAXII and MISP remain unqualified when unconfigured. The current Buildx builder does not advertise linux/arm64. Optional Podman ClamAV remains unwired and is not reported as passed; real ClamAV is tested under Docker.

OIDC/OAuth/SAML/LDAP/AD, MFA/WebAuthn/TOTP, personal API tokens, service accounts, organizations/multi-tenancy, nested teams, deny ACLs, custom permissions, external policy engines and audit retention policy are deferred. No claims of those capabilities are made.
