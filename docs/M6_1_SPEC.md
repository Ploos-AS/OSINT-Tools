# M6.1 — Case ownership, ACLs and teams

Version 0.6.1 extends the M6.0 authentication/RBAC/audit foundation. Forgejo/origin remains the development upstream; this milestone does not change remotes or publish commits.

## Authorization model

Global roles remain `admin`, `analyst`, `viewer`. Case grants are `owner`, `editor`, `viewer`. Effective access is their intersection:

1. Authentication disabled: system-local administrative access; no fake users or ACL rows are created.
2. Authentication enabled: require an enabled, authenticated local user, identified by the **user ID**, never a session ID or username.
3. An enabled global administrator has explicit administrative override across all cases, including unowned legacy cases.
4. Otherwise, an unowned legacy case is inaccessible. For owned cases, choose the strongest positive grant from ownership, direct user ACLs, and enabled teams with explicit membership: owner > editor > viewer.
5. A global viewer is capped at case viewer even if an existing ownership field or editor grant is present. Global analysts can use viewer/editor/owner case permissions. Global admin-only operations, including case deletion, retain that ceiling.

Owners manage case metadata, ownership and ACLs and have analytical read/write access. Editors modify analytical content (targets, notes, pivots, uploads, analysis, provider enrichment and AV) but cannot administer ACLs, transfer ownership or update case metadata. Viewers read evidence, graph, timeline, reports and exports; the existing viewer export policy is retained.

`case_access.py` owns policy and transactional security administration. `access_http.py` applies it to every HTTP case, target and file route, including UI aliases. Object routes resolve their containing case before dispatch. Similarity results are restricted to visible cases; note target/artifact references must belong to the same case. New routes containing case-owned objects must use this boundary.

Non-disclosure: unauthenticated protected requests return 401 (HTML browsing may redirect to login); inaccessible and nonexistent case/object lookups return 404. A readable case with insufficient mutation privileges returns 403. Explicit admin management uses 403. Malformed fields return 400, missing principals 404, duplicate grants/memberships/names and conflicting adoption 409. Listings are filtered by SQL, not browser JavaScript.

## Storage and migration

Schema 8 → 9 is additive: `cases.owner_user_id` is nullable and references `users.id`; `teams`, `team_members`, and `case_acl` are added. Existing evidence, users, sessions and audit remain intact; WAL and foreign keys remain enabled. ACL rows contain exactly one user/team foreign key, and grant only editor/viewer. Unique constraints prevent duplicate case/principal grants and team membership. Owners are represented only by the case field. Deleting an owner user is restricted by the foreign key; there is no user deletion API.

Legacy cases remain NULL-owned. They remain usable with authentication disabled. With authentication enabled, only an administrator can see and explicitly assign them. `POST /api/v1/cases/{id}/claim` accepts `{"owner_user_id": 123}` (defaults to the acting admin when omitted), requires an unowned case and records adoption. `PATCH /api/v1/cases/{id}/owner` also permits explicit administrative assignment. No request implicitly adopts a case.

Authenticated case creation inserts the creator's stable user ID with the case in the same transaction. Ownership targets must exist, be enabled and have analyst/admin role. Transfers and ACL/team changes use `BEGIN IMMEDIATE`, recheck policy inside the transaction and commit their audit event together with the change. Transfer replaces ownership; the previous owner retains only separately persisted direct/team access, if any. A later demotion to viewer suppresses management without rewriting evidence or ownership.

Analytical requests authorize immediately before dispatch. A concurrent permission change does not cancel work already authorized and in flight; the next request observes current membership and enabled state. This is a deliberately small request-boundary model, not an external policy engine.

## APIs

All mutations use the M6.0 session-bound `X-CSRF-Token` header. Missing, wrong, cross-session and query-string-only tokens are rejected. GET is non-mutating. Bodies below are JSON.

| Method/path | Body / behavior |
| --- | --- |
| GET `/api/v1/cases/{id}/access` | Owner ID, effective access and explicit admin override flag |
| GET `/api/v1/cases/{id}/acl` | Owner/admin only; safe direct/team grants |
| POST `/api/v1/cases/{id}/acl` | `{"principal_type":"user","principal_id":123,"access":"viewer"}`; type also `team`, access also `editor` |
| PATCH `/api/v1/cases/{id}/acl/{acl_id}` | `{"access":"editor"}` |
| DELETE `/api/v1/cases/{id}/acl/{acl_id}` | Revoke grant |
| PATCH `/api/v1/cases/{id}/owner` | `{"owner_user_id":123}` |
| POST `/api/v1/cases/{id}/claim` | Explicit admin legacy adoption |
| GET/POST `/api/v1/admin/teams` | List/create; create body `{"name":"Analysts","description":"Optional","enabled":true}` |
| GET/PATCH `/api/v1/admin/teams/{id}` | Read/update name, description, enabled |
| GET/POST `/api/v1/admin/teams/{id}/members` | List/add; add body `{"user_id":123}` |
| DELETE `/api/v1/admin/teams/{id}/members/{user_id}` | Remove explicit membership |

Only administrators manage teams and membership. Disabled teams confer no access, but their grants/memberships persist for deliberate re-enabling. Disabled users cannot use sessions or membership. Changes take effect on subsequent authorization checks without issuing a new ACL. No nested teams, inferred membership, deny rules or custom permission vocabulary exists.

## Import/export trust boundary

Native `.osintcase`, STIX, TAXII and MISP imports create a **new** case owned by the local authenticated importer. The owner argument is supplied internally by the handler, not read from request/import authorization metadata. Native import inserts ownership in its case/evidence transaction; STIX/MISP case creation atomically includes the owner before analytical import proceeds.

Foreign `owner`, `owner_user_id`, `acl`, `permissions`, `team`, `role`, `users`, `sessions` and configuration-like fields are not local authorization instructions. Importers do not write users, password hashes, sessions, teams, memberships, ACLs or authentication/audit configuration. Supported hostile analytical display metadata remains escaped ordinary content. Import audit remains locally generated; imports do not restore foreign audit history.

Native JSON/bundle export omits the local owner field. STIX, MISP and reports do not publish local owner/ACL/team security state, password/session material, authentication configuration or unrelated membership. No portable export is authoritative security state on import.

## UI and audit

The case workspace displays owner and effective access. Owners/admins receive escaped ACL grant/change/revoke and ownership assignment controls. Administrators use `/admin/teams` for team and membership management. Read-only viewers receive no mutation forms. Analytical editors receive existing analytical controls but no ACL management controls. All enforcement remains server-side.

The server-rendered HTML uses local CSS/vanilla JavaScript, no CDN or build system, and the existing restrictive CSP. Core browsing works without JavaScript. JavaScript login uses the existing API login and keeps its session-bound CSRF token in tab-local sessionStorage; forms send it in the existing header. No second CSRF token scheme is introduced. No-JavaScript login permits browsing; authenticated browser mutations require JavaScript/API header support.

Persistent security audit records `case_created`, `case_claimed`, `case_owner_changed`, `case_acl_granted/changed/revoked`, `team_created/updated/enabled/disabled`, and `team_member_added/removed`. Metadata is a fixed set of IDs/access levels, never request bodies or credentials. Existing authentication, provider, AV, upload, import and deletion events remain.

## Qualification

`tests/test_m61.py` adds policy/constraint/migration tests and actual localhost HTTP isolation. `scripts/qualification_m61_runtime.py` runs cross-user HTTP checks within the canonical authenticated Docker stack with real ClamAV and controlled TAXII/MISP fixtures. Independent rows feed the existing PASS/FAIL/SKIPPED aggregation. Restart checks prove persisted team access. `qualification_m61_migration_runtime.py` creates a temporary schema-8 database from the immutable M6.0 storage source, starts schema 9 against it, checks evidence/users/sessions/audit, adopts the legacy case and restarts. Generated databases are never checked in.

## Deferred scope

OIDC/OAuth/SAML/LDAP/AD, MFA/WebAuthn/TOTP, personal API tokens, service accounts, organizations/multi-tenancy, nested teams, deny ACLs, custom permissions and external policy engines are deferred. Authorization is for authenticated multi-user deployments; auth-disabled mode intentionally provides local administrative access to every caller. Deployment operators remain responsible for TLS and restricting access to that mode.
