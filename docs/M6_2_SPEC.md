# M6.2 Security Hardening & Concurrency Qualification

Version target: **0.6.2**

## Purpose

M6.2 closes the highest-value security and concurrency gaps left after the qualified M6.1 ownership/ACL/team model. It is deliberately a hardening milestone, not a feature-expansion milestone.

The goal is to make the existing multi-user security boundary more deterministic under concurrent mutation and to add real-browser evidence for the security-sensitive UI flows before release-focused work begins.

## Scope

### 1. Deterministic authorization race tests

Add repeatable tests for concurrent or interleaved security mutations, especially:

- ownership transfer while the previous owner is attempting a protected mutation;
- direct ACL revocation while the revoked user is attempting a protected mutation;
- team membership removal/disable while a team-derived user is attempting a protected mutation;
- user disable while an authenticated session attempts a protected mutation;
- stale authorization decisions must be rechecked at the mutation boundary;
- database constraints and transactions must prevent invalid or duplicate security state.

The tests must avoid timing-only assertions where possible. Use explicit barriers/hooks/transactions or other deterministic orchestration so a failure is reproducible.

M6.2 does **not** require cancellation of analytical work that was already fully authorized and committed before a later revocation. The security boundary is the point at which a protected mutation is authorized/committed.

### 2. Real-browser security-flow qualification

Add a small browser E2E suite for the security-sensitive flows that were code-reviewed or HTTP-tested in M6.1:

- login/logout;
- case creation and ownership display;
- grant viewer/editor access;
- revoke access and verify the case disappears/becomes inaccessible;
- ownership transfer;
- team-derived access and membership removal;
- read-only users do not receive working mutation controls;
- CSRF/session behavior survives normal browser navigation;
- hostile user/team/case names remain escaped in rendered UI.

The browser suite should remain bounded and focused on security behavior rather than becoming a general UI test framework.

### 3. Security regression review

Re-review the centralized case-access boundary after the race-test work:

- no route should bypass centralized case authorization;
- inaccessible case-scoped resources remain non-disclosing (`404` where required);
- global viewer ceiling remains enforced;
- admin override remains explicit and auditable;
- imports/exports remain isolated from local authentication/ACL state;
- security audit events retain actor identity without recording secrets.

### 4. Qualification integration

Extend the canonical qualification path so M6.2 evidence is reproducible in CI.

Required gates:

- existing regression suite remains green;
- new deterministic concurrency tests pass;
- browser E2E security suite passes on the supported CI runner;
- canonical Docker runtime qualification remains green;
- migration/restart qualification from M6.1 remains green;
- `git diff --check` passes.

Browser tooling and downloaded browser binaries are build/test dependencies only and must not be included in the production OCI image.

## Explicitly deferred

The following remain outside M6.2 unless needed to fix a demonstrated security defect:

- OIDC/SAML/LDAP;
- MFA;
- API tokens/service accounts;
- organizations/nested teams;
- custom policy languages or explicit deny rules;
- cancellation of already-running analytical work after revocation;
- new OSINT providers;
- new artifact parsers;
- broad UI redesign;
- release/distribution work that belongs to the release-hardening milestones.

## Acceptance criteria

M6.2 is complete when:

1. deterministic ownership/ACL/team/user revocation race tests exist and pass;
2. protected mutations recheck authorization at the effective mutation boundary;
3. a bounded real-browser E2E suite proves the critical multi-user security flows;
4. the existing M6.1 security, migration, persistence, Docker and Podman guarantees do not regress;
5. qualification output clearly separates PASS/FAIL/SKIPPED gates;
6. residual risks are documented rather than silently treated as proven;
7. the canonical CI qualification is green.

## Non-goal

M6.2 must not expand OSINT Tools into a general enterprise IAM platform. Its purpose is to harden the already implemented local multi-user model sufficiently to proceed toward v1.0 release engineering.
