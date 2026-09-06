# M6.2 browser security qualification

This document defines the bounded real-browser security qualification required by `M6_2_SPEC.md`.

## Purpose

HTTP/API qualification remains mandatory, but M6.2 also requires evidence that the rendered browser UI preserves the same authorization boundary. This is a security qualification suite, not a general UI regression framework.

## Required scenarios

A browser runner must prove all of the following against a real OSINT Tools server with authentication enabled:

1. **Login/logout** — a valid user can establish a browser session, logout invalidates it, and protected navigation returns to the login flow.
2. **Case ownership** — a newly created case shows the authenticated creator as owner and is not visible to an unrelated analyst.
3. **Direct viewer grant** — the granted user can open the case but mutation controls are absent or disabled and direct mutation attempts remain rejected server-side.
4. **Direct editor grant** — the granted editor receives the permitted case mutation controls and can perform an allowed mutation.
5. **Revocation** — after the owner revokes a grant, the previously granted user's subsequent browser navigation can no longer disclose the case.
6. **Ownership transfer** — after transfer, the previous owner loses owner-only controls and the new owner receives them.
7. **Team-derived access** — a team member receives the effective case access granted to the team; after membership removal the access disappears on subsequent navigation.
8. **Global viewer ceiling** — a global viewer remains read-only even when a case grant would otherwise provide editor access.
9. **CSRF/session behavior** — normal form/navigation flows carry valid CSRF state; missing or invalid CSRF state on a protected mutation is rejected.
10. **Escaping** — hostile case, team and user display names are rendered as text and cannot create executable markup/script in the browser DOM.

## Runner constraints

- Use a mainstream headless browser supported on the canonical Ubuntu CI runner.
- The browser and its downloaded binaries are test-only dependencies and must not be copied into the production OCI image.
- Start from an isolated temporary data directory/database.
- Use deterministic fixture identities and explicit waits for DOM/navigation state; do not use arbitrary sleeps as synchronization.
- Capture enough failure context to identify the scenario and failing assertion without recording passwords, session cookies, CSRF tokens or provider secrets.
- Keep the suite small. Provider workflows, general styling and exhaustive page coverage are outside this gate.

## CI gate

The canonical qualification must expose a named `M6.2 browser security` gate. It is mandatory on the canonical GitHub Actions runner once the browser harness is installed there.

A local environment may report the browser gate as `SKIPPED` only when the browser test dependency is unavailable. CI must install the dependency, so a canonical CI skip is a qualification failure for M6.2 closure.

## Acceptance evidence

M6.2 browser qualification is complete only when the canonical CI log demonstrates that all ten scenarios above pass against the real server and the existing M6.1 HTTP/runtime qualification remains green.
