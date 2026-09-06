# M6.2 Qualification

## Qualified baseline

M6.2 was qualified on canonical GitHub Actions run **Qualification #12**, run ID **34033148383**, against commit **3ca69a46676451ea5aa65ae23362f9d6a4db64cf** on `main`.

Result: **SUCCESS**.

The canonical job completed both the existing `Run canonical qualification` step and the named `M6.2 browser security` step successfully.

## Evidence

The existing canonical qualification retained the M6.1 security, migration, persistence, Docker, Podman and real-ClamAV gates. The last recorded full harness result before M6.2 closure was **PASS=236, FAIL=0, SKIPPED=8**. The skips are capability/credential-dependent rather than silently accepted mandatory failures.

M6.2 adds deterministic authorization-race tests for stale authorization after ownership transfer, direct ACL revocation, team-membership removal and user disable. These tests order the security-state change before the protected mutation and verify that fresh authorization rejects the mutation.

The canonical CI also installs Chromium and runs the bounded Playwright browser-security suite. Qualification #12 passed that named browser gate after the ownership-transfer scenario was made deterministic and aligned with the server's non-disclosing `not_found` response.

## Known skips / external qualification gaps

The canonical environment may skip:

1. optional Podman ClamAV composition, which is not wired into the current Podman harness;
2. linux/arm64 image/runtime qualification when the runner has no arm64-capable builder;
3. live IPinfo without a token;
4. live VirusTotal without an API key;
5. live AbuseIPDB without an API key;
6. live Shodan without an API key;
7. live TAXII without endpoint/credentials;
8. live MISP without endpoint/credentials.

Controlled TAXII/MISP fixtures remain covered by mandatory tests.

## Closure

M6.2 acceptance is satisfied for the available canonical environment: deterministic authorization-race coverage is present, real-browser security flows are a mandatory CI gate, the existing M6.1 security/migration/persistence qualification remains green, and residual risks are documented in `docs/M6_2_SECURITY_REVIEW.md`.

M6.2 is therefore closed. The next milestone is **M7 Release Engineering & Polish**, followed by **M8 v1.0 Qualification**.
