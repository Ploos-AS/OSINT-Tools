# M6.1 qualification closure

M6.1 — Case Ownership, ACLs & Teams — is qualified complete.

## Qualified revision

The canonical GitHub Actions qualification passed on commit:

- `01e11b6333984bcd828387e5699977e0c94797d1`
- workflow: `Qualification`
- run: `34020889299` (run #2)
- runner: Ubuntu 24.04, Python 3.12

The workflow uses a full-history checkout because the schema 8 -> 9 migration qualification reconstructs its fixture from the immutable M6.0 source revision.

## Result

`sh scripts/qualify.sh` completed successfully with:

- `PASS=236`
- `FAIL=0`
- `SKIPPED=8`
- full Python suite: `172 passed`

The successful mandatory gates include Docker build/runtime, M6.0 compatibility, authenticated M6.1 cross-user authorization, ownership and transfer, direct and team ACLs, revocation, role ceilings, CSRF protections, access-aware UI behavior, import/export confinement, audit and secret redaction, ACL/team persistence, schema 8 -> 9 runtime migration and legacy adoption, auth-disabled compatibility, real Docker ClamAV qualification, Podman build/runtime/non-root/data/auth smoke, and linux/amd64 image build.

## Non-blocking skipped gates

The eight skipped gates are environment- or configuration-dependent and were already classified as residual/deferred rather than mandatory M6.1 closure blockers:

- Podman ClamAV runtime: optional Compose-profile clamd is not wired into the Podman application harness.
- linux/arm64 build: the qualification runner's current Buildx builder does not advertise `linux/arm64`.
- live IPinfo: no `IPINFO_TOKEN` configured.
- live VirusTotal: no `VIRUSTOTAL_API_KEY` configured.
- live AbuseIPDB: no `ABUSEIPDB_API_KEY` configured.
- live Shodan: no `SHODAN_API_KEY` configured.
- live TAXII: no live TAXII qualification endpoint/credentials configured.
- live MISP: no live MISP qualification endpoint/credentials configured.

Controlled TAXII/MISP fixtures remain covered by the mandatory qualification path. Docker ClamAV is runtime-proven. Podman application behavior is runtime-proven without the optional clamd profile.

## Closure

M6.1 is complete. The remaining residual/deferred items stay documented in `docs/M6_1_SECURITY_REVIEW.md` and do not change the M6.1 completion claim.
