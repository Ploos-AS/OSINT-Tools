# M7.5 Release Candidate Closure

M7.5 closes the release-engineering milestone and hands the repository to M8 final v1.0 qualification. It does not create a release tag or publish an image.

## Verified release-engineering baseline

The M7 chain now requires:

- M7.2 backup/restore/upgrade qualification.
- M7.3 tag-driven release automation qualification.
- M7.4 distribution/deployment qualification.
- M7.5 release-candidate closure qualification.
- canonical Docker/Podman/security qualification and the M6.2 Chromium browser-security gate.

The release workflow publishes one multi-architecture build to both `ghcr.io/ploos-as/osint-tools` and `ploos1/osint-tools`, requires amd64 and arm64 manifests, verifies digest equality, emits SBOM/provenance, and creates GitHub release metadata only after qualification succeeds.

## Source distribution

The intended source topology remains:

1. Ploos-AS Forgejo is canonical.
2. GitHub is a public mirror and currently hosts qualification/release automation.
3. Codeberg is the second public mirror target.

M7.5 does not claim that Forgejo-to-GitHub/Codeberg automation has been externally verified from this GitHub-only qualification environment. That verification is an explicit M8/manual release prerequisite. Tags must resolve to the same source commit on all configured mirrors before v1.0.0 publication.

## Registry prerequisites

The release contract requires:

- GHCR write access through the GitHub release workflow.
- Docker Hub repository `ploos1/osint-tools`.
- `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN` available to the release workflow.

Secret values are not readable by repository qualification and are therefore an operator prerequisite rather than a claim made by M7.5.

## M8 handoff / remaining final-release gates

M8 must complete all of the following before `v1.0.0` is created:

- align the final project/runtime/API version to `1.0.0` and verify `/api/v1/info` reports it;
- run the complete qualification suite on the exact release commit;
- verify Forgejo canonical source and GitHub/Codeberg mirrors resolve the same release commit/tag;
- verify Docker Hub credentials/repository access and GHCR publication access;
- create `v1.0.0` only after those checks are green;
- verify the published GHCR and Docker Hub images expose identical digests and amd64/arm64 manifests.

Current development metadata remains pre-1.0 during M7.5. No published `latest` or `1.0.0` image is implied by documentation examples until the release workflow has successfully published them.
