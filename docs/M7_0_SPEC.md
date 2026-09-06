# M7.0 Release Engineering Baseline

## Purpose

M7 turns the qualified 0.6.2 application into a reproducible, operator-friendly release candidate for v1.0. M7.0 defines the release contract before implementation so later release work does not silently change persistence, upgrade or distribution semantics.

## Current baseline

At M7.0 entry the repository has:

- one application OCI definition usable as `Dockerfile` and `Containerfile`;
- Docker Compose deployment with persistent `/data`;
- Podman Quadlet deployment under `deploy/quadlet`;
- non-root application runtime;
- schema migrations exercised by canonical qualification;
- canonical GitHub Actions qualification including M6.2 Chromium security flows;
- no published GitHub releases yet.

M6.2 commit `3db3c293eb1320aa4de7b1198d5bd5ef20637c98` is the qualified entry baseline.

## Release contract

### Versioning and tags

- Project releases use SemVer-style `vMAJOR.MINOR.PATCH` Git tags.
- The application version in `pyproject.toml`, `/api/v1/info`, release notes and OCI labels/tags must agree.
- Release tags are immutable. A bad release is superseded by a new patch release rather than moving a published tag.
- `main` remains the development line; v1.0 qualification must identify an exact commit before tagging.

### OCI distribution

The intended distribution chain is:

1. canonical source repository: Ploos-AS Forgejo;
2. source mirrors: GitHub and Codeberg;
3. OCI publication: GHCR and Docker Hub;
4. optional self-hosted Harbor later.

A release must publish the same source revision for `linux/amd64` and `linux/arm64`. Registry tags should include the immutable full version plus moving compatibility tags where appropriate (`1.0.0`, `1.0`, `1`, `latest`). Digest equality/manifest membership must be verifiable after publication.

Release publication must not require provider credentials and must not bake credentials, local data or ClamAV databases into the application image.

### Installation

Supported operator entry points for v1.0 are:

- Docker Compose using the published OCI image;
- Podman using the supplied Quadlet units.

Source builds remain supported for development/qualification but are not the primary production installation path.

Persistent state is exclusively rooted at `/data` from the application's perspective. Deployment examples must make persistence explicit and must not require root inside the container.

### Upgrade

The supported upgrade model is stop → backup → pull new immutable release → start → verify health/version/migration. Schema upgrades must be forward and automatically applied by the application where already designed; downgrade across a schema migration is not promised.

Every release that changes the persistent schema must document the schema transition and must be qualified from the previous supported release with existing data intact.

Operators must be told not to replace an existing persistent data store with an older application version unless they restore a backup compatible with that version.

### Backup and restore

The authoritative backup boundary is the complete persistent `/data` state while the application is stopped or otherwise quiesced. This includes the SQLite database and content-addressed uploaded-file storage. Provider credentials supplied through environment/configuration are deployment secrets and are not part of the application-data backup.

M7 must provide documented Docker and Podman/Quadlet backup/restore procedures and a qualification that proves restored cases, files, authorization state and application startup.

### Configuration and secrets

Environment variables remain the deployment configuration interface. Release documentation must distinguish:

- required deployment settings;
- optional provider credentials;
- authentication/security settings;
- parser/upload/resource limits;
- optional ClamAV integration.

Secrets must never be committed, embedded in OCI layers, emitted by status APIs or copied into release artifacts.

### Release artifacts and provenance

Before v1.0, release automation must produce or record:

- source tag and exact commit SHA;
- multi-architecture OCI image(s);
- image digests/manifests;
- SBOM for the released application image;
- build provenance/attestation where supported by the registry workflow;
- release notes including upgrade/migration notes and known limitations;
- checksums for downloadable non-OCI release artifacts, if such artifacts are introduced.

The release process must be reproducible from the tagged source and fail closed if mandatory qualification fails.

## M7 work breakdown

### M7.1 Operator documentation

Create concise install, configuration, upgrade, backup/restore and troubleshooting documentation. Keep Compose and Quadlet examples aligned with the published image contract.

### M7.2 Backup/restore and upgrade qualification

Add deterministic qualification for a populated persistent store, backup/restore, restart and previous-version/schema upgrade path. Verify cases, uploaded content, ACL/team/auth state and health/version after recovery.

### M7.3 Release automation

Add tag-driven release automation for multi-architecture OCI publication, immutable/moving tags, SBOM/provenance and release metadata. Registry publication must be separated from ordinary `main` qualification.

### M7.4 Distribution and documentation polish

Align README/deployment examples with released images and the canonical Forgejo → GitHub + Codeberg source distribution model. Document GHCR/Docker Hub consumption and leave Harbor as an optional future target.

### M7.5 Release-candidate closure

Run the complete qualification suite, document residual release risks and freeze the exact candidate commit for M8 v1.0 qualification.

## Acceptance criteria

M7 is complete when:

1. a new operator can install from a published-image deployment example without building source;
2. upgrade and backup/restore procedures are documented and mechanically qualified;
3. amd64/arm64 release automation exists and is tag-driven;
4. release metadata includes exact source revision, OCI digests and SBOM/provenance evidence;
5. no credentials or persistent user data enter release artifacts;
6. Compose and Quadlet use the same persistence/configuration contract;
7. canonical qualification remains green;
8. M7 closure identifies one exact commit ready for M8 v1.0 qualification.

## Deferred / non-goals

M7 does not add OSINT providers, parsers, enterprise IAM, HA database clustering, Kubernetes/Helm, automatic downgrade migrations, Harbor deployment, or a broad UI redesign. Those are separate future decisions.
