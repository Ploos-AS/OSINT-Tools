# M7.3 Release Automation

## Purpose

M7.3 implements the M7.0 release contract without creating a v1.0 release. Publication is separated from ordinary `main` qualification and can start only from a Git tag. The final v1.0 tag remains a later M7.5/M8 decision.

## Trigger and version contract

`.github/workflows/release.yml` runs only for pushed tags matching `v*`; the first executable gate then requires the exact core-SemVer form `vMAJOR.MINOR.PATCH`. The tag without its leading `v` must exactly equal `[project].version` in `pyproject.toml`. A mismatch fails before registry login or publication.

Release tags are treated as immutable inputs. The workflow never creates or moves a tag and ordinary branch pushes cannot invoke publication.

## Mandatory qualification before publication

The tagged source is checked out with full history and must pass, in order:

1. canonical `scripts/qualify.sh`;
2. M7.2 backup/restore/upgrade qualification;
3. M7.3 static release-contract qualification;
4. M6.2 Chromium browser-security qualification.

The publish job depends on this qualification job. Any failure prevents registry authentication and publication.

## OCI publication

One Buildx solve publishes the same tagged source to:

- `ghcr.io/ploos-as/osint-tools`;
- `docker.io/ploosas/osint-tools`.

Platforms are `linux/amd64` and `linux/arm64`. For a version such as `1.0.0`, both registries receive `1.0.0`, `1.0`, `1`, and `latest` tags.

The image receives OCI version, source-revision and source-URL labels. Runtime still comes from the single repository `Containerfile`, remains non-root, and keeps `/data` as its persistent boundary.

GitHub authentication uses the job-scoped `GITHUB_TOKEN`. Docker Hub uses repository/organization Actions secrets `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN`; their values are never written into the source tree, image build arguments or release metadata.

## SBOM and provenance

Buildx is required to publish an OCI SBOM attestation and max-mode build provenance. The workflow additionally publishes GitHub build provenance for the GHCR subject using OIDC-backed attestation permissions. These records are associated with the released image digest rather than copied into the application filesystem.

## Post-publication verification

After push, the workflow inspects the immutable full-version tag in each registry, requires both `linux/amd64` and `linux/arm64`, extracts each index digest and requires both to equal the digest returned by the Buildx publication step. Failure is release-fatal.

## Release metadata

A text metadata artifact records the source tag, exact source SHA, version, both immutable image references, digest, platforms, and the SBOM/provenance mechanism. A GitHub Release is then created for the already-existing tag with concise upgrade, persistence, secret and ClamAV notes plus the metadata attachment.

The GitHub Release is distribution metadata for the GitHub mirror; it does not change the canonical-source policy that Forgejo is authoritative and GitHub/Codeberg are mirrors.

## Qualification

`scripts/qualification_m73_release.py` statically verifies the fail-closed trigger, SemVer/version gate, mandatory qualification steps, both registries, multiarchitecture build, compatibility tags, OCI labels, SBOM/provenance, digest verification, release metadata, non-root runtime and `/data` persistence. Canonical CI runs this on `main` so accidental weakening of the release contract is detected before a release tag is used.

## Deferred

M7.3 does not create `v1.0.0`, publish a release from the current 0.6.2 development version, configure Codeberg/Forgejo mirroring, add Harbor, or switch Compose/Quadlet examples to released-image references. Those distribution/documentation items remain M7.4/M7.5 work.
