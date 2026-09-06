# M8 v1.0 Final Qualification

M8 qualifies the exact source tree for the first stable `v1.0.0` release. **M8.0 defines and gates the final qualification plan; it does not create or push the release tag.**

## Automated final gates

The exact release commit must pass the complete canonical qualification harness plus M7.2 backup/restore/upgrade, M7.3 release contract, M7.4 distribution/deployment, M7.5 release-candidate closure, M6.2 Chromium browser security, and the M8 final gate.

The canonical harness already exercises Docker build/runtime, persistence/restart, authentication/RBAC/ACL/security regression, real ClamAV, Podman when available, and Buildx architecture checks. M8 requires linux/amd64 and linux/arm64 release support; capability-dependent skips must be resolved by the release workflow's mandatory multi-architecture build before publication.

## M8.1 exact release-source alignment

The next M8 step must align `pyproject.toml`, `osint_tools.__version__`, and `/api/v1/info` to `1.0.0`, update the canonical runtime assertion accordingly, and run the complete qualification suite on that exact commit. The current M8.0 planning commit deliberately remains pre-1.0 so a source tree is not labelled stable before the final qualification contract exists.

## Manual pre-tag gates

The following cannot be truthfully proven by the GitHub-only source qualification environment and remain mandatory operator checks before creating `v1.0.0`:

1. Verify the Ploos-AS Forgejo canonical `main` commit equals this qualified release commit.
2. Verify GitHub and Codeberg mirrors resolve the same commit before the tag is created, and verify the resulting `v1.0.0` tag resolves to that same commit on every configured mirror.
3. Verify the Docker Hub repository `ploos1/osint-tools` exists and that `DOCKERHUB_USERNAME` plus `DOCKERHUB_TOKEN` are available to the GitHub release workflow.
4. Verify GHCR publication permission is available to the release workflow.
5. Verify the actual tag-delivery path from canonical Forgejo to GitHub triggers the GitHub tag release workflow, or push the immutable release tag through the explicitly qualified operator path.

No M8 source commit or CI result may be interpreted as proof of these external checks.

## Post-tag publication gates

The release workflow must succeed before v1.0.0 is called published. It must verify that `ghcr.io/ploos-as/osint-tools:1.0.0` and `ploos1/osint-tools:1.0.0` expose linux/amd64 and linux/arm64 manifests and the same OCI digest produced by the release build, with SBOM and provenance/attestation metadata plus GitHub release metadata identifying tag, source SHA, image names, digest and platforms.

If publication fails after the immutable tag exists, fix the release pipeline without moving or recreating `v1.0.0`.

## Release boundary

M8 closes only after the exact 1.0.0 source commit has a green Qualification run and all manual pre-tag gates are explicitly verified. Only then may `v1.0.0` be created.
