# Distribution

## Source

The project distribution model is intentionally multi-channel:

1. the Ploos-AS Forgejo repository is the canonical source of truth;
2. GitHub is a public source mirror and currently hosts qualification/release automation;
3. Codeberg is the second public source mirror target and must be configured and verified before release-candidate closure;
4. source tags are immutable and must identify the same commit on every configured mirror.

A mirror is not canonical merely because CI runs there. Release metadata records the exact tagged source SHA so the published OCI image can be traced back to one source revision.

## OCI images

A release publishes one multi-platform build from the tagged source to both registries:

- GHCR: `ghcr.io/ploos-as/osint-tools`
- Docker Hub: `ploos1/osint-tools`

Supported release platforms are `linux/amd64` and `linux/arm64`. The immutable full-version tag is authoritative. Moving compatibility tags are also published: `MAJOR.MINOR`, `MAJOR`, and `latest`.

Example after v1.0.0 exists:

```sh
docker pull ghcr.io/ploos-as/osint-tools:1.0.0
docker pull ploos1/osint-tools:1.0.0
```

The release workflow requires the GHCR and Docker Hub full-version references to resolve to the same manifest digest and to contain both supported platforms.

## Provenance and SBOM

Release builds include BuildKit SBOM and provenance attestations. GitHub additionally publishes build provenance for the GHCR subject. Release metadata records the source tag, exact SHA, image names, digest, and platforms.

## Registry credentials

Provider credentials are never required to build or publish OSINT Tools. Docker Hub publication uses repository secrets `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN`; GHCR uses the workflow's scoped GitHub token. Application provider tokens, `/data`, case data, uploaded evidence, and ClamAV databases are not release inputs.

## Harbor

A self-hosted Harbor registry remains an optional future third OCI target. Harbor is not part of the v1.0 release gate and must not block GHCR/Docker Hub publication.
