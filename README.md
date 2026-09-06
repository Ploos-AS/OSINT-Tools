# OSINT Tools

Self-hosted, open-source, passive-first OSINT workbench inspired by the convenience of IT-Tools.

**M7 Release Engineering & Polish** is now in release-candidate closure. M0-M6 functionality is implemented and M7.1-M7.4 operator docs, backup/restore qualification, release automation, and distribution/deployment contracts are in place. M7.5 closes the release-engineering path before M8 final v1.0 qualification.

## Run with Docker or Podman

Published releases use the same multi-architecture OCI image for Docker and Podman. The primary registry is GHCR, with Docker Hub as the second publication target:

```sh
docker pull ghcr.io/ploos-as/osint-tools:1.0.0
# equivalent release image after publication:
docker pull ploos1/osint-tools:1.0.0
```

Before the first v1.0.0 release exists, build the current source checkout locally:

```sh
OSINT_TOOLS_IMAGE=osint-tools:dev docker compose build
OSINT_TOOLS_IMAGE=osint-tools:dev docker compose up -d
```

Open `http://localhost:8080/` for the browser workspace, `http://localhost:8080/healthz` for health, and `http://localhost:8080/api/v1/info` for runtime information.

Persistent application data lives under `/data`. The application image runs as a non-root user. Authentication is enabled by default; `OSINT_TOOLS_AUTH_ENABLED=false` is retained only for trusted, network-restricted single-system deployments.

Optional credentials are `IPINFO_TOKEN`, `VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY`, and `SHODAN_API_KEY`. Provider credentials are server-side deployment secrets and are never accepted from API clients or returned by status APIs.

ClamAV is optional and disabled by default. The optional Compose profile starts the external ClamAV service with a separate signature database volume; OSINT Tools streams bytes to the configured local scanner and never executes uploaded content.

## Release and operator documentation

See:

- `docs/INSTALL.md` — deployment and image selection
- `docs/CONFIGURATION.md` — runtime configuration
- `docs/UPGRADE.md` — supported upgrade procedure
- `docs/BACKUP_RESTORE.md` — `/data` backup/restore contract
- `docs/TROUBLESHOOTING.md` — operator diagnostics
- `docs/DISTRIBUTION.md` — Forgejo/GitHub/Codeberg and GHCR/Docker Hub distribution model
- `docs/M7_5_RELEASE_CANDIDATE.md` — M7.5 closure and M8 handoff
- `ROADMAP.md` — milestone roadmap

The release path is tag-driven and fail-closed. A release tag must be exact `vMAJOR.MINOR.PATCH`, match the project version, pass canonical qualification plus M7 release gates and browser security qualification, then publish the same amd64/arm64 digest to `ghcr.io/ploos-as/osint-tools` and `ploos1/osint-tools` with SBOM/provenance metadata.

No `v1.0.0` tag is created by M7.5. M8 performs final v1.0 qualification and version alignment before the first stable release.
