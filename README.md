# OSINT Tools

Self-hosted, open-source, passive-first OSINT workbench inspired by the convenience of IT-Tools.

**M3.1 Provider Framework** adds optional, server-configured external providers to the M2 case and pivot workbench. Target detection, passive primitives, SQLite cases, artifacts, relationships, notes and pivots remain available without API keys.

## Run with Docker or Podman

```sh
docker compose up --build
# or
podman compose up --build
```

Open `http://localhost:8080/healthz` and `http://localhost:8080/api/v1/info`.

Example:

```sh
curl 'http://localhost:8080/api/v1/dns?domain=example.com'
curl 'http://localhost:8080/api/v1/tls?host=example.com'
curl 'http://localhost:8080/api/v1/providers'
```

The built-in IPinfo provider supports `lookup` for IP targets. Set `IPINFO_TOKEN` in the server/container environment to configure it; set `OSINT_PROVIDER_IPINFO_ENABLED=false` to disable it explicitly. Credentials are never accepted from API clients or returned by status APIs.

Run the non-interactive qualification harness with `scripts/qualify.sh`. It reports each Docker, Podman, regression, persistence, and live-provider gate as `PASS`, `FAIL`, or `SKIPPED`; a live IPinfo call runs only when `IPINFO_TOKEN` is present.

The same OCI image is intended for Docker and Podman, amd64 and arm64, and runs as a non-root user. Persistent application data lives under `/data`.

See `docs/M0_SPEC.md`, `docs/M1_SPEC.md`, `docs/M2_SPEC.md`, `docs/M3_1_SPEC.md`, `docs/ARCHITECTURE.md` and `ROADMAP.md`.
