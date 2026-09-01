# OSINT Tools

Self-hosted, open-source, passive-first OSINT workbench inspired by the convenience of IT-Tools.

**M1 Core Passive OSINT** provides target detection, DNS, RDAP, IP classification, HTTP header inspection, TLS certificate inspection and mail-domain (MX/SPF/DMARC) analysis through a small JSON API.

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
```

The same OCI image is intended for Docker and Podman, amd64 and arm64, and runs as a non-root user. Persistent application data lives under `/data`.

See `docs/M0_SPEC.md`, `docs/M1_SPEC.md`, `docs/ARCHITECTURE.md` and `ROADMAP.md`.
