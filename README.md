# OSINT Tools

Self-hosted, open-source OSINT workbench inspired by the simplicity of IT-Tools.

## M0 goals

- One OCI image for Docker and Podman
- amd64 + arm64 ready
- non-root/rootless friendly
- passive OSINT first
- useful without API keys
- persistent application data only under `/data`
- SQLite first; PostgreSQL later
- no Docker socket dependency
- foundation for cases, targets, artifacts, relationships, notes and pivots

## Quick start

### Docker / Docker Compose

```sh
docker compose up --build -d
curl -fsS http://localhost:8080/healthz
```

### Podman

```sh
podman build -t osint-tools:dev .
podman run --rm -p 8080:8080 -v osint-tools-data:/data:Z osint-tools:dev
```

A Podman Quadlet example is in `deploy/quadlet/osint-tools.container`.

## M0 status

M0 is deliberately small: it proves packaging/runtime portability and establishes the project contract. Functional OSINT modules begin in M1.
