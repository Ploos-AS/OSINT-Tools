# M0 — Foundation specification

## Product contract

OSINT Tools is a self-hosted, open-source OSINT workbench with an IT-Tools-like UX: small focused tools, fast pivots, and optional case-oriented investigation workflows.

## Runtime contract

1. Build one OCI-compatible image; do not maintain Docker and Podman editions.
2. Support Docker and Podman from the same image.
3. Target linux/amd64 and linux/arm64.
4. Run as a non-root user by default and remain suitable for rootless Podman.
5. Do not require docker.sock, podman.sock, privileged mode, host networking, or host PID namespace.
6. Keep mutable application state beneath `/data`.
7. Accept configuration via environment variables and, later, mounted secrets.
8. Provide a health endpoint.

## Security posture

Passive OSINT is the default product boundary. External fetchers must receive explicit egress/SSRF controls before arbitrary user-supplied URLs or addresses are accepted. Uploaded objects are inspected as data and are never executed. Provider credentials remain server-side.

## Initial information model

- Case
- Target
- Observation
- Artifact
- Relationship
- Note
- Pivot
- Provider result/provenance

M0 does not need to implement the full model; it reserves these concepts for M2.

## Milestones

- M0: foundation, OCI packaging, Docker/Podman examples, health/info API
- M1: passive core tools (DNS/RDAP/TLS/CT/HTTP parsing and local transforms)
- M2: case store, targets, artifacts, relationships, notes and pivots
- M3: optional external providers/adapters and secrets handling
- M4: safe file/image metadata intelligence
- M5: UX polish, export/import, release hardening and documentation

## M0 acceptance gates

- Python package imports and compiles.
- Service starts without root privileges.
- `/healthz` returns HTTP 200 JSON.
- `/api/v1/info` identifies M0.
- Containerfile contains no runtime-specific socket dependency.
- Compose and Podman Quadlet examples persist `/data`.
- Repository contains no required API key.
