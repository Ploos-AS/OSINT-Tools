# OSINT Tools

Self-hosted, open-source, passive-first OSINT workbench inspired by the convenience of IT-Tools.

**M3.2 Provider Enrichment** adds curated, server-configured IPinfo, VirusTotal, AbuseIPDB, and Shodan enrichment to the M2 case and pivot workbench. Target detection, passive primitives, SQLite cases, artifacts, relationships, notes and pivots remain available without API keys.

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
# For an existing target:
curl -X POST 'http://localhost:8080/api/v1/targets/1/enrich' -d '{}'
```

Optional credentials are `IPINFO_TOKEN`, `VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY`, and `SHODAN_API_KEY`. Each provider can be disabled with `OSINT_PROVIDER_<PROVIDER>_ENABLED=false`. Credentials are never accepted from API clients or returned by status APIs. VirusTotal supports IP, domain, URL, and MD5/SHA-1/SHA-256 hash targets; the other providers enrich IPs.

Run the non-interactive qualification harness with `scripts/qualify.sh`. It reports each Docker, Podman, regression, persistence, and per-provider live gate as `PASS`, `FAIL`, or `SKIPPED`; live calls run only when the corresponding credential is present.

The same OCI image is intended for Docker and Podman, amd64 and arm64, and runs as a non-root user. Persistent application data lives under `/data`.

See `docs/M0_SPEC.md`, `docs/M1_SPEC.md`, `docs/M2_SPEC.md`, `docs/M3_1_SPEC.md`, `docs/M3_2_SPEC.md`, `docs/ARCHITECTURE.md` and `ROADMAP.md`.
