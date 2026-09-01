# OSINT Tools

Self-hosted, open-source, passive-first OSINT workbench inspired by the convenience of IT-Tools.

**M4.3 Executable & Binary Static Analysis** adds bounded, non-executing PE, ELF, Mach-O and Amiga Hunk parsing, printable strings, entropy measurements, candidate OSINT indicators, and explicit graph promotion. Existing ingestion, structured analysis, passive primitives, cases, pivots, and optional providers remain available without API keys.

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
# Binary upload; the filename is untrusted display metadata only:
curl -X POST -H 'X-Filename: sample.bin' --data-binary '@sample.bin' \
  'http://localhost:8080/api/v1/cases/1/files'
```

Optional credentials are `IPINFO_TOKEN`, `VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY`, and `SHODAN_API_KEY`. Each provider can be disabled with `OSINT_PROVIDER_<PROVIDER>_ENABLED=false`. Credentials are never accepted from API clients or returned by status APIs. VirusTotal supports IP, domain, URL, and MD5/SHA-1/SHA-256 hash targets; the other providers enrich IPs.

Uploaded bytes are stored under `/data/files` and are never executed, unpacked, rendered, or sent to providers. The default maximum is 25 MiB and can be changed with `OSINT_TOOLS_MAX_UPLOAD_BYTES`. Explicit enrichment of the resulting SHA-256 target may query VirusTotal by hash; it never uploads the file body.

Archive members are never unpacked into filename-derived paths. Eligible children are streamed into the same content-addressed store under shared depth/member/expanded-byte/compression-ratio limits. Structured results are returned under the existing file-analysis API. See the M4.2 specification for limit environment variables and parser boundaries.

Binary candidates are metadata, not targets or evidence of runtime behavior. List them with `GET /api/v1/files/{file_id}/candidates` and explicitly promote a supported candidate with `POST /api/v1/files/{file_id}/candidates/{candidate_id}/promote`. Promotion only updates the local case graph; it performs no DNS, HTTP, provider enrichment, or file upload. Email observations remain candidates because email is not yet a normal target type.

Run the non-interactive qualification harness with `scripts/qualify.sh`. It reports each Docker, Podman, regression, persistence, and per-provider live gate as `PASS`, `FAIL`, or `SKIPPED`; live calls run only when the corresponding credential is present.

The same OCI image is intended for Docker and Podman, amd64 and arm64, and runs as a non-root user. Persistent application data lives under `/data`.

See `docs/M0_SPEC.md`, `docs/M1_SPEC.md`, `docs/M2_SPEC.md`, `docs/M3_1_SPEC.md`, `docs/M3_2_SPEC.md`, `docs/M4_1_SPEC.md`, `docs/M4_2_SPEC.md`, `docs/M4_3_SPEC.md`, `docs/ARCHITECTURE.md` and `ROADMAP.md`.
