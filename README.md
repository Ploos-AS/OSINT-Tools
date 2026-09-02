# OSINT Tools

Self-hosted, open-source, passive-first OSINT workbench inspired by the convenience of IT-Tools.

**M5.2 Interactive Analysis Workspace** adds bounded server-rendered graph and timeline views over persisted case evidence. M5.1 workflows, M4.5 ClamAV, and all prior local/provider analysis remain available.

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

Local detections remain evidence rather than malware verdicts. Managed rule packs and hash sets are imported as immutable named versions through `/api/v1/signatures/rulepacks` and `/api/v1/signatures/hashsets`. File evidence is available from `GET /api/v1/files/{file_id}/detections`; `GET /api/v1/files/{file_id}/similar` returns native `simhash64-v1` Hamming distances. Explicit reanalysis uses `POST /api/v1/files/{file_id}/detections/reanalyze` and never invokes providers or the network.

ClamAV is optional and disabled by default. Enable it with `OSINT_TOOLS_CLAMAV_ENABLED=true` and the administrator-configured `OSINT_TOOLS_CLAMAV_HOST`/`PORT`; an optional Compose profile starts `clamav/clamav:1.4.3` with a separate `clamav-db` volume. Scan files explicitly with `POST /api/v1/files/{file_id}/av/scan`, inspect status at `/api/v1/av/engines`, and retrieve persisted results at `/api/v1/files/{file_id}/av`. `OSINT_TOOLS_AV_SCAN_ON_UPLOAD=true` enables only a top-level local scan; archive children are never multiplied into automatic AV requests. ClamAV receives streamed bytes over the configured local service boundary, never a host path.

AV `clean`, `detected`, `error`, `timeout`, `unavailable`, `unsupported`, and `skipped` states are evidence. Clean does not mean safe, and detection does not prove maliciousness. ClamAV signature updates are owned by the optional service; OSINT Tools never downloads or updates signatures.

Run the non-interactive qualification harness with `scripts/qualify.sh`. It reports each Docker, Podman, regression, persistence, and per-provider live gate as `PASS`, `FAIL`, or `SKIPPED`; live calls run only when the corresponding credential is present.

The same OCI image is intended for Docker and Podman, amd64 and arm64, and runs as a non-root user. Persistent application data lives under `/data`.

Open `http://localhost:8080/` for the browser workspace. UI mutations are same-origin checked when a browser supplies an Origin header; authentication remains future work for local/private deployments.

See `docs/M0_SPEC.md`, `docs/M1_SPEC.md`, `docs/M2_SPEC.md`, `docs/M3_1_SPEC.md`, `docs/M3_2_SPEC.md`, `docs/M4_1_SPEC.md`, `docs/M4_2_SPEC.md`, `docs/M4_3_SPEC.md`, `docs/M4_4_SPEC.md`, `docs/M4_5_SPEC.md`, `docs/M5_1_SPEC.md`, `docs/M5_2_SPEC.md`, `docs/ARCHITECTURE.md` and `ROADMAP.md`.
