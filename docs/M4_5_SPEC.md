# M4.5 — Local Antivirus Engine Framework + ClamAV

M4.5 adds antivirus as another local evidence source. `clean` means ClamAV returned a complete `stream: OK`; it does not mean safe. `detected` is an engine signature observation, not a malware verdict. `error`, `timeout`, `unavailable`, `unsupported`, and `skipped` are never converted to clean.

## Registry and evidence

`src/osint_tools/av` contains an explicit `AVRegistry`, `AVEngine` protocol, normalized `AVResult`, service orchestration, and the ClamAV adapter. There is no dynamic import, plugin path, or user-controlled engine. Evidence is persisted separately from M4.4 YARA/known-hash/similarity evidence using `antivirus_scan` artifacts plus `av_scan_results` and bounded `av_detections` rows. Each result preserves engine, engine version, database version/timestamp when available, state, bounded signatures, scan time/duration, bytes scanned, error category/message, CAS SHA-256, and provenance.

Schema 7 is an additive migration from M4.4 schema 6. Repeated identical scans for the same logical file, engine, engine version, database version, state, and detections reuse the existing result. A changed engine/database provenance creates historical evidence instead of rewriting the old result. File deletion cascades consistently with the existing model.

## ClamAV deployment and protocol

ClamAV is optional and not installed in the application image. The default application starts without it. Compose provides a separate `clamav/clamav:1.4.3` service under the `av` profile and persists `/var/lib/clamav` in `clamav-db`; normal Compose operation does not start or require that service. The image is the upstream ClamAV Docker Hub image, distributed under ClamAV's GPLv2 licensing; it is maintained by the ClamAV project and publishes architecture-specific images according to upstream availability. Signature databases may initialize/update through the ClamAV service's own policy and network; OSINT Tools never initiates updates and never stores those databases in SQLite or CAS. Container user/root behavior is image-defined and isolated from the application, which remains UID 10001.

The adapter uses only administrator-configured TCP host/port and the bounded `PING`, `VERSION`, and `zINSTREAM` commands. File bytes are streamed in 64 KiB chunks from the server-generated CAS path; no path is sent to clamd and no whole-file buffer is created. Responses are capped and parsed as `stream: OK`, `stream: <signature> FOUND`, or safe error/size-limit outcomes. Connect, read, and write operations have timeouts. A size-limit or incomplete stream is `unsupported`/`error`, never clean.

Configuration is environment-only: `OSINT_TOOLS_CLAMAV_ENABLED=false`, `OSINT_TOOLS_CLAMAV_HOST=clamav`, `OSINT_TOOLS_CLAMAV_PORT=3310`, `OSINT_TOOLS_CLAMAV_TIMEOUT_SECONDS=15`, `OSINT_TOOLS_CLAMAV_MAX_RESPONSE_BYTES=4096`, `OSINT_TOOLS_AV_SCAN_ON_UPLOAD=false`, and `OSINT_TOOLS_AV_MAX_ENGINES=4`. API requests may select registered engine IDs but cannot provide host, port, socket, URL, path, or command. The configured endpoint is an intentional administrator-local network boundary, distinct from forbidden file-derived callbacks and external providers.

## APIs and policy

- `GET /api/v1/av/engines` and `GET /api/v1/av/engines/{engine}` expose safe enabled/configured/available/version status.
- `POST /api/v1/files/{file_id}/av/scan` scans all registered engines or a bounded `{"engines":[...]}` selection.
- `GET /api/v1/files/{file_id}/av` returns bounded persisted history; absent results are distinguishable from clean.

Automatic scanning is off by default. When enabled, upload scans only the top-level object after M4.1–M4.4 analysis. Archive children are not automatically scanned, preventing request amplification; ClamAV itself may inspect archives according to its daemon policy. Explicit scan never triggers providers, candidate promotion, DNS, HTTP, or other callbacks.

## Failure and offline semantics

Disabled/unconfigured engines yield `skipped`; daemon connection refusal yields `unavailable`; socket deadlines yield `timeout`; malformed protocol yields `error`; daemon stream-size refusal yields `unsupported`. Failures are isolated per engine and persisted without corrupting baseline/local evidence. Scanning is offline-capable once the daemon has a signature database. Database updates are a separate ClamAV-service concern and may require Internet access.

The qualification harness retains all previous gates, adds fake-protocol unit tests, optional real ClamAV Compose-profile readiness/clean/EICAR/persistence gates, an application-only no-ClamAV runtime gate, and a network-none local AV boundary check. Mocked protocol tests are never reported as real ClamAV runtime qualification.

No uploaded file body is sent to an external provider, and OSINT Tools never executes uploaded content. ClamAV performs bounded signature inspection; it is not a sandbox or dynamic execution environment. Remaining risks include daemon/image supply-chain trust, ClamAV's own parser attack surface, synchronous request handling, daemon `StreamMaxLength` configuration mismatch, and unqualified local Docker/Podman environments.
