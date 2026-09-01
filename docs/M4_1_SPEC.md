# M4.1 Local Artifact Analysis Foundation

## Ingestion and storage

`POST /api/v1/cases/{case_id}/files` accepts a binary request body with a required `Content-Length`. `X-Filename` is optional display metadata and never controls a filesystem path. The default maximum is 26,214,400 bytes (25 MiB), configured by `OSINT_TOOLS_MAX_UPLOAD_BYTES`. Negative, malformed, missing, oversized, and incomplete lengths produce structured errors.

The body streams in 64 KiB chunks to a server-created temporary file under `/data/files/.tmp`. MD5, SHA-1, and SHA-256 are calculated during that single pass. These hashes are identifiers and reputation pivots, not cryptographic recommendations. The canonical SHA-256 storage layout is `/data/files/sha256/{first-two-hex}/{sha256}`. Only the relative `storage_id` is exposed.

Publication uses a same-filesystem hard link, providing atomic create-without-overwrite behavior. Existing content is reused after validating that the destination is a regular, non-symlink file of the expected size. Temporary files are always removed. Duplicate uploads create distinct logical file rows and artifacts but share one physical object. Garbage collection is intentionally out of scope.

## Type identification

The dependency-free detector examines at most the first 8192 bytes. It recognizes PNG, PDF, GIF, JPEG, ZIP, gzip, ELF, PE/MZ, UTF-8 text, empty files, and otherwise reports generic binary. It records a deterministic MIME label and a conservative extension mismatch when both signature and extension knowledge are sufficient. Extensions are metadata only. No decoder, viewer, executable, interpreter, archive extractor, macro engine, or external program is invoked.

## Database model

Schema version 3 additively creates `file_objects` for canonical content metadata and `files` for per-case logical associations. Each logical file references an existing SHA-256 `hash` target and a `file_analysis` artifact with source `local`. Existing schema-2 databases are preserved. Metadata APIs are `GET /api/v1/files/{file_id}` and `GET /api/v1/files/{file_id}/analysis`; raw-byte download is not implemented.

## Security boundaries

Original filenames are bounded to 512 characters and control characters are replaced for safe display. Slashes, traversal text, Unicode, leading dots, and absolute-looking values may remain metadata but are never joined to storage paths. Stored paths are derived solely from a server-calculated lowercase SHA-256 validated by the content store.

Uploaded content is never executed, imported, mounted, rendered, deserialized, extracted, or used for network callbacks. Client MIME declarations are ignored. No arbitrary server-side path or URL parameter exists. M2/M3 SSRF and provider boundaries remain unchanged.

The SHA-256 target is compatible with VirusTotal's existing hash lookup. Ingestion does not call VirusTotal or any other provider. Explicit target enrichment sends only the hash identifier, never file bytes.

## Atomicity and residual risks

Truncated and rejected uploads leave no temporary or published object. A database failure after a newly published object triggers best-effort removal. A process crash in the narrow interval between object publication and the SQLite transaction can leave a complete unreferenced object; it cannot expose a partial upload as a valid database record. Concurrent publication is deduplicated, but garbage collection and reconciliation of crash-orphans are future work.

Signature detection is deliberately shallow and is not a malware verdict. It does not inspect polyglots or validate entire format structures. The application does not claim that uploaded content is benign.

## Qualification

`scripts/qualify.sh` generates zero-byte, text, PNG-signature, duplicate, hostile-name, and oversized fixtures locally. Native Docker qualification validates hashing, type detection, logical/physical deduplication, rejection, APIs, and restart persistence. Podman validates upload and writable `/data` as UID 10001. Docker buildx attempts linux/amd64 and linux/arm64 independently without pushing; unsupported builder platforms are `SKIPPED`. The known Podman OCI `HEALTHCHECK` warning remains harmless because runtime health is probed directly.
