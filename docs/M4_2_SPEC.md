# M4.2 Safe Structured Content Analysis

## Archive and child model

M4.2 inventories ZIP, TAR, and gzip using Python's standard library. It never calls `extract`, materializes archive paths, recreates links/devices/FIFOs, or accepts passwords. Member names are bounded untrusted metadata and traversal-shaped Unix, Windows, absolute, control-character, and overlong forms are flagged. Encrypted and special members are inventoried and skipped.

Eligible regular members stream directly through the M4.1 hashing and content-addressed publication layer. Each receives a normal logical file row, SHA-256 target, and baseline artifact. The parent target gets a `contains` relationship whose `artifact_id` identifies the archive analysis that discovered it. Member inventory records index, safe display name, suspicious-path flag, declared sizes, actual processed bytes, method, CRC where available, flags, child SHA-256/file ID, depth, status, and structured reason.

Schema version 4 adds `file_structured_artifacts(file_id, artifact_id)` so structured results remain associated with the exact logical upload even when multiple uploads share a hash target. Migration from schema 3 is additive and data-preserving. Re-uploading content creates intentional per-upload analysis provenance but deduplicates physical parent and child objects; graph edges retain the existing uniqueness contract.

## Shared limits

One `AnalysisBudget` is shared by every descendant so recursion cannot multiply limits:

| Environment variable | Default |
|---|---:|
| `OSINT_TOOLS_ARCHIVE_MAX_DEPTH` | 3 |
| `OSINT_TOOLS_ARCHIVE_MAX_MEMBERS` | 1000 |
| `OSINT_TOOLS_ARCHIVE_MAX_MEMBER_BYTES` | 25 MiB |
| `OSINT_TOOLS_ARCHIVE_MAX_TOTAL_BYTES` | 100 MiB |
| `OSINT_TOOLS_ARCHIVE_MAX_RATIO` | 100 |
| `OSINT_TOOLS_IMAGE_MAX_PIXELS` | 40,000,000 |

Limits are enforced while reading actual expanded bytes. Declared sizes are inventory/hints only. A member stream reads at most the tightest remaining member, total, or ratio allowance plus one detection byte; failure removes its temporary file. Reasons include `max_depth`, `max_members`, `max_member_bytes`, `max_total_bytes`, `max_compression_ratio`, `encrypted_member`, `special_member`, and `malformed_archive`. Repeated hashes stop recursive analysis.

## Image and EXIF metadata

Pillow 11–12 is the sole new dependency. The standard library cannot consistently parse JPEG/GIF dimensions, frame metadata, and EXIF. Pillow is maintained, requires no external daemon/executable, builds in the existing image, and is imported as UID 10001 during qualification. Analysis opens headers without calling `Image.load()`, applies a 40-million-pixel application limit without disabling Pillow's own bomb protection, caps frame reporting, and extracts only make, model, orientation, software, timestamps, and a bounded GPS dictionary. It does not decode thumbnails, OCR, recognize faces, or reverse-geocode.

## PDF and document metadata

PDF processing is a bounded two-MiB byte scan, not a renderer or full parser. It reports version, approximate `/Page` object count, selected literal-string metadata, encryption presence, and JavaScript/action-name indicators. It never interprets actions, follows URLs, renders pages, or extracts attachments. Complex encodings and incremental metadata may be missed.

DOCX, XLSX, PPTX, ODT, ODS, and ODP are recognized from required ZIP members/mimetype. Core/app/meta XML members are individually capped at two MiB and parsed with standard-library `ElementTree`, which does not resolve external system entities or perform network access. Selected fields are bounded. VBA-project and embedded-object presence are booleans only; content is never interpreted.

## Failure, persistence, and security

Structured parser failures cannot invalidate successful M4.1 ingestion. Expected malformed inputs create bounded structured results; unexpected failures create a redacted `structured_analysis_error`. Structured artifacts and child relationships persist in SQLite and survive restart.

No uploaded bytes are sent to providers. Explicit VirusTotal enrichment still sends only a hash. No content is executed, imported, mounted, rendered, shell-expanded, deserialized with pickle, or used to initiate network callbacks. Unsupported RAR/7z and password cracking remain out of scope.

## Qualification

`scripts/qualify.sh` preserves M2–M4.1 gates and generates small deterministic ZIP traversal, nested ZIP, ratio/member/expanded-limit, TAR symlink, gzip, PNG, JPEG/EXIF, malformed ZIP, PDF, and DOCX fixtures locally. Docker validates structured APIs and restart persistence; Podman verifies Pillow import as UID 10001 and writable `/data`. Independent buildx amd64/arm64 attempts never push. Mocked tests are not reported as live-provider qualification.
