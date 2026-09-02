# M5.3 Case export, import and reporting

M5.3 adds a versioned `osint-tools-case` JSON representation, ZIP-based
`.osintcase` bundles, safe import, and a print-friendly HTML report. Export
uses deterministic UTF-8 JSON with sorted keys and stable array ordering;
the manifest records SHA-256 hashes and lengths for every entry. File bodies
are stored as `files/<sha256>` and are verified against CAS identity. The
`metadata-only` option omits bodies; importing it requires the referenced CAS
object to already exist locally.

Imports validate ZIP paths, member counts and sizes, manifest hashes and the
canonical payload before creating a new case. Local IDs are remapped and
imports never run providers, pivots, detections, AV scans, or network calls.
Imported file paths are derived only from verified SHA-256 values.

Redaction profiles are `none`, `analyst-safe` (description, notes and logical
filenames replaced with explicit placeholders), and `metadata-only` for
body omission. Credentials, environment data and absolute paths are never
exported. Reports regenerate escaped HTML from structured evidence and keep
provider, rule, hash, similarity and antivirus evidence as separate classes;
they do not produce a universal risk verdict. The report includes print CSS
and no remote assets. Digital signatures, PDF generation, sharing and
authentication remain deferred.
