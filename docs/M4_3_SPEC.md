# M4.3 — Executable & Binary Static Analysis

M4.3 adds bounded static metadata analysis for PE, ELF, thin and fat Mach-O, and classic Amiga Hunk objects. Uploaded bytes remain in the M4 content-addressed store and are never loaded, executed, mounted, or passed to an external binary-analysis executable. Binary children found by M4.2 archive analysis reuse the same file pipeline and shared archive budget.

## Parsers and normalized metadata

The implementation uses small internal `struct`-based parsers. This adds no dependency or native executable and keeps validation and bounds visible in the repository. PE reports bitness, machine, entry point, image base, subsystem, timestamp, sections and entropy, PDB strings, Authenticode presence, and overlay size. ELF reports class, byte order, machine, object type, entry point, counts, bounded sections, interpreter and a stripped heuristic. Mach-O reports thin/fat variants, CPU, byte order, file type, bounded load commands, segments, dylibs, rpaths, UUID, entry point, and code-signature presence. Amiga Hunk reports header ranges, CODE/DATA/BSS, relocation counts, symbols, NAME/DEBUG and END records. Unsupported or malformed structures return stable reasons rather than parser exception text.

Imports, exports, and deep resource/version decoding are deliberately limited in this foundation. Parser outputs never constitute a malware verdict. PE timestamps are spoofable metadata, and `high_entropy` is only the documented `entropy >= 7.2` heuristic.

## Limits

Defaults are configured by environment variable names only:

- `OSINT_TOOLS_BINARY_MAX_SCAN_BYTES=16777216`
- `OSINT_TOOLS_BINARY_MAX_STRINGS=2000`
- `OSINT_TOOLS_BINARY_MIN_STRING_LENGTH=4`
- `OSINT_TOOLS_BINARY_MAX_STRING_LENGTH=1024`
- `OSINT_TOOLS_BINARY_MAX_SECTIONS=256`
- `OSINT_TOOLS_BINARY_MAX_SYMBOLS=2000`
- `OSINT_TOOLS_BINARY_MAX_IMPORTS=1000`
- `OSINT_TOOLS_BINARY_MAX_EXPORTS=1000`
- `OSINT_TOOLS_BINARY_MAX_CANDIDATES=500`

ASCII and UTF-16LE strings retain encoding and byte offset. Long strings and total results are truncated explicitly. Shannon entropy is deterministic and rounded to six decimal places. Parser counts and byte ranges are checked before loops and slices.

## Candidates and promotion

URLs, domains, IPv4, IPv6, and conservative email-shaped strings are normalized and stored in schema 5 `file_candidates`. Each observation retains logical file, binary artifact, raw and normalized value, offset, encoding, and timestamp. Observations at different offsets retain separate provenance; exact observations are deduplicated. Results are bounded through `GET /api/v1/files/{file_id}/candidates?type=...&limit=...&offset=...` (server maximum 200).

`POST /api/v1/files/{file_id}/candidates/{candidate_id}/promote` explicitly creates or reuses a normal case target and an idempotent `contains_indicator` relationship whose artifact reference identifies the binary analysis. URL, domain, and IP candidates are promotable. Email remains retrievable but is not promotable because M4.3 does not introduce an email target model. Promotion performs no enrichment, DNS, HTTP, or other network request.

## Persistence and failure semantics

Schema 5 is an additive migration from schema 4. Binary artifact replacement and candidate replacement occur in one SQLite transaction, preventing partial candidate state and bounding repeated analysis. Baseline file analysis survives malformed binary parsing. Content deduplication remains physical while candidates belong to each logical file association.

## Security boundary and residual risks

Analysis reads only server-generated managed object paths. It has no socket, URL client, subprocess, shell, dynamic loader, executable mapping, or unsafe deserialization path. Derived URLs/domains are inert metadata. Uploaded bodies are never sent to VirusTotal or another provider.

Internal parsers intentionally cover useful common structures rather than every producer extension. They may omit metadata from unusual but valid binaries, and bounded scanning can miss data beyond configured limits. Recognition includes structural validation beyond magic bytes but is not a formal verifier. Fat Mach-O inventories at most 32 slices. Analysis is synchronous and CPU time is indirectly constrained by byte/count limits rather than a separate worker timeout.

## Qualification

`scripts/qualify.sh` retains M2–M4.2 gates and adds deterministic unit and Docker-runtime binary fixtures, candidate API/promotion/persistence checks, archive-child analysis, parser import checks as UID 10001, and an offline `--network none` analyzer invocation. Live provider gates remain conditional on credentials and are never substitutes for local binary qualification. Multiarchitecture builds are attempted without pushing and are reported `SKIPPED` when the active builder lacks a platform.
