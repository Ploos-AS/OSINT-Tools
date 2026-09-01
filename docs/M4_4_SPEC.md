# M4.4 — Signatures, Rules & Similarity

M4.4 adds local static evidence. A rule match, known-hash match, structural heuristic, similarity distance, provider reputation result, and future antivirus result remain distinct concepts. No M4.4 result is represented as `malicious: true`.

## YARA-compatible engine and rule packs

OSINT Tools uses the dependency-free `osint-tools-yara-subset` engine version 1. It accepts a deliberately restricted, YARA-compatible rule syntax: named rules, tags, bounded scalar metadata, literal strings with `ascii`, `wide`, or `nocase` modifiers, and `any of them`/`all of them` conditions. Regex, hex patterns, modules, includes, callbacks, external variables, `fullword`, and arbitrary condition expressions are rejected.

This choice followed evaluation of `yara-python` (libyara/C native extension) and YARA-X (Rust native extension). Neither was locally installed. Avoiding them removes new native-code, Alpine packaging, architecture, and parser-license implications. The tradeoff is subset compatibility rather than full YARA. The internal engine is covered by the project MIT license and performs no networking or execution.

Rule packs are managed in SQLite under `/data`, never loaded from client paths. They are immutable by `(name, version)` and preserve namespace, source, description, complete rule-text SHA-256, and creation time. Evidence snapshots the pack ID/name/version/digest and analyzer version, so later packs cannot rewrite historical provenance. A tiny OSINT Tools v1 built-in pack matches only the harmless `OSINT_TOOLS_DEMO_SIGNATURE` qualification marker.

Malformed packs are rejected atomically through `POST /api/v1/signatures/rulepacks`; startup and unrelated file analysis continue. Compilation errors use bounded public messages without host paths. Matching retains only rule ID, tags, bounded metadata, string identifiers, and offsets—never file fragments.

Defaults: timeout 5 seconds, 100 rule matches, 100 string-match observations, 256 KiB per rule, 1 MiB per pack, and 100 managed packs per analysis. Deadline checks occur between every bounded rule/string search. This is a real elapsed deadline for the internal deterministic matcher, but not a separate process-level kill timer.

## Known-hash sets

Hash sets are immutable `(name, version)` records with source, description, category, canonical content digest, import time, and entry count. Categories are `known_good`, `known_bad`, `reference`, `user_defined`, and `unknown`; applications must preserve this meaning rather than treating any match as malware.

The JSON import API accepts bounded `entries` containing `algorithm`, `digest`, optional `label`, `tags`, and bounded metadata. MD5, SHA-1, and SHA-256 are supported using hashes already computed during M4.1 ingestion. Duplicate digests within a set collapse transactionally. Invalid input leaves no partial set. Defaults are 4 MiB and 100,000 entries.

## Similarity

The dependency-free `simhash64-v1` algorithm computes a 64-bit SimHash from byte 4-grams using BLAKE2b features. It deterministically samples at most 65,536 evenly stepped features for large inputs; empty and short inputs are defined. Fingerprints belong to the content object, so identical CAS bytes are computed once and shared by logical files.

Comparison returns native Hamming distance from 0 through 64; lower means more similar and zero means identical fingerprints. It is not a percentage, malware judgment, or proof of shared origin. Exact duplicate content is separately flagged using SHA-256 identity. `GET /api/v1/files/{file_id}/similar` sorts deterministically by distance then logical file ID, excludes the queried logical file, and returns at most 100 results by default. The initial SQLite implementation scans at most 10,000 fingerprinted logical files and is intended for self-hosted baseline scale.

## Evidence, reanalysis, and APIs

Schema 6 adds `rule_packs`, `hash_sets`, `hash_entries`, `file_detections`, and content-level `file_fingerprints`. `file_detections` keeps typed analyzer, version, method (`yara` or `known_hash`), signature ID, namespace, title, tags, metadata, result, provenance, artifact, and timestamp. One `local_detections` artifact summarizes each run.

- `GET/POST /api/v1/signatures/rulepacks`
- `GET/POST /api/v1/signatures/hashsets`
- `GET /api/v1/signatures/hashsets/{id}`
- `GET /api/v1/files/{file_id}/detections`
- `POST /api/v1/files/{file_id}/detections/reanalyze`
- `GET /api/v1/files/{file_id}/similar?limit=20`

Reanalysis transactionally replaces only M4.4 evidence and its artifact. The content fingerprint is recomputed only if absent or its implementation version changed. No startup-wide rescan occurs. Rule/hash evidence does not create targets, promote candidates, or invoke provider enrichment.

Archive children use the existing M4.2 CAS/child pipeline and receive the same local detection and fingerprint analysis under the shared archive controls.

## Offline and security boundary

M4.4 contains no URL client, DNS, socket, subprocess, dynamic plugin, arbitrary import, rule download, hash reputation query, telemetry, or external upload path. APIs accept managed JSON content, never paths or URLs. Uploaded content is never executed. Provider artifacts remain separate.

Residual risks include synchronous analysis (bounded by input/count/deadline rather than worker isolation), the restricted YARA feature set, possible SimHash false similarity/dissimilarity, SQLite scan cost at larger collections, and the collision properties of MD5/SHA-1. Hashes are identity/reputation pivots, not security recommendations.

`scripts/qualify.sh` retains prior gates and adds deterministic rules, known hashes, similarity, reanalysis, archive-child, persistence, container-import and network-none runtime checks. Docker/Podman/live/multiarch results remain explicitly skipped when unavailable.
