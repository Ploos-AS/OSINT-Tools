# Roadmap

- **M0 Foundation — complete:** OCI-native container, Docker/Podman deployment, non-root runtime, `/data`, health API and tests.
- **M1 Core Passive OSINT — complete:** target detection, DNS, RDAP, IP classification, HTTP/TLS inspection and mail-domain analysis.
- **M2 Case & Pivot Engine — complete:** cases, targets, artifacts, relationships, notes, provenance and pivots.
- **M3.1 Provider Framework — complete:** explicit provider registry, safe server-side configuration, structured failures, provenance artifacts, one IPinfo adapter and automated qualification.
- **M3.2 Provider Expansion & Enrichment — complete:** curated VirusTotal, AbuseIPDB, and Shodan adapters; hash targets; multi-provider enrichment; provenance-linked graph pivots; normalized rate-limit failures.
- **M3 Providers:** future additions remain deliberately selective; usefulness without API keys remains a requirement.
- **M4.1 Local Artifact Analysis Foundation — complete:** bounded streaming upload, content-addressed storage, hashes, baseline signatures, file targets and persistent local analysis.
- **M4.2 Safe Structured Content Analysis — complete:** bounded ZIP/TAR/gzip recursion, child provenance, image/EXIF headers, PDF metadata and ZIP-office/ODF metadata.
- **M4.3 Executable & Binary Static Analysis — complete:** bounded internal PE/ELF/Mach-O/Amiga Hunk parsers, strings, entropy, persistent indicator candidates and explicit graph promotion.
- **M4.4 Signatures, Rules & Similarity — complete:** managed versioned YARA-compatible rules and known-hash sets, normalized local evidence, SimHash fingerprints, local comparison and explicit reanalysis.
- **M4.5 Local Antivirus Engine Framework + ClamAV — complete:** explicit local AV registry, optional ClamAV INSTREAM adapter, normalized states/evidence, engine/database provenance and bounded local scan policy.
- **M5.1 Web UI Foundation & Case Workspace — complete:** server-rendered case, target, file and evidence workspaces with local static assets and safe browser mutations.
- **M5.2 Interactive Analysis Workspace — complete:** bounded relationship graph, provenance-aware timeline, target-centric navigation, and accessible no-JavaScript fallbacks.
- **M5.3 Case Export, Import & Reporting — complete:** deterministic JSON, integrity-checked `.osintcase` bundles, safe ID-remapped import, redaction profiles, and printable evidence reports.
- **M5.4 Structured Intelligence Interoperability — complete:** bounded STIX 2.1 export/import with conservative mappings and provenance-preserving diagnostics.
- **M4 File/Image Intelligence:** later safe parsers may add archives, EXIF and perceptual hashes without executing content.
- **M5 Release & Polish:** richer web UI, exports, documentation, packaging, security review and release qualification.
