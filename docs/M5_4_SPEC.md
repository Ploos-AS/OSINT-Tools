# M5.4 STIX 2.1 interoperability

STIX export is a conservative interoperability view; the native M5.3
`.osintcase` format remains lossless. The dependency-free implementation
exports Bundle, Grouping, domain-name, ipv4-addr, ipv6-addr, url, file,
relationship and note objects. Stable SCO/SRO IDs use UUIDv5; Bundle IDs are
per-export. Native relationship artifact provenance is retained in the
controlled `x_osint_tools_artifact_id` property. Unsupported objects are
reported during import and never become inferred native entities.

STIX import validates bounded JSON and IDs, creates a new case, normalizes
targets through existing validation, remaps IDs, and performs no network,
provider, DNS, AV, or reanalysis operations. STIX file objects are metadata
only. Imported strings remain hostile data and are escaped by the existing
UI. STIX may be lossy; no malware, threat-actor, campaign, incident, risk,
or confidence semantics are invented.
