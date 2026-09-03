# M5.5 TAXII 2.1 and MISP interoperability

M5.5 adds bounded, operator-configured remote intelligence sources. TAXII
is read-only transport for bounded collection/object preview and explicit
import; MISP supports conservative Event export/import and explicit remote
event preview/import. Native `.osintcase` remains lossless and STIX/MISP are
lossy interoperability views.

Source authorities and credentials come only from server environment
configuration (`OSINT_TAXII_*`, `OSINT_MISP_*`). Requests cannot override
hosts, ports or URLs. HTTP(S) URLs reject userinfo/fragments; redirects are
not followed by the bounded stdlib client. Responses, objects and imports
are size-bounded, validated, and produce new local cases. Imports remap IDs,
normalize targets, preserve remote provenance in the result, and perform no
providers, DNS, AV, enrichment, downloads, or other callbacks. MISP
attributes default to `to_ids: false`; no threat, malware, actor, campaign,
risk or confidence semantics are inferred. TAXII push, TAXII server,
continuous polling, MISP objects/galaxies, and live-feed synchronization are
deferred.
