# M5.2 Interactive Analysis Workspace

M5.2 adds read-only, provenance-aware graph and timeline surfaces to the
M5.1 server-rendered workbench. Graph data comes only from persisted targets
and relationships; timeline entries come only from persisted case, target,
artifact, and note timestamps. No view performs enrichment, pivots,
promotion, reanalysis, or scanning.

`GET /api/v1/cases/{id}/graph` returns bounded target nodes and relationship
edges (including relation and causative artifact IDs). Nodes are capped at
250 and edges at 500 with available counts and a truncation flag. Results are
deterministically ordered. `GET /api/v1/cases/{id}/timeline` returns up to
500 newest-first factual events with deterministic tie-breaking.

The browser graph uses local SVG and bounded vanilla JavaScript. It also
renders an accessible textual relationship list, keyboard-focusable nodes,
and application-generated internal links. Timeline HTML is complete without
JavaScript. Hostile labels and metadata are escaped; stored values never
become navigation destinations. Existing restrictive CSP and same-origin
mutation policy remain in force.

Empty graphs and timelines are normal analyst states, not errors. Advanced
force layouts, graph databases, entity resolution, risk scoring, automatic
relationships, and collaboration remain deferred.
