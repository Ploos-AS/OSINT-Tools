# M2 — Cases & Pivot Graph

M2 turns OSINT Tools from a stateless passive lookup API into a persistent OSINT workbench.

## Storage

SQLite lives at `/data/osint-tools.db`. The database enables foreign keys and WAL mode and records an explicit schema version. No external database is required for M2.

Entities:

- cases
- targets
- artifacts
- relationships
- notes

Targets are deduplicated within a case by `(type, normalized)`.

## Case API

- `POST /api/v1/cases`
- `GET /api/v1/cases`
- `GET /api/v1/cases/{id}`
- `PATCH /api/v1/cases/{id}`
- `DELETE /api/v1/cases/{id}`
- `POST /api/v1/cases/{id}/targets`
- `POST /api/v1/cases/{id}/notes`
- `GET /api/v1/targets/{id}/artifacts`

## DNS pivot

`POST /api/v1/targets/{id}/pivot/dns` stores the DNS result as an artifact and derives new targets and graph relationships from A, AAAA, NS and CNAME records.

The initial relationship vocabulary is:

- `resolves_to`
- `nameserver`
- `cname`

## HTTP SSRF hardening

M2 replaces urllib's automatic redirect handling for HTTP inspection. Redirects are followed manually, with a maximum of five redirects. Every redirect target hostname is resolved and rejected if any resolved address is non-global. This closes the known M1 redirect gap; deployment-level egress policy remains recommended for exposed multi-user installations.

## Non-goals

M2 does not add active scanning, arbitrary port scanning, API-key providers, PostgreSQL, authentication, or a graph UI. Those remain later milestones.
