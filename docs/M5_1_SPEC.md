# M5.1 Web UI Foundation & Case Workspace

M5.1 adds a small server-rendered HTML workspace to the existing Python
application. It deliberately uses semantic HTML, local CSS/JavaScript, and
the existing storage/services rather than introducing a frontend build or a
parallel persistence model.

## Routes and workflow

`/` redirects to `/cases`. Cases, case workspaces, target details, and file
details are available at `/cases`, `/cases/{id}`,
`/cases/{case}/targets/{target}`, and `/files/{file}`. Forms call the same
case, target, ingestion, pivot, enrichment, candidate-promotion, and AV
services used by the API. No GET route mutates state.

The case workspace presents targets, relationships, artifacts, notes, and
logical files. File pages present baseline, structured, binary, candidate,
M4.4 detection, and M4.5 antivirus evidence. Evidence remains attributed:
ClamAV clean means only that a completed scan had no detection, not that a
file is safe. Missing AV history is shown as **Not scanned**.

## Security model

All rendered values are HTML-escaped, including filenames, parser metadata,
provider strings, and detection names. UI responses send a restrictive
same-origin CSP, `nosniff`, no-referrer, and no-store headers. Static assets
are a fixed package directory with explicit names; `/data`, CAS objects,
SQLite, and source files are never served.

Browser POST mutations validate an Origin header against Host when supplied;
requests without Origin remain compatible with existing local API-style
clients. This is lightweight browser mutation protection, not authentication.
Deployment is assumed local/private until a future authentication milestone.

The core pages and evidence remain usable without JavaScript. JavaScript is
only progressive enhancement for binary upload: it streams the selected file
to the existing bounded upload endpoint and never chooses a destination path.
No provider, DNS, AV, or candidate action runs merely by viewing a page.

## Deployment and limitations

The UI is served by the same OCI image and uses no CDN, remote fonts,
analytics, telemetry, or frontend build tool. It retains the existing
Docker/Podman, non-root, `/data`, provider, SSRF, archive, binary, detection,
and ClamAV boundaries. Advanced graph visualizations, authentication,
multi-user workflows, dashboards, and background jobs remain deferred.
