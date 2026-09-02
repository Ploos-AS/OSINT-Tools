"""Small server-rendered UI helpers for the local analyst workspace."""
from __future__ import annotations

import html
import json
from typing import Any


def esc(value: Any) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def pretty(value: Any, limit: int = 12000) -> str:
    text = json.dumps(value, indent=2, sort_keys=True, default=str)
    return esc(text[:limit] + ("…" if len(text) > limit else ""))


def page(title: str, body: str, case: dict | None = None) -> bytes:
    case_link = f'<a href="/cases/{case["id"]}">Case: {esc(case["name"])}</a>' if case else ""
    document = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{esc(title)} · OSINT Tools</title><link rel="stylesheet" href="/static/app.css"></head>
<body><header class="topbar"><a class="brand" href="/cases">OSINT Tools <span>0.5.1</span></a>
<nav aria-label="Primary"><a href="/cases">Cases</a>{case_link}</nav></header>
<main class="shell"><h1>{esc(title)}</h1>{body}</main>
<script src="/static/app.js" defer></script></body></html>"""
    return document.encode("utf-8")


def cases(cases: list[dict]) -> str:
    rows = "".join(f'<li><a href="/cases/{c["id"]}"><strong>{esc(c["name"])}</strong></a> · {esc(c.get("status"))}<small>{esc(c.get("updated_at"))}</small></li>' for c in cases)
    return f'''<section class="card"><h2>Cases</h2>{"<ul class=\"items\">"+rows+"</ul>" if rows else "<p class=\"empty\">No cases yet.</p>"}</section>
<section class="card"><h2>Create case</h2><form method="post" action="/ui/cases"><label>Name <input name="name" required maxlength="200"></label><label>Description <textarea name="description" maxlength="4000"></textarea></label><button type="submit">Create case</button></form></section>'''


def workspace(case: dict, files: list[dict]) -> str:
    targets = "".join(f'<li><a href="/cases/{case["id"]}/targets/{t["id"]}">{esc(t["type"])}: {esc(t["normalized"])}</a></li>' for t in case["targets"])
    artifacts = "".join(f'<li><strong>{esc(a["type"])}</strong> · {esc(a["source"])} · {esc(a.get("created_at"))}</li>' for a in case["artifacts"])
    relationships = "".join(f'<li>{esc(r["source_target_id"])} — {esc(r["relation"])} → {esc(r["destination_target_id"])}</li>' for r in case["relationships"])
    file_rows = "".join(f'<li><a href="/files/{f["id"]}">{esc(f["original_filename"])}</a> · {esc(f["detected_type"])} · {esc(f["size"])} bytes · <code>{esc(f["sha256"])}</code></li>' for f in files)
    notes = "".join(f'<li>{esc(n["body"])}</li>' for n in case["notes"])
    return f'''<p class="muted">{esc(case.get("description"))}</p><p>Status: <strong>{esc(case.get("status"))}</strong></p>
<div class="grid"><section class="card"><h2>Targets</h2>{"<ul class=items>"+targets+"</ul>" if targets else "<p class=empty>No targets.</p>"}<form method="post" action="/ui/cases/{case["id"]}/targets"><label>Add target <input name="value" required maxlength="2048"></label><button type="submit">Add target</button></form></section>
<section class="card"><h2>Files</h2>{"<ul class=items>"+file_rows+"</ul>" if file_rows else "<p class=empty>No files.</p>"}<form class="file-upload" method="post" action="/ui/cases/{case["id"]}/files" enctype="multipart/form-data"><label>Upload file <input type="file" name="file" required></label><button type="submit">Upload</button></form></section>
<section class="card"><h2>Relationships</h2>{"<ul class=items>"+relationships+"</ul>" if relationships else "<p class=empty>No relationships.</p>"}</section>
<section class="card"><h2>Artifacts</h2>{"<ul class=items>"+artifacts+"</ul>" if artifacts else "<p class=empty>No artifacts.</p>"}</section>
<section class="card"><h2>Notes</h2>{"<ul class=items>"+notes+"</ul>" if notes else "<p class=empty>No notes.</p>"}</section></div>'''


def target(case: dict, target: dict, artifacts: list[dict], providers: list[dict] | None = None) -> str:
    items = "".join(f'<li><strong>{esc(a["type"])}</strong> · {esc(a["source"])}<details><summary>Evidence</summary><pre>{pretty(a.get("data"))}</pre></details></li>' for a in artifacts)
    actions = f'''<form method="post" action="/ui/targets/{target["id"]}/dns"><button type="submit">Run DNS pivot</button></form>
<form method="post" action="/ui/targets/{target["id"]}/enrich"><button type="submit">Run provider enrichment</button></form>'''
    provider_rows = "".join(f'<li>{esc(p.get("name"))}: {esc(p.get("status"))}</li>' for p in (providers or []))
    return f'<p><strong>Type:</strong> {esc(target["type"])}</p><p><strong>Normalized:</strong> <code>{esc(target["normalized"])}</code></p><div class="actions">{actions}</div><section class="card"><h2>Provider status</h2>{"<ul class=items>"+provider_rows+"</ul>" if provider_rows else "<p class=empty>No providers.</p>"}</section><section class="card"><h2>Evidence</h2>{"<ul class=items>"+items+"</ul>" if items else "<p class=empty>No evidence.</p>"}</section>'


def file_detail(file: dict, analysis: dict | None, detections: list[dict], av: list[dict], candidates: list[dict]) -> str:
    identity = "".join(f'<dt>{esc(k)}</dt><dd>{esc(file.get(k))}</dd>' for k in ("original_filename", "size", "detected_type", "extension", "md5", "sha1", "sha256"))
    structured = "".join(f'<li><strong>{esc(a["type"])}</strong><details><summary>Details</summary><pre>{pretty(a.get("data"))}</pre></details></li>' for a in (analysis or {}).get("structured", []))
    det = "".join(f'<li><strong>{esc(d.get("method"))}</strong> · {esc(d.get("rule_id") or d.get("label") or d.get("state") or "evidence")}<details><summary>Provenance</summary><pre>{pretty(d)}</pre></details></li>' for d in detections)
    av_rows = "".join(f'<li><strong>Antivirus: {esc(a.get("state"))}</strong> · {esc(a.get("engine"))}<details><summary>Scan evidence</summary><pre>{pretty(a)}</pre></details></li>' for a in av)
    cand = "".join(f'<li>{esc(c.get("type"))}: <code>{esc(c.get("normalized_value") or c.get("raw_value"))}</code><form class="inline" method="post" action="/ui/files/{file["id"]}/candidates/{c["id"]}/promote"><button type="submit">Promote</button></form></li>' for c in candidates)
    scan = f'<form method="post" action="/ui/files/{file["id"]}/av/scan"><button type="submit">Scan with local AV</button></form><form method="post" action="/ui/files/{file["id"]}/detections/reanalyze"><button type="submit">Reanalyze local detections</button></form>'
    return f'''<p><a href="/cases/{file["case_id"]}">← Back to case</a></p><section class="card"><h2>Identity</h2><dl>{identity}</dl></section>
<section class="card"><h2>Baseline analysis</h2><pre>{pretty((analysis or {}).get("data", {}))}</pre></section>
<section class="card"><h2>Structured analysis</h2>{"<ul class=items>"+structured+"</ul>" if structured else "<p class=empty>None.</p>"}</section>
<section class="card"><h2>Candidate indicators</h2>{"<ul class=items>"+cand+"</ul>" if cand else "<p class=empty>None.</p>"}</section>
<section class="card"><h2>Local detections</h2>{"<ul class=items>"+det+"</ul>" if det else "<p class=empty>None.</p>"}</section>
<section class="card"><h2>Antivirus evidence</h2>{scan}{"<ul class=items>"+av_rows+"</ul>" if av_rows else "<p class=empty>Not scanned.</p>"}</section>'''
