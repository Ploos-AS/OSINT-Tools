"""Portable, deterministic case export/import and printable reporting."""
from __future__ import annotations

import hashlib
import io
import json
import re
import zipfile
from datetime import datetime, timezone
from typing import Any
from . import __version__

FORMAT = "osint-tools-case"
FORMAT_VERSION = 1
MAX_BUNDLE_BYTES = 64 * 1024 * 1024
MAX_MEMBERS = 2048
MAX_ENTRY_BYTES = 32 * 1024 * 1024
MAX_TOTAL_BYTES = 128 * 1024 * 1024


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _safe_profile(profile: str | None) -> str:
    return profile if profile in {"none", "analyst-safe", "metadata-only"} else "none"


def canonical_case(store, case_id: int, profile: str = "none") -> dict[str, Any] | None:
    case = store.get_case(case_id)
    if case is None:
        return None
    profile = _safe_profile(profile)
    out: dict[str, Any] = {
        "format": FORMAT,
        "format_version": FORMAT_VERSION,
        "exported_at": None,
        "application": {"name": "OSINT Tools", "version": __version__},
        "redaction": {"profile": profile, "categories": []},
        "case": {k:v for k,v in case.items() if k != "owner_user_id"},
        "targets": sorted(case["targets"], key=lambda x: x["id"]),
        "artifacts": [], "relationships": sorted(case["relationships"], key=lambda x: x["id"]),
        "notes": [], "files": [], "structured_artifacts": [], "candidates": [], "detections": [], "av_results": [],
        "timeline": store.case_timeline(case_id) or [],
    }
    if profile == "analyst-safe":
        out["case"]["description"] = "[REDACTED: description]"
        out["redaction"]["categories"] += ["case.description", "notes", "original_filename"]
    for artifact in sorted(store.list_target_artifacts(-1) if False else case["artifacts"], key=lambda x: x["id"]):
        full = store.get_artifact(artifact["id"]) if hasattr(store, "get_artifact") else artifact
        out["artifacts"].append(full or artifact)
    out["notes"] = [dict(n) for n in sorted(case["notes"], key=lambda x: x["id"])]
    if profile == "analyst-safe":
        for note in out["notes"]: note["body"] = "[REDACTED: note]"
    for file in store.list_case_files(case_id):
        item = dict(file)
        if profile == "analyst-safe": item["original_filename"] = "[REDACTED: filename]"
        out["files"].append(item)
        analysis = store.get_file_analysis(file["id"])
        if analysis:
            out["structured_artifacts"].append({"file_id": file["id"], "analysis": analysis})
        out["candidates"].extend(store.list_file_candidates(file["id"], limit=200))
        out["detections"].extend(store.list_file_detections(file["id"]))
        out["av_results"].extend(store.list_av_results(file["id"]))
    if profile == "metadata-only":
        out["redaction"]["categories"].append("file_bodies")
    return out


def stable_payload(payload: dict[str, Any]) -> bytes:
    copy = json.loads(json.dumps(payload, ensure_ascii=False))
    copy["exported_at"] = None
    return _json_bytes(copy)


def payload_sha256(payload: dict[str, Any]) -> str:
    return hashlib.sha256(stable_payload(payload)).hexdigest()


def export_json(store, case_id: int, profile: str = "none") -> bytes | None:
    payload = canonical_case(store, case_id, profile)
    return _json_bytes(payload) if payload is not None else None


def export_bundle(store, objects, case_id: int, profile: str = "none", include_bodies: bool = True) -> bytes | None:
    payload = canonical_case(store, case_id, profile)
    if payload is None: return None
    payload["exported_at"] = datetime.now(timezone.utc).isoformat()
    case_bytes = _json_bytes(payload)
    entries: list[tuple[str, bytes]] = [("case.json", case_bytes)]
    if include_bodies and profile != "metadata-only":
        for file in payload["files"]:
            path = objects.physical_path(file["storage_id"])
            if not path.is_file(): raise ValueError("referenced file body is unavailable")
            data = path.read_bytes()
            if len(data) != int(file["size"]) or hashlib.sha256(data).hexdigest() != file["sha256"]:
                raise ValueError("referenced file body failed integrity validation")
            entries.append((f"files/{file['sha256']}", data))
    report = report_html(payload)
    entries.append(("report.html", report))
    manifest_entries = [{"path": p, "length": len(b), "sha256": hashlib.sha256(b).hexdigest()} for p, b in entries]
    manifest = {"format": FORMAT, "format_version": FORMAT_VERSION, "application": payload["application"], "exported_at": payload["exported_at"], "case_id": case_id, "canonical_payload_sha256": payload_sha256(payload), "file_count": len(payload["files"]), "included_file_body_count": sum(p.startswith("files/") for p, _ in entries), "redaction_profile": payload["redaction"]["profile"], "entries": manifest_entries}
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("manifest.json", _json_bytes(manifest))
        for path, data in entries: z.writestr(path, data)
    return out.getvalue()


def _safe_entry(name: str) -> bool:
    return bool(name and not name.startswith(("/", "\\")) and ".." not in name.replace("\\", "/").split("/")) and not re.match(r"^[A-Za-z]:", name)


def import_bundle(store, objects, raw: bytes, *, owner_user_id=None) -> dict[str, Any]:
    if len(raw) > MAX_BUNDLE_BYTES: raise ValueError("bundle exceeds maximum size")
    try: z = zipfile.ZipFile(io.BytesIO(raw))
    except zipfile.BadZipFile: raise ValueError("invalid case bundle") from None
    infos = z.infolist()
    if len(infos) > MAX_MEMBERS or len({i.filename for i in infos}) != len(infos): raise ValueError("invalid bundle entries")
    total = 0
    for i in infos:
        if not _safe_entry(i.filename) or i.is_dir() or i.file_size > MAX_ENTRY_BYTES: raise ValueError("unsafe bundle entry")
        total += i.file_size
        if total > MAX_TOTAL_BYTES: raise ValueError("bundle expanded size exceeds limit")
    names = {i.filename for i in infos}
    if "manifest.json" not in names or "case.json" not in names: raise ValueError("bundle manifest/case missing")
    try: manifest = json.loads(z.read("manifest.json")); payload = json.loads(z.read("case.json"))
    except (json.JSONDecodeError, KeyError): raise ValueError("invalid bundle JSON") from None
    if manifest.get("format") != FORMAT or manifest.get("format_version") != FORMAT_VERSION or payload.get("format") != FORMAT: raise ValueError("unsupported case format")
    declared = {e.get("path"): e for e in manifest.get("entries", [])}
    for path, entry in declared.items():
        if path not in names: raise ValueError("declared bundle entry missing")
        data = z.read(path)
        if len(data) != entry.get("length") or hashlib.sha256(data).hexdigest() != entry.get("sha256"): raise ValueError("bundle entry integrity check failed")
    if manifest.get("canonical_payload_sha256") != payload_sha256(payload): raise ValueError("canonical payload integrity check failed")
    # Restore a new case and remap all authoritative IDs in one transaction.
    original = payload.get("case") or {}
    with store.connect() as conn:
        from .case_access import validate_owner, audit
        if owner_user_id is not None: validate_owner(conn, owner_user_id)
        now = datetime.now(timezone.utc).isoformat()
        cur = conn.execute("INSERT INTO cases(name,description,status,created_at,updated_at,owner_user_id) VALUES(?,?,?,?,?,?)", (str(original.get("name", "Imported case"))[:200], str(original.get("description", ""))[:4000], str(original.get("status", "open")), original.get("created_at", now), now, owner_user_id))
        audit(conn,"case_created",owner_user_id,{"case_id":cur.lastrowid,"owner_user_id":owner_user_id})
        new_case = int(cur.lastrowid); target_map: dict[int, int] = {}; artifact_map: dict[int, int] = {}; file_map: dict[int, int] = {}
        for t in payload.get("targets", []):
            cur = conn.execute("INSERT OR IGNORE INTO targets(case_id,type,value,normalized,created_at) VALUES(?,?,?,?,?)", (new_case, t.get("type", "unknown"), t.get("value", ""), t.get("normalized", ""), t.get("created_at", now)))
            row = conn.execute("SELECT id FROM targets WHERE case_id=? AND type=? AND normalized=?", (new_case, t.get("type", "unknown"), t.get("normalized", ""))).fetchone(); target_map[int(t.get("id", 0))] = int(row[0])
        for a in payload.get("artifacts", []):
            tid = target_map.get(a.get("target_id")); cur = conn.execute("INSERT INTO artifacts(case_id,target_id,type,source,data_json,created_at) VALUES(?,?,?,?,?,?)", (new_case, tid, a.get("type", "imported"), a.get("source", "imported"), json.dumps(a.get("data", {}), separators=(",", ":"), sort_keys=True), a.get("created_at", now))); artifact_map[int(a.get("id", 0))] = int(cur.lastrowid)
        for r in payload.get("relationships", []):
            if r.get("source_target_id") in target_map and r.get("destination_target_id") in target_map:
                conn.execute("INSERT OR IGNORE INTO relationships(case_id,source_target_id,relation,destination_target_id,artifact_id,created_at) VALUES(?,?,?,?,?,?)", (new_case, target_map[r["source_target_id"]], r.get("relation", "related_to"), target_map[r["destination_target_id"]], artifact_map.get(r.get("artifact_id")), r.get("created_at", now)))
        for n in payload.get("notes", []): conn.execute("INSERT INTO notes(case_id,target_id,artifact_id,body,created_at,updated_at) VALUES(?,?,?,?,?,?)", (new_case, target_map.get(n.get("target_id")), artifact_map.get(n.get("artifact_id")), n.get("body", ""), n.get("created_at", now), n.get("updated_at", now)))
        for f in payload.get("files", []):
            sha = str(f.get("sha256", "")); entry_name = f"files/{sha}"
            if entry_name in names:
                body = z.read(entry_name)
                if hashlib.sha256(body).hexdigest() != sha or len(body) != int(f.get("size", -1)) or hashlib.md5(body).hexdigest() != f.get("md5") or hashlib.sha1(body).hexdigest() != f.get("sha1"): raise ValueError("file body integrity check failed")
            storage_id = f"sha256/{sha[:2]}/{sha}"
            row = conn.execute("SELECT sha256 FROM file_objects WHERE sha256=?", (sha,)).fetchone()
            if row is None:
                if entry_name not in names: raise ValueError("metadata-only bundle references unavailable file body")
                conn.execute("INSERT INTO file_objects(sha256,storage_id,size,md5,sha1,detected_type,mime_type,created_at) VALUES(?,?,?,?,?,?,?,?)", (sha, storage_id, f.get("size", 0), f.get("md5", ""), f.get("sha1", ""), f.get("detected_type", "unknown"), f.get("mime_type", "application/octet-stream"), f.get("ingested_at", now)))
                # Publish the verified body through the managed CAS before associating it.
                path = objects.physical_path(storage_id); path.parent.mkdir(parents=True, exist_ok=True)
                if not path.exists(): path.write_bytes(body)
            curf = conn.execute("INSERT INTO files(case_id,target_id,artifact_id,object_sha256,original_filename,extension,ingested_at) VALUES(?,?,?,?,?,?,?)", (new_case, target_map.get(f.get("target_id")), artifact_map.get(f.get("artifact_id")), sha, f.get("original_filename", "unnamed"), f.get("extension", ""), f.get("ingested_at", now)))
            file_map[int(f.get("id", 0))] = int(curf.lastrowid)
        for item in payload.get("structured_artifacts", []):
            nf = file_map.get(item.get("file_id")); analysis = item.get("analysis") or {}
            if nf and analysis.get("structured"):
                for a in analysis["structured"]:
                    cur = conn.execute("INSERT INTO artifacts(case_id,target_id,type,source,data_json,created_at) VALUES(?,?,?,?,?,?)", (new_case, target_map.get(next((x.get("target_id") for x in payload.get("files", []) if x.get("id") == item.get("file_id")), None)), a.get("type", "structured"), a.get("source", "local"), json.dumps(a.get("data", {}), separators=(",", ":"), sort_keys=True), a.get("created_at", now)))
                    conn.execute("INSERT INTO file_structured_artifacts(file_id,artifact_id) VALUES(?,?)", (nf, int(cur.lastrowid)))
        # Candidate/detection rows are restored as bounded evidence when their source file was imported.
        for c in payload.get("candidates", []):
            if c.get("file_id") in file_map:
                aid = artifact_map.get(c.get("artifact_id"))
                if aid: conn.execute("INSERT OR IGNORE INTO file_candidates(file_id,artifact_id,type,raw_value,normalized_value,offset,encoding,created_at) VALUES(?,?,?,?,?,?,?,?)", (file_map[c["file_id"]], aid, c.get("type", ""), c.get("raw_value", ""), c.get("normalized_value"), c.get("offset", 0), c.get("encoding", "ascii"), c.get("created_at", now)))
        for d in payload.get("detections", []):
            if d.get("file_id") in file_map and d.get("artifact_id") in artifact_map:
                conn.execute("INSERT OR IGNORE INTO file_detections(file_id,artifact_id,analyzer,analyzer_version,method,signature_id,namespace,title,tags_json,metadata_json,result,provenance_json,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)", (file_map[d["file_id"]], artifact_map[d["artifact_id"]], d.get("analyzer", "imported"), d.get("analyzer_version", ""), d.get("method", ""), d.get("signature_id", ""), d.get("namespace", ""), d.get("title", ""), json.dumps(d.get("tags", [])), json.dumps(d.get("metadata", {}), separators=(",", ":"), sort_keys=True), d.get("result", "match"), json.dumps(d.get("provenance", {}), separators=(",", ":"), sort_keys=True), d.get("created_at", now)))
        for av in payload.get("av_results", []):
            if av.get("file_id") in file_map and av.get("artifact_id") in artifact_map:
                conn.execute("INSERT INTO av_scan_results(file_id,artifact_id,object_sha256,engine,engine_version,database_version,database_timestamp,state,scanned_at,duration_ms,bytes_scanned,error_code,message,detections_json,provenance_json,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (file_map[av["file_id"]], artifact_map[av["artifact_id"]], av.get("object_sha256", ""), av.get("engine", "imported"), av.get("engine_version"), av.get("database_version"), av.get("database_timestamp"), av.get("state", "error"), av.get("scanned_at", now), av.get("duration_ms"), av.get("bytes_scanned"), av.get("error_code"), av.get("message"), json.dumps(av.get("detections", []), separators=(",", ":"), sort_keys=True), json.dumps(av.get("provenance", {}), separators=(",", ":"), sort_keys=True), av.get("created_at", now)))
    return {"case_id": new_case, "source_case_id": manifest.get("case_id"), "source_payload_sha256": manifest.get("canonical_payload_sha256"), "imported_at": datetime.now(timezone.utc).isoformat()}


def report_html(payload: dict[str, Any]) -> bytes:
    import html
    def e(v): return html.escape("" if v is None else str(v), quote=True)
    case = payload.get("case", {})
    targets = "".join(f"<li>{e(t.get('type'))}: {e(t.get('normalized'))}</li>" for t in payload.get("targets", []))
    rels = "".join(f"<tr><td>{e(r.get('source_target_id'))}</td><td>{e(r.get('relation'))}</td><td>{e(r.get('destination_target_id'))}</td><td>{e(r.get('artifact_id') or 'unavailable')}</td></tr>" for r in payload.get("relationships", []))
    files = "".join(f"<li>{e(f.get('original_filename'))} · {e(f.get('sha256'))} · {e(f.get('size'))} bytes</li>" for f in payload.get("files", []))
    notes = "".join(f"<li>{e(n.get('body'))}</li>" for n in payload.get("notes", []))
    return (f"<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width'><title>{e(case.get('name'))} report</title><style>body{{font:14px sans-serif;max-width:960px;margin:2rem auto;color:#111}}h1,h2{{break-after:avoid}}table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #777;padding:.4rem;text-align:left}}section{{break-inside:avoid;margin:1.5rem 0}}@media print{{a{{color:#000;text-decoration:none}}}}</style></head><body><h1>{e(case.get('name'))}</h1><p>{e(case.get('description'))}</p><p>Generated from persisted evidence · redaction: {e(payload.get('redaction',{}).get('profile'))}</p><section><h2>Targets</h2><ul>{targets or '<li>None</li>'}</ul></section><section><h2>Relationships</h2><table><thead><tr><th>Source</th><th>Relation</th><th>Destination</th><th>Artifact</th></tr></thead><tbody>{rels or '<tr><td colspan="4">None</td></tr>'}</tbody></table></section><section><h2>Files</h2><ul>{files or '<li>None</li>'}</ul></section><section><h2>Notes</h2><ul>{notes or '<li>None</li>'}</ul></section><section><h2>Evidence classes</h2><p>Parser metadata, extracted indicators, local detections, similarity, antivirus evidence, provider evidence and analyst notes remain separate classes. No universal risk verdict is produced.</p></section></body></html>").encode("utf-8")
