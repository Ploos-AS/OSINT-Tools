from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

SCHEMA_VERSION = 9


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


class Store:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _init_db(self) -> None:
        with self.connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS schema_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS cases (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    description TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL DEFAULT 'open',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS targets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
                    type TEXT NOT NULL,
                    value TEXT NOT NULL,
                    normalized TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(case_id, type, normalized)
                );

                CREATE TABLE IF NOT EXISTS artifacts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
                    target_id INTEGER REFERENCES targets(id) ON DELETE SET NULL,
                    type TEXT NOT NULL,
                    source TEXT NOT NULL,
                    data_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS relationships (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
                    source_target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
                    relation TEXT NOT NULL,
                    destination_target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
                    artifact_id INTEGER REFERENCES artifacts(id) ON DELETE SET NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(case_id, source_target_id, relation, destination_target_id)
                );

                CREATE TABLE IF NOT EXISTS notes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
                    target_id INTEGER REFERENCES targets(id) ON DELETE CASCADE,
                    artifact_id INTEGER REFERENCES artifacts(id) ON DELETE CASCADE,
                    body TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS file_objects (
                    sha256 TEXT PRIMARY KEY,
                    storage_id TEXT NOT NULL UNIQUE,
                    size INTEGER NOT NULL,
                    md5 TEXT NOT NULL,
                    sha1 TEXT NOT NULL,
                    detected_type TEXT NOT NULL,
                    mime_type TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS files (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
                    target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
                    artifact_id INTEGER NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
                    object_sha256 TEXT NOT NULL REFERENCES file_objects(sha256),
                    original_filename TEXT NOT NULL,
                    extension TEXT NOT NULL,
                    ingested_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS file_structured_artifacts (
                    file_id INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
                    artifact_id INTEGER NOT NULL UNIQUE REFERENCES artifacts(id) ON DELETE CASCADE,
                    PRIMARY KEY(file_id, artifact_id)
                );

                CREATE TABLE IF NOT EXISTS file_candidates (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_id INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
                    artifact_id INTEGER NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
                    type TEXT NOT NULL,
                    raw_value TEXT NOT NULL,
                    normalized_value TEXT,
                    offset INTEGER NOT NULL,
                    encoding TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(file_id, type, raw_value, normalized_value, offset, encoding)
                );
                CREATE INDEX IF NOT EXISTS idx_file_candidates_file_type
                    ON file_candidates(file_id, type, id);

                CREATE TABLE IF NOT EXISTS rule_packs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    version TEXT NOT NULL,
                    namespace TEXT NOT NULL,
                    source TEXT NOT NULL,
                    description TEXT NOT NULL,
                    rules_text TEXT NOT NULL,
                    rules_sha256 TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(name, version)
                );
                CREATE TABLE IF NOT EXISTS hash_sets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    version TEXT NOT NULL,
                    source TEXT NOT NULL,
                    description TEXT NOT NULL,
                    category TEXT NOT NULL,
                    entry_count INTEGER NOT NULL,
                    content_sha256 TEXT NOT NULL,
                    imported_at TEXT NOT NULL,
                    UNIQUE(name, version)
                );
                CREATE TABLE IF NOT EXISTS hash_entries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    hash_set_id INTEGER NOT NULL REFERENCES hash_sets(id) ON DELETE CASCADE,
                    algorithm TEXT NOT NULL,
                    digest TEXT NOT NULL,
                    label TEXT NOT NULL,
                    tags_json TEXT NOT NULL,
                    metadata_json TEXT NOT NULL,
                    UNIQUE(hash_set_id, algorithm, digest)
                );
                CREATE INDEX IF NOT EXISTS idx_hash_entries_digest ON hash_entries(algorithm, digest);
                CREATE TABLE IF NOT EXISTS file_detections (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_id INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
                    artifact_id INTEGER NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
                    analyzer TEXT NOT NULL,
                    analyzer_version TEXT NOT NULL,
                    method TEXT NOT NULL,
                    signature_id TEXT NOT NULL,
                    namespace TEXT NOT NULL,
                    title TEXT NOT NULL,
                    tags_json TEXT NOT NULL,
                    metadata_json TEXT NOT NULL,
                    result TEXT NOT NULL,
                    provenance_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(file_id, method, signature_id, namespace, artifact_id)
                );
                CREATE INDEX IF NOT EXISTS idx_file_detections_file_method ON file_detections(file_id, method, id);
                CREATE TABLE IF NOT EXISTS file_fingerprints (
                    object_sha256 TEXT NOT NULL REFERENCES file_objects(sha256) ON DELETE CASCADE,
                    algorithm TEXT NOT NULL,
                    implementation_version TEXT NOT NULL,
                    fingerprint TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY(object_sha256, algorithm)
                );
                CREATE TABLE IF NOT EXISTS av_scan_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_id INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
                    artifact_id INTEGER NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
                    object_sha256 TEXT NOT NULL REFERENCES file_objects(sha256),
                    engine TEXT NOT NULL,
                    engine_version TEXT,
                    database_version TEXT,
                    database_timestamp TEXT,
                    state TEXT NOT NULL,
                    scanned_at TEXT NOT NULL,
                    duration_ms INTEGER,
                    bytes_scanned INTEGER,
                    error_code TEXT,
                    message TEXT,
                    detections_json TEXT NOT NULL,
                    provenance_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_av_scan_results_file ON av_scan_results(file_id, id);
                CREATE TABLE IF NOT EXISTS av_detections (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_result_id INTEGER NOT NULL REFERENCES av_scan_results(id) ON DELETE CASCADE,
                    signature TEXT NOT NULL,
                    metadata_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                    display_name TEXT NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL CHECK(role IN ('admin','analyst','viewer')),
                    enabled INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    last_login_at TEXT
                );
                CREATE TABLE IF NOT EXISTS sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    token_hash TEXT NOT NULL UNIQUE,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    csrf_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token_hash);
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    actor_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
                    actor_username TEXT,
                    action TEXT NOT NULL,
                    object_type TEXT,
                    object_id TEXT,
                    outcome TEXT NOT NULL,
                    metadata_json TEXT NOT NULL DEFAULT '{}'
                );
                CREATE INDEX IF NOT EXISTS idx_audit_events_time ON audit_events(id DESC);
                """
            )
            if "owner_user_id" not in {r[1] for r in conn.execute("PRAGMA table_info(cases)")}:
                conn.execute("ALTER TABLE cases ADD COLUMN owner_user_id INTEGER REFERENCES users(id)")
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS teams (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE COLLATE NOCASE,
                    description TEXT NOT NULL DEFAULT '',
                    enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),
                    created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS team_members (
                    team_id INTEGER NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    created_at TEXT NOT NULL, PRIMARY KEY(team_id,user_id));
                CREATE TABLE IF NOT EXISTS case_acl (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
                    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                    team_id INTEGER REFERENCES teams(id) ON DELETE CASCADE,
                    access TEXT NOT NULL CHECK(access IN ('editor','viewer')),
                    CHECK((user_id IS NOT NULL) != (team_id IS NOT NULL)),
                    UNIQUE(case_id,user_id), UNIQUE(case_id,team_id));
                CREATE INDEX IF NOT EXISTS idx_team_members_user ON team_members(user_id);
                CREATE INDEX IF NOT EXISTS idx_cases_owner ON cases(owner_user_id);
            """)
            relationship_columns = {row[1] for row in conn.execute("PRAGMA table_info(relationships)")}
            if "artifact_id" not in relationship_columns:
                conn.execute("ALTER TABLE relationships ADD COLUMN artifact_id INTEGER REFERENCES artifacts(id) ON DELETE SET NULL")
            conn.execute(
                "INSERT OR REPLACE INTO schema_meta(key, value) VALUES('schema_version', ?)",
                (str(SCHEMA_VERSION),),
            )

    @staticmethod
    def _row(row: sqlite3.Row | None) -> dict[str, Any] | None:
        return dict(row) if row is not None else None

    def create_case(self, name: str, description: str = "", status: str = "open", *, owner_user_id: int | None = None) -> dict[str, Any]:
        now = utcnow()
        with self.connect() as conn:
            if owner_user_id is not None:
                from .case_access import validate_owner
                validate_owner(conn, owner_user_id)
            cur = conn.execute(
                "INSERT INTO cases(name, description, status, created_at, updated_at, owner_user_id) VALUES(?,?,?,?,?,?)",
                (name.strip(), description, status, now, now, owner_user_id),
            )
            from .case_access import audit
            audit(conn, "case_created", owner_user_id, {"case_id": cur.lastrowid, "owner_user_id": owner_user_id})
            row = conn.execute("SELECT * FROM cases WHERE id=?", (cur.lastrowid,)).fetchone()
        return dict(row)

    def list_cases(self) -> list[dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute("SELECT * FROM cases ORDER BY id DESC").fetchall()
        return [dict(r) for r in rows]

    def get_case(self, case_id: int) -> dict[str, Any] | None:
        with self.connect() as conn:
            case = conn.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
            if case is None:
                return None
            targets = conn.execute("SELECT * FROM targets WHERE case_id=? ORDER BY id", (case_id,)).fetchall()
            artifacts = conn.execute("SELECT id, case_id, target_id, type, source, created_at FROM artifacts WHERE case_id=? ORDER BY id", (case_id,)).fetchall()
            relationships = conn.execute("SELECT * FROM relationships WHERE case_id=? ORDER BY id", (case_id,)).fetchall()
            notes = conn.execute("SELECT * FROM notes WHERE case_id=? ORDER BY id", (case_id,)).fetchall()
        result = dict(case)
        result["targets"] = [dict(r) for r in targets]
        result["artifacts"] = [dict(r) for r in artifacts]
        result["relationships"] = [dict(r) for r in relationships]
        result["notes"] = [dict(r) for r in notes]
        return result

    def case_graph(self, case_id: int, max_nodes: int = 250, max_edges: int = 500, target_type: str | None = None, relation: str | None = None) -> dict[str, Any] | None:
        case = self.get_case(case_id)
        if case is None: return None
        targets = sorted((t for t in case["targets"] if not target_type or t["type"] == target_type), key=lambda x: x["id"])
        target_ids = {t["id"] for t in targets}
        relationships = sorted((r for r in case["relationships"] if (not relation or r["relation"] == relation) and r["source_target_id"] in target_ids and r["destination_target_id"] in target_ids), key=lambda x: x["id"])
        nodes = [{"id": t["id"], "kind": "target", "type": t["type"], "value": t["normalized"], "url": f"/cases/{case_id}/targets/{t['id']}"} for t in targets[:max_nodes]]
        allowed = {n["id"] for n in nodes}
        edges = [{"id": r["id"], "source": r["source_target_id"], "target": r["destination_target_id"], "relation": r["relation"], "artifact_id": r.get("artifact_id")} for r in relationships if r["source_target_id"] in allowed and r["destination_target_id"] in allowed][:max_edges]
        return {"case_id": case_id, "nodes": nodes, "edges": edges, "available_nodes": len(targets), "available_edges": len(relationships), "truncated": len(nodes) < len(targets) or len(edges) < len(relationships), "filters": {"target_type": target_type, "relation": relation}}

    def case_timeline(self, case_id: int, limit: int = 500) -> list[dict[str, Any]] | None:
        case = self.get_case(case_id)
        if case is None: return None
        events = [{"timestamp": case["created_at"], "event_type": "case_created", "entity_type": "case", "entity_id": case_id, "label": "Case created", "source": "local", "url": f"/cases/{case_id}"}]
        events += [{"timestamp": t["created_at"], "event_type": "target_added", "entity_type": "target", "entity_id": t["id"], "label": f"Target added: {t['type']} {t['normalized']}", "source": "local", "url": f"/cases/{case_id}/targets/{t['id']}"} for t in case["targets"]]
        events += [{"timestamp": a["created_at"], "event_type": "artifact_recorded", "entity_type": "artifact", "entity_id": a["id"], "label": f"Artifact recorded: {a['type']}", "source": a["source"], "url": f"/cases/{case_id}#artifact-{a['id']}"} for a in case["artifacts"]]
        events += [{"timestamp": n["created_at"], "event_type": "note_added", "entity_type": "note", "entity_id": n["id"], "label": "Note added", "source": "local", "url": f"/cases/{case_id}#note-{n['id']}"} for n in case["notes"]]
        return sorted(events, key=lambda x: (x["timestamp"], x["entity_type"], x["entity_id"]), reverse=True)[:limit]

    def update_case(self, case_id: int, *, name: str | None = None, description: str | None = None, status: str | None = None) -> dict[str, Any] | None:
        fields: list[str] = []
        values: list[Any] = []
        for key, value in (("name", name), ("description", description), ("status", status)):
            if value is not None:
                fields.append(f"{key}=?")
                values.append(value.strip() if key == "name" else value)
        if not fields:
            return self.get_case(case_id)
        fields.append("updated_at=?")
        values.append(utcnow())
        values.append(case_id)
        with self.connect() as conn:
            cur = conn.execute(f"UPDATE cases SET {', '.join(fields)} WHERE id=?", values)
            if cur.rowcount == 0:
                return None
            row = conn.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
        return dict(row)

    def delete_case(self, case_id: int) -> bool:
        with self.connect() as conn:
            cur = conn.execute("DELETE FROM cases WHERE id=?", (case_id,))
        return bool(cur.rowcount)

    def count_users(self) -> int:
        with self.connect() as conn: return int(conn.execute("SELECT COUNT(*) FROM users").fetchone()[0])

    def create_user(self, username: str, display_name: str, password_hash: str, role: str = "viewer") -> dict[str, Any]:
        now = utcnow()
        with self.connect() as conn:
            cur = conn.execute("INSERT INTO users(username,display_name,password_hash,role,created_at,updated_at) VALUES(?,?,?,?,?,?)", (username, display_name, password_hash, role, now, now))
            row = conn.execute("SELECT id,username,display_name,role,enabled,created_at,updated_at,last_login_at FROM users WHERE id=?", (cur.lastrowid,)).fetchone()
        return dict(row)

    def get_user(self, user_id: int) -> dict[str, Any] | None:
        with self.connect() as conn: row = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        return self._row(row)

    def get_user_by_username(self, username: str) -> dict[str, Any] | None:
        with self.connect() as conn: row = conn.execute("SELECT * FROM users WHERE username=? COLLATE NOCASE", (username,)).fetchone()
        return self._row(row)

    def list_users(self, limit: int = 100) -> list[dict[str, Any]]:
        with self.connect() as conn: rows = conn.execute("SELECT id,username,display_name,role,enabled,created_at,updated_at,last_login_at FROM users ORDER BY id LIMIT ?", (max(1,min(limit,1000)),)).fetchall()
        return [dict(r) for r in rows]

    def update_user(self, user_id: int, **fields) -> dict[str, Any] | None:
        allowed={k:v for k,v in fields.items() if k in {'display_name','role','enabled','password_hash'} and v is not None}
        if not allowed: return self.get_user(user_id)
        allowed['updated_at']=utcnow(); sets=', '.join(f'{k}=?' for k in allowed)
        with self.connect() as conn:
            conn.execute(f"UPDATE users SET {sets} WHERE id=?", (*allowed.values(), user_id))
        return self.get_user(user_id)

    def touch_login(self, user_id: int) -> None:
        with self.connect() as conn: conn.execute("UPDATE users SET last_login_at=?, updated_at=? WHERE id=?", (utcnow(),utcnow(),user_id))

    def create_session(self, token_hash: str, user_id: int, csrf_hash: str, expires_at: str) -> None:
        with self.connect() as conn: conn.execute("INSERT INTO sessions(token_hash,user_id,csrf_hash,created_at,expires_at) VALUES(?,?,?,?,?)", (token_hash,user_id,csrf_hash,utcnow(),expires_at))

    def get_session(self, token_hash: str) -> dict[str, Any] | None:
        with self.connect() as conn: row=conn.execute("SELECT s.*,u.username,u.display_name,u.role,u.enabled FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=?", (token_hash,)).fetchone()
        return self._row(row)

    def delete_session(self, token_hash: str) -> None:
        with self.connect() as conn: conn.execute("DELETE FROM sessions WHERE token_hash=?", (token_hash,))

    def add_audit(self, action: str, outcome: str, actor_user_id: int | None = None, actor_username: str | None = None, object_type: str | None = None, object_id: str | None = None, metadata: Any = None) -> dict[str, Any]:
        payload=json.dumps(metadata or {}, separators=(",",":"), sort_keys=True)
        if len(payload)>8192: payload=json.dumps({"truncated": True}, separators=(",",":"))
        with self.connect() as conn:
            cur=conn.execute("INSERT INTO audit_events(timestamp,actor_user_id,actor_username,action,object_type,object_id,outcome,metadata_json) VALUES(?,?,?,?,?,?,?,?)", (utcnow(),actor_user_id,actor_username,action,object_type,object_id,outcome,payload))
            row=conn.execute("SELECT * FROM audit_events WHERE id=?",(cur.lastrowid,)).fetchone()
        d=dict(row); d['metadata']=json.loads(d.pop('metadata_json')); return d

    def list_audit(self, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
        with self.connect() as conn: rows=conn.execute("SELECT * FROM audit_events ORDER BY id DESC LIMIT ? OFFSET ?", (max(1,min(limit,200)),max(0,offset))).fetchall()
        out=[]
        for r in rows:
            d=dict(r); d['metadata']=json.loads(d.pop('metadata_json')); out.append(d)
        return out

    def add_target(self, case_id: int, target_type: str, value: str, normalized: str) -> dict[str, Any]:
        now = utcnow()
        with self.connect() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO targets(case_id,type,value,normalized,created_at) VALUES(?,?,?,?,?)",
                (case_id, target_type, value, normalized, now),
            )
            row = conn.execute(
                "SELECT * FROM targets WHERE case_id=? AND type=? AND normalized=?",
                (case_id, target_type, normalized),
            ).fetchone()
            if row is None:
                raise KeyError("case not found")
        return dict(row)

    def get_target(self, target_id: int) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM targets WHERE id=?", (target_id,)).fetchone()
        return self._row(row)

    def list_target_artifacts(self, target_id: int) -> list[dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute("SELECT * FROM artifacts WHERE target_id=? ORDER BY id DESC", (target_id,)).fetchall()
        out = []
        for row in rows:
            item = dict(row)
            item["data"] = json.loads(item.pop("data_json"))
            out.append(item)
        return out

    def get_artifact(self, artifact_id: int) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM artifacts WHERE id=?", (artifact_id,)).fetchone()
        if row is None:
            return None
        item = dict(row)
        item["data"] = json.loads(item.pop("data_json"))
        return item

    def add_artifact(self, case_id: int, target_id: int | None, artifact_type: str, source: str, data: Any) -> dict[str, Any]:
        with self.connect() as conn:
            cur = conn.execute(
                "INSERT INTO artifacts(case_id,target_id,type,source,data_json,created_at) VALUES(?,?,?,?,?,?)",
                (case_id, target_id, artifact_type, source, json.dumps(data, separators=(",", ":"), sort_keys=True), utcnow()),
            )
            row = conn.execute("SELECT * FROM artifacts WHERE id=?", (cur.lastrowid,)).fetchone()
        item = dict(row)
        item["data"] = json.loads(item.pop("data_json"))
        return item

    def add_relationship(self, case_id: int, source_target_id: int, relation: str, destination_target_id: int, artifact_id: int | None = None) -> dict[str, Any]:
        with self.connect() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO relationships(case_id,source_target_id,relation,destination_target_id,artifact_id,created_at) VALUES(?,?,?,?,?,?)",
                (case_id, source_target_id, relation, destination_target_id, artifact_id, utcnow()),
            )
            if artifact_id is not None:
                conn.execute("UPDATE relationships SET artifact_id=? WHERE case_id=? AND source_target_id=? AND relation=? AND destination_target_id=?", (artifact_id, case_id, source_target_id, relation, destination_target_id))
            row = conn.execute(
                "SELECT * FROM relationships WHERE case_id=? AND source_target_id=? AND relation=? AND destination_target_id=?",
                (case_id, source_target_id, relation, destination_target_id),
            ).fetchone()
        return dict(row)

    def add_note(self, case_id: int, body: str, target_id: int | None = None, artifact_id: int | None = None) -> dict[str, Any]:
        now = utcnow()
        with self.connect() as conn:
            for table, oid in (("targets",target_id),("artifacts",artifact_id)):
                if oid is not None and not conn.execute(f"SELECT 1 FROM {table} WHERE id=? AND case_id=?",(oid,case_id)).fetchone():
                    from .case_access import AccessError
                    raise AccessError(404,"not found")
            cur = conn.execute(
                "INSERT INTO notes(case_id,target_id,artifact_id,body,created_at,updated_at) VALUES(?,?,?,?,?,?)",
                (case_id, target_id, artifact_id, body, now, now),
            )
            row = conn.execute("SELECT * FROM notes WHERE id=?", (cur.lastrowid,)).fetchone()
        return dict(row)

    def add_file_ingestion(self, case_id: int, filename: str, analysis: dict[str, Any]) -> dict[str, Any]:
        hashes = analysis["hashes"]
        with self.connect() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO file_objects(sha256,storage_id,size,md5,sha1,detected_type,mime_type,created_at) VALUES(?,?,?,?,?,?,?,?)",
                (hashes["sha256"], analysis["storage_id"], analysis["size"], hashes["md5"], hashes["sha1"], analysis["detected_type"], analysis["mime_type"], analysis["ingested_at"]),
            )
            conn.execute(
                "INSERT OR IGNORE INTO targets(case_id,type,value,normalized,created_at) VALUES(?,?,?,?,?)",
                (case_id, "hash", hashes["sha256"], hashes["sha256"], analysis["ingested_at"]),
            )
            target = conn.execute("SELECT * FROM targets WHERE case_id=? AND type='hash' AND normalized=?", (case_id, hashes["sha256"])).fetchone()
            if target is None:
                raise KeyError("case not found")
            cur = conn.execute(
                "INSERT INTO artifacts(case_id,target_id,type,source,data_json,created_at) VALUES(?,?,?,?,?,?)",
                (case_id, target["id"], "file_analysis", "local", json.dumps(analysis, separators=(",", ":"), sort_keys=True), analysis["ingested_at"]),
            )
            artifact_id = cur.lastrowid
            file_cur = conn.execute(
                "INSERT INTO files(case_id,target_id,artifact_id,object_sha256,original_filename,extension,ingested_at) VALUES(?,?,?,?,?,?,?)",
                (case_id, target["id"], artifact_id, hashes["sha256"], filename, analysis["extension"], analysis["ingested_at"]),
            )
            file_id = file_cur.lastrowid
        result = self.get_file(file_id)
        if result is None:
            raise RuntimeError("file record was not persisted")
        return result

    def get_file(self, file_id: int) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT f.id,f.case_id,f.target_id,f.artifact_id,f.original_filename,f.extension,f.ingested_at,o.sha256,o.storage_id,o.size,o.md5,o.sha1,o.detected_type,o.mime_type FROM files f JOIN file_objects o ON o.sha256=f.object_sha256 WHERE f.id=?",
                (file_id,),
            ).fetchone()
        return self._row(row)

    def list_case_files(self, case_id: int) -> list[dict[str, Any]]:
        """Return logical file associations for a case without exposing paths."""
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT f.id,f.case_id,f.target_id,f.artifact_id,f.original_filename,f.extension,f.ingested_at,o.sha256,o.storage_id,o.size,o.md5,o.sha1,o.detected_type,o.mime_type "
                "FROM files f JOIN file_objects o ON o.sha256=f.object_sha256 WHERE f.case_id=? ORDER BY f.id DESC",
                (case_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_file_analysis(self, file_id: int) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute("SELECT a.* FROM files f JOIN artifacts a ON a.id=f.artifact_id WHERE f.id=?", (file_id,)).fetchone()
        if row is None:
            return None
        item = dict(row)
        item["data"] = json.loads(item.pop("data_json"))
        with self.connect() as conn:
            rows = conn.execute("SELECT a.* FROM file_structured_artifacts fsa JOIN artifacts a ON a.id=fsa.artifact_id WHERE fsa.file_id=? ORDER BY a.id", (file_id,)).fetchall()
        item["structured"] = []
        for structured in rows:
            value = dict(structured); value["data"] = json.loads(value.pop("data_json")); item["structured"].append(value)
        return item

    def add_structured_artifact(self, file_id: int, artifact_type: str, data: dict[str, Any]) -> dict[str, Any]:
        file = self.get_file(file_id)
        if file is None: raise KeyError("file not found")
        artifact = self.add_artifact(file["case_id"], file["target_id"], artifact_type, "local", data)
        with self.connect() as conn:
            conn.execute("INSERT INTO file_structured_artifacts(file_id,artifact_id) VALUES(?,?)", (file_id, artifact["id"]))
        return artifact

    def add_binary_analysis(self, file_id: int, data: dict[str, Any], candidates: list[dict[str, Any]]) -> dict[str, Any]:
        """Atomically replace a logical file's binary analysis and candidates."""
        file = self.get_file(file_id)
        if file is None:
            raise KeyError("file not found")
        now = utcnow()
        with self.connect() as conn:
            old = conn.execute(
                "SELECT a.id FROM file_structured_artifacts fsa JOIN artifacts a ON a.id=fsa.artifact_id WHERE fsa.file_id=? AND a.type='binary_analysis'",
                (file_id,),
            ).fetchall()
            for row in old:
                conn.execute("DELETE FROM artifacts WHERE id=?", (row["id"],))
            cur = conn.execute(
                "INSERT INTO artifacts(case_id,target_id,type,source,data_json,created_at) VALUES(?,?,?,?,?,?)",
                (file["case_id"], file["target_id"], "binary_analysis", "local", json.dumps(data, separators=(",", ":"), sort_keys=True), now),
            )
            artifact_id = int(cur.lastrowid)
            conn.execute("INSERT INTO file_structured_artifacts(file_id,artifact_id) VALUES(?,?)", (file_id, artifact_id))
            conn.execute("DELETE FROM file_candidates WHERE file_id=?", (file_id,))
            for candidate in candidates:
                conn.execute(
                    "INSERT OR IGNORE INTO file_candidates(file_id,artifact_id,type,raw_value,normalized_value,offset,encoding,created_at) VALUES(?,?,?,?,?,?,?,?)",
                    (file_id, artifact_id, candidate["type"], candidate["raw_value"], candidate.get("normalized_value"), candidate["offset"], candidate["encoding"], now),
                )
            row = conn.execute("SELECT * FROM artifacts WHERE id=?", (artifact_id,)).fetchone()
        item = dict(row)
        item["data"] = json.loads(item.pop("data_json"))
        return item

    def list_file_candidates(self, file_id: int, candidate_type: str | None = None, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
        if self.get_file(file_id) is None:
            raise KeyError("file not found")
        limit = max(1, min(int(limit), 200)); offset = max(0, int(offset))
        sql = "SELECT * FROM file_candidates WHERE file_id=?"
        args: list[Any] = [file_id]
        if candidate_type:
            sql += " AND type=?"; args.append(candidate_type)
        sql += " ORDER BY id LIMIT ? OFFSET ?"; args.extend((limit, offset))
        with self.connect() as conn:
            rows = conn.execute(sql, args).fetchall()
        return [dict(row) for row in rows]

    def get_file_candidate(self, file_id: int, candidate_id: int) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM file_candidates WHERE file_id=? AND id=?", (file_id, candidate_id)).fetchone()
        return self._row(row)

    def add_rule_pack(self, pack: dict[str, Any]) -> dict[str, Any]:
        with self.connect() as conn:
            conn.execute("INSERT OR IGNORE INTO rule_packs(name,version,namespace,source,description,rules_text,rules_sha256,created_at) VALUES(?,?,?,?,?,?,?,?)", (pack["name"], pack["version"], pack["namespace"], pack["source"], pack["description"], pack["rules_text"], pack["rules_sha256"], utcnow()))
            row = conn.execute("SELECT id,name,version,namespace,source,description,rules_sha256,created_at FROM rule_packs WHERE name=? AND version=?", (pack["name"], pack["version"])).fetchone()
        return dict(row)

    def list_rule_packs(self, include_rules: bool = False) -> list[dict[str, Any]]:
        columns = "*" if include_rules else "id,name,version,namespace,source,description,rules_sha256,created_at"
        with self.connect() as conn: rows = conn.execute(f"SELECT {columns} FROM rule_packs ORDER BY id").fetchall()
        return [dict(row) for row in rows]

    def import_hash_set(self, item: dict[str, Any]) -> dict[str, Any]:
        with self.connect() as conn:
            existing = conn.execute("SELECT * FROM hash_sets WHERE name=? AND version=?", (item["name"], item["version"])).fetchone()
            if existing is not None:
                if existing["content_sha256"] != item["content_sha256"]:
                    raise ValueError("hash-set name and version already identify different content")
                return dict(existing)
            cur = conn.execute("INSERT INTO hash_sets(name,version,source,description,category,entry_count,content_sha256,imported_at) VALUES(?,?,?,?,?,?,?,?)", (item["name"], item["version"], item["source"], item["description"], item["category"], len({(e["algorithm"],e["digest"]) for e in item["entries"]}), item["content_sha256"], utcnow()))
            set_id = int(cur.lastrowid)
            for entry in item["entries"]:
                conn.execute("INSERT OR IGNORE INTO hash_entries(hash_set_id,algorithm,digest,label,tags_json,metadata_json) VALUES(?,?,?,?,?,?)", (set_id, entry["algorithm"], entry["digest"], entry["label"], json.dumps(entry["tags"]), json.dumps(entry["metadata"], separators=(",", ":"), sort_keys=True)))
            row = conn.execute("SELECT * FROM hash_sets WHERE id=?", (set_id,)).fetchone()
        return dict(row)

    def list_hash_sets(self) -> list[dict[str, Any]]:
        with self.connect() as conn: rows = conn.execute("SELECT * FROM hash_sets ORDER BY id").fetchall()
        return [dict(row) for row in rows]

    def get_hash_set(self, set_id: int) -> dict[str, Any] | None:
        with self.connect() as conn: row = conn.execute("SELECT * FROM hash_sets WHERE id=?", (set_id,)).fetchone()
        return self._row(row)

    def matching_hash_entries(self, hashes: dict[str, str]) -> list[dict[str, Any]]:
        clauses=[]; args=[]
        for algorithm,digest in hashes.items(): clauses.append("(he.algorithm=? AND he.digest=?)"); args.extend((algorithm,digest))
        with self.connect() as conn:
            rows=conn.execute("SELECT he.*,hs.name set_name,hs.version set_version,hs.source set_source,hs.category set_category FROM hash_entries he JOIN hash_sets hs ON hs.id=he.hash_set_id WHERE "+" OR ".join(clauses),args).fetchall()
        result=[]
        for row in rows:
            item=dict(row); item["tags"]=json.loads(item.pop("tags_json")); item["metadata"]=json.loads(item.pop("metadata_json")); result.append(item)
        return result

    def replace_local_detections(self, file_id: int, summary: dict[str, Any], detections: list[dict[str, Any]]) -> dict[str, Any]:
        file=self.get_file(file_id)
        if file is None: raise KeyError("file not found")
        now=utcnow()
        with self.connect() as conn:
            old=conn.execute("SELECT a.id FROM file_structured_artifacts fsa JOIN artifacts a ON a.id=fsa.artifact_id WHERE fsa.file_id=? AND a.type='local_detections'",(file_id,)).fetchall()
            for row in old: conn.execute("DELETE FROM artifacts WHERE id=?",(row["id"],))
            cur=conn.execute("INSERT INTO artifacts(case_id,target_id,type,source,data_json,created_at) VALUES(?,?,?,?,?,?)",(file["case_id"],file["target_id"],"local_detections","local",json.dumps(summary,separators=(",",":"),sort_keys=True),now))
            artifact_id=int(cur.lastrowid); conn.execute("INSERT INTO file_structured_artifacts(file_id,artifact_id) VALUES(?,?)",(file_id,artifact_id))
            conn.execute("DELETE FROM file_detections WHERE file_id=?",(file_id,))
            for item in detections:
                conn.execute("INSERT INTO file_detections(file_id,artifact_id,analyzer,analyzer_version,method,signature_id,namespace,title,tags_json,metadata_json,result,provenance_json,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",(file_id,artifact_id,item["analyzer"],item["analyzer_version"],item["method"],item["signature_id"],item["namespace"],item["title"],json.dumps(item["tags"]),json.dumps(item["metadata"],separators=(",",":"),sort_keys=True),item["result"],json.dumps(item["provenance"],separators=(",",":"),sort_keys=True),now))
            row=conn.execute("SELECT * FROM artifacts WHERE id=?",(artifact_id,)).fetchone()
        result=dict(row); result["data"]=json.loads(result.pop("data_json")); return result

    def list_file_detections(self, file_id: int) -> list[dict[str, Any]]:
        if self.get_file(file_id) is None: raise KeyError("file not found")
        with self.connect() as conn: rows=conn.execute("SELECT * FROM file_detections WHERE file_id=? ORDER BY method,namespace,signature_id",(file_id,)).fetchall()
        result=[]
        for row in rows:
            item=dict(row); item["tags"]=json.loads(item.pop("tags_json")); item["metadata"]=json.loads(item.pop("metadata_json")); item["provenance"]=json.loads(item.pop("provenance_json")); result.append(item)
        return result

    def put_fingerprint(self, object_sha256: str, algorithm: str, version: str, value: str) -> None:
        with self.connect() as conn: conn.execute("INSERT OR REPLACE INTO file_fingerprints(object_sha256,algorithm,implementation_version,fingerprint,created_at) VALUES(?,?,?,?,?)",(object_sha256,algorithm,version,value,utcnow()))

    def get_fingerprint(self, object_sha256: str, algorithm: str) -> dict[str, Any] | None:
        with self.connect() as conn: row=conn.execute("SELECT * FROM file_fingerprints WHERE object_sha256=? AND algorithm=?",(object_sha256,algorithm)).fetchone()
        return self._row(row)

    def similarity_candidates(self, file_id: int, algorithm: str, maximum: int = 10000) -> list[dict[str, Any]]:
        with self.connect() as conn:
            rows=conn.execute("SELECT f.id file_id,f.case_id,f.original_filename,f.object_sha256,fp.fingerprint,fp.implementation_version FROM files f JOIN file_fingerprints fp ON fp.object_sha256=f.object_sha256 WHERE fp.algorithm=? AND f.id<>? ORDER BY f.id LIMIT ?",(algorithm,file_id,maximum)).fetchall()
        return [dict(row) for row in rows]

    def persist_av_result(self, file_id: int, result: dict[str, Any]) -> dict[str, Any]:
        file = self.get_file(file_id)
        if file is None: raise KeyError("file not found")
        detections = result.get("detections", [])[:100]
        provenance = dict(result.get("provenance", {})); provenance["object_sha256"] = file["sha256"]
        with self.connect() as conn:
            recent = conn.execute("SELECT * FROM av_scan_results WHERE file_id=? AND engine=? ORDER BY id DESC LIMIT 5", (file_id, result["engine"])).fetchall()
            detection_json = json.dumps(detections, separators=(",", ":"), sort_keys=True)
            for old in recent:
                if old["engine_version"] == result.get("engine_version") and old["database_version"] == result.get("database_version") and old["state"] == result["state"] and old["detections_json"] == detection_json:
                    return self._av_row(old)
            artifact_data = {"engine": result["engine"], "engine_version": result.get("engine_version"), "database_version": result.get("database_version"), "state": result["state"], "detections": detections, "scanned_at": result.get("scanned_at"), "bytes_scanned": result.get("bytes_scanned"), "error_code": result.get("error_code"), "provenance": provenance}
            cur = conn.execute("INSERT INTO artifacts(case_id,target_id,type,source,data_json,created_at) VALUES(?,?,?,?,?,?)", (file["case_id"], file["target_id"], "antivirus_scan", "local", json.dumps(artifact_data, separators=(",", ":"), sort_keys=True), result.get("scanned_at") or utcnow()))
            artifact_id = int(cur.lastrowid)
            conn.execute("INSERT INTO file_structured_artifacts(file_id,artifact_id) VALUES(?,?)", (file_id, artifact_id))
            cur = conn.execute("INSERT INTO av_scan_results(file_id,artifact_id,object_sha256,engine,engine_version,database_version,database_timestamp,state,scanned_at,duration_ms,bytes_scanned,error_code,message,detections_json,provenance_json,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (file_id, artifact_id, file["sha256"], result["engine"], result.get("engine_version"), result.get("database_version"), result.get("database_timestamp"), result["state"], result.get("scanned_at") or utcnow(), result.get("duration_ms"), result.get("bytes_scanned"), result.get("error_code"), result.get("message"), detection_json, json.dumps(provenance, separators=(",", ":"), sort_keys=True), utcnow()))
            scan_id = int(cur.lastrowid)
            for detection in detections:
                conn.execute("INSERT INTO av_detections(scan_result_id,signature,metadata_json) VALUES(?,?,?)", (scan_id, str(detection.get("signature", ""))[:256], json.dumps({key: value for key, value in detection.items() if key != "signature"}, separators=(",", ":"), sort_keys=True)))
            row = conn.execute("SELECT * FROM av_scan_results WHERE id=?", (scan_id,)).fetchone()
        return self._av_row(row)

    @staticmethod
    def _av_row(row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row); item["detections"] = json.loads(item.pop("detections_json")); item["provenance"] = json.loads(item.pop("provenance_json")); return item

    def list_av_results(self, file_id: int, limit: int = 100) -> list[dict[str, Any]]:
        if self.get_file(file_id) is None: raise KeyError("file not found")
        with self.connect() as conn: rows = conn.execute("SELECT * FROM av_scan_results WHERE file_id=? ORDER BY id DESC LIMIT ?", (file_id, max(1, min(int(limit), 100)))).fetchall()
        return [self._av_row(row) for row in rows]
