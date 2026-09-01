from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

SCHEMA_VERSION = 1


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
                """
            )
            conn.execute(
                "INSERT OR REPLACE INTO schema_meta(key, value) VALUES('schema_version', ?)",
                (str(SCHEMA_VERSION),),
            )

    @staticmethod
    def _row(row: sqlite3.Row | None) -> dict[str, Any] | None:
        return dict(row) if row is not None else None

    def create_case(self, name: str, description: str = "", status: str = "open") -> dict[str, Any]:
        now = utcnow()
        with self.connect() as conn:
            cur = conn.execute(
                "INSERT INTO cases(name, description, status, created_at, updated_at) VALUES(?,?,?,?,?)",
                (name.strip(), description, status, now, now),
            )
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

    def add_relationship(self, case_id: int, source_target_id: int, relation: str, destination_target_id: int) -> dict[str, Any]:
        with self.connect() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO relationships(case_id,source_target_id,relation,destination_target_id,created_at) VALUES(?,?,?,?,?)",
                (case_id, source_target_id, relation, destination_target_id, utcnow()),
            )
            row = conn.execute(
                "SELECT * FROM relationships WHERE case_id=? AND source_target_id=? AND relation=? AND destination_target_id=?",
                (case_id, source_target_id, relation, destination_target_id),
            ).fetchone()
        return dict(row)

    def add_note(self, case_id: int, body: str, target_id: int | None = None, artifact_id: int | None = None) -> dict[str, Any]:
        now = utcnow()
        with self.connect() as conn:
            cur = conn.execute(
                "INSERT INTO notes(case_id,target_id,artifact_id,body,created_at,updated_at) VALUES(?,?,?,?,?,?)",
                (case_id, target_id, artifact_id, body, now, now),
            )
            row = conn.execute("SELECT * FROM notes WHERE id=?", (cur.lastrowid,)).fetchone()
        return dict(row)
