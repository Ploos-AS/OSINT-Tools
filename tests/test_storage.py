from osint_tools.storage import Store
import sqlite3


def test_case_target_artifact_relationship_note(tmp_path):
    store = Store(tmp_path / "test.db")
    case = store.create_case("Example", "demo")
    assert case["status"] == "open"

    domain = store.add_target(case["id"], "domain", "Example.COM", "example.com")
    same = store.add_target(case["id"], "domain", "example.com", "example.com")
    assert same["id"] == domain["id"]

    ip = store.add_target(case["id"], "ip", "1.1.1.1", "1.1.1.1")
    artifact = store.add_artifact(case["id"], domain["id"], "dns", "dns", {"A": ["1.1.1.1"]})
    rel = store.add_relationship(case["id"], domain["id"], "resolves_to", ip["id"])
    note = store.add_note(case["id"], "interesting", target_id=domain["id"])

    assert artifact["data"]["A"] == ["1.1.1.1"]
    assert rel["relation"] == "resolves_to"
    assert note["body"] == "interesting"
    loaded = store.get_case(case["id"])
    assert len(loaded["targets"]) == 2
    assert len(loaded["relationships"]) == 1
    assert len(loaded["notes"]) == 1


def test_case_update_and_delete_cascades(tmp_path):
    store = Store(tmp_path / "test.db")
    case = store.create_case("A")
    target = store.add_target(case["id"], "domain", "example.com", "example.com")
    changed = store.update_case(case["id"], status="closed")
    assert changed["status"] == "closed"
    assert store.delete_case(case["id"])
    assert store.get_case(case["id"]) is None
    assert store.get_target(target["id"]) is None


def test_schema_two_migrates_without_data_loss(tmp_path):
    path = tmp_path / "old.db"
    conn = sqlite3.connect(path)
    conn.executescript("""
        CREATE TABLE schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        INSERT INTO schema_meta VALUES ('schema_version', '2');
        CREATE TABLE cases (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'open', created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
        CREATE TABLE targets (id INTEGER PRIMARY KEY AUTOINCREMENT, case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE, type TEXT NOT NULL, value TEXT NOT NULL, normalized TEXT NOT NULL, created_at TEXT NOT NULL, UNIQUE(case_id,type,normalized));
        CREATE TABLE artifacts (id INTEGER PRIMARY KEY AUTOINCREMENT, case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE, target_id INTEGER REFERENCES targets(id) ON DELETE SET NULL, type TEXT NOT NULL, source TEXT NOT NULL, data_json TEXT NOT NULL, created_at TEXT NOT NULL);
        CREATE TABLE relationships (id INTEGER PRIMARY KEY AUTOINCREMENT, case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE, source_target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE, relation TEXT NOT NULL, destination_target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE, artifact_id INTEGER REFERENCES artifacts(id) ON DELETE SET NULL, created_at TEXT NOT NULL, UNIQUE(case_id,source_target_id,relation,destination_target_id));
        CREATE TABLE notes (id INTEGER PRIMARY KEY AUTOINCREMENT, case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE, target_id INTEGER REFERENCES targets(id) ON DELETE CASCADE, artifact_id INTEGER REFERENCES artifacts(id) ON DELETE CASCADE, body TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
        INSERT INTO cases VALUES (1, 'preserved', '', 'open', 'now', 'now');
    """)
    conn.commit(); conn.close()
    store = Store(path)
    assert store.get_case(1)["name"] == "preserved"
    with store.connect() as migrated:
        assert "artifact_id" in {row[1] for row in migrated.execute("PRAGMA table_info(relationships)")}
        assert migrated.execute("SELECT value FROM schema_meta WHERE key='schema_version'").fetchone()[0] == "5"
        tables = {row[0] for row in migrated.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        assert {"file_objects", "files", "file_structured_artifacts"} <= tables


def test_schema_three_adds_structured_artifact_association(tmp_path):
    path = tmp_path / "schema3.db"
    store = Store(path)
    case = store.create_case("preserved schema 3")
    with store.connect() as conn:
        conn.execute("DROP TABLE file_structured_artifacts")
        conn.execute("UPDATE schema_meta SET value='3' WHERE key='schema_version'")
    migrated = Store(path)
    assert migrated.get_case(case["id"])["name"] == "preserved schema 3"
    with migrated.connect() as conn:
        assert conn.execute("SELECT value FROM schema_meta WHERE key='schema_version'").fetchone()[0] == "5"


def test_schema_four_adds_binary_candidates_without_data_loss(tmp_path):
    path = tmp_path / "schema4.db"; store = Store(path); case = store.create_case("preserved schema 4")
    with store.connect() as conn:
        conn.execute("DROP TABLE file_candidates")
        conn.execute("UPDATE schema_meta SET value='4' WHERE key='schema_version'")
    migrated = Store(path)
    assert migrated.get_case(case["id"])["name"] == "preserved schema 4"
    with migrated.connect() as conn:
        assert conn.execute("SELECT value FROM schema_meta WHERE key='schema_version'").fetchone()[0] == "5"
        assert {row[1] for row in conn.execute("PRAGMA table_info(file_candidates)")} >= {"file_id", "artifact_id", "normalized_value", "offset"}
        assert conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='file_structured_artifacts'").fetchone()
