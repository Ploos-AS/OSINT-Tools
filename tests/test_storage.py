from osint_tools.storage import Store


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
