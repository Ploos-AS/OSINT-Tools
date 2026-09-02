from osint_tools.storage import Store
from osint_tools import ui


def setup(tmp_path):
    s = Store(tmp_path / "db"); c = s.create_case("<script>alert(1)</script>")
    a = s.add_target(c["id"], "domain", "Example.COM", "example.com")
    b = s.add_target(c["id"], "ip", "1.1.1.1", "1.1.1.1")
    art = s.add_artifact(c["id"], a["id"], "dns", "local", {"x": 1})
    s.add_relationship(c["id"], a["id"], "resolved_to", b["id"], art["id"])
    s.add_note(c["id"], "<img src=x onerror=alert(1)>")
    return s, c


def test_graph_and_timeline_are_bounded_deterministic_and_provenanced(tmp_path):
    s, c = setup(tmp_path)
    graph = s.case_graph(c["id"]); assert [n["id"] for n in graph["nodes"]] == [1, 2]; assert graph["edges"][0]["relation"] == "resolved_to" and graph["edges"][0]["artifact_id"] == 1
    assert graph == s.case_graph(c["id"])
    timeline = s.case_timeline(c["id"]); assert timeline and timeline == s.case_timeline(c["id"])
    assert {e["event_type"] for e in timeline} >= {"case_created", "target_added", "artifact_recorded", "note_added"}


def test_graph_and_timeline_render_hostile_values_as_text(tmp_path):
    s, c = setup(tmp_path); body = ui.graph(c, s.case_graph(c["id"])) + ui.timeline(c, s.case_timeline(c["id"]))
    assert "<script>alert(1)</script>" not in body and "<img src=x" not in body
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in body


def test_graph_filters_and_bounds_are_deterministic(tmp_path):
    s, c = setup(tmp_path)
    for i in range(3, 8):
        s.add_target(c["id"], "domain", f"host{i}.example", f"host{i}.example")
    bounded = s.case_graph(c["id"], max_nodes=2, max_edges=1)
    assert len(bounded["nodes"]) == 2 and bounded["truncated"]
    filtered = s.case_graph(c["id"], target_type="domain", relation="resolved_to")
    assert {n["type"] for n in filtered["nodes"]} == {"domain"}
    assert filtered["edges"] == []
    assert filtered == s.case_graph(c["id"], target_type="domain", relation="resolved_to")


def test_timeline_limit_is_bounded(tmp_path):
    s, c = setup(tmp_path)
    for i in range(5):
        s.add_target(c["id"], "domain", f"timeline{i}.example", f"timeline{i}.example")
    events = s.case_timeline(c["id"], limit=3)
    assert len(events) == 3
