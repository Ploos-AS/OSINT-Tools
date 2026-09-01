import io
import os

os.environ.setdefault("OSINT_TOOLS_DATA_DIR", "/tmp/osint-tools-test-import")
from osint_tools import server
from test_binary_analysis import LIMITS, pe_fixture


def handler(path, method="GET"):
    instance = object.__new__(server.Handler); instance.path = path; instance.headers = {}; instance.rfile = io.BytesIO(b"")
    instance.responses = []
    instance._json = lambda status, payload: instance.responses.append((status, payload))
    return instance


def test_candidate_retrieval_and_promotion_api(tmp_path, monkeypatch):
    from osint_tools.files.store import ContentStore
    from osint_tools.files.service import ingest_file
    from osint_tools.storage import Store
    store = Store(tmp_path / "db"); objects = ContentStore(tmp_path / "files"); case = store.create_case("api"); content = pe_fixture()
    file = ingest_file(store, objects, case["id"], io.BytesIO(content), len(content), "x", len(content), binary_limits=LIMITS)
    monkeypatch.setattr(server, "STORE", store)
    request = handler(f"/api/v1/files/{file['id']}/candidates?type=url&limit=10"); request.do_GET()
    assert request.responses[0][0] == 200 and len(request.responses[0][1]["result"]) == 1
    candidate = request.responses[0][1]["result"][0]
    request = handler(f"/api/v1/files/{file['id']}/candidates/{candidate['id']}/promote", "POST"); request.do_POST()
    assert request.responses[0][0] == 200
    assert request.responses[0][1]["result"]["relationship"]["relation"] == "contains_indicator"


def test_candidate_api_errors_are_safe(tmp_path, monkeypatch):
    from osint_tools.storage import Store
    monkeypatch.setattr(server, "STORE", Store(tmp_path / "db"))
    request = handler("/api/v1/files/999/candidates"); request.do_GET()
    assert request.responses[0] == (404, {"ok": False, "error": {"code": "file_not_found", "message": "file not found"}})
