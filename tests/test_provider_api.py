import json
import io
import os

os.environ.setdefault("OSINT_TOOLS_DATA_DIR", "/tmp/osint-tools-test-import")
from osint_tools import server
from osint_tools.providers import ProviderRegistry
from osint_tools.providers.ipinfo import IPInfoProvider
from osint_tools.storage import Store


def handler(path, body=None):
    instance = object.__new__(server.Handler)
    instance.path = path
    instance._body = lambda: body or {}
    captured = {}
    def respond(status, payload):
        captured.update(status=status, payload=payload)
        return payload
    instance._json = respond
    return instance, captured


def upload_handler(path, content, filename="sample.bin", length=None):
    instance, captured = handler(path)
    instance.rfile = io.BytesIO(content)
    headers = {"Content-Length": str(len(content) if length is None else length), "X-Filename": filename}
    instance.headers = headers
    return instance, captured


def setup_api(tmp_path):
    server.STORE = Store(tmp_path / "api.db")
    server.PROVIDERS = ProviderRegistry()
    server.PROVIDERS.register(IPInfoProvider(env={}))
    return server.STORE


def test_provider_list_and_status_are_safe(tmp_path):
    setup_api(tmp_path)
    request, response = handler("/api/v1/providers")
    request.do_GET()
    assert response["status"] == 200
    assert response["payload"]["result"][0]["id"] == "ipinfo"
    assert response["payload"]["result"][0]["configured"] is False
    request, response = handler("/api/v1/providers/ipinfo")
    request.do_GET()
    assert response["status"] == 200
    assert response["payload"]["result"]["operations"] == ["lookup"]
    request, response = handler("/api/v1/providers/unknown")
    request.do_GET()
    assert response["status"] == 404
    assert response["payload"]["error"]["code"] == "unknown_provider"


def test_provider_execution_api_validation_and_secret_redaction(tmp_path):
    store = setup_api(tmp_path)
    case = store.create_case("API")
    target = store.add_target(case["id"], "ip", "1.1.1.1", "1.1.1.1")
    request, response = handler(f"/api/v1/targets/{target['id']}/providers/ipinfo/lookup")
    request.do_POST()
    assert response["status"] == 409
    assert response["payload"]["error"]["code"] == "provider_not_configured"
    assert "IPINFO_TOKEN" not in json.dumps(response["payload"])
    request, response = handler("/api/v1/targets/999999/providers/ipinfo/lookup")
    request.do_POST()
    assert response["status"] == 404
    assert response["payload"]["error"]["code"] == "target_not_found"
    request, response = handler(f"/api/v1/targets/{target['id']}/providers/ipinfo/missing")
    request.do_POST()
    assert response["status"] == 404
    assert response["payload"]["error"]["code"] == "unknown_operation"


def test_generic_enrichment_api_reports_unconfigured_as_skipped(tmp_path):
    store = setup_api(tmp_path)
    case = store.create_case("Enrich API")
    target = store.add_target(case["id"], "ip", "1.1.1.1", "1.1.1.1")
    request, response = handler(f"/api/v1/targets/{target['id']}/enrich")
    request.do_POST()
    assert response["status"] == 200
    assert response["payload"]["result"]["summary"] == {"success": 0, "skipped": 1, "failed": 0}
    assert response["payload"]["result"]["results"][0]["reason"]["code"] == "provider_not_configured"


def test_file_upload_and_retrieval_api(tmp_path):
    store = setup_api(tmp_path)
    server.FILE_STORE = server.ContentStore(tmp_path / "files")
    server.MAX_UPLOAD_BYTES = 10
    case = store.create_case("Upload API")
    request, response = upload_handler(f"/api/v1/cases/{case['id']}/files", b"hello", "../hello.txt")
    request.do_POST()
    assert response["status"] == 201
    file_id = response["payload"]["result"]["id"]
    request, response = handler(f"/api/v1/files/{file_id}")
    request.do_GET()
    assert response["payload"]["result"]["original_filename"] == "../hello.txt"
    request, response = handler(f"/api/v1/files/{file_id}/analysis")
    request.do_GET()
    assert response["payload"]["result"]["data"]["detected_type"] == "text"


def test_file_upload_api_errors_are_structured(tmp_path):
    setup_api(tmp_path)
    server.FILE_STORE = server.ContentStore(tmp_path / "files")
    server.MAX_UPLOAD_BYTES = 2
    request, response = upload_handler("/api/v1/cases/999/files", b"x")
    request.do_POST()
    assert response["status"] == 404 and response["payload"]["error"]["code"] == "case_not_found"
    case = server.STORE.create_case("errors")
    request, response = upload_handler(f"/api/v1/cases/{case['id']}/files", b"abc")
    request.do_POST()
    assert response["status"] == 413 and response["payload"]["error"]["code"] == "upload_too_large"
    request, response = upload_handler(f"/api/v1/cases/{case['id']}/files", b"x", length=2)
    request.do_POST()
    assert response["status"] == 400 and response["payload"]["error"]["code"] == "incomplete_upload"
