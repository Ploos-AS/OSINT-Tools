import json
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
