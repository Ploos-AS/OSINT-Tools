import json
import socket
from io import BytesIO
from urllib.error import HTTPError, URLError

import pytest

from osint_tools.provider_service import execute_provider
from osint_tools.providers import ProviderError, ProviderRegistry
from osint_tools.providers.base import ProviderResult
from osint_tools.providers.ipinfo import IPInfoProvider
from osint_tools.storage import Store


class Response:
    def __init__(self, data=b'{"ip":"1.1.1.1"}', status=200, headers=None):
        self._data = data
        self.status = status
        self.headers = headers or {}

    def read(self):
        return self._data


class FakeProvider:
    id = "fake"
    name = "Fake"
    description = "test provider"
    supported_target_types = ("ip",)
    operations = ("lookup",)
    required_config = ("FAKE_TOKEN",)
    default_timeout = 1.0
    default_operation = "lookup"

    def __init__(self, configured=True):
        self._configured = configured

    def configured(self):
        return self._configured

    def status(self):
        return {"id": self.id, "configured": self.configured(), "enabled": self.configured(), "required_configuration": ["FAKE_TOKEN"], "supported_target_types": ["ip"], "operations": ["lookup"]}

    def execute(self, operation, target, *, timeout=None):
        return ProviderResult({"asn": "AS13335"}, 200, {"remaining": "4"}, {"upstream": "fake.example"})


def target_store(tmp_path, target_type="ip"):
    store = Store(tmp_path / "provider.db")
    case = store.create_case("Provider case")
    value = "1.1.1.1" if target_type == "ip" else "example.com"
    target = store.add_target(case["id"], target_type, value, value)
    return store, target


def test_registry_is_explicit_and_rejects_duplicates():
    registry = ProviderRegistry()
    registry.register(FakeProvider())
    assert registry.get("fake").name == "Fake"
    assert [provider.id for provider in registry.list()] == ["fake"]
    with pytest.raises(ValueError):
        registry.register(FakeProvider())


def test_ipinfo_safe_status_and_missing_credentials():
    secret = "do-not-disclose"
    missing = IPInfoProvider(env={})
    assert missing.status()["configured"] is False
    assert "IPINFO_TOKEN" in missing.status()["required_configuration"]
    assert secret not in json.dumps(missing.status())
    with pytest.raises(ProviderError) as caught:
        missing.execute("lookup", {"normalized": "1.1.1.1"})
    assert caught.value.code == "provider_not_configured"
    assert IPInfoProvider(env={"IPINFO_TOKEN": "secret", "OSINT_PROVIDER_IPINFO_ENABLED": "false"}).status()["enabled"] is False


def test_ipinfo_request_and_rate_limit_do_not_expose_token():
    secret = "highly-secret-token"
    captured = {}

    def opener(request, timeout):
        captured["request"] = request
        captured["timeout"] = timeout
        return Response(headers={"X-RateLimit-Remaining": "9"})

    result = IPInfoProvider(env={"IPINFO_TOKEN": secret}, opener=opener).execute("lookup", {"normalized": "1.1.1.1"})
    assert result.data["ip"] == "1.1.1.1"
    assert result.rate_limit == {"remaining": "9"}
    assert captured["request"].full_url == "https://ipinfo.io/1.1.1.1/json"
    assert secret not in captured["request"].full_url
    assert secret not in json.dumps(result.data)


@pytest.mark.parametrize(
    "failure,code,status",
    [
        (TimeoutError(), "provider_timeout", 504),
        (URLError(socket.timeout()), "provider_timeout", 504),
        (HTTPError("https://ipinfo.io", 429, "secret-in-upstream", {}, BytesIO()), "rate_limit_exhausted", 429),
        (URLError("token=must-not-leak"), "provider_unavailable", 502),
    ],
)
def test_ipinfo_structured_safe_failures(failure, code, status):
    def opener(request, timeout):
        raise failure

    with pytest.raises(ProviderError) as caught:
        IPInfoProvider(env={"IPINFO_TOKEN": "must-not-leak"}, opener=opener).execute("lookup", {"normalized": "1.1.1.1"})
    assert caught.value.code == code
    assert caught.value.status == status
    assert "must-not-leak" not in json.dumps(caught.value.payload())


def test_ipinfo_malformed_response():
    provider = IPInfoProvider(env={"IPINFO_TOKEN": "secret"}, opener=lambda request, timeout: Response(b"not-json"))
    with pytest.raises(ProviderError) as caught:
        provider.execute("lookup", {"normalized": "1.1.1.1"})
    assert caught.value.code == "malformed_provider_response"


def test_execution_creates_persistent_artifact_with_provenance(tmp_path):
    store, target = target_store(tmp_path)
    registry = ProviderRegistry()
    registry.register(FakeProvider())
    output = execute_provider(store, registry, target["id"], "fake", "lookup")
    artifact = output["artifact"]
    assert artifact["source"] == "fake"
    assert artifact["data"]["result"] == {"asn": "AS13335"}
    provenance = artifact["data"]["provenance"]
    assert provenance["provider"] == "fake"
    assert provenance["operation"] == "lookup"
    assert provenance["target"]["id"] == target["id"]
    assert provenance["collected_at"]
    assert provenance["rate_limit"] == {"remaining": "4"}
    reloaded = Store(store.path).list_target_artifacts(target["id"])
    assert reloaded[0]["data"] == artifact["data"]


@pytest.mark.parametrize(
    "provider,operation,target_type,expected",
    [
        ("missing", "lookup", "ip", "unknown_provider"),
        ("fake", "missing", "ip", "unknown_operation"),
        ("fake", "lookup", "domain", "unsupported_target_type"),
    ],
)
def test_execution_validation(tmp_path, provider, operation, target_type, expected):
    store, target = target_store(tmp_path, target_type)
    registry = ProviderRegistry()
    registry.register(FakeProvider())
    with pytest.raises(ProviderError) as caught:
        execute_provider(store, registry, target["id"], provider, operation)
    assert caught.value.code == expected


def test_execution_invalid_target_and_not_configured(tmp_path):
    store, target = target_store(tmp_path)
    registry = ProviderRegistry()
    registry.register(FakeProvider(configured=False))
    with pytest.raises(ProviderError) as missing:
        execute_provider(store, registry, 999999, "fake", "lookup")
    assert missing.value.code == "target_not_found"
    with pytest.raises(ProviderError) as unconfigured:
        execute_provider(store, registry, target["id"], "fake", "lookup")
    assert unconfigured.value.code == "provider_not_configured"
