import json
from io import BytesIO
from urllib.error import HTTPError

import pytest

from osint_tools.providers import builtin_registry
from osint_tools.providers.abuseipdb import AbuseIPDBProvider
from osint_tools.providers.shodan import ShodanProvider
from osint_tools.providers.virustotal import VirusTotalProvider


class Response:
    def __init__(self, payload, headers=None):
        self._raw = json.dumps(payload).encode()
        self.status = 200
        self.headers = headers or {}
    def read(self): return self._raw


CASES = [
    (VirusTotalProvider, "VIRUSTOTAL_API_KEY", "ip", "lookup", {"data": {"id": "1.1.1.1", "attributes": {}}}, "www.virustotal.com"),
    (AbuseIPDBProvider, "ABUSEIPDB_API_KEY", "ip", "check", {"data": {"ipAddress": "1.1.1.1"}}, "api.abuseipdb.com"),
    (ShodanProvider, "SHODAN_API_KEY", "ip", "host", {"ip_str": "1.1.1.1", "hostnames": ["Example.COM"]}, "api.shodan.io"),
]


def test_builtin_registry_expansion_and_safe_status():
    secret = "never-display-this"
    registry = builtin_registry(env={"VIRUSTOTAL_API_KEY": secret})
    assert [p.id for p in registry.list()] == ["abuseipdb", "ipinfo", "shodan", "virustotal"]
    statuses = [p.status() for p in registry.list()]
    assert secret not in json.dumps(statuses)
    assert next(s for s in statuses if s["id"] == "virustotal")["configured"] is True
    assert next(s for s in statuses if s["id"] == "shodan")["configured"] is False


@pytest.mark.parametrize("provider_cls,key,target_type,operation,payload,host", CASES)
def test_new_provider_success_configuration_and_fixed_host(provider_cls, key, target_type, operation, payload, host):
    captured = {}
    def opener(request, timeout):
        captured["request"] = request
        return Response(payload, {"X-RateLimit-Limit": "100", "X-RateLimit-Remaining": "99", "X-RateLimit-Reset": "123"})
    provider = provider_cls(env={key: "secret-value"}, opener=opener)
    assert provider.configured() and provider.enabled()
    assert target_type in provider.supported_target_types
    assert operation in provider.operations
    result = provider.execute(operation, {"type": target_type, "normalized": "1.1.1.1"})
    assert result.upstream_status == 200
    assert captured["request"].full_url.startswith("https://" + host + "/")
    assert "secret-value" not in json.dumps(result.data)
    if provider_cls is not ShodanProvider:
        assert result.rate_limit == {"limit": "100", "remaining": "99", "reset": "123"}


@pytest.mark.parametrize("provider_cls,key,target_type,operation,payload,host", CASES)
def test_new_provider_disabled_unconfigured_timeout_http_and_malformed(provider_cls, key, target_type, operation, payload, host):
    provider = provider_cls(env={})
    assert not provider.configured()
    disabled_name = "OSINT_PROVIDER_" + provider.id.upper() + "_ENABLED"
    assert provider_cls(env={key: "secret", disabled_name: "false"}).enabled() is False
    target = {"type": target_type, "normalized": "1.1.1.1"}
    for failure, code in ((TimeoutError(), "provider_timeout"), (HTTPError("https://fixed", 500, "secret", {}, BytesIO()), "upstream_http_error"), (HTTPError("https://fixed", 429, "secret", {"X-RateLimit-Remaining": "0"}, BytesIO()), "rate_limit_exhausted")):
        def opener(request, timeout, failure=failure): raise failure
        with pytest.raises(Exception) as caught:
            provider_cls(env={key: "secret-value"}, opener=opener).execute(operation, target)
        assert caught.value.code == code
        assert "secret-value" not in json.dumps(caught.value.payload())
        if code == "rate_limit_exhausted" and provider_cls is not ShodanProvider:
            assert caught.value.payload()["rate_limit"]["remaining"] == "0"
    malformed = provider_cls(env={key: "secret"}, opener=lambda request, timeout: Response([]))
    with pytest.raises(Exception) as caught:
        malformed.execute(operation, target)
    assert caught.value.code == "malformed_provider_response"


def test_virustotal_supports_all_enrichment_targets_and_url_is_encoded():
    provider = VirusTotalProvider(env={"VIRUSTOTAL_API_KEY": "secret"}, opener=lambda request, timeout: Response({"data": {}}))
    assert provider.supported_target_types == ("ip", "domain", "url", "hash")
    result = provider.execute("lookup", {"type": "url", "normalized": "https://example.com/a?x=1"})
    assert result.data == {"data": {}}
