from __future__ import annotations

import os
from typing import Any, Mapping
from urllib.parse import quote, urlencode
from urllib.request import Request

from .base import DerivedTarget, ProviderError, ProviderResult
from .http import fixed_urlopen, request_json


class ShodanProvider:
    id = "shodan"
    name = "Shodan"
    description = "Passive host, service, and hostname intelligence"
    supported_target_types = ("ip",)
    operations = ("host",)
    default_operation = "host"
    required_config = ("SHODAN_API_KEY",)
    default_timeout = 10.0
    _base_url = "https://api.shodan.io/shodan/host"

    def __init__(self, env: Mapping[str, str] | None = None, opener=None):
        self._env = os.environ if env is None else env
        self._opener = fixed_urlopen if opener is None else opener
    def configured(self): return bool(self._env.get("SHODAN_API_KEY", "").strip())
    def enabled(self): return self._env.get("OSINT_PROVIDER_SHODAN_ENABLED", "true").strip().lower() not in ("0", "false", "no", "off")
    def status(self) -> dict[str, Any]:
        return {"id": self.id, "name": self.name, "description": self.description, "enabled": self.enabled(), "configured": self.configured(), "required_configuration": list(self.required_config), "supported_target_types": ["ip"], "operations": ["host"], "metadata": {"timeout_seconds": self.default_timeout, "upstream": "api.shodan.io"}}
    def execute(self, operation, target, *, timeout=None):
        if operation not in self.operations: raise ProviderError("unknown_operation", "provider operation not found", status=404)
        key = self._env.get("SHODAN_API_KEY", "").strip()
        if not key: raise ProviderError("provider_not_configured", "provider is not configured", status=409)
        request = Request(f"{self._base_url}/{quote(target['normalized'], safe='')}?{urlencode({'key': key})}", headers={"Accept": "application/json", "User-Agent": "OSINT-Tools/0.3.2"})
        data, status, limits = request_json(self._opener, request, timeout or self.default_timeout)
        hostnames = data.get("hostnames", [])
        if not isinstance(hostnames, list): raise ProviderError("malformed_provider_response", "provider returned a malformed response", status=502)
        pivots = tuple(DerivedTarget(value, "observed_hostname") for value in hostnames if isinstance(value, str))
        return ProviderResult(data, status, limits, {"upstream": "api.shodan.io"}, pivots)
