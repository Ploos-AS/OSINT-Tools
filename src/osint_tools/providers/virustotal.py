from __future__ import annotations

import base64
import os
from typing import Any, Mapping
from urllib.parse import quote
from urllib.request import Request

from .base import ProviderError, ProviderResult
from .http import fixed_urlopen, request_json


class VirusTotalProvider:
    id = "virustotal"
    name = "VirusTotal"
    description = "Reputation reports for IPs, domains, URLs, and file hashes"
    supported_target_types = ("ip", "domain", "url", "hash")
    operations = ("lookup",)
    default_operation = "lookup"
    required_config = ("VIRUSTOTAL_API_KEY",)
    default_timeout = 10.0
    _base_url = "https://www.virustotal.com/api/v3"
    _rate_headers = (("X-RateLimit-Limit", "limit"), ("X-RateLimit-Remaining", "remaining"), ("X-RateLimit-Reset", "reset"))

    def __init__(self, env: Mapping[str, str] | None = None, opener=None):
        self._env = os.environ if env is None else env
        self._opener = fixed_urlopen if opener is None else opener

    def configured(self): return bool(self._env.get("VIRUSTOTAL_API_KEY", "").strip())
    def enabled(self): return self._env.get("OSINT_PROVIDER_VIRUSTOTAL_ENABLED", "true").strip().lower() not in ("0", "false", "no", "off")

    def status(self) -> dict[str, Any]:
        return {"id": self.id, "name": self.name, "description": self.description, "enabled": self.enabled(), "configured": self.configured(), "required_configuration": list(self.required_config), "supported_target_types": list(self.supported_target_types), "operations": list(self.operations), "metadata": {"timeout_seconds": self.default_timeout, "upstream": "virustotal.com"}}

    def execute(self, operation, target, *, timeout=None):
        if operation not in self.operations:
            raise ProviderError("unknown_operation", "provider operation not found", status=404)
        key = self._env.get("VIRUSTOTAL_API_KEY", "").strip()
        if not key:
            raise ProviderError("provider_not_configured", "provider is not configured", status=409)
        target_type = target["type"]
        value = target["normalized"]
        if target_type == "url":
            value = base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
            resource = "urls"
        else:
            resource = {"ip": "ip_addresses", "domain": "domains", "hash": "files"}[target_type]
        request = Request(f"{self._base_url}/{resource}/{quote(value, safe='')}", headers={"Accept": "application/json", "x-apikey": key, "User-Agent": "OSINT-Tools/0.3.2"})
        data, status, limits = request_json(self._opener, request, timeout or self.default_timeout, self._rate_headers)
        if not isinstance(data.get("data"), dict):
            raise ProviderError("malformed_provider_response", "provider returned a malformed response", status=502)
        return ProviderResult(data, status, limits, {"upstream": "virustotal.com"})
