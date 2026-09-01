from __future__ import annotations

import os
from typing import Any, Mapping
from urllib.parse import urlencode
from urllib.request import Request

from .base import ProviderError, ProviderResult
from .http import fixed_urlopen, request_json


class AbuseIPDBProvider:
    id = "abuseipdb"
    name = "AbuseIPDB"
    description = "IP abuse confidence and report metadata"
    supported_target_types = ("ip",)
    operations = ("check",)
    default_operation = "check"
    required_config = ("ABUSEIPDB_API_KEY",)
    default_timeout = 8.0
    _base_url = "https://api.abuseipdb.com/api/v2/check"
    _rate_headers = (("X-RateLimit-Limit", "limit"), ("X-RateLimit-Remaining", "remaining"), ("X-RateLimit-Reset", "reset"))

    def __init__(self, env: Mapping[str, str] | None = None, opener=None):
        self._env = os.environ if env is None else env
        self._opener = fixed_urlopen if opener is None else opener
    def configured(self): return bool(self._env.get("ABUSEIPDB_API_KEY", "").strip())
    def enabled(self): return self._env.get("OSINT_PROVIDER_ABUSEIPDB_ENABLED", "true").strip().lower() not in ("0", "false", "no", "off")
    def status(self) -> dict[str, Any]:
        return {"id": self.id, "name": self.name, "description": self.description, "enabled": self.enabled(), "configured": self.configured(), "required_configuration": list(self.required_config), "supported_target_types": ["ip"], "operations": ["check"], "metadata": {"timeout_seconds": self.default_timeout, "upstream": "api.abuseipdb.com"}}
    def execute(self, operation, target, *, timeout=None):
        if operation not in self.operations: raise ProviderError("unknown_operation", "provider operation not found", status=404)
        key = self._env.get("ABUSEIPDB_API_KEY", "").strip()
        if not key: raise ProviderError("provider_not_configured", "provider is not configured", status=409)
        query = urlencode({"ipAddress": target["normalized"], "maxAgeInDays": "90", "verbose": ""})
        request = Request(f"{self._base_url}?{query}", headers={"Accept": "application/json", "Key": key, "User-Agent": "OSINT-Tools/0.3.2"})
        data, status, limits = request_json(self._opener, request, timeout or self.default_timeout, self._rate_headers)
        if not isinstance(data.get("data"), dict): raise ProviderError("malformed_provider_response", "provider returned a malformed response", status=502)
        return ProviderResult(data, status, limits, {"upstream": "api.abuseipdb.com"})
