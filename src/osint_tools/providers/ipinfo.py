from __future__ import annotations

import os
from typing import Any, Mapping
from urllib.parse import quote
from urllib.request import Request

from .base import DerivedTarget, ProviderError, ProviderResult
from .http import fixed_urlopen, request_json


class IPInfoProvider:
    id = "ipinfo"
    name = "IPinfo"
    description = "IP network and geolocation metadata"
    supported_target_types = ("ip",)
    operations = ("lookup",)
    required_config = ("IPINFO_TOKEN",)
    default_timeout = 8.0
    default_operation = "lookup"
    _base_url = "https://ipinfo.io"

    def __init__(self, env: Mapping[str, str] | None = None, opener=None):
        self._env = os.environ if env is None else env
        self._opener = fixed_urlopen if opener is None else opener

    def configured(self) -> bool:
        return bool(self._env.get("IPINFO_TOKEN", "").strip())

    def enabled(self) -> bool:
        return self._env.get("OSINT_PROVIDER_IPINFO_ENABLED", "true").strip().lower() not in ("0", "false", "no", "off")

    def status(self) -> dict[str, Any]:
        return {
            "id": self.id, "name": self.name, "description": self.description,
            "enabled": self.enabled(), "configured": self.configured(),
            "required_configuration": list(self.required_config),
            "supported_target_types": list(self.supported_target_types),
            "operations": list(self.operations),
            "metadata": {"timeout_seconds": self.default_timeout, "upstream": "ipinfo.io"},
        }

    def execute(self, operation: str, target: dict[str, Any], *, timeout: float | None = None) -> ProviderResult:
        if operation not in self.operations:
            raise ProviderError("unknown_operation", "provider operation not found", status=404)
        token = self._env.get("IPINFO_TOKEN", "").strip()
        if not token:
            raise ProviderError("provider_not_configured", "provider is not configured", status=409)
        request = Request(
            f"{self._base_url}/{quote(target['normalized'], safe='')}/json",
            headers={"Accept": "application/json", "Authorization": f"Bearer {token}", "User-Agent": "OSINT-Tools/0.3.2"},
        )
        data, status, limits = request_json(self._opener, request, timeout or self.default_timeout, (("X-RateLimit-Limit", "limit"), ("X-RateLimit-Remaining", "remaining"), ("X-RateLimit-Reset", "reset")))
        pivots = (DerivedTarget(data["hostname"], "observed_hostname"),) if isinstance(data.get("hostname"), str) else ()
        return ProviderResult(data=data, upstream_status=status, rate_limit=limits, metadata={"upstream": "ipinfo.io"}, pivots=pivots)
