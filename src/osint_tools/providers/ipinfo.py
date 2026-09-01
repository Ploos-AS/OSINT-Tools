from __future__ import annotations

import json
import os
import socket
from typing import Any, Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from .base import ProviderError, ProviderResult


class IPInfoProvider:
    id = "ipinfo"
    name = "IPinfo"
    description = "IP network and geolocation metadata"
    supported_target_types = ("ip",)
    operations = ("lookup",)
    required_config = ("IPINFO_TOKEN",)
    default_timeout = 8.0
    _base_url = "https://ipinfo.io"

    def __init__(self, env: Mapping[str, str] | None = None, opener=None):
        self._env = os.environ if env is None else env
        self._opener = urlopen if opener is None else opener

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
            headers={"Accept": "application/json", "Authorization": f"Bearer {token}", "User-Agent": "OSINT-Tools/0.3"},
        )
        try:
            response = self._opener(request, timeout=timeout or self.default_timeout)
            status = getattr(response, "status", 200)
            raw = response.read()
            headers = response.headers
        except (TimeoutError, socket.timeout):
            raise ProviderError("provider_timeout", "provider request timed out", status=504) from None
        except HTTPError as exc:
            raise ProviderError("upstream_http_error", "provider returned an HTTP error", status=502, upstream_status=exc.code) from None
        except URLError as exc:
            if isinstance(exc.reason, (TimeoutError, socket.timeout)):
                raise ProviderError("provider_timeout", "provider request timed out", status=504) from None
            raise ProviderError("provider_unavailable", "provider request failed", status=502) from None
        except Exception:
            raise ProviderError("provider_unavailable", "provider request failed", status=502) from None
        try:
            data = json.loads(raw)
            if not isinstance(data, dict):
                raise ValueError
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
            raise ProviderError("malformed_provider_response", "provider returned a malformed response", status=502) from None
        rate_limit = {}
        for header, key in (("X-RateLimit-Limit", "limit"), ("X-RateLimit-Remaining", "remaining"), ("X-RateLimit-Reset", "reset")):
            value = headers.get(header)
            if value is not None:
                rate_limit[key] = value
        return ProviderResult(data=data, upstream_status=status, rate_limit=rate_limit, metadata={"upstream": "ipinfo.io"})
