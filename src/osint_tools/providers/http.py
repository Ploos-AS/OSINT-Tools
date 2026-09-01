from __future__ import annotations

import json
import socket
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, build_opener

from .base import ProviderError


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_fixed_opener = build_opener(_NoRedirect())


def fixed_urlopen(request, timeout):
    return _fixed_opener.open(request, timeout=timeout)


def rate_limit(headers, mapping) -> dict[str, str]:
    values = {}
    for header, key in mapping:
        value = headers.get(header) if headers else None
        if value is not None:
            values[key] = str(value)
    return values


def request_json(opener, request, timeout: float, rate_headers=()):
    try:
        response = opener(request, timeout=timeout)
        status = getattr(response, "status", 200)
        raw = response.read()
        headers = response.headers
    except (TimeoutError, socket.timeout):
        raise ProviderError("provider_timeout", "provider request timed out", status=504) from None
    except HTTPError as exc:
        limits = rate_limit(exc.headers, rate_headers)
        if exc.code == 429:
            raise ProviderError("rate_limit_exhausted", "provider rate limit exhausted", status=429, upstream_status=429, rate_limit=limits) from None
        raise ProviderError("upstream_http_error", "provider returned an HTTP error", status=502, upstream_status=exc.code, rate_limit=limits) from None
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
    return data, status, rate_limit(headers, rate_headers)
