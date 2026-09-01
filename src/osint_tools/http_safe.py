from __future__ import annotations

import urllib.error
import urllib.parse
import urllib.request

from .core import _public_host

MAX_REDIRECTS = 5


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def safe_head(url: str, *, timeout: float = 10.0, max_redirects: int = MAX_REDIRECTS):
    opener = urllib.request.build_opener(_NoRedirect)
    current = url
    visited: list[str] = []

    for _ in range(max_redirects + 1):
        parsed = urllib.parse.urlsplit(current)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("only http(s) URLs with a hostname are supported")
        _public_host(parsed.hostname)
        visited.append(current)
        req = urllib.request.Request(current, method="HEAD", headers={"User-Agent": "OSINT-Tools/0.2"})
        try:
            response = opener.open(req, timeout=timeout)
            return response, visited
        except urllib.error.HTTPError as exc:
            if exc.code not in {301, 302, 303, 307, 308}:
                raise
            location = exc.headers.get("Location")
            if not location:
                raise ValueError("redirect without Location header") from exc
            current = urllib.parse.urljoin(current, location)

    raise ValueError("too many redirects")
