from __future__ import annotations

import hashlib
import ipaddress
import json
import socket
import ssl
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any

import dns.resolver


@dataclass(frozen=True)
class Target:
    type: str
    value: str
    normalized: str


def detect_target(value: str) -> Target:
    raw = value.strip()
    if not raw:
        raise ValueError("target is required")
    try:
        ip = ipaddress.ip_address(raw)
        return Target("ip", raw, ip.compressed)
    except ValueError:
        pass
    parsed = urllib.parse.urlsplit(raw)
    if parsed.scheme in {"http", "https"} and parsed.hostname:
        normalized = urllib.parse.urlunsplit(
            (parsed.scheme, parsed.netloc, parsed.path, parsed.query, "")
        )
        return Target("url", raw, normalized)
    candidate = raw.rstrip(".").lower()
    if candidate and "." in candidate and all(part and len(part) <= 63 for part in candidate.split(".")):
        allowed = set("abcdefghijklmnopqrstuvwxyz0123456789-")
        if all(set(part) <= allowed and not part.startswith("-") and not part.endswith("-") for part in candidate.split(".")):
            return Target("domain", raw, candidate)
    raise ValueError("unsupported target")


def target_dict(target: Target) -> dict[str, str]:
    return {"type": target.type, "value": target.value, "normalized": target.normalized}


def ip_info(value: str) -> dict[str, Any]:
    ip = ipaddress.ip_address(value.strip())
    return {
        "ip": ip.compressed,
        "version": ip.version,
        "is_private": ip.is_private,
        "is_global": ip.is_global,
        "is_loopback": ip.is_loopback,
        "is_link_local": ip.is_link_local,
        "is_multicast": ip.is_multicast,
        "is_reserved": ip.is_reserved,
        "reverse_pointer": ip.reverse_pointer,
    }


def dns_lookup(domain: str) -> dict[str, Any]:
    domain = domain.strip().rstrip(".").lower()
    records: dict[str, list[str]] = {}
    for record_type in ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA"):
        try:
            answers = dns.resolver.resolve(domain, record_type)
            records[record_type] = [answer.to_text() for answer in answers]
        except Exception:
            records[record_type] = []
    return {"domain": domain, "records": records}


def rdap_lookup(value: str) -> Any:
    target = detect_target(value)
    if target.type == "ip":
        path = f"ip/{urllib.parse.quote(target.normalized, safe='')}"
    elif target.type == "domain":
        path = f"domain/{urllib.parse.quote(target.normalized, safe='')}"
    else:
        raise ValueError("RDAP supports domain or IP targets")
    req = urllib.request.Request(f"https://rdap.org/{path}", headers={"User-Agent": "OSINT-Tools/0.2"})
    with urllib.request.urlopen(req, timeout=15) as response:
        return json.load(response)


def _public_host(host: str) -> list[str]:
    resolved: list[str] = []
    for family, _, _, _, sockaddr in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM):
        address = sockaddr[0]
        ip = ipaddress.ip_address(address)
        if not ip.is_global:
            raise ValueError(f"non-public destination blocked: {address}")
        if address not in resolved:
            resolved.append(address)
    if not resolved:
        raise ValueError("hostname did not resolve")
    return resolved


def http_inspect(url: str) -> dict[str, Any]:
    from .http_safe import safe_head

    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("only http(s) URLs are supported")
    initial_ips = _public_host(parsed.hostname)
    response, visited = safe_head(url)
    try:
        final_url = response.geturl()
        final_host = urllib.parse.urlsplit(final_url).hostname
        final_ips = _public_host(final_host) if final_host else []
        return {
            "requested_url": url,
            "final_url": final_url,
            "status": response.status,
            "resolved_ips": final_ips or initial_ips,
            "redirect_chain": visited,
            "headers": dict(response.headers.items()),
        }
    finally:
        response.close()


def tls_inspect(host: str, port: int = 443) -> dict[str, Any]:
    _public_host(host)
    context = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=10) as sock:
        with context.wrap_socket(sock, server_hostname=host) as tls:
            cert_bin = tls.getpeercert(binary_form=True)
            cert = tls.getpeercert()
            return {
                "host": host,
                "port": port,
                "protocol": tls.version(),
                "cipher": tls.cipher(),
                "sha256": hashlib.sha256(cert_bin).hexdigest(),
                "subject": cert.get("subject", []),
                "issuer": cert.get("issuer", []),
                "notBefore": cert.get("notBefore"),
                "notAfter": cert.get("notAfter"),
                "subjectAltName": cert.get("subjectAltName", []),
            }


def mail_domain(domain: str) -> dict[str, Any]:
    domain = domain.strip().rstrip(".").lower()
    dns = dns_lookup(domain)
    dmarc = dns_lookup(f"_dmarc.{domain}")
    return {
        "domain": domain,
        "mx": dns["records"].get("MX", []),
        "spf": [v for v in dns["records"].get("TXT", []) if "v=spf1" in v.lower()],
        "dmarc": [v for v in dmarc["records"].get("TXT", []) if "v=dmarc1" in v.lower()],
    }
