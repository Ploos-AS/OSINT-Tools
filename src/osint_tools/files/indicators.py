from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit

URL = re.compile(r"https?://[^\s\"'<>]{3,2048}", re.I)
EMAIL = re.compile(r"(?<![\w.+-])([A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64})@([A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,63})(?![\w.-])")
IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
IPV6 = re.compile(r"(?<![\w:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![\w:])")
DOMAIN = re.compile(r"(?<![@\w.-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}(?![\w.-])")


def extract_candidates(strings: list[dict], maximum: int) -> tuple[list[dict], bool]:
    results, seen = [], set()
    for item in strings:
        text = item["value"]
        occupied = []
        matches = []
        for match in URL.finditer(text):
            raw = match.group().rstrip(".,;:)")
            parsed = urlsplit(raw)
            if parsed.hostname:
                normalized = urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), parsed.path, parsed.query, ""))
                matches.append((match.start(), match.end(), "url", raw, normalized)); occupied.append((match.start(), match.end()))
        for match in EMAIL.finditer(text):
            raw = match.group(); normalized = match.group(1) + "@" + match.group(2).lower()
            matches.append((match.start(), match.end(), "email", raw, normalized)); occupied.append((match.start(), match.end()))
        for regex, candidate_type in ((IPV4, "ipv4"), (IPV6, "ipv6"), (DOMAIN, "domain")):
            for match in regex.finditer(text):
                if any(start <= match.start() < end for start, end in occupied): continue
                raw = match.group()
                try:
                    normalized = ipaddress.ip_address(raw).compressed if candidate_type in ("ipv4", "ipv6") else raw.rstrip(".").lower()
                except ValueError: continue
                matches.append((match.start(), match.end(), candidate_type, raw, normalized))
        for start, _, candidate_type, raw, normalized in sorted(matches):
            key = (candidate_type, normalized, item["offset"] + start, item["encoding"])
            if key in seen: continue
            seen.add(key)
            results.append({"type": candidate_type, "raw_value": raw[:2048], "normalized_value": normalized[:2048], "offset": item["offset"] + start, "encoding": item["encoding"]})
            if len(results) >= maximum: return results, True
    return results, False
