from __future__ import annotations

import re

FIELDS = {b"Title": "title", b"Author": "author", b"Subject": "subject", b"Creator": "creator", b"Producer": "producer", b"CreationDate": "creation_date", b"ModDate": "modification_date"}


def _text(value: bytes) -> str:
    return value.replace(b"\\(", b"(").replace(b"\\)", b")").decode("utf-8", "replace")[:2048]


def analyze_pdf(path, max_bytes: int) -> dict:
    with open(path, "rb") as stream:
        data = stream.read(max_bytes + 1)
    if not data.startswith(b"%PDF-") or b"%%EOF" not in data:
        return {"status": "failed", "reason": "malformed_pdf"}
    version = data[5:8].decode("ascii", "replace")
    metadata = {}
    for key, name in FIELDS.items():
        match = re.search(rb"/" + key + rb"\s*\((.{0,4096}?)\)", data, re.DOTALL)
        if match: metadata[name] = _text(match.group(1))
    return {"status": "success", "version": version, "page_count": len(re.findall(rb"/Type\s*/Page\b", data)), "encrypted": b"/Encrypt" in data, "javascript_present": bool(re.search(rb"/(JavaScript|JS|OpenAction|AA)\b", data)), "metadata": metadata, "truncated_scan": len(data) > max_bytes}
