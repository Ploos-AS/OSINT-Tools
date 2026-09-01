from __future__ import annotations

import json
import re

ALGORITHMS = {"md5": 32, "sha1": 40, "sha256": 64}
CATEGORIES = {"known_good", "known_bad", "reference", "user_defined", "unknown"}


class HashSetError(Exception):
    pass


def validate_hashset(payload: dict, max_entries: int) -> dict:
    name = str(payload.get("name", "")).strip()[:128]
    version = str(payload.get("version", "")).strip()[:64]
    category = str(payload.get("category", "unknown"))
    if not name or not version or category not in CATEGORIES:
        raise HashSetError("name, version, and valid category are required")
    entries = payload.get("entries")
    if not isinstance(entries, list) or len(entries) > max_entries:
        raise HashSetError("hash-set entries are invalid or exceed the limit")
    normalized = []
    for item in entries:
        if not isinstance(item, dict): raise HashSetError("hash-set entry must be an object")
        algorithm = str(item.get("algorithm", "")).lower().replace("-", "")
        digest = str(item.get("digest", "")).lower()
        if algorithm not in ALGORITHMS or len(digest) != ALGORITHMS[algorithm] or not re.fullmatch("[0-9a-f]+", digest):
            raise HashSetError("hash-set entry has an invalid algorithm or digest")
        metadata=item.get("metadata", {})
        if not isinstance(metadata,dict) or len(json.dumps(metadata,separators=(",",":"),sort_keys=True).encode())>4096:
            raise HashSetError("hash-set entry metadata is invalid or too large")
        tags=item.get("tags",[])
        if not isinstance(tags,list): raise HashSetError("hash-set entry tags must be a list")
        normalized.append({"algorithm": algorithm, "digest": digest, "label": str(item.get("label", ""))[:256], "metadata": metadata, "tags": [str(tag)[:64] for tag in tags[:32]]})
    return {"name": name, "version": version, "source": str(payload.get("source", "local"))[:256], "description": str(payload.get("description", ""))[:1024], "category": category, "entries": normalized}
