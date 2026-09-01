from __future__ import annotations

from .core import dns_lookup, detect_target
from .storage import Store


def pivot_dns(store: Store, target_id: int) -> dict:
    target = store.get_target(target_id)
    if target is None:
        raise KeyError("target not found")
    if target["type"] != "domain":
        raise ValueError("DNS pivot requires a domain target")

    result = dns_lookup(target["normalized"])
    artifact = store.add_artifact(target["case_id"], target_id, "dns", "dns", result)
    created_targets = []
    relationships = []

    mapping = {
        "A": ("ip", "resolves_to"),
        "AAAA": ("ip", "resolves_to"),
        "NS": ("domain", "nameserver"),
        "CNAME": ("domain", "cname"),
    }
    for record_type, (target_type, relation) in mapping.items():
        for raw_value in result.get("records", {}).get(record_type, []):
            value = raw_value.rstrip(".")
            try:
                detected = detect_target(value)
            except ValueError:
                continue
            if detected.type != target_type:
                continue
            child = store.add_target(target["case_id"], detected.type, value, detected.normalized)
            rel = store.add_relationship(target["case_id"], target_id, relation, child["id"])
            created_targets.append(child)
            relationships.append(rel)

    return {
        "artifact": artifact,
        "targets": created_targets,
        "relationships": relationships,
    }
