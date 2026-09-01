from __future__ import annotations

from ..core import detect_target
from ..storage import Store
from .service import FileError


def promote_candidate(store: Store, file_id: int, candidate_id: int) -> dict:
    file = store.get_file(file_id)
    if file is None:
        raise FileError("file_not_found", "file not found", 404)
    candidate = store.get_file_candidate(file_id, candidate_id)
    if candidate is None:
        raise FileError("candidate_not_found", "candidate not found", 404)
    if not candidate.get("normalized_value") or candidate["type"] == "email":
        raise FileError("candidate_not_promotable", "candidate is not a supported target", 422)
    try:
        detected = detect_target(candidate["normalized_value"])
    except ValueError:
        raise FileError("candidate_not_promotable", "candidate is not a supported target", 422) from None
    expected = "ip" if candidate["type"] in ("ipv4", "ipv6") else candidate["type"]
    if detected.type != expected:
        raise FileError("candidate_not_promotable", "candidate target type is inconsistent", 422)
    target = store.add_target(file["case_id"], detected.type, detected.value, detected.normalized)
    relationship = store.add_relationship(file["case_id"], file["target_id"], "contains_indicator", target["id"], candidate["artifact_id"])
    return {"candidate": candidate, "target": target, "relationship": relationship}
