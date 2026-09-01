from __future__ import annotations

from .archive import analyze_archive
from .budget import AnalysisBudget, AnalysisLimits
from .document import analyze_document
from .image import analyze_image
from .pdf import analyze_pdf
from .binary import analyze_binary
from .binary_common import BinaryLimits
from .detections import DetectionLimits, analyze_detections


def analyze_structured(store, objects, file_record: dict, limits: AnalysisLimits, budget: AnalysisBudget | None = None, depth: int = 0, visited: set[str] | None = None, binary_limits: BinaryLimits | None = None, detection_limits: DetectionLimits | None = None) -> list[dict]:
    budget = budget or AnalysisBudget(limits)
    visited = visited or {file_record["sha256"]}
    artifacts = []
    detected = file_record["detected_type"]
    path = objects.physical_path(file_record["storage_id"])

    if detected in ("zip", "tar", "gzip"):
        archive_data, children = analyze_archive(store, objects, file_record, detected, budget, depth)
        if archive_data is not None:
            artifact = store.add_structured_artifact(file_record["id"], "archive_analysis", archive_data)
            artifacts.append(artifact)
            for child, member, child_depth in children:
                if child["target_id"] != file_record["target_id"]:
                    store.add_relationship(file_record["case_id"], file_record["target_id"], "contains", child["target_id"], artifact["id"])
                if child["sha256"] in visited:
                    member["recursion_status"] = "repeated_content"
                    continue
                visited.add(child["sha256"])
                analyze_structured(store, objects, child, limits, budget, child_depth, visited, binary_limits, detection_limits)

    if detected in ("png", "jpeg", "gif"):
        artifacts.append(store.add_structured_artifact(file_record["id"], "image_metadata", analyze_image(path, limits)))
    elif detected == "pdf":
        artifacts.append(store.add_structured_artifact(file_record["id"], "pdf_metadata", analyze_pdf(path, limits.max_metadata_bytes)))
    if detected == "zip":
        document = analyze_document(path, limits.max_metadata_bytes)
        if document is not None:
            artifacts.append(store.add_structured_artifact(file_record["id"], "document_metadata", document))
    if detected in ("pe", "elf", "macho", "amiga_hunk"):
        binary, candidates = analyze_binary(path, detected, binary_limits or BinaryLimits())
        artifacts.append(store.add_binary_analysis(file_record["id"], binary, candidates))
    artifacts.append(analyze_detections(store, objects, file_record, detection_limits or DetectionLimits()))
    return artifacts
