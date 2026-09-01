from __future__ import annotations

from datetime import datetime, timezone
from typing import BinaryIO

from .analysis import identify, safe_filename
from .budget import AnalysisLimits
from .binary_common import BinaryLimits
from .store import ContentStore, UploadError
from .structured import analyze_structured
from ..storage import Store


class FileError(Exception):
    def __init__(self, code: str, message: str, status: int):
        super().__init__(message)
        self.code, self.message, self.status = code, message, status
    def payload(self): return {"code": self.code, "message": self.message}


def ingest_file(store: Store, content_store: ContentStore, case_id: int, stream: BinaryIO, content_length: int, filename: str, max_bytes: int, analysis_limits: AnalysisLimits | None = None, binary_limits: BinaryLimits | None = None) -> dict:
    if store.get_case(case_id) is None:
        raise FileError("case_not_found", "case not found", 404)
    filename = safe_filename(filename)
    try:
        content = content_store.ingest(stream, content_length, max_bytes)
    except UploadError as exc:
        raise FileError(exc.code, exc.message, exc.status) from None
    detected = identify(content.pop("sample"), filename)
    created = content.pop("created")
    ingested_at = datetime.now(timezone.utc).isoformat()
    analysis = {"size": content["size"], "hashes": content["hashes"], "filename": filename, **detected, "ingested_at": ingested_at, "storage_id": content["storage_id"]}
    try:
        file_record = store.add_file_ingestion(case_id, filename, analysis)
    except Exception:
        if created:
            content_store.physical_path(content["storage_id"]).unlink(missing_ok=True)
        raise
    try:
        analyze_structured(store, content_store, file_record, analysis_limits or AnalysisLimits(), binary_limits=binary_limits or BinaryLimits())
    except Exception:
        store.add_structured_artifact(file_record["id"], "structured_analysis_error", {"status": "failed", "reason": "analysis_failed"})
    return file_record
