from __future__ import annotations

from datetime import datetime, timezone

from .base import AVResult


class AVError(Exception):
    def __init__(self, code: str, message: str, status: int = 400):
        super().__init__(message); self.code, self.message, self.status = code, message, status

    def payload(self): return {"code": self.code, "message": self.message}


def _now() -> str: return datetime.now(timezone.utc).isoformat()


def _skip(engine, code: str, message: str) -> AVResult:
    return AVResult(engine.id, None, None, None, "skipped", scanned_at=_now(), error_code=code, message=message, provenance={"engine": engine.id})


def scan_file(store, objects, registry, file_id: int, engine_ids: list[str] | None = None, timeout: float = 15.0, max_response_bytes: int = 4096) -> list[dict]:
    file = store.get_file(file_id)
    if file is None: raise AVError("file_not_found", "file not found", 404)
    if engine_ids is None: engines = registry.list()
    else:
        engines = []
        for engine_id in engine_ids:
            engine = registry.get(engine_id)
            if engine is None: raise AVError("unknown_engine", "antivirus engine not found", 404)
            if engine not in engines: engines.append(engine)
    results=[]
    for engine in engines:
        try:
            if not getattr(engine, "enabled", False): result=_skip(engine,"disabled","antivirus engine is disabled")
            elif not getattr(engine, "configured", False): result=_skip(engine,"unconfigured","antivirus engine is not configured")
            else:
                status=engine.status()
                if not status.get("available"):
                    state=status.get("status")
                    code="timeout" if state=="timeout" else "unavailable"
                    result=AVResult(engine.id,None,status.get("database_version"),status.get("database_timestamp"),"timeout" if code=="timeout" else "unavailable",scanned_at=_now(),error_code=code,message="antivirus engine is unavailable",provenance={"engine":engine.id})
                else:
                    result=engine.scan(objects.physical_path(file["storage_id"]),file["size"],file["sha256"],timeout,max_response_bytes)
        except Exception:
            result=AVResult(engine.id,None,None,None,"error",scanned_at=_now(),error_code="engine_failure",message="antivirus engine failed",provenance={"engine":engine.id,"sha256":file["sha256"]})
        data={"engine":result.engine,"engine_version":result.engine_version,"database_version":result.database_version,"database_timestamp":result.database_timestamp,"state":result.state,"detections":result.detections,"scanned_at":result.scanned_at,"duration_ms":result.duration_ms,"bytes_scanned":result.bytes_scanned,"error_code":result.error_code,"message":result.message,"provenance":result.provenance}
        results.append(store.persist_av_result(file_id,data))
    return results
