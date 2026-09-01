from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol


AV_STATES = {"clean", "detected", "error", "timeout", "unavailable", "unsupported", "skipped"}


@dataclass(frozen=True)
class AVResult:
    engine: str
    engine_version: str | None
    database_version: str | None
    database_timestamp: str | None
    state: str
    detections: list[dict[str, Any]] = field(default_factory=list)
    scanned_at: str = ""
    duration_ms: int | None = None
    bytes_scanned: int | None = None
    error_code: str | None = None
    message: str | None = None
    provenance: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if self.state not in AV_STATES:
            raise ValueError("invalid antivirus result state")


class AVEngine(Protocol):
    id: str
    name: str

    def status(self) -> dict[str, Any]: ...
    def scan(self, path, size: int, sha256: str, timeout: float, max_response_bytes: int) -> AVResult: ...
