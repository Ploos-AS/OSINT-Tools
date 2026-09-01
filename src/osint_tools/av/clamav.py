from __future__ import annotations

import socket
import time
from datetime import datetime, timezone

from .base import AVResult


def _now() -> str: return datetime.now(timezone.utc).isoformat()


class ClamAVEngine:
    id = "clamav"
    name = "ClamAV"

    def __init__(self, enabled: bool = False, host: str = "clamav", port: int = 3310):
        self.enabled, self.host = bool(enabled), str(host)[:255]
        try: self.port = int(port)
        except (TypeError, ValueError): self.port = 0
        self._last_probe: dict | None = None

    @property
    def configured(self) -> bool: return bool(self.host and 1 <= self.port <= 65535)

    def _connect(self, timeout: float):
        # host/port are process administrator configuration, never request data.
        return socket.create_connection((self.host, self.port), timeout=max(0.01, timeout))

    @staticmethod
    def _read_line(sock, maximum: int) -> bytes:
        value = bytearray()
        while len(value) < maximum:
            chunk = sock.recv(min(256, maximum - len(value)))
            if not chunk: break
            value.extend(chunk)
            # clamd uses newline framing for PING/VERSION, but the
            # zINSTREAM response is NUL terminated (e.g. ``stream: OK\0``).
            # Accept either bounded terminator without treating an embedded
            # response byte as an unbounded read.
            if b"\n" in chunk or b"\0" in chunk: break
        if len(value) >= maximum and b"\n" not in value and b"\0" not in value:
            raise ValueError("response too large")
        raw = bytes(value)
        newline = raw.find(b"\n")
        nul = raw.find(b"\0")
        positions = [p for p in (newline, nul) if p >= 0]
        return raw[:min(positions)].strip() if positions else raw.strip()

    def _version(self, timeout: float, maximum: int) -> tuple[str | None, str | None, str | None]:
        with self._connect(timeout) as sock:
            sock.settimeout(max(0.01, timeout)); sock.sendall(b"VERSION\n")
            line = self._read_line(sock, maximum).decode("utf-8", "replace")[:512]
        if not line.lower().startswith("clamav"):
            raise ValueError("malformed version response")
        parts = line.split("/", 1); engine = parts[0].strip()[:128]; database = parts[1].strip()[:256] if len(parts) > 1 else None
        return engine, database, line

    def status(self) -> dict:
        result = {"id": self.id, "name": self.name, "enabled": self.enabled, "configured": self.configured, "available": False, "engine_version": None, "database_version": None, "database_timestamp": None, "last_probe": self._last_probe}
        if not self.enabled:
            result["status"] = "disabled"; return result
        if not self.configured:
            result["status"] = "unconfigured"; return result
        try:
            with self._connect(2.0) as sock:
                sock.settimeout(2.0); sock.sendall(b"PING\n"); response = self._read_line(sock, 1024)
            if response != b"PONG": raise ValueError("malformed ping response")
            engine, database, raw = self._version(2.0, 4096)
            self._last_probe = {"at": _now(), "status": "available"}
            result.update({"available": True, "status": "available", "engine_version": engine, "database_version": database, "version_metadata": raw})
        except socket.timeout:
            self._last_probe = {"at": _now(), "status": "timeout"}; result.update({"status": "timeout", "error": {"code": "timeout", "message": "ClamAV probe timed out"}})
        except (OSError, ValueError):
            self._last_probe = {"at": _now(), "status": "unavailable"}; result.update({"status": "unavailable", "error": {"code": "unavailable", "message": "ClamAV is unavailable"}})
        return result

    def scan(self, path, size: int, sha256: str, timeout: float = 15.0, max_response_bytes: int = 4096) -> AVResult:
        started = time.monotonic(); scanned = 0; engine_version = database_version = None
        try:
            engine_version, database_version, _ = self._version(timeout, max_response_bytes)
            with self._connect(timeout) as sock:
                sock.settimeout(max(0.01, timeout)); sock.sendall(b"zINSTREAM\0")
                with open(path, "rb") as stream:
                    while True:
                        chunk = stream.read(64 * 1024)
                        if not chunk: break
                        scanned += len(chunk); sock.sendall(len(chunk).to_bytes(4, "big") + chunk)
                sock.sendall((0).to_bytes(4, "big"))
                line = self._read_line(sock, max_response_bytes).decode("utf-8", "replace")[:max_response_bytes]
            lower = line.lower()
            duration = int((time.monotonic() - started) * 1000)
            provenance = {"engine": self.id, "engine_version": engine_version, "database_version": database_version, "sha256": sha256}
            if not lower.startswith("stream:"):
                return AVResult(self.id, engine_version, database_version, None, "error", scanned_at=_now(), duration_ms=duration, bytes_scanned=scanned, error_code="malformed_response", message="ClamAV returned a malformed response", provenance=provenance)
            detail = line.split(":", 1)[1].strip()
            if detail.endswith("FOUND"):
                signature = detail[:-5].strip()[:256]
                return AVResult(self.id, engine_version, database_version, None, "detected", [{"signature": signature}], _now(), duration, scanned, provenance=provenance)
            if detail == "OK":
                if scanned != size:
                    return AVResult(self.id, engine_version, database_version, None, "error", scanned_at=_now(), duration_ms=duration, bytes_scanned=scanned, error_code="incomplete_scan", message="ClamAV did not scan the complete object", provenance=provenance)
                return AVResult(self.id, engine_version, database_version, None, "clean", scanned_at=_now(), duration_ms=duration, bytes_scanned=scanned, provenance=provenance)
            state = "unsupported" if "size limit" in lower or "exceed" in lower else "error"
            return AVResult(self.id, engine_version, database_version, None, state, scanned_at=_now(), duration_ms=duration, bytes_scanned=scanned, error_code="stream_limit" if state == "unsupported" else "clamav_error", message="ClamAV could not complete the scan", provenance=provenance)
        except socket.timeout:
            return AVResult(self.id, engine_version, database_version, None, "timeout", scanned_at=_now(), duration_ms=int((time.monotonic()-started)*1000), bytes_scanned=scanned, error_code="timeout", message="ClamAV scan timed out", provenance={"engine":self.id,"sha256":sha256})
        except ValueError:
            return AVResult(self.id, engine_version, database_version, None, "error", scanned_at=_now(), duration_ms=int((time.monotonic()-started)*1000), bytes_scanned=scanned or None, error_code="malformed_response", message="ClamAV returned a malformed response", provenance={"engine":self.id,"sha256":sha256})
        except OSError:
            return AVResult(self.id, engine_version, database_version, None, "unavailable", scanned_at=_now(), duration_ms=int((time.monotonic()-started)*1000), bytes_scanned=scanned or None, error_code="unavailable", message="ClamAV is unavailable", provenance={"engine":self.id,"sha256":sha256})
