from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from . import __version__
from .core import dns_lookup, http_inspect, ip_info, mail_domain, rdap_lookup, target_dict, detect_target, tls_inspect
from .files import ContentStore, FileError, ingest_file
from .files.budget import AnalysisLimits
from .files.binary_common import BinaryLimits
from .files.candidates import promote_candidate
from .files.detections import DetectionLimits, analyze_detections, import_hashset, import_rule_pack, similar_files
from .files.hashsets import HashSetError
from .files.yara_engine import RuleError, YaraLimits
from .av import AVRegistry, ClamAVEngine
from .av.service import AVError, scan_file
from .pivots import pivot_dns
from .provider_service import enrich_target, execute_provider
from .providers import ProviderError, builtin_registry
from .storage import Store

HOST = os.environ.get("OSINT_TOOLS_HOST", "0.0.0.0")
PORT = int(os.environ.get("OSINT_TOOLS_PORT", "8080"))
DATA_DIR = os.environ.get("OSINT_TOOLS_DATA_DIR", "/data")
STORE = Store(os.path.join(DATA_DIR, "osint-tools.db"))
PROVIDERS = builtin_registry()
FILE_STORE = ContentStore(os.path.join(DATA_DIR, "files"))
MAX_UPLOAD_BYTES = int(os.environ.get("OSINT_TOOLS_MAX_UPLOAD_BYTES", str(25 * 1024 * 1024)))
ANALYSIS_LIMITS = AnalysisLimits(
    max_depth=int(os.environ.get("OSINT_TOOLS_ARCHIVE_MAX_DEPTH", "3")),
    max_members=int(os.environ.get("OSINT_TOOLS_ARCHIVE_MAX_MEMBERS", "1000")),
    max_member_bytes=int(os.environ.get("OSINT_TOOLS_ARCHIVE_MAX_MEMBER_BYTES", str(25 * 1024 * 1024))),
    max_total_bytes=int(os.environ.get("OSINT_TOOLS_ARCHIVE_MAX_TOTAL_BYTES", str(100 * 1024 * 1024))),
    max_ratio=float(os.environ.get("OSINT_TOOLS_ARCHIVE_MAX_RATIO", "100")),
    max_image_pixels=int(os.environ.get("OSINT_TOOLS_IMAGE_MAX_PIXELS", "40000000")),
)
BINARY_LIMITS = BinaryLimits(
    max_scan_bytes=int(os.environ.get("OSINT_TOOLS_BINARY_MAX_SCAN_BYTES", str(16 * 1024 * 1024))),
    max_strings=int(os.environ.get("OSINT_TOOLS_BINARY_MAX_STRINGS", "2000")),
    min_string_length=int(os.environ.get("OSINT_TOOLS_BINARY_MIN_STRING_LENGTH", "4")),
    max_string_length=int(os.environ.get("OSINT_TOOLS_BINARY_MAX_STRING_LENGTH", "1024")),
    max_sections=int(os.environ.get("OSINT_TOOLS_BINARY_MAX_SECTIONS", "256")),
    max_symbols=int(os.environ.get("OSINT_TOOLS_BINARY_MAX_SYMBOLS", "2000")),
    max_imports=int(os.environ.get("OSINT_TOOLS_BINARY_MAX_IMPORTS", "1000")),
    max_exports=int(os.environ.get("OSINT_TOOLS_BINARY_MAX_EXPORTS", "1000")),
    max_candidates=int(os.environ.get("OSINT_TOOLS_BINARY_MAX_CANDIDATES", "500")),
)
DETECTION_LIMITS = DetectionLimits(
    yara=YaraLimits(
        timeout_seconds=float(os.environ.get("OSINT_TOOLS_YARA_TIMEOUT_SECONDS", "5")),
        max_matches=int(os.environ.get("OSINT_TOOLS_YARA_MAX_MATCHES", "100")),
        max_string_matches=int(os.environ.get("OSINT_TOOLS_YARA_MAX_STRING_MATCHES", "100")),
        max_rule_bytes=int(os.environ.get("OSINT_TOOLS_RULE_MAX_BYTES", str(256 * 1024))),
        max_pack_bytes=int(os.environ.get("OSINT_TOOLS_RULEPACK_MAX_BYTES", str(1024 * 1024))),
    ),
    hashset_max_entries=int(os.environ.get("OSINT_TOOLS_HASHSET_MAX_ENTRIES", "100000")),
    hashset_max_bytes=int(os.environ.get("OSINT_TOOLS_HASHSET_MAX_BYTES", str(4 * 1024 * 1024))),
    similar_max_results=int(os.environ.get("OSINT_TOOLS_SIMILAR_MAX_RESULTS", "100")),
)
def _env_bool(name: str, default: bool = False) -> bool:
    return os.environ.get(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int, minimum: int | None = None, maximum: int | None = None) -> int:
    try: value = int(os.environ.get(name, str(default)))
    except (TypeError, ValueError): value = default
    if minimum is not None: value = max(minimum, value)
    if maximum is not None: value = min(maximum, value)
    return value


def _env_float(name: str, default: float, minimum: float | None = None) -> float:
    try: value = float(os.environ.get(name, str(default)))
    except (TypeError, ValueError): value = default
    if minimum is not None: value = max(minimum, value)
    return value


AV_TIMEOUT_SECONDS = _env_float("OSINT_TOOLS_CLAMAV_TIMEOUT_SECONDS", 15.0, 0.01)
AV_MAX_RESPONSE_BYTES = _env_int("OSINT_TOOLS_CLAMAV_MAX_RESPONSE_BYTES", 4096, 256, 1024 * 1024)
AV_SCAN_ON_UPLOAD = _env_bool("OSINT_TOOLS_AV_SCAN_ON_UPLOAD", False)
AV_MAX_ENGINES = _env_int("OSINT_TOOLS_AV_MAX_ENGINES", 4, 1, 32)
AV_REGISTRY = AVRegistry([ClamAVEngine(_env_bool("OSINT_TOOLS_CLAMAV_ENABLED", False), os.environ.get("OSINT_TOOLS_CLAMAV_HOST", "clamav"), _env_int("OSINT_TOOLS_CLAMAV_PORT", 3310, 1, 65535))])


class Handler(BaseHTTPRequestHandler):
    server_version = "OSINT-Tools/0.4.5"

    def log_message(self, fmt, *args):
        print(f"{self.address_string()} - {fmt % args}")

    def _json(self, status: int, payload) -> None:
        data = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _body(self, max_bytes: int = 1024 * 1024) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        if length > max_bytes:
            raise ValueError("request body too large")
        raw = self.rfile.read(length) if length else b"{}"
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise ValueError("JSON object required")
        return value

    def _parts(self):
        parsed = urlsplit(self.path)
        return parsed, [p for p in parsed.path.split("/") if p]

    def do_GET(self):
        parsed, parts = self._parts()
        q = parse_qs(parsed.query)
        try:
            if parsed.path == "/healthz":
                return self._json(200, {"status": "ok"})
            if parsed.path == "/api/v1/info":
                return self._json(200, {"name": "OSINT Tools", "version": __version__, "milestone": "M4.5", "passive_first": True, "data_dir": DATA_DIR, "storage": "sqlite", "max_upload_bytes": MAX_UPLOAD_BYTES, "archive_limits": {"max_depth": ANALYSIS_LIMITS.max_depth, "max_members": ANALYSIS_LIMITS.max_members, "max_member_bytes": ANALYSIS_LIMITS.max_member_bytes, "max_total_bytes": ANALYSIS_LIMITS.max_total_bytes, "max_ratio": ANALYSIS_LIMITS.max_ratio}, "binary_limits": BINARY_LIMITS.__dict__, "detection_limits": {"yara_timeout_seconds": DETECTION_LIMITS.yara.timeout_seconds, "yara_max_matches": DETECTION_LIMITS.yara.max_matches, "hashset_max_entries": DETECTION_LIMITS.hashset_max_entries, "similar_max_results": DETECTION_LIMITS.similar_max_results}, "av_scan_on_upload": AV_SCAN_ON_UPLOAD})
            if parsed.path == "/api/v1/av/engines":
                return self._json(200, {"ok": True, "result": [engine.status() for engine in AV_REGISTRY.list()[:AV_MAX_ENGINES]]})
            if len(parts) == 5 and parts[:3] == ["api", "v1", "av"] and parts[3] == "engines":
                engine=AV_REGISTRY.get(parts[4]); return self._json(200,{"ok":True,"result":engine.status()}) if engine else self._json(404,{"ok":False,"error":{"code":"unknown_engine","message":"antivirus engine not found"}})
            if len(parts) == 4 and parts[:3] == ["api", "v1", "files"]:
                result = STORE.get_file(int(parts[3]))
                return self._json(200, {"ok": True, "result": result}) if result else self._json(404, {"ok": False, "error": {"code": "file_not_found", "message": "file not found"}})
            if len(parts) == 5 and parts[:3] == ["api", "v1", "files"] and parts[4] == "analysis":
                result = STORE.get_file_analysis(int(parts[3]))
                return self._json(200, {"ok": True, "result": result}) if result else self._json(404, {"ok": False, "error": {"code": "file_not_found", "message": "file not found"}})
            if len(parts) == 5 and parts[:3] == ["api", "v1", "files"] and parts[4] == "candidates":
                candidate_type = q.get("type", [None])[0]
                if candidate_type and candidate_type not in {"url", "domain", "ipv4", "ipv6", "email"}:
                    raise ValueError("unsupported candidate type")
                try:
                    result = STORE.list_file_candidates(int(parts[3]), candidate_type, int(q.get("limit", ["100"])[0]), int(q.get("offset", ["0"])[0]))
                except KeyError:
                    return self._json(404, {"ok": False, "error": {"code": "file_not_found", "message": "file not found"}})
                return self._json(200, {"ok": True, "result": result})
            if len(parts) == 5 and parts[:3] == ["api", "v1", "files"] and parts[4] == "detections":
                try: result = STORE.list_file_detections(int(parts[3]))
                except KeyError: return self._json(404, {"ok": False, "error": {"code": "file_not_found", "message": "file not found"}})
                return self._json(200, {"ok": True, "result": result})
            if len(parts) == 5 and parts[:3] == ["api", "v1", "files"] and parts[4] == "similar":
                try: result = similar_files(STORE, int(parts[3]), int(q.get("limit", ["20"])[0]), DETECTION_LIMITS.similar_max_results)
                except KeyError: return self._json(404, {"ok": False, "error": {"code": "file_not_found", "message": "file not found"}})
                return self._json(200, {"ok": True, "result": result})
            if len(parts) == 5 and parts[:3] == ["api", "v1", "files"] and parts[4] == "av":
                try: result=STORE.list_av_results(int(parts[3]))
                except KeyError: return self._json(404,{"ok":False,"error":{"code":"file_not_found","message":"file not found"}})
                return self._json(200,{"ok":True,"result":{"file_id":int(parts[3]),"results":result}})
            if parsed.path == "/api/v1/signatures/rulepacks":
                return self._json(200, {"ok": True, "result": STORE.list_rule_packs()})
            if parsed.path == "/api/v1/signatures/hashsets":
                return self._json(200, {"ok": True, "result": STORE.list_hash_sets()})
            if len(parts) == 5 and parts[:4] == ["api", "v1", "signatures", "hashsets"]:
                result=STORE.get_hash_set(int(parts[4])); return self._json(200,{"ok":True,"result":result}) if result else self._json(404,{"ok":False,"error":{"code":"hash_set_not_found","message":"hash set not found"}})
            if parsed.path == "/api/v1/providers":
                return self._json(200, {"ok": True, "result": [provider.status() for provider in PROVIDERS.list()]})
            if len(parts) == 4 and parts[:3] == ["api", "v1", "providers"]:
                provider = PROVIDERS.get(parts[3])
                return self._json(200, {"ok": True, "result": provider.status()}) if provider else self._provider_error(ProviderError("unknown_provider", "provider not found", status=404))
            if parsed.path == "/api/v1/target":
                return self._json(200, {"ok": True, "result": target_dict(detect_target(self._required(q, "value")))})
            if parsed.path == "/api/v1/ip":
                return self._json(200, {"ok": True, "result": ip_info(self._required(q, "value"))})
            if parsed.path == "/api/v1/dns":
                return self._json(200, {"ok": True, "result": dns_lookup(self._required(q, "domain"))})
            if parsed.path == "/api/v1/rdap":
                return self._json(200, {"ok": True, "result": rdap_lookup(self._required(q, "value"))})
            if parsed.path == "/api/v1/http":
                return self._json(200, {"ok": True, "result": http_inspect(self._required(q, "url"))})
            if parsed.path == "/api/v1/tls":
                host = self._required(q, "host")
                port = int(q.get("port", ["443"])[0])
                return self._json(200, {"ok": True, "result": tls_inspect(host, port)})
            if parsed.path == "/api/v1/mail":
                return self._json(200, {"ok": True, "result": mail_domain(self._required(q, "domain"))})
            if parsed.path == "/api/v1/cases":
                return self._json(200, {"ok": True, "result": STORE.list_cases()})
            if len(parts) == 4 and parts[:3] == ["api", "v1", "cases"]:
                case = STORE.get_case(int(parts[3]))
                return self._json(200, {"ok": True, "result": case}) if case else self._json(404, {"ok": False, "error": "case not found"})
            if len(parts) == 5 and parts[:3] == ["api", "v1", "targets"] and parts[4:] == ["artifacts"]:
                return self._json(200, {"ok": True, "result": STORE.list_target_artifacts(int(parts[3]))})
            return self._json(404, {"ok": False, "error": "not found"})
        except (ValueError, KeyError, json.JSONDecodeError) as exc:
            return self._json(400, {"ok": False, "error": str(exc)})
        except Exception:
            return self._json(502, {"ok": False, "error": {"code": "request_failed", "message": "request failed"}})

    def do_POST(self):
        _, parts = self._parts()
        try:
            if len(parts) == 5 and parts[:3] == ["api", "v1", "cases"] and parts[4] == "files":
                if self.headers.get("Transfer-Encoding"):
                    raise FileError("unsupported_transfer_encoding", "content length is required", 411)
                raw_length = self.headers.get("Content-Length")
                if raw_length is None:
                    raise FileError("content_length_required", "content length is required", 411)
                try:
                    content_length = int(raw_length)
                except ValueError:
                    raise FileError("invalid_content_length", "content length must be an integer", 400) from None
                result = ingest_file(STORE, FILE_STORE, int(parts[3]), self.rfile, content_length, self.headers.get("X-Filename", "unnamed"), MAX_UPLOAD_BYTES, ANALYSIS_LIMITS, BINARY_LIMITS, DETECTION_LIMITS)
                if AV_SCAN_ON_UPLOAD:
                    scan_file(STORE, FILE_STORE, AV_REGISTRY, result["id"], None, AV_TIMEOUT_SECONDS, AV_MAX_RESPONSE_BYTES)
                return self._json(201, {"ok": True, "result": result})
            if len(parts) == 7 and parts[:3] == ["api", "v1", "files"] and parts[4] == "candidates" and parts[6] == "promote":
                return self._json(200, {"ok": True, "result": promote_candidate(STORE, int(parts[3]), int(parts[5]))})
            if parts == ["api", "v1", "signatures", "hashsets"]:
                body = self._body(DETECTION_LIMITS.hashset_max_bytes)
            elif parts == ["api", "v1", "signatures", "rulepacks"]:
                body = self._body(DETECTION_LIMITS.yara.max_pack_bytes)
            else:
                body = self._body()
            if len(parts) == 6 and parts[:3] == ["api", "v1", "files"] and parts[4:] == ["av", "scan"]:
                selected=body.get("engines")
                if selected is not None and (not isinstance(selected,list) or len(selected)>AV_MAX_ENGINES or any(not isinstance(item,str) for item in selected)):
                    raise AVError("invalid_engines", "engines must be a bounded list", 400)
                result=scan_file(STORE, FILE_STORE, AV_REGISTRY, int(parts[3]), selected, AV_TIMEOUT_SECONDS, AV_MAX_RESPONSE_BYTES)
                return self._json(200,{"ok":True,"result":result})
            if parts == ["api", "v1", "signatures", "rulepacks"]:
                return self._json(201, {"ok": True, "result": import_rule_pack(STORE, body, DETECTION_LIMITS)})
            if parts == ["api", "v1", "signatures", "hashsets"]:
                return self._json(201, {"ok": True, "result": import_hashset(STORE, body, DETECTION_LIMITS)})
            if len(parts) == 6 and parts[:3] == ["api", "v1", "files"] and parts[4:] == ["detections", "reanalyze"]:
                file=STORE.get_file(int(parts[3]));
                if file is None: raise FileError("file_not_found", "file not found", 404)
                result=analyze_detections(STORE, FILE_STORE, file, DETECTION_LIMITS)
                return self._json(200, {"ok": True, "result": result})
            if parts == ["api", "v1", "cases"]:
                name = str(body.get("name", "")).strip()
                if not name:
                    raise ValueError("name is required")
                result = STORE.create_case(name, str(body.get("description", "")), str(body.get("status", "open")))
                return self._json(201, {"ok": True, "result": result})
            if len(parts) == 5 and parts[:3] == ["api", "v1", "cases"] and parts[4] == "targets":
                case_id = int(parts[3])
                if STORE.get_case(case_id) is None:
                    return self._json(404, {"ok": False, "error": "case not found"})
                detected = detect_target(str(body.get("value", "")))
                result = STORE.add_target(case_id, detected.type, detected.value, detected.normalized)
                return self._json(201, {"ok": True, "result": result})
            if len(parts) == 5 and parts[:3] == ["api", "v1", "cases"] and parts[4] == "notes":
                case_id = int(parts[3])
                note = STORE.add_note(case_id, str(body.get("body", "")), body.get("target_id"), body.get("artifact_id"))
                return self._json(201, {"ok": True, "result": note})
            if len(parts) == 6 and parts[:3] == ["api", "v1", "targets"] and parts[4:] == ["pivot", "dns"]:
                result = pivot_dns(STORE, int(parts[3]))
                return self._json(200, {"ok": True, "result": result})
            if len(parts) == 7 and parts[:3] == ["api", "v1", "targets"] and parts[4] == "providers":
                result = execute_provider(STORE, PROVIDERS, int(parts[3]), parts[5], parts[6])
                return self._json(201, {"ok": True, "result": result})
            if len(parts) == 5 and parts[:3] == ["api", "v1", "targets"] and parts[4] == "enrich":
                return self._json(200, {"ok": True, "result": enrich_target(STORE, PROVIDERS, int(parts[3]))})
            return self._json(404, {"ok": False, "error": "not found"})
        except ProviderError as exc:
            return self._provider_error(exc)
        except FileError as exc:
            return self._json(exc.status, {"ok": False, "error": exc.payload()})
        except AVError as exc:
            return self._json(exc.status, {"ok": False, "error": exc.payload()})
        except (RuleError, HashSetError) as exc:
            return self._json(422, {"ok": False, "error": {"code": "invalid_signature_material", "message": str(exc)}})
        except (ValueError, KeyError, json.JSONDecodeError) as exc:
            return self._json(400, {"ok": False, "error": str(exc)})
        except Exception:
            return self._json(502, {"ok": False, "error": {"code": "request_failed", "message": "request failed"}})

    def do_PATCH(self):
        _, parts = self._parts()
        try:
            if len(parts) == 4 and parts[:3] == ["api", "v1", "cases"]:
                body = self._body()
                result = STORE.update_case(int(parts[3]), name=body.get("name"), description=body.get("description"), status=body.get("status"))
                return self._json(200, {"ok": True, "result": result}) if result else self._json(404, {"ok": False, "error": "case not found"})
            return self._json(404, {"ok": False, "error": "not found"})
        except (ValueError, json.JSONDecodeError) as exc:
            return self._json(400, {"ok": False, "error": str(exc)})

    def do_DELETE(self):
        _, parts = self._parts()
        if len(parts) == 4 and parts[:3] == ["api", "v1", "cases"]:
            return self._json(200, {"ok": True}) if STORE.delete_case(int(parts[3])) else self._json(404, {"ok": False, "error": "case not found"})
        return self._json(404, {"ok": False, "error": "not found"})

    @staticmethod
    def _required(query: dict, key: str) -> str:
        value = query.get(key, [""])[0].strip()
        if not value:
            raise ValueError(f"{key} is required")
        return value

    def _provider_error(self, exc: ProviderError):
        return self._json(exc.status, {"ok": False, "error": exc.payload()})


def main() -> None:
    print(f"OSINT Tools M4.5 listening on {HOST}:{PORT}", flush=True)
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
