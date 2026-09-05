from __future__ import annotations

import json
import os
import hashlib
import hmac
from http.cookies import SimpleCookie
from datetime import datetime, timezone, timedelta
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit, unquote

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
from . import ui
from .export import export_json, export_bundle, import_bundle, canonical_case, report_html
from .stix import export_stix, import_stix
from .intelligence import builtin_sources, SourceError, taxii_collections, taxii_objects, misp_event
from .misp import export_event, import_event
from .auth import hash_password, verify_password, token_hash, new_session, allowed, login_limited, note_login_failure

HOST = os.environ.get("OSINT_TOOLS_HOST", "0.0.0.0")
PORT = int(os.environ.get("OSINT_TOOLS_PORT", "8080"))
AUTH_ENABLED = os.environ.get("OSINT_TOOLS_AUTH_ENABLED", "true").strip().lower() not in {"0","false","no","off"}
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
INTELLIGENCE_SOURCES = builtin_sources()


from .access_http import scoped
from .case_access import AccessError, visible_cases, effective_case_access


class Handler(BaseHTTPRequestHandler):
    def _case_access_ui(self, case):
        from .case_access import acl_rows
        with STORE.connect() as conn:
            access=effective_case_access(conn,case['id'],self._auth_user(),AUTH_ENABLED)
            owner=conn.execute('SELECT display_name FROM users WHERE id=?',(case['owner_user_id'],)).fetchone()
            grants=acl_rows(conn,case['id']) if access=='owner' else []
        return ui.case_access(case, access, owner[0] if owner else 'Unassigned legacy case', grants)

    def _auth_user(self):
        if not AUTH_ENABLED: return {"id":0,"username":"local","role":"admin","enabled":1}
        raw=self.headers.get("Cookie",""); c=SimpleCookie(); c.load(raw); token=c.get("osint_session");
        if token:
            s=STORE.get_session(token_hash(token.value))
            if s and s["enabled"] and datetime.fromisoformat(s["expires_at"]) > datetime.now(timezone.utc): return {"id":s["user_id"],"username":s["username"],"display_name":s["display_name"],"role":s["role"],"enabled":s["enabled"]}
        return None
    def _require_auth(self, role="viewer"):
        u=self._auth_user()
        if u is None: self._json(401,{"ok":False,"error":{"code":"unauthenticated","message":"authentication required"}}); return None
        if not allowed(u["role"],role): self._json(403,{"ok":False,"error":{"code":"forbidden","message":"insufficient role"}}); return None
        return u
    def _csrf_ok(self, user):
        if not AUTH_ENABLED: return True
        c=SimpleCookie(); c.load(self.headers.get("Cookie", "")); t=c.get("osint_session")
        if not t: return False
        s=STORE.get_session(token_hash(t.value)); supplied=self.headers.get("X-CSRF-Token", "")
        return bool(s and supplied and hmac.compare_digest(token_hash(supplied), s["csrf_hash"]))
    server_version = "OSINT-Tools/0.6.1"

    def log_message(self, fmt, *args):
        # Do not log query strings: rejected query-only CSRF input may contain a token.
        print(f"{self.address_string()} - {getattr(self, 'command', 'request')} {urlsplit(getattr(self, 'path', '')).path!r}")

    def _json(self, status: int, payload) -> None:
        data = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        if getattr(self, "_set_cookie", None): self.send_header("Set-Cookie", self._set_cookie)
        self.end_headers()
        self.wfile.write(data)

    def _bytes(self, status: int, data: bytes, content_type: str, filename: str | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        if filename:
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.end_headers(); self.wfile.write(data)

    def _html(self, status: int, data: bytes) -> None:
        if AUTH_ENABLED and self._auth_user():
            user=self._auth_user()
            editable=allowed(user['role'],'analyst')
            case_id=getattr(self,'_case_scope',None)
            if case_id is not None:
                with STORE.connect() as conn: editable=effective_case_access(conn,case_id,user,True) in {'editor','owner'}
            if not editable: data=ui.read_only(data)
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers(); self.wfile.write(data)

    def _redirect(self, location: str) -> None:
        self.send_response(303); self.send_header("Location", location); self.send_header("Content-Length", "0")
        if getattr(self, "_set_cookie", None): self.send_header("Set-Cookie", self._set_cookie)
        self.end_headers()

    def _browser_origin_ok(self) -> None:
        origin = self.headers.get("Origin")
        if not origin:
            return
        parsed = urlsplit(origin)
        host = self.headers.get("Host", "")
        if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.netloc != host:
            raise ValueError("cross-origin browser mutation rejected")

    def _form(self) -> dict[str, str]:
        length = int(self.headers.get("Content-Length", "0"))
        if length > 64 * 1024:
            raise ValueError("form body too large")
        raw = self.rfile.read(length) if length else b""
        from urllib.parse import parse_qs
        return {key: values[0] for key, values in parse_qs(raw.decode("utf-8", "replace"), keep_blank_values=True).items()}

    def _ui_error(self, status: int, message: str, case: dict | None = None):
        return self._html(status, ui.page("Request error", f'<p class="error">{ui.esc(message)}</p><p><a href="/cases">Back to cases</a></p>', case))

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

    @scoped
    def do_GET(self):
        parsed, parts = self._parts()
        q = parse_qs(parsed.query)
        try:
            if parsed.path == "/":
                return self._redirect("/cases")
            if parsed.path in {"/static/app.css", "/static/app.js"}:
                filename = parsed.path.rsplit("/", 1)[1]
                try:
                    data = open(os.path.join(os.path.dirname(__file__), "static", filename), "rb").read(256 * 1024)
                except OSError:
                    return self._json(404, {"ok": False, "error": "not found"})
                content_type = "text/css; charset=utf-8" if filename.endswith(".css") else "text/javascript; charset=utf-8"
                self.send_response(200); self.send_header("Content-Type", content_type); self.send_header("X-Content-Type-Options", "nosniff"); self.send_header("Cache-Control", "no-store"); self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data); return
            if parsed.path.startswith("/static/"):
                return self._json(404, {"ok": False, "error": "not found"})
            if parsed.path == "/admin/teams":
                user=self._require_auth("admin")
                if user is None: return
                from .case_access import teams_api
                teams=teams_api(STORE,user,"GET",[],{},AUTH_ENABLED)
                members={t['id']:teams_api(STORE,user,"GET",[str(t['id']),"members"],{},AUTH_ENABLED) for t in teams}
                return self._html(200,ui.page("Teams",ui.teams(teams,members)))
            if parsed.path == "/cases":
                if AUTH_ENABLED and self._auth_user() is None: return self._redirect("/login")
                return self._html(200, ui.page("Cases", ui.cases(visible_cases(STORE,self._auth_user(),AUTH_ENABLED)) + ('<p><a href="/admin/teams">Manage teams</a></p>' if self._auth_user()["role"]=="admin" else "")))
            if parsed.path == "/login":
                return self._html(200, ui.page("Login", '<h1>Sign in</h1><form method="post" action="/ui/login"><label>Username <input name="username" autocomplete="username"></label><label>Password <input type="password" name="password" autocomplete="current-password"></label><button type="submit">Sign in</button></form>'))
            if AUTH_ENABLED and self._auth_user() is None and parsed.path not in {"/healthz","/api/v1/info","/api/v1/auth/status","/api/v1/auth/me"} and not parsed.path.startswith("/static/"):
                return self._redirect("/login") if not parsed.path.startswith("/api/") else self._json(401,{"ok":False,"error":{"code":"unauthenticated","message":"authentication required"}})
            if len(parts) == 3 and parts[0] == "cases" and parts[2] == "report":
                payload = canonical_case(STORE, int(parts[1]))
                if payload is None:
                    return self._html(404, ui.page("Case not found", '<p class="error">Case not found.</p>'))
                return self._html(200, report_html(payload))
            if len(parts) == 5 and parts[:3] == ["api", "v1", "cases"] and parts[4] == "report.html":
                payload = canonical_case(STORE, int(parts[3]))
                if payload is None: return self._json(404, {"ok": False, "error": "case not found"})
                return self._bytes(200, report_html(payload), "text/html; charset=utf-8", f"case-{int(parts[3])}-report.html")
            if len(parts) == 5 and parts[:3] == ["api", "v1", "cases"] and parts[4] == "export":
                raw = export_json(STORE, int(parts[3]), q.get("redaction", ["none"])[0])
                if raw is None: return self._json(404, {"ok": False, "error": "case not found"})
                return self._bytes(200, raw, "application/json; charset=utf-8", f"case-{int(parts[3])}.json")
            if len(parts) == 5 and parts[:3] == ["api", "v1", "cases"] and parts[4] == "stix":
                doc = export_stix(STORE, int(parts[3]))
                if doc is None: return self._json(404, {"ok": False, "error": "case not found"})
                return self._bytes(200, json.dumps(doc, sort_keys=True, separators=(",", ":")).encode(), "application/stix+json", f"case-{int(parts[3])}.stix.json")
            if len(parts) == 5 and parts[:3] == ["api", "v1", "cases"] and parts[4] == "misp":
                doc = export_event(STORE, int(parts[3]))
                if doc is None: return self._json(404, {"ok": False, "error": "case not found"})
                return self._bytes(200, json.dumps(doc, sort_keys=True, separators=(",", ":")).encode(), "application/json; charset=utf-8", f"case-{int(parts[3])}.misp.json")
            if len(parts) == 5 and parts[:3] == ["api", "v1", "cases"] and parts[4] == "bundle":
                raw = export_bundle(STORE, FILE_STORE, int(parts[3]), q.get("redaction", ["none"])[0], q.get("bodies", ["full"])[0] != "metadata-only")
                if raw is None: return self._json(404, {"ok": False, "error": "case not found"})
                return self._bytes(200, raw, "application/zip", f"case-{int(parts[3])}.osintcase")
            if parsed.path == "/api/v1/intelligence/sources": return self._json(200, {"ok": True, "result": [s.status() for s in INTELLIGENCE_SOURCES.list()]})
            if len(parts) == 6 and parts[:4] == ["api", "v1", "intelligence", "sources"] and parts[5] == "collections":
                source=INTELLIGENCE_SOURCES.get(parts[4])
                if source is None: return self._json(404, {"ok": False, "error": "source not found"})
                return self._json(200, {"ok": True, "result": taxii_collections(source)})
            if len(parts) == 2 and parts[0] == "cases":
                case = STORE.get_case(int(parts[1]))
                if case is None: return self._html(404, ui.page("Case not found", '<p class="error">Case not found.</p>'))
                return self._html(200, ui.page(case["name"], ui.workspace(case, STORE.list_case_files(case["id"])) + self._case_access_ui(case), case))
            if len(parts) == 4 and parts[0] == "cases" and parts[2] == "targets":
                case = STORE.get_case(int(parts[1])); target = STORE.get_target(int(parts[3]))
                if case is None or target is None or target["case_id"] != case["id"]: return self._html(404, ui.page("Target not found", '<p class="error">Target not found.</p>'))
                return self._html(200, ui.page(f"Target {target['normalized']}", ui.target(case, target, STORE.list_target_artifacts(target["id"]), [p.status() for p in PROVIDERS.list()]), case))
            if len(parts) == 2 and parts[0] == "files":
                file = STORE.get_file(int(parts[1]))
                if file is None: return self._html(404, ui.page("File not found", '<p class="error">File not found.</p>'))
                return self._html(200, ui.page(file["original_filename"], ui.file_detail(file, STORE.get_file_analysis(file["id"]), STORE.list_file_detections(file["id"]), STORE.list_av_results(file["id"]), STORE.list_file_candidates(file["id"])), STORE.get_case(file["case_id"])))
            if len(parts) == 3 and parts[0] == "cases" and parts[2] in {"graph", "timeline"}:
                case = STORE.get_case(int(parts[1]))
                if case is None: return self._html(404, ui.page("Case not found", '<p class="error">Case not found.</p>'))
                if parts[2] == "graph":
                    target_type = q.get("type", [None])[0] or None
                    relation = q.get("relation", [None])[0] or None
                    if target_type and len(target_type) > 64: target_type = None
                    if relation and len(relation) > 128: relation = None
                    return self._html(200, ui.page("Case graph", ui.graph(case, STORE.case_graph(case["id"], target_type=target_type, relation=relation)), case))
                return self._html(200, ui.page("Case timeline", ui.timeline(case, STORE.case_timeline(case["id"]) or []), case))
            if parsed.path == "/healthz":
                return self._json(200, {"status": "ok"})
            if parsed.path == "/api/v1/info":
                return self._json(200, {"name": "OSINT Tools", "version": __version__, "milestone": "M6.1", "auth_enabled": AUTH_ENABLED, "bootstrap_required": AUTH_ENABLED and STORE.count_users()==0, "passive_first": True, "data_dir": DATA_DIR, "storage": "sqlite", "max_upload_bytes": MAX_UPLOAD_BYTES, "archive_limits": {"max_depth": ANALYSIS_LIMITS.max_depth, "max_members": ANALYSIS_LIMITS.max_members, "max_member_bytes": ANALYSIS_LIMITS.max_member_bytes, "max_total_bytes": ANALYSIS_LIMITS.max_total_bytes, "max_ratio": ANALYSIS_LIMITS.max_ratio}, "binary_limits": BINARY_LIMITS.__dict__, "detection_limits": {"yara_timeout_seconds": DETECTION_LIMITS.yara.timeout_seconds, "yara_max_matches": DETECTION_LIMITS.yara.max_matches, "hashset_max_entries": DETECTION_LIMITS.hashset_max_entries, "similar_max_results": DETECTION_LIMITS.similar_max_results}, "av_scan_on_upload": AV_SCAN_ON_UPLOAD})
            if parsed.path == "/api/v1/auth/status": return self._json(200,{"ok":True,"result":{"enabled":AUTH_ENABLED,"bootstrap_required":AUTH_ENABLED and STORE.count_users()==0,"user":self._auth_user() if AUTH_ENABLED else None}})
            if parsed.path == "/api/v1/auth/me":
                u=self._require_auth(); return None if u is None else self._json(200,{"ok":True,"result":{"id":u["id"],"username":u["username"],"display_name":u.get("display_name",u["username"]),"role":u["role"]}})
            if AUTH_ENABLED and self._auth_user() is None:
                return self._json(401,{"ok":False,"error":{"code":"unauthenticated","message":"authentication required"}})
            if parts == ["api","v1","admin","users"]:
                u=self._require_auth("admin"); return None if u is None else self._json(200,{"ok":True,"result":STORE.list_users(int(q.get("limit",["100"])[0]))})
            if parts == ["api","v1","admin","audit"]:
                u=self._require_auth("admin"); return None if u is None else self._json(200,{"ok":True,"result":STORE.list_audit(int(q.get("limit",["100"])[0]),int(q.get("offset",["0"])[0]))})
            if parsed.path == "/api/v1/av/engines":
                return self._json(200, {"ok": True, "result": [engine.status() for engine in AV_REGISTRY.list()[:AV_MAX_ENGINES]]})
            if len(parts) == 5 and parts[:3] == ["api", "v1", "cases"] and parts[4] == "graph":
                target_type = q.get("type", [None])[0] or None
                relation = q.get("relation", [None])[0] or None
                if target_type and len(target_type) > 64: target_type = None
                if relation and len(relation) > 128: relation = None
                result = STORE.case_graph(int(parts[3]), target_type=target_type, relation=relation); return self._json(200, {"ok": True, "result": result}) if result else self._json(404, {"ok": False, "error": "case not found"})
            if len(parts) == 5 and parts[:3] == ["api", "v1", "cases"] and parts[4] == "timeline":
                result = STORE.case_timeline(int(parts[3])); return self._json(200, {"ok": True, "result": result}) if result is not None else self._json(404, {"ok": False, "error": "case not found"})
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
                try: result = similar_files(STORE, int(parts[3]), int(q.get("limit", ["20"])[0]), DETECTION_LIMITS.similar_max_results, {c["id"] for c in visible_cases(STORE,self._auth_user(),AUTH_ENABLED)})
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
                return self._json(200, {"ok": True, "result": visible_cases(STORE,self._auth_user(),AUTH_ENABLED)})
            if len(parts) == 4 and parts[:3] == ["api", "v1", "cases"]:
                case = STORE.get_case(int(parts[3]))
                return self._json(200, {"ok": True, "result": case}) if case else self._json(404, {"ok": False, "error": "case not found"})
            if len(parts) == 5 and parts[:3] == ["api", "v1", "targets"] and parts[4:] == ["artifacts"]:
                return self._json(200, {"ok": True, "result": STORE.list_target_artifacts(int(parts[3]))})
            return self._json(404, {"ok": False, "error": "not found"})
        except (ValueError, KeyError, json.JSONDecodeError) as exc:
            if not parsed.path.startswith("/api/"):
                return self._ui_error(400, str(exc))
            return self._json(400, {"ok": False, "error": str(exc)})
        except Exception:
            if not parsed.path.startswith("/api/"):
                return self._ui_error(500, "request failed")
            return self._json(502, {"ok": False, "error": {"code": "request_failed", "message": "request failed"}})

    @scoped
    def do_POST(self):
        _, parts = self._parts()
        try:
            if parts == ["api","v1","auth","bootstrap"]:
                if not AUTH_ENABLED or STORE.count_users()!=0: return self._json(409,{"ok":False,"error":{"code":"bootstrap_unavailable","message":"bootstrap is unavailable"}})
                b=self._body(64*1024); username=str(b.get("username","")).strip().lower(); password=str(b.get("password","")); display=str(b.get("display_name") or username)
                if not username or len(username)>64 or not username.replace("_","").replace("-","").isalnum() or not password: raise ValueError("valid username and password are required")
                u=STORE.create_user(username,display,hash_password(password),"admin"); STORE.add_audit("user_created","success",u["id"],u["username"],"user",str(u["id"])); return self._json(201,{"ok":True,"result":u})
            if parts == ["api","v1","auth","login"]:
                b=self._body(64*1024); u=STORE.get_user_by_username(str(b.get("username","")).strip());
                if login_limited(str(b.get("username","")).strip().lower()): return self._json(429,{"ok":False,"error":{"code":"login_rate_limited","message":"Too many login attempts"}})
                if not u or not u["enabled"] or not verify_password(str(b.get("password","")),u["password_hash"]):
                    note_login_failure(str(b.get("username","")).strip().lower())
                    STORE.add_audit("login","failure",None,str(b.get("username","")[:64])); return self._json(401,{"ok":False,"error":{"code":"invalid_credentials","message":"Invalid username or password"}})
                token,csrf=new_session(); expires=(datetime.now(timezone.utc)+timedelta(hours=12)).isoformat(); STORE.create_session(token_hash(token),u["id"],token_hash(csrf),expires); STORE.touch_login(u["id"]); STORE.add_audit("login","success",u["id"],u["username"])
                self._set_cookie=f"osint_session={token}; HttpOnly; SameSite=Lax; Path=/"; return self._json(200,{"ok":True,"result":{"id":u["id"],"username":u["username"],"role":u["role"],"csrf_token":csrf}})
            if parts == ["ui","login"]:
                b=self._form(); u=STORE.get_user_by_username(b.get("username", ""))
                if not u or not u["enabled"] or not verify_password(b.get("password", ""),u["password_hash"]): return self._ui_error(401,"Invalid username or password")
                token,csrf=new_session(); expires=(datetime.now(timezone.utc)+timedelta(hours=12)).isoformat(); STORE.create_session(token_hash(token),u["id"],token_hash(csrf),expires); STORE.touch_login(u["id"]); STORE.add_audit("login","success",u["id"],u["username"]); self._set_cookie=f"osint_session={token}; HttpOnly; SameSite=Lax; Path=/"; return self._redirect("/cases")
            if parts == ["api","v1","auth","logout"]:
                u=self._require_auth();
                if u is None:return None
                c=SimpleCookie(); c.load(self.headers.get("Cookie","")); t=c.get("osint_session");
                if t: STORE.delete_session(token_hash(t.value))
                STORE.add_audit("logout","success",u["id"],u["username"]); return self._json(200,{"ok":True,"result":{"logged_out":True}})
            if AUTH_ENABLED and self._auth_user() is None:
                return self._json(401,{"ok":False,"error":{"code":"unauthenticated","message":"authentication required"}})
            if AUTH_ENABLED and not self._csrf_ok(self._auth_user()):
                return self._json(403,{"ok":False,"error":{"code":"csrf_required","message":"CSRF token required"}})
            preview = ((len(parts) == 7 and parts[:4] == ["api", "v1", "intelligence", "sources"] and parts[6] == "preview") or
                       (len(parts) == 6 and parts[:4] == ["api", "v1", "intelligence", "sources"] and parts[5] == "preview"))
            u = self._require_auth("viewer" if preview else "analyst")
            if u is None: return None
            if parts == ["api","v1","admin","users"]:
                u=self._require_auth("admin")
                if u is None:return None
                b=self._body(64*1024); username=str(b.get("username","")).strip().lower(); password=str(b.get("password","")); role=str(b.get("role","viewer"))
                if role not in {"admin","analyst","viewer"} or not username or not password: raise ValueError("valid user fields are required")
                created=STORE.create_user(username,str(b.get("display_name") or username),hash_password(password),role); STORE.add_audit("user_created","success",u["id"],u["username"],"user",str(created["id"])); return self._json(201,{"ok":True,"result":created})
            if parts and parts[0] == "ui":
                self._browser_origin_ok()
                if parts == ["ui", "cases"]:
                    body = self._form(); name = body.get("name", "").strip()
                    if not name: raise ValueError("name is required")
                    case = STORE.create_case(name, body.get("description", ""), owner_user_id=self._auth_user()["id"] or None)
                    return self._redirect(f"/cases/{case['id']}")
                if len(parts) == 4 and parts[:2] == ["ui", "cases"] and parts[3] == "targets":
                    body = self._form(); case_id = int(parts[2]); detected = detect_target(body.get("value", ""))
                    if STORE.get_case(case_id) is None: return self._ui_error(404, "Case not found")
                    STORE.add_target(case_id, detected.type, detected.value, detected.normalized); return self._redirect(f"/cases/{case_id}")
                if len(parts) == 4 and parts[:2] == ["ui", "cases"] and parts[3] == "files":
                    case_id = int(parts[2]); length = int(self.headers.get("Content-Length", "0"))
                    if self.headers.get("Transfer-Encoding") or length <= 0: raise ValueError("choose a file to upload")
                    result = ingest_file(STORE, FILE_STORE, case_id, self.rfile, length, self.headers.get("X-Filename", "unnamed"), MAX_UPLOAD_BYTES, ANALYSIS_LIMITS, BINARY_LIMITS, DETECTION_LIMITS)
                    return self._redirect(f"/files/{result['id']}")
                if len(parts) == 4 and parts[:2] == ["ui", "targets"] and parts[3] in {"dns", "enrich"}:
                    target_id = int(parts[2])
                    if parts[3] == "dns": pivot_dns(STORE, target_id)
                    else:
                        enrich_target(STORE, PROVIDERS, target_id)
                        STORE.add_audit("provider_enrichment","success",u.get("id") or None,u.get("username"),"target",str(target_id))
                    target = STORE.get_target(target_id); return self._redirect(f"/cases/{target['case_id']}/targets/{target_id}") if target else self._ui_error(404, "Target not found")
                if len(parts) == 5 and parts[:2] == ["ui", "files"] and parts[3] == "av" and parts[4] == "scan":
                    result = scan_file(STORE, FILE_STORE, AV_REGISTRY, int(parts[2]), None, AV_TIMEOUT_SECONDS, AV_MAX_RESPONSE_BYTES)
                    STORE.add_audit("av_scan","success",u.get("id") or None,u.get("username"),"file",parts[2])
                    file = STORE.get_file(int(parts[2])); return self._redirect(f"/files/{file['id']}") if file else self._ui_error(404, "File not found")
                if len(parts) == 5 and parts[:2] == ["ui", "files"] and parts[3:] == ["detections", "reanalyze"]:
                    file_id = int(parts[2]); file = STORE.get_file(file_id)
                    if file is None: return self._ui_error(404, "File not found")
                    analyze_detections(STORE, FILE_STORE, file, DETECTION_LIMITS); return self._redirect(f"/files/{file_id}")
                if len(parts) == 6 and parts[:2] == ["ui", "files"] and parts[3] == "candidates" and parts[5] == "promote":
                    file_id = int(parts[2]); promote_candidate(STORE, file_id, int(parts[4])); return self._redirect(f"/files/{file_id}")
                return self._ui_error(404, "UI action not found")
            if parts == ["api", "v1", "cases", "import"]:
                length = int(self.headers.get("Content-Length", "0"))
                if length <= 0 or length > 64 * 1024 * 1024:
                    raise ValueError("invalid bundle size")
                raw = self.rfile.read(length)
                result=import_bundle(STORE, FILE_STORE, raw, owner_user_id=u["id"] or None); STORE.add_audit("case_import","success",self._auth_user().get("id") or None,self._auth_user().get("username")); return self._json(201, {"ok": True, "result": result})
            if parts == ["api", "v1", "cases", "import", "stix"]:
                length = int(self.headers.get("Content-Length", "0"))
                if length <= 0 or length > 16 * 1024 * 1024: raise ValueError("invalid STIX bundle size")
                result=import_stix(STORE, self.rfile.read(length), owner_user_id=u["id"] or None); STORE.add_audit("stix_import","success",self._auth_user().get("id") or None,self._auth_user().get("username")); return self._json(201, {"ok": True, "result": result})
            if parts == ["api", "v1", "cases", "import", "misp"]:
                result=import_event(STORE, self._body(4 * 1024 * 1024), owner_user_id=u["id"] or None); STORE.add_audit("misp_import","success",self._auth_user().get("id") or None,self._auth_user().get("username")); return self._json(201, {"ok": True, "result": result})
            if len(parts) == 7 and parts[:4] == ["api", "v1", "intelligence", "sources"] and parts[5] in {"taxii", "misp"} and parts[6] in {"preview", "import"}:
                source=INTELLIGENCE_SOURCES.get(parts[4])
                if source is None: raise SourceError("source_not_found", "source not found", 404)
                body=self._body(4 * 1024 * 1024)
                doc=taxii_objects(source, body.get("collection", ""), body.get("limit", 100)) if parts[5] == "taxii" else misp_event(source, str(body.get("event", "")))
                if parts[6] == "preview": return self._json(200, {"ok": True, "result": {"source": source.name, "kind": source.kind, "objects": len(doc.get("objects", [])) if isinstance(doc, dict) else 0, "lossy": True}})
                provenance={"transport":source.kind,"source":source.name,"source_hostname":source.hostname,"collection":body.get("collection")} if source.kind == "taxii" else {"source_format":"MISP","source":source.name,"source_hostname":source.hostname,"event":body.get("event")}
                result = import_stix(STORE, json.dumps(doc).encode(), provenance, owner_user_id=u["id"] or None) if source.kind == "taxii" else import_event(STORE, doc, provenance, owner_user_id=u["id"] or None)
                STORE.add_audit(f"{source.kind}_import","success",u.get("id") or None,u.get("username"))
                return self._json(201, {"ok": True, "result": result})
            if len(parts) == 6 and parts[:4] == ["api", "v1", "intelligence", "sources"] and parts[5] in {"preview", "import"}:
                source = INTELLIGENCE_SOURCES.get(parts[4])
                if source is None: raise SourceError("source_not_found", "source not found", 404)
                body = self._body(4 * 1024 * 1024)
                doc = taxii_objects(source, body.get("collection", ""), body.get("limit", 100)) if source.kind == "taxii" else misp_event(source, str(body.get("event", "")))
                if parts[5] == "preview": return self._json(200, {"ok": True, "result": {"source": source.name, "kind": source.kind, "objects": len(doc.get("objects", [])) if isinstance(doc, dict) else 0, "lossy": True}})
                provenance={"transport":source.kind,"source":source.name,"source_hostname":source.hostname,"collection":body.get("collection")} if source.kind == "taxii" else {"source_format":"MISP","source":source.name,"source_hostname":source.hostname,"event":body.get("event")}
                result = import_stix(STORE, json.dumps(doc).encode(), provenance, owner_user_id=u["id"] or None) if source.kind == "taxii" else import_event(STORE, doc, provenance, owner_user_id=u["id"] or None)
                STORE.add_audit(f"{source.kind}_import","success",u.get("id") or None,u.get("username"))
                return self._json(201, {"ok": True, "result": result})
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
                result = ingest_file(STORE, FILE_STORE, int(parts[3]), self.rfile, content_length, self.headers.get("X-Filename", "unnamed"), MAX_UPLOAD_BYTES, ANALYSIS_LIMITS, BINARY_LIMITS, DETECTION_LIMITS); u=self._auth_user(); STORE.add_audit("file_upload","success",u.get("id") or None,u.get("username"),"file",str(result.get("id")))
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
                result=scan_file(STORE, FILE_STORE, AV_REGISTRY, int(parts[3]), selected, AV_TIMEOUT_SECONDS, AV_MAX_RESPONSE_BYTES); u=self._auth_user(); STORE.add_audit("av_scan","success",u.get("id") or None,u.get("username"),"file",parts[3])
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
                result = STORE.create_case(name, str(body.get("description", "")), str(body.get("status", "open")), owner_user_id=u["id"] or None)
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
                STORE.add_audit("provider_enrichment","success",u.get("id") or None,u.get("username"),"target",parts[3])
                return self._json(201, {"ok": True, "result": result})
            if len(parts) == 5 and parts[:3] == ["api", "v1", "targets"] and parts[4] == "enrich":
                result=enrich_target(STORE, PROVIDERS, int(parts[3])); u=self._auth_user(); STORE.add_audit("provider_enrichment","success",u.get("id") or None,u.get("username"),"target",parts[3]); return self._json(200, {"ok": True, "result": result})
            return self._json(404, {"ok": False, "error": "not found"})
        except AccessError:
            raise
        except ProviderError as exc:
            return self._provider_error(exc)
        except SourceError as exc:
            return self._json(exc.status, {"ok": False, "error": {"code": exc.code, "message": exc.message}})
        except FileError as exc:
            if parts and parts[0] == "ui": return self._ui_error(exc.status, exc.message)
            return self._json(exc.status, {"ok": False, "error": exc.payload()})
        except AVError as exc:
            if parts and parts[0] == "ui": return self._ui_error(exc.status, exc.message)
            return self._json(exc.status, {"ok": False, "error": exc.payload()})
        except (RuleError, HashSetError) as exc:
            return self._json(422, {"ok": False, "error": {"code": "invalid_signature_material", "message": str(exc)}})
        except (ValueError, KeyError, json.JSONDecodeError) as exc:
            if parts and parts[0] == "ui": return self._ui_error(400, str(exc))
            return self._json(400, {"ok": False, "error": str(exc)})
        except Exception:
            if parts and parts[0] == "ui": return self._ui_error(500, "request failed")
            return self._json(502, {"ok": False, "error": {"code": "request_failed", "message": "request failed"}})

    @scoped
    def do_PATCH(self):
        _, parts = self._parts()
        try:
            if AUTH_ENABLED and self._auth_user() is None: return self._json(401,{"ok":False,"error":{"code":"unauthenticated","message":"authentication required"}})
            u=self._require_auth()
            if u is None:return None
            if AUTH_ENABLED and not self._csrf_ok(u): return self._json(403,{"ok":False,"error":{"code":"csrf_required","message":"CSRF token required"}})
            if len(parts)==4 and parts[:3]==["api","v1","cases"]:
                if not allowed(u["role"],"analyst"): return self._json(403,{"ok":False,"error":{"code":"forbidden","message":"insufficient role"}})
                b=self._body(); result=STORE.update_case(int(parts[3]),name=b.get("name"),description=b.get("description"),status=b.get("status")); return self._json(200,{"ok":True,"result":result}) if result else self._json(404,{"ok":False,"error":"case not found"})
            if len(parts)!=5 or parts[:4]!=["api","v1","admin","users"]: return self._json(404,{"ok":False,"error":"not found"})
            if not allowed(u["role"],"admin"): return self._json(403,{"ok":False,"error":{"code":"forbidden","message":"insufficient role"}})
            target=STORE.get_user(int(parts[4]));
            if target is None:return self._json(404,{"ok":False,"error":"user not found"})
            b=self._body(64*1024); changes={k:b[k] for k in ("display_name","role","enabled") if k in b}
            if "enabled" in changes and type(changes["enabled"]) is not bool: raise ValueError("enabled must be boolean")
            if "role" in changes and changes["role"] not in {"admin","analyst","viewer"}: raise ValueError("invalid role")
            if (changes.get("enabled") is False or changes.get("role") not in (None,"admin")) and target["role"]=="admin" and target["enabled"]:
                admins=[x for x in STORE.list_users() if x["role"]=="admin" and x["enabled"] and x["id"]!=target["id"]]
                if not admins: return self._json(409,{"ok":False,"error":{"code":"final_admin","message":"cannot disable or demote final administrator"}})
            result=STORE.update_user(target["id"],**changes); STORE.add_audit("user_updated","success",u["id"],u["username"],"user",str(target["id"]),{"fields":sorted(changes)})
            return self._json(200,{"ok":True,"result":{k:result[k] for k in ("id","username","display_name","role","enabled","created_at","updated_at","last_login_at")}})
        except (ValueError, KeyError, json.JSONDecodeError) as exc:
            return self._json(400,{"ok":False,"error":str(exc)})

    @scoped
    def do_DELETE(self):
        _, parts = self._parts()
        u=self._require_auth("admin")
        if u is None:return None
        if AUTH_ENABLED and not self._csrf_ok(u): return self._json(403,{"ok":False,"error":{"code":"csrf_required","message":"CSRF token required"}})
        if len(parts) == 4 and parts[:3] == ["api", "v1", "cases"]:
            ok=STORE.delete_case(int(parts[3]));
            if ok: STORE.add_audit("case_delete","success",u.get("id") or None,u.get("username"),"case",parts[3])
            return self._json(200, {"ok": True}) if ok else self._json(404, {"ok": False, "error": "case not found"})
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
    print(f"OSINT Tools M6.0 listening on {HOST}:{PORT}", flush=True)
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
