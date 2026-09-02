#!/bin/sh
set -u

cd "$(dirname "$0")/.." || exit 1
FAILED=0
RESULTS=""

record() {
    RESULTS="${RESULTS}$1|$2|$3
"
    [ "$2" = FAIL ] && FAILED=1
    printf '%-36s %s%s\n' "$1" "$2" "${3:+ — $3}"
}

run_gate() {
    name=$1
    shift
    if "$@"; then record "$name" PASS ""; else record "$name" FAIL "command failed"; fi
}

# Keep runtime failures diagnosable without dumping arbitrary response data.
dump_http_response() {
    label=$1
    file=$2
    printf '%s actual response (bounded): ' "$label" >&2
    python - "$file" <<'PY' 2>/dev/null || true
import json, pathlib, sys
try:
    raw = pathlib.Path(sys.argv[1]).read_bytes()[:8192]
except Exception:
    print("<unavailable>")
    raise SystemExit
try:
    print(json.dumps(json.loads(raw), sort_keys=True)[:8192])
except Exception:
    print(raw.decode("utf-8", "replace")[:8192])
PY
}

extract_id() {
    python - "$1" "$2" <<'PY'
import json, re, sys
path, label = sys.argv[1:]
try:
    value = json.load(open(path)).get("result", {}).get("id")
except Exception as exc:
    print(f"{label} response is not valid JSON: {exc}", file=sys.stderr)
    raise SystemExit(1)
if not isinstance(value, int) or value <= 0:
    print(f"{label} response did not return a valid id", file=sys.stderr)
    raise SystemExit(1)
print(value)
PY
}

run_gate "Python tests" python -m pytest -v
run_gate "git diff --check" git diff --check

# These regressions are named separately so qualification does not imply runtime coverage.
run_gate "SSRF regression" python -m pytest -q tests/test_http_safe.py
run_gate "secret-redaction regression" python -m pytest -q tests/test_providers.py tests/test_m32_providers.py tests/test_provider_api.py
run_gate "M3.1 IPinfo regression" python -m pytest -q tests/test_providers.py
run_gate "M3.2 provider registry" python -m pytest -q tests/test_m32_providers.py
run_gate "M3.2 generic enrichment" python -m pytest -q tests/test_enrichment.py tests/test_provider_api.py
run_gate "artifact persistence" python -m pytest -q tests/test_storage.py tests/test_enrichment.py
run_gate "derived pivot persistence" python -m pytest -q tests/test_enrichment.py::test_generic_enrichment_partial_success_and_pivot_provenance
run_gate "M4.1 file foundation" python -m pytest -q tests/test_files.py tests/test_provider_api.py
run_gate "hash verification" python -m pytest -q tests/test_files.py::test_streaming_hashes_zero_and_exact_limit
run_gate "type detection" python -m pytest -q tests/test_files.py::test_type_detection_and_extension_mismatch
run_gate "hostile filename protection" python -m pytest -q tests/test_files.py -k hostile
run_gate "oversize/partial cleanup" python -m pytest -q tests/test_files.py::test_oversize_and_incomplete_cleanup
run_gate "content deduplication" python -m pytest -q tests/test_files.py::test_content_addressing_and_physical_deduplication
run_gate "file persistence" python -m pytest -q tests/test_files.py::test_file_association_artifact_persistence_and_hash_pivot
run_gate "M4.2 structured analysis" python -m pytest -q tests/test_structured_analysis.py
run_gate "ZIP inventory/child analysis" python -m pytest -q tests/test_structured_analysis.py::test_zip_inventory_child_hash_dedup_and_provenance
run_gate "TAR analysis" python -m pytest -q tests/test_structured_analysis.py::test_tar_regular_and_symlink_are_safe
run_gate "gzip/nested archive" python -m pytest -q tests/test_structured_analysis.py::test_gzip_and_nested_archive
run_gate "archive resource limits" python -m pytest -q tests/test_structured_analysis.py::test_archive_limits
run_gate "archive traversal protection" python -m pytest -q tests/test_structured_analysis.py -k traversal
run_gate "special/encrypted protection" python -m pytest -q tests/test_structured_analysis.py::test_tar_regular_and_symlink_are_safe tests/test_structured_analysis.py::test_malformed_and_encrypted_zip
run_gate "image/EXIF metadata" python -m pytest -q tests/test_structured_analysis.py -k 'image or exif'
run_gate "PDF metadata" python -m pytest -q tests/test_structured_analysis.py::test_pdf_metadata_and_active_indicator
run_gate "office metadata" python -m pytest -q tests/test_structured_analysis.py -k 'office or odf'
run_gate "M4.3 binary analysis" python -m pytest -q tests/test_binary_analysis.py tests/test_binary_api.py
run_gate "binary formats/malformed" python -m pytest -q tests/test_binary_analysis.py -k 'formats_and_malformed or metadata'
run_gate "strings/entropy/candidates" python -m pytest -q tests/test_binary_analysis.py -k 'entropy or candidate'
run_gate "binary ZIP-child analysis" python -m pytest -q tests/test_binary_analysis.py::test_binary_child_inside_zip_uses_existing_pipeline
run_gate "M4.4 rules and detections" python -m pytest -q tests/test_m44_detections.py tests/test_m44_api.py
run_gate "YARA local/nonmatch/malformed" python -m pytest -q tests/test_m44_detections.py -k yara
run_gate "YARA provenance/limits/timeout" python -m pytest -q tests/test_m44_detections.py -k 'rule_pack or yara'
run_gate "known hash/import/provenance" python -m pytest -q tests/test_m44_detections.py -k 'known_hash or hashset'
run_gate "similarity fingerprint/search" python -m pytest -q tests/test_m44_detections.py -k similarity
run_gate "detection reanalysis/idempotency" python -m pytest -q tests/test_m44_detections.py -k reanalysis
run_gate "archive-child detection" python -m pytest -q tests/test_m44_detections.py -k archive_child
run_gate "AV registry" python -m pytest -q tests/test_av.py
run_gate "ClamAV protocol" python -m pytest -q tests/test_av.py -k 'ping or detected or normalized'
run_gate "ClamAV unavailable/failure isolation" python -m pytest -q tests/test_av.py -k 'disabled or persistence'
run_gate "scan-on-upload/archive policy" python -m pytest -q tests/test_av_policy.py
run_gate "M5.1 UI unit tests" python -m pytest -q tests/test_ui.py
run_gate "M5.1 XSS/evidence semantics" python -m pytest -q tests/test_ui.py -k 'escape or distinguish'
run_gate "M5.2 graph unit tests" python -m pytest -q tests/test_m52.py -k graph
run_gate "M5.2 timeline unit tests" python -m pytest -q tests/test_m52.py -k timeline
run_gate "M5.2 graph bounds/filtering" python -m pytest -q tests/test_m52.py::test_graph_filters_and_bounds_are_deterministic
run_gate "M5.2 timeline bounds/ordering" python -m pytest -q tests/test_m52.py::test_timeline_limit_is_bounded tests/test_m52.py::test_graph_and_timeline_are_bounded_deterministic_and_provenanced
run_gate "M5.2 graph/timeline XSS safety" python -m pytest -q tests/test_m52.py::test_graph_and_timeline_render_hostile_values_as_text
run_gate "M5.3 export/import/report unit tests" python -m pytest -q tests/test_m53.py
run_gate "M5.3 canonical export" python -m pytest -q tests/test_m53.py::test_export_is_deterministic_and_redactable
run_gate "M5.3 bundle integrity" python -m pytest -q tests/test_m53.py::test_bundle_manifest_integrity_and_metadata_only
run_gate "M5.3 import safety/round trip" python -m pytest -q tests/test_m53.py::test_import_remaps_and_rejects_tampering
run_gate "M5.3 report semantics/XSS" python -m pytest -q tests/test_m53.py::test_report_escapes_and_preserves_evidence_semantics
run_gate "M5.4 STIX export/import" python -m pytest -q tests/test_m54.py

docker_project="osint-tools-qualify-$$"
docker_port=$((18090 + ($$ % 1000)))
docker_ready=0
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    export OSINT_TOOLS_PORT_PUBLISHED=$docker_port
    export OSINT_TOOLS_MAX_UPLOAD_BYTES=16384
    export OSINT_TOOLS_ARCHIVE_MAX_DEPTH=2 OSINT_TOOLS_ARCHIVE_MAX_MEMBERS=5
    export OSINT_TOOLS_ARCHIVE_MAX_MEMBER_BYTES=1024 OSINT_TOOLS_ARCHIVE_MAX_TOTAL_BYTES=1200 OSINT_TOOLS_ARCHIVE_MAX_RATIO=10
    if docker compose -p "$docker_project" build; then
        record "Docker build" PASS ""
        if docker compose -p "$docker_project" up -d && \
           i=0; while [ "$i" -lt 30 ]; do curl -fsS "http://127.0.0.1:$docker_port/healthz" >/dev/null 2>&1 && break; i=$((i+1)); sleep 1; done; \
           curl -fsS "http://127.0.0.1:$docker_port/healthz" >/dev/null; then
            docker_ready=1
            record "Docker runtime" PASS ""
        else
            record "Docker runtime" FAIL "container did not become healthy"
        fi
    else
        record "Docker build" FAIL "compose build failed"
        record "Docker runtime" SKIPPED "Docker image did not build"
    fi
else
    record "Docker build" SKIPPED "Docker daemon is unavailable"
    record "Docker runtime" SKIPPED "Docker daemon is unavailable"
fi

if [ "$docker_ready" -eq 1 ]; then
    base="http://127.0.0.1:$docker_port"
    tmp_dir=$(mktemp -d)
    api_ok=1
    curl -fsS "$base/api/v1/info" >"$tmp_dir/info.json" || api_ok=0
    python - "$tmp_dir/info.json" <<'PY' || api_ok=0
import json, sys
i = json.load(open(sys.argv[1]))
assert i["version"] == "0.5.4" and i["milestone"] == "M5.4" and i["max_upload_bytes"] == 16384
assert i["binary_limits"]["max_candidates"] == 500
assert i["detection_limits"]["yara_timeout_seconds"] == 5
PY
    curl -fsS "$base/api/v1/providers" >"$tmp_dir/providers.json" || api_ok=0
    case_code=$(curl -sS -o "$tmp_dir/case.json" -w '%{http_code}' -H 'Content-Type: application/json' -d '{"name":"qualification"}' "$base/api/v1/cases" || true)
    [ "$case_code" = 201 ] || api_ok=0
    if case_id=$(extract_id "$tmp_dir/case.json" case); then :; else api_ok=0; case_id=0; fi
    ui_ok=1
    ui_code=$(curl -sS -o /dev/null -w '%{http_code}' "$base/") || ui_ok=0
    [ "$ui_code" = 303 ] || ui_ok=0
    curl -fsS "$base/cases" >"$tmp_dir/cases.html" || ui_ok=0
    curl -fsS "$base/static/app.css" >"$tmp_dir/app.css" || ui_ok=0
    curl -fsS "$base/static/app.js" >"$tmp_dir/app.js" || ui_ok=0
    python - "$tmp_dir/cases.html" <<'PY' || ui_ok=0
from pathlib import Path
s = Path(__import__('sys').argv[1]).read_text()
assert '<script>alert(1)</script>' not in s and 'Content-Security-Policy' not in s
assert 'Cases' in s and '/static/app.css' in s
PY
    [ "$ui_ok" -eq 1 ] && record "M5.1 browser routes" PASS "" || record "M5.1 browser routes" FAIL "UI shell or static asset request failed"
    traversal_code=$(curl --path-as-is -sS -o /dev/null -w '%{http_code}' "$base/static/../server.py" || true)
    [ "$traversal_code" = 404 ] && record "M5.1 static traversal protection" PASS "" || record "M5.1 static traversal protection" FAIL "static path traversal was not rejected"
    origin_code=$(curl -sS -o /dev/null -w '%{http_code}' -X POST -H 'Origin: https://evil.invalid' -d 'name=blocked' "$base/ui/cases" || true)
    [ "$origin_code" = 400 ] && record "M5.1 browser mutation protection" PASS "" || record "M5.1 browser mutation protection" FAIL "cross-origin UI mutation was accepted"
    ui_case_code=$(curl -sS -o /dev/null -w '%{http_code}' -X POST -d 'name=UI+qualification&description=browser+workflow' "$base/ui/cases") || ui_case_code=000
    [ "$ui_case_code" = 303 ] && record "M5.1 case workflow" PASS "" || record "M5.1 case workflow" FAIL "browser case creation failed"
    curl -fsS "$base/cases/$case_id" >"$tmp_dir/workspace.html" && grep -q 'Targets' "$tmp_dir/workspace.html" && record "M5.1 file evidence rendering" PASS "" || record "M5.1 file evidence rendering" FAIL "case workspace unavailable"
    curl -fsS "$base/cases/$case_id" | grep -q '<h1>' && record "M5.1 no-JS browsing" PASS "server-rendered HTML" || record "M5.1 no-JS browsing" FAIL "HTML workspace unavailable"
    ui_target_code=$(curl -sS -o /dev/null -w '%{http_code}' -X POST -d 'value=example.com' "$base/ui/cases/$case_id/targets" || true)
    target_id=0
    if [ "$ui_target_code" = 303 ]; then
        curl -fsS "$base/api/v1/cases/$case_id" >"$tmp_dir/ui-target-case.json" || true
        target_id=$(python - "$tmp_dir/ui-target-case.json" <<'PY'
import json, sys
items=json.load(open(sys.argv[1])).get("result", {}).get("targets", [])
matches=[x["id"] for x in items if x.get("normalized") == "example.com" and isinstance(x.get("id"), int)]
if not matches: raise SystemExit(1)
print(matches[-1])
PY
        ) || target_id=0
    fi
    target_html_ok=1
    target_page=$(curl -si "$base/cases/$case_id/targets/$target_id" 2>/dev/null || true)
    printf '%s' "$target_page" | grep -qi 'Content-Type: text/html' || target_html_ok=0
    printf '%s' "$target_page" | grep -q 'Provider status' || target_html_ok=0
    printf '%s' "$target_page" | grep -q 'example.com' || target_html_ok=0
    if [ "$target_id" -gt 0 ] && [ "$target_html_ok" -eq 1 ]; then record "M5.1 target workflow" PASS "browser mutation, HTML detail, and normalized value verified"; else record "M5.1 target workflow" FAIL "target creation did not return a valid target id or detail failed"; fi
    upload_code=$(printf 'ui upload fixture' | curl -sS -o "$tmp_dir/ui-upload.json" -w '%{http_code}' -X POST -H 'X-Filename: ui.txt' --data-binary @- "$base/api/v1/cases/$case_id/files" || true)
    [ "$upload_code" = 201 ] && record "M5.1 file upload workflow" PASS "" || record "M5.1 file upload workflow" FAIL "file upload failed"
    [ "$ui_ok" -eq 1 ] && record "M5.1 API compatibility" PASS "" || record "M5.1 API compatibility" FAIL "UI checks failed"
    m52_ok=1
    curl -fsS "$base/api/v1/cases/$case_id/graph" >"$tmp_dir/graph.json" || m52_ok=0
    curl -fsS "$base/api/v1/cases/$case_id/timeline" >"$tmp_dir/timeline.json" || m52_ok=0
    curl -fsS "$base/cases/$case_id/graph" >"$tmp_dir/graph.html" || m52_ok=0
    curl -fsS "$base/cases/$case_id/timeline" >"$tmp_dir/timeline.html" || m52_ok=0
    python - "$tmp_dir/graph.json" "$tmp_dir/timeline.json" "$tmp_dir/graph.html" "$tmp_dir/timeline.html" <<'PY' || m52_ok=0
import json, sys
g=json.load(open(sys.argv[1]))["result"]; t=json.load(open(sys.argv[2]))["result"]
assert "nodes" in g and "edges" in g and isinstance(t,list)
assert "Relationship graph" in open(sys.argv[3]).read() and "Timeline" in open(sys.argv[4]).read()
PY
    [ "$m52_ok" -eq 1 ] && record "M5.2 graph API" PASS "" || record "M5.2 graph API" FAIL "graph API failed"
    [ "$m52_ok" -eq 1 ] && record "M5.2 graph UI" PASS "" || record "M5.2 graph UI" FAIL "graph HTML failed"
    [ "$m52_ok" -eq 1 ] && record "M5.2 timeline API" PASS "" || record "M5.2 timeline API" FAIL "timeline API failed"
    [ "$m52_ok" -eq 1 ] && record "M5.2 timeline UI" PASS "" || record "M5.2 timeline UI" FAIL "timeline HTML failed"
    [ "$m52_ok" -eq 1 ] && record "M5.2 no-JS relationship fallback" PASS "" || record "M5.2 no-JS relationship fallback" FAIL "relationship fallback unavailable"
    csp_headers=$(curl -sS -D - -o /dev/null "$base/cases/$case_id/graph" || true)
    printf '%s' "$csp_headers" | grep -q "Content-Security-Policy:" && ! printf '%s' "$csp_headers" | grep -qi "unsafe-inline\|unsafe-eval" && record "M5.2 CSP compatibility" PASS "restrictive CSP served" || record "M5.2 CSP compatibility" FAIL "restrictive CSP missing or weakened"
    before_targets=$(curl -fsS "$base/api/v1/cases/$case_id" | python -c 'import json,sys; print(len(json.load(sys.stdin)["result"]["targets"]))') || before_targets=0
    curl -fsS "$base/api/v1/cases/$case_id/graph" >/dev/null && curl -fsS "$base/api/v1/cases/$case_id/timeline" >/dev/null || true
    after_targets=$(curl -fsS "$base/api/v1/cases/$case_id" | python -c 'import json,sys; print(len(json.load(sys.stdin)["result"]["targets"]))') || after_targets=-1
    [ "$before_targets" = "$after_targets" ] && record "M5.2 GET non-mutation" PASS "graph/timeline reads preserved target count" || record "M5.2 GET non-mutation" FAIL "read-only graph/timeline changed state"
    m53_ok=1
    curl -fsS "$base/api/v1/cases/$case_id/export" >"$tmp_dir/case-export.json" || m53_ok=0
    curl -fsS "$base/api/v1/cases/$case_id/bundle" >"$tmp_dir/case.osintcase" || m53_ok=0
    curl -fsS "$base/cases/$case_id/report" >"$tmp_dir/report.html" || m53_ok=0
    import_code=$(curl -sS -o "$tmp_dir/import.json" -w '%{http_code}' -X POST -H 'Content-Type: application/zip' --data-binary @"$tmp_dir/case.osintcase" "$base/api/v1/cases/import" || true)
    [ "$import_code" = 201 ] || m53_ok=0
    python - "$tmp_dir/case-export.json" "$tmp_dir/import.json" "$tmp_dir/report.html" <<'PY' || m53_ok=0
import json,sys
payload=json.load(open(sys.argv[1])); imported=json.load(open(sys.argv[2])); report=open(sys.argv[3]).read()
assert payload["format"] == "osint-tools-case" and payload["format_version"] == 1
assert imported["result"]["case_id"] != payload["case"].get("id")
assert "No universal risk verdict" in report
PY
    [ "$m53_ok" -eq 1 ] && record "M5.3 export/import/report runtime" PASS "JSON, bundle, report, and remapped import verified" || record "M5.3 export/import/report runtime" FAIL "export/import/report runtime failed"
    # M2 uses the target created through the browser mutation above; no
    # second target is needed and the ID has already been validated.
    m2_ok=1
    if [ "$target_id" -le 0 ]; then m2_ok=0; else curl -sS -X POST -H 'Content-Type: application/json' -d '{}' "$base/api/v1/targets/$target_id/pivot/dns" -o "$tmp_dir/pivot.json" -w '%{http_code}' >"$tmp_dir/pivot.status" || m2_ok=0; [ "$(cat "$tmp_dir/pivot.status")" = 200 ] || m2_ok=0; fi
    if [ "$m2_ok" -ne 1 ] && [ -f "$tmp_dir/pivot.json" ]; then dump_http_response "M2 DNS pivot" "$tmp_dir/pivot.json"; fi
    [ "$m2_ok" -eq 1 ] && record "M2 regression" PASS "" || record "M2 regression" FAIL "representative case/target/DNS pivot failed"

    av_ok=1
    curl -fsS "$base/api/v1/av/engines" >"$tmp_dir/av-engines.json" || av_ok=0
    code=$(curl -sS -o "$tmp_dir/av-scan.json" -w '%{http_code}' -X POST -H 'Content-Type: application/json' -d '{"engines":["clamav"],"host":"127.0.0.1","port":1}' "$base/api/v1/files/999/av/scan" || true)
    python - "$tmp_dir/av-engines.json" <<'PY' || av_ok=0
import json,sys
items=json.load(open(sys.argv[1]))["result"]
assert any(item["id"]=="clamav" and item["enabled"] is False for item in items)
PY
    [ "$av_ok" -eq 1 ] && record "AV disabled behavior" PASS "" || record "AV disabled behavior" FAIL "optional AV status contract failed"

    provider_ok=1
    code=$(curl -sS -o "$tmp_dir/provider-error.json" -w '%{http_code}' -X POST -H 'Content-Type: application/json' -d '{}' "$base/api/v1/targets/$target_id/providers/ipinfo/lookup") || provider_ok=0
    [ "$code" = 422 ] || provider_ok=0
    python - "$tmp_dir/providers.json" "$tmp_dir/provider-error.json" <<'PY' || provider_ok=0
import json, sys
p = json.load(open(sys.argv[1]))
e = json.load(open(sys.argv[2]))
assert {item["id"] for item in p["result"]} == {"ipinfo", "virustotal", "abuseipdb", "shodan"}
assert e["error"]["code"] == "unsupported_target_type"
PY
    ip_code=$(curl -sS -o "$tmp_dir/ip.json" -w '%{http_code}' -H 'Content-Type: application/json' -d '{"value":"1.1.1.1"}' "$base/api/v1/cases/$case_id/targets" || true)
    [ "$ip_code" = 201 ] || provider_ok=0
    if ip_id=$(extract_id "$tmp_dir/ip.json" ip); then :; else provider_ok=0; ip_id=0; fi
    code=$(curl -sS -o "$tmp_dir/unconfigured.json" -w '%{http_code}' -X POST -H 'Content-Type: application/json' -d '{}' "$base/api/v1/targets/$ip_id/providers/ipinfo/lookup") || provider_ok=0
    [ "$code" = 409 ] || provider_ok=0
    python - "$tmp_dir/unconfigured.json" <<'PY' || provider_ok=0
import json, sys
e = json.load(open(sys.argv[1]))
assert e["error"]["code"] == "provider_not_configured"
assert "TOKEN" not in json.dumps(e)
PY
    [ "$provider_ok" -eq 1 ] && record "M3.1 provider framework runtime" PASS "" || record "M3.1 provider framework runtime" FAIL "provider runtime contract failed"

    enrich_ok=1
    curl -fsS -X POST -H 'Content-Type: application/json' -d '{}' "$base/api/v1/targets/$ip_id/enrich" >"$tmp_dir/enrich.json" || enrich_ok=0
    python - "$tmp_dir/enrich.json" <<'PY' || enrich_ok=0
import json, sys
r = json.load(open(sys.argv[1]))["result"]
assert r["summary"] == {"success": 0, "skipped": 4, "failed": 0}
assert all(item["reason"]["code"] == "provider_not_configured" for item in r["results"])
PY
    [ "$enrich_ok" -eq 1 ] && record "M3.2 enrichment runtime" PASS "" || record "M3.2 enrichment runtime" FAIL "generic enrichment contract failed"

    m4_ok=1
    m4_case_code=$(curl -sS -o "$tmp_dir/m4-case.json" -w '%{http_code}' -H 'Content-Type: application/json' -d '{"name":"m4.1-upload-qualification"}' "$base/api/v1/cases" || true)
    [ "$m4_case_code" = 201 ] || m4_ok=0
    if m4_case_id=$(extract_id "$tmp_dir/m4-case.json" m4-case); then :; else m4_ok=0; m4_case_id=0; fi
    object_count_before=$(docker compose -p "$docker_project" exec -T osint-tools sh -c 'find /data/files/sha256 -type f | wc -l') || m4_ok=0
    : >"$tmp_dir/empty"
    printf 'deterministic text fixture\n' >"$tmp_dir/text"
    printf '\211PNG\r\n\032\nfixture' >"$tmp_dir/image"
    cp "$tmp_dir/text" "$tmp_dir/duplicate"
    text_sha=$(sha256sum "$tmp_dir/text" | cut -d' ' -f1)
    text_md5=$(md5sum "$tmp_dir/text" | cut -d' ' -f1)
    text_sha1=$(sha1sum "$tmp_dir/text" | cut -d' ' -f1)
    upload_file() { curl -fsS -X POST -H "X-Filename: $2" -H 'Content-Type: application/octet-stream' --data-binary "@$1" "$base/api/v1/cases/$m4_case_id/files"; }
    upload_file "$tmp_dir/empty" "empty.bin" >"$tmp_dir/empty.json" || m4_ok=0
    upload_file "$tmp_dir/text" "notes.txt" >"$tmp_dir/text.json" || m4_ok=0
    upload_file "$tmp_dir/image" "image.png" >"$tmp_dir/image.json" || m4_ok=0
    upload_file "$tmp_dir/duplicate" "different-name.txt" >"$tmp_dir/duplicate.json" || m4_ok=0
    upload_file "$tmp_dir/text" "../../etc/passwd" >"$tmp_dir/hostile.json" || m4_ok=0
    python - "$tmp_dir/text.json" "$tmp_dir/duplicate.json" "$tmp_dir/image.json" "$tmp_dir/hostile.json" "$text_sha" "$text_md5" "$text_sha1" <<'PY' || m4_ok=0
import json, sys
a, b, image, hostile = (json.load(open(path))["result"] for path in sys.argv[1:5])
assert a["sha256"] == sys.argv[5] and a["md5"] == sys.argv[6] and a["sha1"] == sys.argv[7]
assert a["storage_id"] == b["storage_id"] and a["id"] != b["id"]
assert image["detected_type"] == "png" and image["mime_type"] == "image/png"
assert hostile["original_filename"] == "../../etc/passwd"
assert hostile["storage_id"].startswith("sha256/") and ".." not in hostile["storage_id"]
PY
    text_file_id=$(python -c 'import json,sys; print(json.load(open(sys.argv[1]))["result"]["id"])' "$tmp_dir/text.json") || m4_ok=0
    curl -fsS "$base/api/v1/files/$text_file_id/analysis" >"$tmp_dir/analysis.json" || m4_ok=0
    object_count=$(docker compose -p "$docker_project" exec -T osint-tools sh -c 'find /data/files/sha256 -type f | wc -l') || m4_ok=0
    [ "$object_count" -eq "$((object_count_before + 3))" ] || m4_ok=0
    dd if=/dev/zero of="$tmp_dir/oversized" bs=16385 count=1 >/dev/null 2>&1
    code=$(curl -sS -o "$tmp_dir/oversized.json" -w '%{http_code}' -X POST -H 'X-Filename: too-large.bin' --data-binary "@$tmp_dir/oversized" "$base/api/v1/cases/$m4_case_id/files") || true
    [ "$code" = 413 ] || m4_ok=0
    object_count_after=$(docker compose -p "$docker_project" exec -T osint-tools sh -c 'find /data/files/sha256 -type f | wc -l') || m4_ok=0
    temporary_count=$(docker compose -p "$docker_project" exec -T osint-tools sh -c 'find /data/files/.tmp -type f | wc -l') || m4_ok=0
    [ "$object_count_after" -eq "$((object_count_before + 3))" ] && [ "$temporary_count" -eq 0 ] || m4_ok=0
    if [ "$m4_ok" -ne 1 ]; then
        printf 'M4.1 diagnostics: upload codes empty=%s text=%s image=%s duplicate=%s hostile=%s oversize=%s objects=%s objects_after=%s temp=%s\n' \
            "$(test -s "$tmp_dir/empty.json" && echo 201 || echo missing)" "$(test -s "$tmp_dir/text.json" && echo 201 || echo missing)" "$(test -s "$tmp_dir/image.json" && echo 201 || echo missing)" "$(test -s "$tmp_dir/duplicate.json" && echo 201 || echo missing)" "$(test -s "$tmp_dir/hostile.json" && echo 201 || echo missing)" "$code" "$object_count" "$object_count_after" "$temporary_count" >&2
        for f in empty text image duplicate hostile oversized; do [ -f "$tmp_dir/$f.json" ] && dump_http_response "M4.1 $f" "$tmp_dir/$f.json"; done
    fi
    [ "$m4_ok" -eq 1 ] && record "M4.1 upload runtime" PASS "" || record "M4.1 upload runtime" FAIL "upload/hash/type/dedup/oversize checks failed"

    python - "$tmp_dir" <<'PY'
import gzip, io, sys, tarfile, zipfile
from pathlib import Path
from PIL import Image
d = Path(sys.argv[1])
def z(path, entries):
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as a:
        for name, data in entries: a.writestr(name, data)
z(d/"basic.zip", [("hello.txt", b"hello"), ("../../etc/passwd", b"hello")])
inner = io.BytesIO(); z(inner, [("deep.txt", b"deep")])
middle = io.BytesIO(); z(middle, [("inner.zip", inner.getvalue())])
z(d/"nested.zip", [("middle.zip", middle.getvalue())])
z(d/"bomb.zip", [("large.txt", b"A" * 1000)])
z(d/"members.zip", [(str(i), b"x") for i in range(6)])
z(d/"member-limit.zip", [("large.bin", bytes(range(256))*5)])
z(d/"total-limit.zip", [("a.bin", bytes(range(200))*4), ("b.bin", bytes(range(200))*4)])
with tarfile.open(d/"safe.tar", "w") as a:
    x=tarfile.TarInfo("file.txt"); x.size=4; a.addfile(x, io.BytesIO(b"data"))
    x=tarfile.TarInfo("link"); x.type=tarfile.SYMTYPE; x.linkname="/etc/passwd"; a.addfile(x)
(d/"child.txt.gz").write_bytes(gzip.compress(b"gzip child", mtime=0))
Image.new("RGB", (3,2), "red").save(d/"image.png", "PNG")
ex=Image.Exif(); ex[271]="CameraCo"; Image.new("RGB", (3,2), "red").save(d/"image.jpg", "JPEG", exif=ex)
(d/"meta.pdf").write_bytes(b"%PDF-1.7\n<</Type /Page /Title (Case) /JavaScript (x)>>\n%%EOF")
z(d/"report.docx", [("word/document.xml",b"<x/>"),("docProps/core.xml",b'<x xmlns:d="d"><d:title>Report</d:title></x>')])
(d/"bad.zip").write_bytes(b"PK\x03\x04bad")
PY
    structured_ok=1
    for fixture in basic.zip nested.zip bomb.zip members.zip member-limit.zip total-limit.zip safe.tar child.txt.gz image.png image.jpg meta.pdf report.docx bad.zip; do
        upload_file "$tmp_dir/$fixture" "$fixture" >"$tmp_dir/$fixture.json" || structured_ok=0
    done
    python - "$base" "$tmp_dir" <<'PY' || structured_ok=0
import json, sys, urllib.request
base, directory = sys.argv[1:]
def analysis(name):
    file_id=json.load(open(f"{directory}/{name}.json"))["result"]["id"]
    return file_id, json.load(urllib.request.urlopen(f"{base}/api/v1/files/{file_id}/analysis"))["result"]
def typed(result, kind): return next(x["data"] for x in result["structured"] if x["type"] == kind)
basic_id,basic=analysis("basic.zip"); archive=typed(basic,"archive_analysis")
assert len(archive["members"])==2 and archive["members"][1]["suspicious_path"]
assert archive["members"][0]["child_sha256"]==archive["members"][1]["child_sha256"]
_,tar=analysis("safe.tar"); assert typed(tar,"archive_analysis")["members"][1]["reason"]=="special_member"
_,gz=analysis("child.txt.gz"); assert typed(gz,"archive_analysis")["members"][0]["actual_bytes"]==10
_,nested=analysis("nested.zip"); middle_id=typed(nested,"archive_analysis")["members"][0]["child_file_id"]
middle=json.load(urllib.request.urlopen(f"{base}/api/v1/files/{middle_id}/analysis"))["result"]
inner_id=typed(middle,"archive_analysis")["members"][0]["child_file_id"]
inner=json.load(urllib.request.urlopen(f"{base}/api/v1/files/{inner_id}/analysis"))["result"]
assert typed(inner,"archive_analysis")["reason"]=="max_depth"
_,bomb=analysis("bomb.zip"); assert typed(bomb,"archive_analysis")["members"][0]["reason"]=="max_compression_ratio"
_,members=analysis("members.zip"); assert typed(members,"archive_analysis")["reason"]=="max_members"
_,limit=analysis("member-limit.zip"); assert typed(limit,"archive_analysis")["members"][0]["reason"] in ("max_member_bytes","max_total_bytes")
_,total=analysis("total-limit.zip"); assert typed(total,"archive_analysis")["members"][1]["reason"]=="max_total_bytes"
_,png=analysis("image.png"); assert typed(png,"image_metadata")["width"]==3
_,jpeg=analysis("image.jpg"); assert typed(jpeg,"image_metadata")["exif"]["make"]=="CameraCo"
_,pdf=analysis("meta.pdf"); assert typed(pdf,"pdf_metadata")["metadata"]["title"]=="Case"
_,doc=analysis("report.docx"); assert typed(doc,"document_metadata")["format"]=="docx"
_,bad=analysis("bad.zip"); assert typed(bad,"archive_analysis")["reason"]=="malformed_archive"
open(f"{directory}/structured-id", "w").write(str(basic_id))
PY
    [ "$structured_ok" -eq 1 ] && record "M4.2 structured runtime" PASS "" || record "M4.2 structured runtime" FAIL "structured fixture checks failed"
    structured_file_id=$(cat "$tmp_dir/structured-id" 2>/dev/null || true)

    python - "$tmp_dir" <<'PY'
import io, struct, sys, zipfile
from pathlib import Path
d=Path(sys.argv[1])
p=bytearray(0x260); p[:2]=b'MZ'; struct.pack_into('<I',p,0x3c,0x80); p[0x80:0x84]=b'PE\0\0'; struct.pack_into('<HHIIIHH',p,0x84,0x14c,1,1,0,0,224,2); o=0x98; struct.pack_into('<H',p,o,0x10b); struct.pack_into('<I',p,o+16,0x1000); struct.pack_into('<I',p,o+28,0x400000); struct.pack_into('<H',p,o+68,3); s=o+224; p[s:s+8]=b'.text\0\0\0'; payload=b'http://example.com/a admin@example.com 192.0.2.1 2001:db8::1 pivot.example'; struct.pack_into('<IIII',p,s+8,len(payload),0x1000,len(payload),0x200); struct.pack_into('<I',p,s+36,0x60000020); p[0x200:0x200+len(payload)]=payload; (d/'sample.pe').write_bytes(p)
e=bytearray(64); e[:6]=b'\x7fELF\x02\x01'; e[6]=1; struct.pack_into('<HHIQQQIHHHHHH',e,16,2,62,1,0x401000,0,0,0,64,56,0,64,0,0); (d/'sample.elf').write_bytes(e)
(d/'sample.macho').write_bytes(b'\xcf\xfa\xed\xfe'+struct.pack('<IIIIIII',0x01000007,3,2,0,0,0,0))
(d/'sample.hunk').write_bytes(b''.join(struct.pack('>I',x) for x in [1011,0,1,0,0,1,1001,1,0x41424344,1010]))
(d/'bad.exe').write_bytes(b'MZbad')
with zipfile.ZipFile(d/'binary.zip','w') as z:z.writestr('inside.exe',p)
PY
    binary_ok=1
    for fixture in sample.pe sample.elf sample.macho sample.hunk bad.exe binary.zip; do
        upload_file "$tmp_dir/$fixture" "$fixture" >"$tmp_dir/$fixture.json" || binary_ok=0
    done
    python - "$base" "$tmp_dir" <<'PY' || binary_ok=0
import json,sys,urllib.request
base,d=sys.argv[1:]
def get(name):
 f=json.load(open(f'{d}/{name}.json'))['result']; a=json.load(urllib.request.urlopen(f'{base}/api/v1/files/{f["id"]}/analysis'))['result']; return f,a
for name,kind in [('sample.pe','pe'),('sample.elf','elf'),('sample.macho','macho'),('sample.hunk','amiga_hunk')]:
 f,a=get(name); b=next(x for x in a['structured'] if x['type']=='binary_analysis'); assert b['data']['format']==kind and b['data']['status']=='success' and isinstance(b['data']['entropy'],float)
bad,ba=get('bad.exe'); assert next(x for x in ba['structured'] if x['type']=='binary_analysis')['data']['status']=='failed'
pe,_=get('sample.pe'); c=json.load(urllib.request.urlopen(f'{base}/api/v1/files/{pe["id"]}/candidates'))['result']; assert {'url','domain','ipv4','ipv6','email'} <= {x['type'] for x in c}
url=next(x for x in c if x['type']=='url'); req=urllib.request.Request(f'{base}/api/v1/files/{pe["id"]}/candidates/{url["id"]}/promote',data=b'{}',method='POST'); promoted=json.load(urllib.request.urlopen(req))['result']; assert promoted['relationship']['relation']=='contains_indicator'
z,za=get('binary.zip'); arc=next(x for x in za['structured'] if x['type']=='archive_analysis'); child=arc['data']['members'][0]['child_file_id']; ca=json.load(urllib.request.urlopen(f'{base}/api/v1/files/{child}/analysis'))['result']; assert any(x['type']=='binary_analysis' for x in ca['structured'])
open(f'{d}/binary-id','w').write(str(pe['id']))
PY
    [ "$binary_ok" -eq 1 ] && record "M4.3 binary runtime" PASS "" || record "M4.3 binary runtime" FAIL "binary format/candidate/promotion checks failed"
    binary_file_id=$(cat "$tmp_dir/binary-id" 2>/dev/null || true)

    m44_ok=1
    printf 'M44_RUNTIME OSINT_TOOLS_DEMO_SIGNATURE close body alpha' >"$tmp_dir/m44-a"
    printf 'M44_RUNTIME OSINT_TOOLS_DEMO_SIGNATURE close body beta' >"$tmp_dir/m44-b"
    m44_sha=$(sha256sum "$tmp_dir/m44-a" | cut -d' ' -f1)
    curl -fsS -H 'Content-Type: application/json' -d '{"name":"runtime","version":"1","namespace":"qualification","source":"OSINT Tools qualification","rules":"rule RuntimeRule : harmless { meta: title = \"Runtime harmless rule\" strings: $a = \"M44_RUNTIME\" condition: any of them }"}' "$base/api/v1/signatures/rulepacks" >"$tmp_dir/rulepack.json" || m44_ok=0
    python - "$m44_sha" >"$tmp_dir/hashset-body.json" <<'PY'
import json,sys
print(json.dumps({"name":"runtime-reference","version":"1","source":"qualification","category":"reference","entries":[{"algorithm":"sha256","digest":sys.argv[1],"label":"harmless runtime fixture"}]}))
PY
    curl -fsS -H 'Content-Type: application/json' --data-binary "@$tmp_dir/hashset-body.json" "$base/api/v1/signatures/hashsets" >"$tmp_dir/hashset.json" || m44_ok=0
    upload_file "$tmp_dir/m44-a" "m44-a.bin" >"$tmp_dir/m44-a.json" || m44_ok=0
    upload_file "$tmp_dir/m44-b" "m44-b.bin" >"$tmp_dir/m44-b.json" || m44_ok=0
    python - "$tmp_dir" <<'PY'
import zipfile,sys
with zipfile.ZipFile(sys.argv[1]+"/m44-child.zip","w") as z:z.writestr("child.bin",b"OSINT_TOOLS_DEMO_SIGNATURE")
PY
    upload_file "$tmp_dir/m44-child.zip" "m44-child.zip" >"$tmp_dir/m44-child.json" || m44_ok=0
    python - "$base" "$tmp_dir" <<'PY' || m44_ok=0
import json,sys,urllib.request
base,d=sys.argv[1:]
a=json.load(open(d+'/m44-a.json'))['result']; b=json.load(open(d+'/m44-b.json'))['result']
det=json.load(urllib.request.urlopen(f'{base}/api/v1/files/{a["id"]}/detections'))['result']; assert {'yara','known_hash'} <= {x['method'] for x in det}; assert any(x['namespace']=='qualification' and x['provenance']['rule_pack_version']=='1' for x in det)
similar=json.load(urllib.request.urlopen(f'{base}/api/v1/files/{a["id"]}/similar?limit=1'))['result']; assert len(similar)==1 and similar[0]['file_id']==b['id'] and 0 <= similar[0]['distance'] <= 64
req=urllib.request.Request(f'{base}/api/v1/files/{a["id"]}/detections/reanalyze',data=b'{}',headers={'Content-Type':'application/json'},method='POST'); urllib.request.urlopen(req).read(); after=json.load(urllib.request.urlopen(f'{base}/api/v1/files/{a["id"]}/detections'))['result']; assert len(after)==len(det)
parent=json.load(open(d+'/m44-child.json'))['result']; analysis=json.load(urllib.request.urlopen(f'{base}/api/v1/files/{parent["id"]}/analysis'))['result']; child=next(x for x in analysis['structured'] if x['type']=='archive_analysis')['data']['members'][0]['child_file_id']; child_det=json.load(urllib.request.urlopen(f'{base}/api/v1/files/{child}/detections'))['result']; assert any(x['signature_id']=='OSINT_Tools_Harmless_Demo' for x in child_det)
open(d+'/m44-id','w').write(str(a['id']))
PY
    [ "$m44_ok" -eq 1 ] && record "M4.4 detection runtime" PASS "" || record "M4.4 detection runtime" FAIL "rules/hash/similarity/reanalysis/archive checks failed"
    m44_file_id=$(cat "$tmp_dir/m44-id" 2>/dev/null || true)

    if docker compose -p "$docker_project" restart >/dev/null && \
       i=0; while [ "$i" -lt 30 ]; do curl -fsS "$base/healthz" >/dev/null 2>&1 && break; i=$((i+1)); sleep 1; done; \
       curl -fsS "$base/api/v1/cases/$case_id" | python -c 'import json,sys; assert json.load(sys.stdin)["result"]["name"] == "qualification"' && \
       curl -fsS "$base/api/v1/files/$text_file_id/analysis" | python -c 'import json,sys; assert json.load(sys.stdin)["result"]["type"] == "file_analysis"' && \
       curl -fsS "$base/api/v1/files/$structured_file_id/analysis" | python -c 'import json,sys; assert any(x["type"]=="archive_analysis" for x in json.load(sys.stdin)["result"]["structured"])' && \
       curl -fsS "$base/api/v1/files/$binary_file_id/candidates" | python -c 'import json,sys; assert json.load(sys.stdin)["result"]' && \
       curl -fsS "$base/api/v1/files/$m44_file_id/detections" | python -c 'import json,sys; assert json.load(sys.stdin)["result"]'; then
        record "persistence" PASS ""
    else
        record "persistence" FAIL "case did not survive restart"
    fi
    docker compose -p "$docker_project" logs >"$tmp_dir/docker.log" 2>&1 || true
    rm -rf "$tmp_dir"
else
    record "M2 regression" SKIPPED "Docker runtime was not available"
    record "M3.1 provider framework runtime" SKIPPED "Docker runtime was not available"
    record "M3.2 enrichment runtime" SKIPPED "Docker runtime was not available"
    record "M4.1 upload runtime" SKIPPED "Docker runtime was not available"
    record "M4.2 structured runtime" SKIPPED "Docker runtime was not available"
    record "M4.3 binary runtime" SKIPPED "Docker runtime was not available"
    record "M4.4 detection runtime" SKIPPED "Docker runtime was not available"
    record "AV disabled behavior" SKIPPED "Docker runtime was not available"
    record "persistence" SKIPPED "Docker runtime was not available"
fi
[ -z "${OSINT_TOOLS_PORT_PUBLISHED+x}" ] || docker compose -p "$docker_project" down -v >/dev/null 2>&1 || true

av_project="osint-tools-av-qualify-$$"
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    export OSINT_TOOLS_PORT_PUBLISHED=$((19090 + ($$ % 1000))) OSINT_TOOLS_CLAMAV_ENABLED=true OSINT_TOOLS_AV_SCAN_ON_UPLOAD=false
    if docker compose -p "$av_project" --profile av build osint-tools >/dev/null && docker compose -p "$av_project" --profile av up -d >/dev/null; then
        av_ready=0; i=0
        while [ "$i" -lt 90 ]; do
            if curl -fsS "http://127.0.0.1:$OSINT_TOOLS_PORT_PUBLISHED/healthz" >/dev/null 2>&1 && docker compose -p "$av_project" exec -T osint-tools python -c 'import socket; s=socket.create_connection(("clamav",3310),2); s.sendall(b"PING\n"); assert s.recv(64).strip()==b"PONG"; s.close()' >/dev/null 2>&1; then av_ready=1; break; fi
            i=$((i+1)); sleep 1
        done
        if [ "$av_ready" -eq 1 ]; then
            record "ClamAV readiness" PASS ""
            avbase="http://127.0.0.1:$OSINT_TOOLS_PORT_PUBLISHED"; avtmp=$(mktemp -d); av_ok=1; av_diag_failed=0
            docker compose -p "$av_project" exec -T osint-tools sh -c 'printf "AV config enabled=%s host=%s port=%s\\n" "$OSINT_TOOLS_CLAMAV_ENABLED" "$OSINT_TOOLS_CLAMAV_HOST" "$OSINT_TOOLS_CLAMAV_PORT"' >&2 || true
            docker compose -p "$av_project" exec -T osint-tools python -c 'import socket; s=socket.create_connection(("clamav",3310),5); s.sendall(b"VERSION\n"); print("clamd VERSION:",repr(s.recv(1024))); s.close()' >&2 || true
            avcase=$(curl -fsS -H 'Content-Type: application/json' -d '{"name":"clamav-qualification"}' "$avbase/api/v1/cases") || av_ok=0
            avcase_id=$(printf '%s' "$avcase" | python -c 'import json,sys; print(json.load(sys.stdin)["result"]["id"])') || av_ok=0
            printf 'M4.5 harmless local fixture' >"$avtmp/clean"
            clean=$(curl -fsS -X POST -H 'X-Filename: clean.txt' --data-binary "@$avtmp/clean" "$avbase/api/v1/cases/$avcase_id/files") || av_ok=0
            clean_id=$(printf '%s' "$clean" | python -c 'import json,sys; print(json.load(sys.stdin)["result"]["id"])') || av_ok=0
            curl -fsS -X POST -H 'Content-Type: application/json' -d '{"engines":["clamav"]}' "$avbase/api/v1/files/$clean_id/av/scan" >"$avtmp/clean-scan.json" || av_ok=0
            python - "$avtmp/clean-scan.json" <<'PY' || av_ok=0
import json,sys
try:
    r=json.load(open(sys.argv[1]))["result"][0]
    assert r["state"]=="clean" and r["engine"]=="clamav" and r["bytes_scanned"]>0
except Exception:
    print("clean scan JSON:", open(sys.argv[1], encoding="utf-8").read()[:8192], file=sys.stderr)
    raise
PY
            if [ "$av_ok" -eq 1 ]; then record "ClamAV clean scan" PASS ""; else record "ClamAV clean scan" FAIL "real clamd clean scan failed"; av_diag_failed=1; dump_http_response "ClamAV clean scan" "$avtmp/clean-scan.json"; fi
            # Evaluate the detection path independently so one failure does
            # not hide the actual EICAR response.
            av_ok=1
            eicar='X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
            printf '%s' "$eicar" >"$avtmp/eicar"
            printf 'EICAR fixture bytes=%s sha256=' "$(wc -c <"$avtmp/eicar")" >&2; sha256sum "$avtmp/eicar" | cut -d' ' -f1 >&2
            detected=$(curl -fsS -X POST -H 'X-Filename: eicar.txt' --data-binary "@$avtmp/eicar" "$avbase/api/v1/cases/$avcase_id/files") || av_ok=0
            detected_id=$(printf '%s' "$detected" | python -c 'import json,sys; print(json.load(sys.stdin)["result"]["id"])') || av_ok=0
            curl -fsS -X POST -H 'Content-Type: application/json' -d '{"engines":["clamav"]}' "$avbase/api/v1/files/$detected_id/av/scan" >"$avtmp/eicar-scan.json" || av_ok=0
            python - "$avtmp/eicar-scan.json" <<'PY' || av_ok=0
import json,sys
try:
    r=json.load(open(sys.argv[1]))["result"][0]
    assert r["state"]=="detected" and r["detections"] and "Eicar" in r["detections"][0]["signature"]
    assert r.get("engine_version") and r.get("database_version")
except Exception:
    print("EICAR scan JSON:", open(sys.argv[1], encoding="utf-8").read()[:8192], file=sys.stderr)
    raise
PY
            if [ "$av_ok" -eq 1 ]; then record "ClamAV EICAR detection" PASS ""; record "ClamAV detection provenance" PASS ""; else record "ClamAV EICAR detection" FAIL "real clamd EICAR scan failed"; record "ClamAV detection provenance" FAIL "real clamd provenance check failed"; av_diag_failed=1; dump_http_response "ClamAV EICAR scan" "$avtmp/eicar-scan.json"; fi
            restart_ok=1; docker compose -p "$av_project" restart osint-tools >/dev/null || restart_ok=0; i=0; while [ "$i" -lt 30 ]; do curl -fsS "$avbase/healthz" >/dev/null 2>&1 && break; i=$((i+1)); sleep 1; done
            curl -fsS "$avbase/api/v1/files/$detected_id/av" | python -c 'import json,sys; r=json.load(sys.stdin)["result"]["results"]; assert r and r[0]["state"]=="detected"' >/dev/null || restart_ok=0
            [ "$restart_ok" -eq 1 ] && record "ClamAV persistence" PASS "" || { record "ClamAV persistence" FAIL "AV evidence did not survive restart"; av_diag_failed=1; curl -sS "$avbase/api/v1/files/$detected_id/av" -o "$avtmp/eicar-persist.json" || true; dump_http_response "ClamAV persistence" "$avtmp/eicar-persist.json"; }
            rescan_ok=1
            curl -fsS -X POST -H 'Content-Type: application/json' -d '{"engines":["clamav"]}' "$avbase/api/v1/files/$detected_id/av/scan" >"$avtmp/eicar-rescan.json" || rescan_ok=0
            curl -fsS "$avbase/api/v1/files/$detected_id/av" >"$avtmp/eicar-after-rescan.json" || rescan_ok=0
            python - "$avtmp/eicar-scan.json" "$avtmp/eicar-rescan.json" "$avtmp/eicar-after-rescan.json" <<'PY' || rescan_ok=0
import json, sys
try:
    first = json.load(open(sys.argv[1]))["result"][0]
    second = json.load(open(sys.argv[2]))["result"][0]
    history = json.load(open(sys.argv[3]))["result"]["results"]
    assert second["state"] == "detected"
    assert second["id"] == first["id"]
    assert len([x for x in history if x["engine"] == "clamav"]) == 1
except Exception:
    print("rescan response:", open(sys.argv[2], encoding="utf-8").read()[:8192], file=sys.stderr)
    print("rescan history:", open(sys.argv[3], encoding="utf-8").read()[:8192], file=sys.stderr)
    raise
PY
            [ "$rescan_ok" -eq 1 ] && record "ClamAV rescan/idempotency" PASS "" || { record "ClamAV rescan/idempotency" FAIL "real clamd rescan was not deterministic"; av_diag_failed=1; dump_http_response "ClamAV rescan" "$avtmp/eicar-rescan.json"; dump_http_response "ClamAV rescan history" "$avtmp/eicar-after-rescan.json"; }
            boundary_ok=1
            curl -fsS -X POST -H 'Content-Type: application/json' -d '{"engines":["clamav"],"host":"127.0.0.1","port":1,"socket":"/tmp/forbidden","path":"/etc/passwd","url":"file:///etc/passwd"}' "$avbase/api/v1/files/$detected_id/av/scan" >"$avtmp/boundary.json" || boundary_ok=0
            python - "$avtmp/boundary.json" <<'PY' || boundary_ok=0
import json, sys
r = json.load(open(sys.argv[1]))["result"][0]
assert r["engine"] == "clamav" and r["state"] == "detected"
assert not any(k in r for k in ("host", "port", "socket", "path", "url"))
PY
            [ "$boundary_ok" -eq 1 ] && record "M4.5 local AV boundary" PASS "administrator-configured INSTREAM scan; request destinations ignored" || { record "M4.5 local AV boundary" FAIL "AV destination boundary assertion failed"; av_diag_failed=1; dump_http_response "M4.5 local AV boundary" "$avtmp/boundary.json"; }
            if [ "$av_diag_failed" -eq 1 ]; then
                printf '%s\n' 'ClamAV qualification logs (bounded tails):' >&2
                docker compose -p "$av_project" logs --no-color --tail=80 osint-tools clamav >&2 || true
            fi
            rm -rf "$avtmp"
        else
            record "ClamAV readiness" FAIL "real clamd did not answer PING within 90 seconds"
            record "ClamAV clean scan" SKIPPED "clamd was not ready"
            record "ClamAV EICAR detection" SKIPPED "clamd was not ready"
            record "ClamAV detection provenance" SKIPPED "clamd was not ready"
            record "ClamAV persistence" SKIPPED "clamd was not ready"
            record "ClamAV rescan/idempotency" SKIPPED "clamd was not ready"
            record "M4.5 local AV boundary" SKIPPED "clamd was not ready"
        fi
    else
        record "ClamAV readiness" SKIPPED "optional ClamAV Compose profile could not be started"
        record "ClamAV clean scan" SKIPPED "optional ClamAV profile unavailable"
        record "ClamAV EICAR detection" SKIPPED "optional ClamAV profile unavailable"
        record "ClamAV detection provenance" SKIPPED "optional ClamAV profile unavailable"
        record "ClamAV persistence" SKIPPED "optional ClamAV profile unavailable"
        record "ClamAV rescan/idempotency" SKIPPED "optional ClamAV profile unavailable"
        record "M4.5 local AV boundary" SKIPPED "optional ClamAV profile unavailable"
    fi
    docker compose -p "$av_project" --profile av down -v >/dev/null 2>&1 || true
else
    record "ClamAV readiness" SKIPPED "Docker daemon is unavailable"
    record "ClamAV clean scan" SKIPPED "Docker daemon is unavailable"
    record "ClamAV EICAR detection" SKIPPED "Docker daemon is unavailable"
    record "ClamAV detection provenance" SKIPPED "Docker daemon is unavailable"
    record "ClamAV persistence" SKIPPED "Docker daemon is unavailable"
    record "ClamAV rescan/idempotency" SKIPPED "Docker daemon is unavailable"
    record "M4.5 local AV boundary" SKIPPED "Docker daemon is unavailable"
fi
unset OSINT_TOOLS_CLAMAV_ENABLED OSINT_TOOLS_AV_SCAN_ON_UPLOAD

if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1 && docker image inspect osint-tools:dev >/dev/null 2>&1; then
    if docker run --rm --network none --entrypoint python osint-tools:dev -c 'import struct,tempfile,pathlib; from osint_tools.files.binary import analyze_binary; p=pathlib.Path(tempfile.mkstemp()[1]); p.write_bytes(b"\xcf\xfa\xed\xfe"+struct.pack("<IIIIIII",0x01000007,3,2,0,0,0,0)); assert analyze_binary(p,"macho",__import__("osint_tools.files.binary_common",fromlist=["BinaryLimits"]).BinaryLimits())[0]["status"]=="success"' >/dev/null; then
        record "M4.3 offline analysis" PASS ""
    else
        record "M4.3 offline analysis" FAIL "network-none parser invocation failed"
    fi
else
    record "M4.3 offline analysis" SKIPPED "Docker runtime image is unavailable"
fi

if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1 && docker image inspect osint-tools:dev >/dev/null 2>&1; then
    if docker run --rm --network none --entrypoint python osint-tools:dev -c 'import io,tempfile,pathlib; from osint_tools.storage import Store; from osint_tools.files.store import ContentStore; from osint_tools.files.service import ingest_file; d=pathlib.Path(tempfile.mkdtemp()); s=Store(d/"db"); o=ContentStore(d/"files"); c=s.create_case("offline"); x=b"OSINT_TOOLS_DEMO_SIGNATURE"; f=ingest_file(s,o,c["id"],io.BytesIO(x),len(x),"x",100); assert s.list_file_detections(f["id"])[0]["method"]=="yara"' >/dev/null; then
        record "M4.4 offline analysis" PASS ""
    else
        record "M4.4 offline analysis" FAIL "network-none detection invocation failed"
    fi
else
    record "M4.4 offline analysis" SKIPPED "Docker runtime image is unavailable"
fi

podman_name="osint-tools-qualify-$$"
if command -v podman >/dev/null 2>&1 && podman info >/dev/null 2>&1; then
    if podman build -t "$podman_name" -f Containerfile .; then
        record "Podman build" PASS ""
        if podman run -d --name "$podman_name" -e OSINT_TOOLS_MAX_UPLOAD_BYTES=1024 -p 127.0.0.1::8080 "$podman_name" >/dev/null; then
            host_port=$(podman port "$podman_name" 8080/tcp | sed 's/.*://')
            i=0; while [ "$i" -lt 30 ]; do curl -fsS "http://127.0.0.1:$host_port/healthz" >/dev/null 2>&1 && break; i=$((i+1)); sleep 1; done
            uid=$(podman exec "$podman_name" id -u 2>/dev/null || true)
            podman_case=$(curl -fsS -H 'Content-Type: application/json' -d '{"name":"podman-qualification"}' "http://127.0.0.1:$host_port/api/v1/cases" 2>/dev/null || true)
            podman_case_id=$(printf '%s' "$podman_case" | python -c 'import json,sys; print(json.load(sys.stdin)["result"]["id"])' 2>/dev/null || true)
            podman_target=$(curl -fsS -H 'Content-Type: application/json' -d '{"value":"1.1.1.1"}' "http://127.0.0.1:$host_port/api/v1/cases/$podman_case_id/targets" 2>/dev/null || true)
            podman_upload=$(printf 'podman fixture' | curl -fsS -X POST -H 'X-Filename: podman.txt' --data-binary @- "http://127.0.0.1:$host_port/api/v1/cases/$podman_case_id/files" 2>/dev/null || true)
            if podman exec "$podman_name" test -w /data; then record "Podman /data write" PASS ""; else record "Podman /data write" FAIL "/data is not writable"; fi
            # The application qualification intentionally does not start a
            # second real clamd service under Podman; doing so would require
            # new Podman-specific deployment orchestration.
            record "Podman ClamAV runtime" SKIPPED "optional Compose-profile clamd is not wired into the Podman application harness"
            if [ "$uid" = 10001 ] && [ -n "$podman_target" ] && [ -n "$podman_upload" ] && podman exec "$podman_name" python -c 'import PIL, osint_tools.files.pe, osint_tools.files.elf, osint_tools.files.macho, osint_tools.files.amiga_hunk, osint_tools.files.yara_engine, osint_tools.files.similarity' && curl -fsS "http://127.0.0.1:$host_port/api/v1/info" >/dev/null && curl -fsS "http://127.0.0.1:$host_port/api/v1/providers" >/dev/null; then
                record "Podman runtime/non-root" PASS ""
                record "Podman parser imports" PASS ""
            else
                record "Podman runtime/non-root" FAIL "health/API/UID verification failed"
                record "Podman parser imports" FAIL "parser import or runtime verification failed"
            fi
        else
            record "Podman runtime/non-root" FAIL "container failed to start"
            record "Podman /data write" SKIPPED "Podman container did not start"
            record "Podman parser imports" SKIPPED "Podman container did not start"
            record "Podman ClamAV runtime" SKIPPED "Podman application container did not start"
        fi
    else
        record "Podman build" FAIL "build failed"
        record "Podman runtime/non-root" SKIPPED "Podman image did not build"
        record "Podman /data write" SKIPPED "Podman image did not build"
        record "Podman parser imports" SKIPPED "Podman image did not build"
        record "Podman ClamAV runtime" SKIPPED "Podman image did not build"
    fi
    podman rm -f "$podman_name" >/dev/null 2>&1 || true
    podman rmi "$podman_name" >/dev/null 2>&1 || true
else
    record "Podman build" SKIPPED "Podman is unavailable"
    record "Podman runtime/non-root" SKIPPED "Podman is unavailable"
    record "Podman /data write" SKIPPED "Podman is unavailable"
    record "Podman parser imports" SKIPPED "Podman is unavailable"
    record "Podman ClamAV runtime" SKIPPED "Podman is unavailable"
fi

if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1 && docker buildx inspect --bootstrap >/tmp/osint-tools-buildx-$$ 2>&1; then
    for arch in amd64 arm64; do
        if grep -q "linux/$arch" /tmp/osint-tools-buildx-$$; then
            if docker buildx build --platform "linux/$arch" --output type=cacheonly -f Containerfile . >/dev/null; then record "linux/$arch build" PASS ""; else record "linux/$arch build" FAIL "cross-build failed"; fi
        else
            record "linux/$arch build" SKIPPED "buildx builder does not advertise linux/$arch"
        fi
    done
    rm -f /tmp/osint-tools-buildx-$$
else
    record "linux/amd64 build" SKIPPED "Docker buildx builder is unavailable"
    record "linux/arm64 build" SKIPPED "Docker buildx builder is unavailable"
fi

live_provider() {
    gate=$1 credential=$2 module=$3 class=$4 operation=$5 target_type=$6 value=$7
    eval "present=\${$credential:-}"
    if [ -z "$present" ]; then record "$gate" SKIPPED "$credential is not set"; return; fi
    if PROVIDER_MODULE="$module" PROVIDER_CLASS="$class" PROVIDER_OPERATION="$operation" PROVIDER_TARGET_TYPE="$target_type" PROVIDER_VALUE="$value" python - <<'PY' >/dev/null 2>&1
import importlib, os
cls = getattr(importlib.import_module(os.environ["PROVIDER_MODULE"]), os.environ["PROVIDER_CLASS"])
r = cls().execute(os.environ["PROVIDER_OPERATION"], {"type": os.environ["PROVIDER_TARGET_TYPE"], "normalized": os.environ["PROVIDER_VALUE"]}, timeout=10)
assert isinstance(r.data, dict)
PY
    then record "$gate" PASS ""; else record "$gate" FAIL "credential present but bounded call failed"; fi
}

live_provider "live IPinfo" IPINFO_TOKEN osint_tools.providers.ipinfo IPInfoProvider lookup ip 1.1.1.1
live_provider "live VirusTotal" VIRUSTOTAL_API_KEY osint_tools.providers.virustotal VirusTotalProvider lookup domain example.com
live_provider "live AbuseIPDB" ABUSEIPDB_API_KEY osint_tools.providers.abuseipdb AbuseIPDBProvider check ip 1.1.1.1
live_provider "live Shodan" SHODAN_API_KEY osint_tools.providers.shodan ShodanProvider host ip 1.1.1.1

printf '\nQualification matrix\n%s' "$RESULTS"
exit "$FAILED"
