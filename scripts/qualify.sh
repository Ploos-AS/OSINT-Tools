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
assert i["version"] == "0.4.2" and i["milestone"] == "M4.2" and i["max_upload_bytes"] == 16384
PY
    curl -fsS "$base/api/v1/providers" >"$tmp_dir/providers.json" || api_ok=0
    case_json=$(curl -fsS -H 'Content-Type: application/json' -d '{"name":"qualification"}' "$base/api/v1/cases") || api_ok=0
    case_id=$(printf '%s' "$case_json" | python -c 'import json,sys; print(json.load(sys.stdin)["result"]["id"])') || api_ok=0
    target_json=$(curl -fsS -H 'Content-Type: application/json' -d '{"value":"example.com"}' "$base/api/v1/cases/$case_id/targets") || api_ok=0
    target_id=$(printf '%s' "$target_json" | python -c 'import json,sys; print(json.load(sys.stdin)["result"]["id"])') || api_ok=0
    curl -fsS -X POST -H 'Content-Type: application/json' -d '{}' "$base/api/v1/targets/$target_id/pivot/dns" >"$tmp_dir/pivot.json" || api_ok=0
    [ "$api_ok" -eq 1 ] && record "M2 regression" PASS "" || record "M2 regression" FAIL "representative case/target/DNS pivot failed"

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
    ip_json=$(curl -fsS -H 'Content-Type: application/json' -d '{"value":"1.1.1.1"}' "$base/api/v1/cases/$case_id/targets") || provider_ok=0
    ip_id=$(printf '%s' "$ip_json" | python -c 'import json,sys; print(json.load(sys.stdin)["result"]["id"])') || provider_ok=0
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
    : >"$tmp_dir/empty"
    printf 'deterministic text fixture\n' >"$tmp_dir/text"
    printf '\211PNG\r\n\032\nfixture' >"$tmp_dir/image"
    cp "$tmp_dir/text" "$tmp_dir/duplicate"
    text_sha=$(sha256sum "$tmp_dir/text" | cut -d' ' -f1)
    text_md5=$(md5sum "$tmp_dir/text" | cut -d' ' -f1)
    text_sha1=$(sha1sum "$tmp_dir/text" | cut -d' ' -f1)
    upload_file() { curl -fsS -X POST -H "X-Filename: $2" -H 'Content-Type: application/octet-stream' --data-binary "@$1" "$base/api/v1/cases/$case_id/files"; }
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
    [ "$object_count" -eq 3 ] || m4_ok=0
    dd if=/dev/zero of="$tmp_dir/oversized" bs=16385 count=1 >/dev/null 2>&1
    code=$(curl -sS -o "$tmp_dir/oversized.json" -w '%{http_code}' -X POST -H 'X-Filename: too-large.bin' --data-binary "@$tmp_dir/oversized" "$base/api/v1/cases/$case_id/files") || true
    [ "$code" = 413 ] || m4_ok=0
    object_count_after=$(docker compose -p "$docker_project" exec -T osint-tools sh -c 'find /data/files/sha256 -type f | wc -l') || m4_ok=0
    temporary_count=$(docker compose -p "$docker_project" exec -T osint-tools sh -c 'find /data/files/.tmp -type f | wc -l') || m4_ok=0
    [ "$object_count_after" -eq 3 ] && [ "$temporary_count" -eq 0 ] || m4_ok=0
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

    if docker compose -p "$docker_project" restart >/dev/null && \
       i=0; while [ "$i" -lt 30 ]; do curl -fsS "$base/healthz" >/dev/null 2>&1 && break; i=$((i+1)); sleep 1; done; \
       curl -fsS "$base/api/v1/cases/$case_id" | python -c 'import json,sys; assert json.load(sys.stdin)["result"]["name"] == "qualification"' && \
       curl -fsS "$base/api/v1/files/$text_file_id/analysis" | python -c 'import json,sys; assert json.load(sys.stdin)["result"]["type"] == "file_analysis"' && \
       curl -fsS "$base/api/v1/files/$structured_file_id/analysis" | python -c 'import json,sys; assert any(x["type"]=="archive_analysis" for x in json.load(sys.stdin)["result"]["structured"])'; then
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
    record "persistence" SKIPPED "Docker runtime was not available"
fi
[ -z "${OSINT_TOOLS_PORT_PUBLISHED+x}" ] || docker compose -p "$docker_project" down -v >/dev/null 2>&1 || true

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
            if [ "$uid" = 10001 ] && [ -n "$podman_target" ] && [ -n "$podman_upload" ] && podman exec "$podman_name" python -c 'import PIL' && curl -fsS "http://127.0.0.1:$host_port/api/v1/info" >/dev/null && curl -fsS "http://127.0.0.1:$host_port/api/v1/providers" >/dev/null; then
                record "Podman runtime/non-root" PASS ""
            else
                record "Podman runtime/non-root" FAIL "health/API/UID verification failed"
            fi
        else
            record "Podman runtime/non-root" FAIL "container failed to start"
            record "Podman /data write" SKIPPED "Podman container did not start"
        fi
    else
        record "Podman build" FAIL "build failed"
        record "Podman runtime/non-root" SKIPPED "Podman image did not build"
        record "Podman /data write" SKIPPED "Podman image did not build"
    fi
    podman rm -f "$podman_name" >/dev/null 2>&1 || true
    podman rmi "$podman_name" >/dev/null 2>&1 || true
else
    record "Podman build" SKIPPED "Podman is unavailable"
    record "Podman runtime/non-root" SKIPPED "Podman is unavailable"
    record "Podman /data write" SKIPPED "Podman is unavailable"
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
