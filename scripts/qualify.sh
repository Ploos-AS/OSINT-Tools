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

docker_project="osint-tools-qualify-$$"
docker_port=$((18090 + ($$ % 1000)))
docker_ready=0
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    export OSINT_TOOLS_PORT_PUBLISHED=$docker_port
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
assert i["version"] == "0.3.2" and i["milestone"] == "M3.2"
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

    if docker compose -p "$docker_project" restart >/dev/null && \
       i=0; while [ "$i" -lt 30 ]; do curl -fsS "$base/healthz" >/dev/null 2>&1 && break; i=$((i+1)); sleep 1; done; \
       curl -fsS "$base/api/v1/cases/$case_id" | python -c 'import json,sys; assert json.load(sys.stdin)["result"]["name"] == "qualification"'; then
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
    record "persistence" SKIPPED "Docker runtime was not available"
fi
[ -z "${OSINT_TOOLS_PORT_PUBLISHED+x}" ] || docker compose -p "$docker_project" down -v >/dev/null 2>&1 || true

podman_name="osint-tools-qualify-$$"
if command -v podman >/dev/null 2>&1 && podman info >/dev/null 2>&1; then
    if podman build -t "$podman_name" -f Containerfile .; then
        record "Podman build" PASS ""
        if podman run -d --name "$podman_name" -p 127.0.0.1::8080 "$podman_name" >/dev/null; then
            host_port=$(podman port "$podman_name" 8080/tcp | sed 's/.*://')
            i=0; while [ "$i" -lt 30 ]; do curl -fsS "http://127.0.0.1:$host_port/healthz" >/dev/null 2>&1 && break; i=$((i+1)); sleep 1; done
            uid=$(podman exec "$podman_name" id -u 2>/dev/null || true)
            podman_case=$(curl -fsS -H 'Content-Type: application/json' -d '{"name":"podman-qualification"}' "http://127.0.0.1:$host_port/api/v1/cases" 2>/dev/null || true)
            podman_case_id=$(printf '%s' "$podman_case" | python -c 'import json,sys; print(json.load(sys.stdin)["result"]["id"])' 2>/dev/null || true)
            podman_target=$(curl -fsS -H 'Content-Type: application/json' -d '{"value":"1.1.1.1"}' "http://127.0.0.1:$host_port/api/v1/cases/$podman_case_id/targets" 2>/dev/null || true)
            if [ "$uid" = 10001 ] && [ -n "$podman_target" ] && curl -fsS "http://127.0.0.1:$host_port/api/v1/info" >/dev/null && curl -fsS "http://127.0.0.1:$host_port/api/v1/providers" >/dev/null; then
                record "Podman runtime/non-root" PASS ""
            else
                record "Podman runtime/non-root" FAIL "health/API/UID verification failed"
            fi
        else
            record "Podman runtime/non-root" FAIL "container failed to start"
        fi
    else
        record "Podman build" FAIL "build failed"
        record "Podman runtime/non-root" SKIPPED "Podman image did not build"
    fi
    podman rm -f "$podman_name" >/dev/null 2>&1 || true
    podman rmi "$podman_name" >/dev/null 2>&1 || true
else
    record "Podman build" SKIPPED "Podman is unavailable"
    record "Podman runtime/non-root" SKIPPED "Podman is unavailable"
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
