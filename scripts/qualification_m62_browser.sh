#!/bin/sh
set -eu
cd "$(dirname "$0")/.."

port=$((18180 + ($$ % 500)))
data_dir=$(mktemp -d)
log_file=$(mktemp)
cleanup() {
    [ -n "${server_pid:-}" ] && kill "$server_pid" 2>/dev/null || true
    rm -rf "$data_dir" "$log_file"
}
trap cleanup EXIT INT TERM

export OSINT_TOOLS_HOST=127.0.0.1
export OSINT_TOOLS_PORT="$port"
export OSINT_TOOLS_DATA_DIR="$data_dir"
export OSINT_TOOLS_AUTH_ENABLED=true
export OSINT_TOOLS_BROWSER_BASE_URL="http://127.0.0.1:$port"

python scripts/qualification_m62_browser_server.py >"$log_file" 2>&1 &
server_pid=$!

i=0
while [ "$i" -lt 30 ]; do
    if curl -fsS "$OSINT_TOOLS_BROWSER_BASE_URL/healthz" >/dev/null 2>&1; then break; fi
    i=$((i+1)); sleep 1
done
curl -fsS "$OSINT_TOOLS_BROWSER_BASE_URL/healthz" >/dev/null
python -m pytest -q tests/browser --browser chromium
