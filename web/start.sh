#!/usr/bin/env bash
# Start the Epyon Web UI API server
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-8056}"

echo "Checking dependencies…"
python3 -m pip install -q -r "$SCRIPT_DIR/api/requirements.txt"

echo "Starting Epyon Web UI on http://${HOST}:${PORT}"
RELOAD=""
[[ "${DEV:-}" == "1" ]] && RELOAD="--reload"
exec python3 -m uvicorn api.main:app --host "$HOST" --port "$PORT" --app-dir "$SCRIPT_DIR" $RELOAD
