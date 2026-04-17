#!/usr/bin/env bash
# Epyon Web Interface — start script
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
EPYON_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

HOST="${EPYON_HOST:-127.0.0.1}"
PORT="${EPYON_PORT:-8000}"

# ── Python / uvicorn check ────────────────────────────────────────────────────
if ! command -v python3 &>/dev/null; then
  echo "Error: python3 is required but not found in PATH."
  exit 1
fi

if ! python3 -c 'import uvicorn' 2>/dev/null; then
  echo "Installing Python dependencies…"
  pip3 install -r "$SCRIPT_DIR/api/requirements.txt" -q
fi

# ── Banner ────────────────────────────────────────────────────────────────────
echo ""
echo "┌──────────────────────────────────────────────────────┐"
echo "│                                                      │"
echo "│   ⚡  EPYON  Web Interface (FastAPI)                 │"
echo "│   Absolute Security Control                          │"
echo "│                                                      │"
echo "│   Starting on http://${HOST}:${PORT}                 │"
echo "│                                                      │"
echo "│   Press Ctrl+C to stop                              │"
echo "└──────────────────────────────────────────────────────┘"
echo ""

# ── Start FastAPI ────────────────────────────────────────────────────────────
exec python3 -m uvicorn api.main:app \
  --host "$HOST" \
  --port "$PORT" \
  --app-dir "$SCRIPT_DIR"

