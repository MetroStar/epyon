#!/usr/bin/env bash
# Epyon Web Interface — start script
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

HOST="${EPYON_HOST:-127.0.0.1}"
PORT="${EPYON_PORT:-8000}"

# ── Python check ──────────────────────────────────────────────────────────────
if ! command -v python3 &>/dev/null; then
  echo "Error: python3 is required but not found in PATH."
  exit 1
fi

PYTHON=$(command -v python3)

# ── Install dependencies ───────────────────────────────────────────────────────
if ! "$PYTHON" -c "import fastapi, uvicorn" &>/dev/null 2>&1; then
  echo "Installing Python dependencies..."
  "$PYTHON" -m pip install -r requirements.txt --quiet
fi

# ── Banner ────────────────────────────────────────────────────────────────────
echo ""
echo "┌──────────────────────────────────────────────────────┐"
echo "│                                                      │"
echo "│   ⚡  EPYON  Web Interface                           │"
echo "│   Absolute Security Control                          │"
echo "│                                                      │"
echo "│   http://${HOST}:${PORT}                             │"
echo "│                                                      │"
echo "│   Press Ctrl+C to stop                              │"
echo "└──────────────────────────────────────────────────────┘"
echo ""

# ── Start server ──────────────────────────────────────────────────────────────
exec "$PYTHON" -m uvicorn server:app \
  --host "$HOST" \
  --port "$PORT" \
  --reload \
  --log-level info
