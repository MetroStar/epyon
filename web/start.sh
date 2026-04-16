#!/usr/bin/env bash
# Epyon Web Interface — start script
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

HOST="${EPYON_HOST:-127.0.0.1}"
PORT="${EPYON_PORT:-8000}"

# ── Node.js check ─────────────────────────────────────────────────────────────
if ! command -v node &>/dev/null; then
  echo "Error: node is required but not found in PATH."
  echo "Install it from https://nodejs.org or via your package manager."
  exit 1
fi

# ── Banner ────────────────────────────────────────────────────────────────────
echo ""
echo "┌──────────────────────────────────────────────────────┐"
echo "│                                                      │"
echo "│   ⚡  EPYON  Web Interface                           │"
echo "│   Absolute Security Control                          │"
echo "│                                                      │"
echo "│   Starting on http://${HOST}:${PORT}                 │"
echo "│                                                      │"
echo "│   Press Ctrl+C to stop                              │"
echo "└──────────────────────────────────────────────────────┘"
echo ""

# ── Start server ──────────────────────────────────────────────────────────────
exec node server.js

