#!/bin/bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
echo "start-api-with-debug.sh is deprecated; use ./start-epyon" >&2
exec "${ROOT_DIR}/start-epyon" "$@"
