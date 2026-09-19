#!/bin/bash

set -euo pipefail

# ══════════════════════════════════════════════════════════════════════════════
# Start Epyon FastAPI with Webhook Debug Logging
# ══════════════════════════════════════════════════════════════════════════════

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
LOCAL_ENV_FILE="${ROOT_DIR}/.env.local"

if [[ -f "$LOCAL_ENV_FILE" ]]; then
	chmod 600 "$LOCAL_ENV_FILE"
	set -a
	# shellcheck disable=SC1090
	source "$LOCAL_ENV_FILE"
	set +a
	echo "Loaded local environment from .env.local"
fi

cd "${ROOT_DIR}/web"

echo "════════════════════════════════════════════════════════════════"
echo "  Starting Epyon FastAPI with webhook debug logging enabled"
echo "════════════════════════════════════════════════════════════════"
echo ""
echo "Environment:"
echo "  EPYON_WEBHOOK_DEBUG=1   (verbose webhook logs)"
echo ""
echo "API will be available at: http://127.0.0.1:8056"
echo ""
echo "To test webhooks, run: ./test-webhook-integration.sh"
echo ""
echo "════════════════════════════════════════════════════════════════"
echo ""

export EPYON_WEBHOOK_DEBUG=1

exec python3 -m uvicorn api.main:app --host 127.0.0.1 --port 8056 --app-dir . --reload
