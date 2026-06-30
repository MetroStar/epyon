#!/bin/bash

# ══════════════════════════════════════════════════════════════════════════════
# Start Epyon FastAPI with Webhook Debug Logging
# ══════════════════════════════════════════════════════════════════════════════

cd "$(dirname "$0")/web"

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
