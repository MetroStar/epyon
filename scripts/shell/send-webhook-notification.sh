#!/bin/bash

# ══════════════════════════════════════════════════════════════════════════════
# Epyon Webhook Notification Script
# ══════════════════════════════════════════════════════════════════════════════
# Sends progress notifications to a webhook endpoint during scan execution.
# Used by Barbatos and other management UIs to track scan progress in real-time.
#
# Environment Variables (all optional - gracefully degrades if not set):
#   EPYON_CALLBACK_URL     - Full URL to POST notifications to
#   EPYON_JOB_ID          - Unique job identifier for this scan
#   EPYON_WEBHOOK_SECRET  - Shared secret for HMAC signature validation
#
# Usage:
#   ./send-webhook-notification.sh "event_type" "message" ["status"] ["tool_name"]
#
# Example:
#   ./send-webhook-notification.sh "tool_start" "Starting Trivy scan" "in_progress" "trivy"
#   ./send-webhook-notification.sh "tool_complete" "Trivy scan finished" "success" "trivy"
#   ./send-webhook-notification.sh "scan_complete" "All tools completed" "done"
# ══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

# Debug mode - set EPYON_WEBHOOK_DEBUG=1 to enable verbose logging
DEBUG="${EPYON_WEBHOOK_DEBUG:-0}"

# Colors for logging
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

debug_log() {
    if [[ "$DEBUG" == "1" ]]; then
        echo -e "${BLUE}[webhook-debug]${NC} $*" >&2
    fi
}

# Parse arguments
EVENT_TYPE="${1:-unknown}"
MESSAGE="${2:-No message provided}"
STATUS="${3:-info}"
TOOL_NAME="${4:-}"

debug_log "Event: $EVENT_TYPE, Status: $STATUS, Tool: $TOOL_NAME"

# Check if webhook is configured
if [[ -z "${EPYON_CALLBACK_URL:-}" ]]; then
    # Webhook not configured - silent skip (not an error)
    debug_log "EPYON_CALLBACK_URL not set - skipping webhook"
    exit 0
fi

debug_log "Callback URL: $EPYON_CALLBACK_URL"
debug_log "Job ID: ${EPYON_JOB_ID:-unknown}"

# Optional: validate URL format (basic check)
if [[ ! "$EPYON_CALLBACK_URL" =~ ^https?:// ]]; then
    echo -e "${YELLOW}⚠️  Invalid webhook URL format: $EPYON_CALLBACK_URL${NC}" >&2
    exit 0  # Soft fail - don't block the scan
fi

# Build JSON payload
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
JOB_ID="${EPYON_JOB_ID:-unknown}"
APP_NAME="${APP_NAME:-unknown}"
SCAN_ID="${SCAN_ID:-unknown}"

JSON_PAYLOAD=$(cat <<EOF
{
  "event_type": "$EVENT_TYPE",
  "job_id": "$JOB_ID",
  "app_name": "$APP_NAME",
  "scan_id": "$SCAN_ID",
  "message": "$MESSAGE",
  "status": "$STATUS",
  "tool_name": "$TOOL_NAME",
  "timestamp": "$TIMESTAMP"
}
EOF
)

# Always send Job ID header (required for webhook correlation)
HEADERS=(-H "Content-Type: application/json" -H "X-Epyon-Job-Id: $JOB_ID")

# Generate HMAC signature if secret is provided (optional security layer)
if [[ -n "${EPYON_WEBHOOK_SECRET:-}" ]]; then
    SIGNATURE=$(echo -n "$JSON_PAYLOAD" | openssl dgst -sha256 -hmac "$EPYON_WEBHOOK_SECRET" | sed 's/^.* //')
    HEADERS+=(-H "X-Epyon-Signature: sha256=$SIGNATURE")
    debug_log "HMAC signature generated"
fi

debug_log "Payload: $JSON_PAYLOAD"

# Send webhook with retry logic
MAX_RETRIES=3
RETRY_DELAY=2
SUCCESS=false

for ((i=1; i<=MAX_RETRIES; i++)); do
    debug_log "Attempt $i/$MAX_RETRIES: POST to $EPYON_CALLBACK_URL"
    
    HTTP_CODE=$(curl -s -S -X POST "$EPYON_CALLBACK_URL" \
        "${HEADERS[@]}" \
        -d "$JSON_PAYLOAD" \
        --max-time 10 \
        --connect-timeout 5 \
        -o /dev/null \
        -w "%{http_code}" 2>&1 || echo "000")
    
    debug_log "Response: HTTP $HTTP_CODE"
    
    if echo "$HTTP_CODE" | grep -qE '^(200|201|202|204)$'; then
        SUCCESS=true
        debug_log "Webhook delivered successfully"
        break
    else
        if [[ "$i" -lt "$MAX_RETRIES" ]]; then
            echo -e "${YELLOW}⚠️  Webhook notification failed (attempt $i/$MAX_RETRIES, HTTP $HTTP_CODE), retrying in ${RETRY_DELAY}s...${NC}" >&2
            debug_log "Retrying after ${RETRY_DELAY}s delay..."
            sleep "$RETRY_DELAY"
        fi
    fi
done

if [[ "$SUCCESS" != "true" ]]; then
    echo -e "${YELLOW}⚠️  Webhook notification failed after $MAX_RETRIES attempts - continuing scan${NC}" >&2
    debug_log "Final status: FAILED after $MAX_RETRIES attempts"
    # Soft fail - don't block the scan
    exit 0
fi

debug_log "Final status: SUCCESS"
# Silent success - don't clutter logs
exit 0
