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
PROGRESS="${5:-}"

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

# Map Epyon layer names to Barbatos tool names (lowercase, simple)
map_tool_name() {
    local layer_name="$1"
    case "$layer_name" in
        layer-1---sbom|sbom) echo "syft" ;;
        layer-2---trufflehog|trufflehog) echo "trufflehog" ;;
        layer-3---sonar|sonar) echo "sonarqube" ;;
        layer-4---clamav|clamav) echo "clamav" ;;
        layer-5---helm|helm) echo "helm" ;;
        layer-6---checkov|checkov) echo "checkov" ;;
        layer-7---trivy|trivy) echo "trivy" ;;
        layer-8---grype|grype) echo "grype" ;;
        layer-9---xeol|xeol) echo "xeol" ;;
        layer-10---anchore|anchore) echo "anchore" ;;
        layer-11---api-discovery|api-discovery) echo "api-discovery" ;;
        layer-115---pip-audit|pip-audit) echo "pip-audit" ;;
        layer-116---python-safety-check|safety) echo "safety" ;;
        *) echo "${layer_name}" ;;
    esac
}

# Build Barbatos-compatible JSON payload
# Barbatos API contract:
# - Progress: { tool: "grype", content: "message", progress: 0.5 }
# - Completion: { done: true }
# - Error: { error: "message" }
# - jobId goes in header only (X-Epyon-Job-Id), NOT in body

SIMPLE_TOOL=$(map_tool_name "$TOOL_NAME")

case "$EVENT_TYPE" in
    scan_complete)
        # Scan finished - simple done flag
        JSON_PAYLOAD='{"done":true}'
        ;;
    error|scan_error)
        # Error occurred
        JSON_PAYLOAD=$(cat <<EOF
{"error":"$MESSAGE"}
EOF
)
        ;;
    tool_start|tool_complete|scan_start)
        # Progress update - tool + content + optional progress
        if [[ -n "$PROGRESS" ]]; then
            JSON_PAYLOAD=$(cat <<EOF
{"tool":"$SIMPLE_TOOL","content":"$MESSAGE","progress":$PROGRESS}
EOF
)
        else
            JSON_PAYLOAD=$(cat <<EOF
{"tool":"$SIMPLE_TOOL","content":"$MESSAGE"}
EOF
)
        fi
        ;;
    *)
        # Unknown event - send as content with tool name if available
        if [[ -n "$SIMPLE_TOOL" ]]; then
            JSON_PAYLOAD=$(cat <<EOF
{"tool":"$SIMPLE_TOOL","content":"$MESSAGE"}
EOF
)
        else
            JSON_PAYLOAD=$(cat <<EOF
{"content":"$MESSAGE"}
EOF
)
        fi
        ;;
esac

# Job ID is sent via header only (NOT in payload body per Barbatos API contract)
JOB_ID="${EPYON_JOB_ID:-unknown}"
HEADERS=(-H "Content-Type: application/json" -H "X-Epyon-Job-Id: $JOB_ID")

debug_log "Simplified payload: $JSON_PAYLOAD"

# Generate HMAC signature if secret is provided (optional security layer)
if [[ -n "${EPYON_WEBHOOK_SECRET:-}" ]]; then
    SIGNATURE=$(echo -n "$JSON_PAYLOAD" | openssl dgst -sha256 -hmac "$EPYON_WEBHOOK_SECRET" | sed 's/^.* //')
    HEADERS+=(-H "X-Epyon-Signature: sha256=$SIGNATURE")
    debug_log "HMAC signature generated"
fi

# Send webhook with retry logic
MAX_RETRIES=3
RETRY_DELAY=2
SUCCESS=false
RESPONSE_FILE=$(mktemp)

for ((i=1; i<=MAX_RETRIES; i++)); do
    debug_log "Attempt $i/$MAX_RETRIES: POST to $EPYON_CALLBACK_URL"
    
    HTTP_CODE=$(curl -s -S -X POST "$EPYON_CALLBACK_URL" \
        "${HEADERS[@]}" \
        -d "$JSON_PAYLOAD" \
        --max-time 10 \
        --connect-timeout 5 \
        -o "$RESPONSE_FILE" \
        -w "%{http_code}" 2>&1 || echo "000")
    
    debug_log "Response: HTTP $HTTP_CODE"
    
    # Show response body for non-success status codes in debug mode
    if [[ "$EPYON_WEBHOOK_DEBUG" == "1" ]] && ! echo "$HTTP_CODE" | grep -qE '^(200|201|202|204)$'; then
        RESPONSE_BODY=$(cat "$RESPONSE_FILE" 2>/dev/null | head -c 500)
        if [[ -n "$RESPONSE_BODY" ]]; then
            debug_log "Response body: $RESPONSE_BODY"
        fi
    fi
    
    if echo "$HTTP_CODE" | grep -qE '^(200|201|202|204)$'; then
        SUCCESS=true
        debug_log "Webhook delivered successfully"
        rm -f "$RESPONSE_FILE"
        break
    else
        if [[ "$i" -lt "$MAX_RETRIES" ]]; then
            echo -e "${YELLOW}⚠️  Webhook notification failed (attempt $i/$MAX_RETRIES, HTTP $HTTP_CODE), retrying in ${RETRY_DELAY}s...${NC}" >&2
            debug_log "Retrying after ${RETRY_DELAY}s delay..."
            sleep "$RETRY_DELAY"
        fi
    fi
done

rm -f "$RESPONSE_FILE"

if [[ "$SUCCESS" != "true" ]]; then
    echo -e "${YELLOW}⚠️  Webhook notification failed after $MAX_RETRIES attempts - continuing scan${NC}" >&2
    debug_log "Final status: FAILED after $MAX_RETRIES attempts"
    # Soft fail - don't block the scan
    exit 0
fi

debug_log "Final status: SUCCESS"
# Silent success - don't clutter logs
exit 0
