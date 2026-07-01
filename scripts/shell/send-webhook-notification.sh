#!/usr/bin/env bash
# Send webhook notifications to Barbatos management UI during security scans.
# Called by run-epyon-scan-ci.sh to provide real-time progress updates.
#
# Barbatos API Contract (from official spec v1.0):
# 1. Progress (layer): {"progress": {"layer": 1, "name": "syft", "total": 16}}
# 2. Progress (step): {"progress": {"step": "checkout-repo", "label": "message"}}
# 3. Tool results: {"tool": "grype", "content": {...actual grype JSON...}}
# 4. Completion: {"done": true}
# 5. Error: {"error": "message"}
#
# Job ID MUST be in X-Epyon-Job-Id header, NEVER in body.
#
# Usage:
#   send-webhook-notification.sh EVENT_TYPE MESSAGE [STATUS] [TOOL_NAME] [LAYER_NUM] [TOTAL_LAYERS] [RESULT_FILE]
#
# Arguments:
#   EVENT_TYPE    - scan_start|tool_start|tool_complete|scan_complete|error|step
#   MESSAGE       - Human-readable message  
#   STATUS        - info|success|error (optional, default: info)
#   TOOL_NAME     - Tool slug (e.g., "layer-1---sbom") (optional)
#   LAYER_NUM     - Layer number 1-16 (optional, for tool_start)
#   TOTAL_LAYERS  - Total layer count (optional, default: 16)
#   RESULT_FILE   - Path to tool JSON output (optional, for tool_complete with results)
#
# Environment Variables (all optional):
#   EPYON_CALLBACK_URL     - Webhook endpoint (required to send)
#   EPYON_JOB_ID           - Job ID for correlation
#   EPYON_WEBHOOK_SECRET   - HMAC secret for signature verification
#   EPYON_WEBHOOK_DEBUG    - Set to "1" for verbose output

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Debug logging helper
debug_log() {
    if [[ "${EPYON_WEBHOOK_DEBUG:-0}" == "1" ]]; then
        echo "[webhook-debug] $*" >&2
    fi
}

# Parse arguments
EVENT_TYPE="${1:-unknown}"
MESSAGE="${2:-No message provided}"
STATUS="${3:-info}"
TOOL_NAME="${4:-}"
LAYER_NUM="${5:-}"
TOTAL_LAYERS="${6:-16}"
RESULT_FILE="${7:-}"

debug_log "Event: $EVENT_TYPE, Layer: ${LAYER_NUM:-N/A}, Tool: ${TOOL_NAME:-N/A}, Results: ${RESULT_FILE:-none}"

# Check if webhook is configured
if [[ -z "${EPYON_CALLBACK_URL:-}" ]]; then
    debug_log "EPYON_CALLBACK_URL not set - skipping webhook"
    exit 0
fi

debug_log "Callback URL: $EPYON_CALLBACK_URL"
debug_log "Job ID: ${EPYON_JOB_ID:-unknown}"

# Validate URL format (basic check)
if [[ ! "$EPYON_CALLBACK_URL" =~ ^https?:// ]]; then
    echo -e "${YELLOW}⚠️  Invalid webhook URL format: $EPYON_CALLBACK_URL${NC}" >&2
    exit 0  # Soft fail - don't block the scan
fi

# Map Epyon layer names to Barbatos tool names (lowercase, simple)
# Barbatos expects: syft, trivy, grype, trufflehog, checkov, xeol, etc.
map_tool_name() {
    local layer_name="$1"
    case "$layer_name" in
        layer-1---sbom|layer-1-*|sbom) echo "syft" ;;
        layer-2---trufflehog|layer-2-*|trufflehog) echo "trufflehog" ;;
        layer-3---sonar*|layer-3-*|sonar*) echo "sonarqube" ;;
        layer-4---clamav|layer-4-*|clamav) echo "clamav" ;;
        layer-5---helm|layer-5-*|helm) echo "helm" ;;
        layer-6---checkov|layer-6-*|checkov) echo "checkov" ;;
        layer-7---trivy|layer-7-*|trivy) echo "trivy" ;;
        layer-8---grype|layer-8-*|grype) echo "grype" ;;
        layer-9---xeol|layer-9-*|xeol) echo "xeol" ;;
        layer-10---anchore|layer-10-*|anchore) echo "anchore" ;;
        layer-11---api-discovery|layer-11-*|api-discovery) echo "api-discovery" ;;
        layer-115---pip-audit|pip-audit) echo "pip-audit" ;;
        layer-116---*safety*|safety) echo "safety" ;;
        *) 
            # Fallback: extract tool name from layer name
            echo "${layer_name}" | tr '[:upper:]' '[:lower:]' | sed 's/^layer-[0-9]*---//; s/^layer-[0-9]*-//' | sed 's/[^a-z0-9-]/-/g'
            ;;
    esac
}

# Extract layer number from layer name (e.g., "Layer 1 - SBOM" → 1)
extract_layer_number() {
    local layer_name="$1"
    # Try to extract from "Layer N" format
    if [[ "$layer_name" =~ [Ll]ayer[[:space:]]+([0-9]+) ]]; then
        echo "${BASH_REMATCH[1]}"
    # Try to extract from "layer-N-" format
    elif [[ "$layer_name" =~ layer-([0-9]+) ]]; then
        echo "${BASH_REMATCH[1]}"
    else
        echo ""
    fi
}

# Build Barbatos-compatible JSON payload
# Barbatos API contract (v1.0):
# - Progress (layer): { progress: { layer: 1, name: "syft", total: 16 } }
# - Progress (step): { progress: { step: "checkout-repo", label: "message" } }
# - Tool results: { tool: "grype", content: {...actual JSON...} }
# - Completion: { done: true }
# - Error: { error: "message" }
# - jobId goes in header X-Epyon-Job-Id ONLY, not in body

SIMPLE_TOOL=$(map_tool_name "$TOOL_NAME")

# If layer number not provided, try to extract from tool name
if [[ -z "$LAYER_NUM" && -n "$TOOL_NAME" ]]; then
    LAYER_NUM=$(extract_layer_number "$TOOL_NAME")
fi

case "$EVENT_TYPE" in
    scan_complete)
        # Scan finished - simple done flag
        JSON_PAYLOAD='{"done":true}'
        debug_log "Payload: completion signal"
        ;;
        
    error|scan_error)
        # Error occurred
        # Escape double quotes and newlines in message
        ESCAPED_MSG=$(echo -n "$MESSAGE" | sed 's/"/\\"/g' | tr '\n' ' ')
        JSON_PAYLOAD="{\"error\":\"$ESCAPED_MSG\"}"
        debug_log "Payload: error - $ESCAPED_MSG"
        ;;
        
    tool_start)
        # Tool starting - send progress update with layer info
        if [[ -n "$LAYER_NUM" ]]; then
            JSON_PAYLOAD="{\"progress\":{\"layer\":$LAYER_NUM,\"name\":\"$SIMPLE_TOOL\",\"total\":$TOTAL_LAYERS}}"
            debug_log "Payload: progress layer $LAYER_NUM/$TOTAL_LAYERS - $SIMPLE_TOOL"
        else
            # Fallback if no layer number - use step format
            ESCAPED_MSG=$(echo -n "$MESSAGE" | sed 's/"/\\"/g' | tr '\n' ' ')
            JSON_PAYLOAD="{\"progress\":{\"step\":\"$SIMPLE_TOOL\",\"label\":\"$ESCAPED_MSG\"}}"
            debug_log "Payload: progress step $SIMPLE_TOOL"
        fi
        ;;
        
    tool_complete)
        # Tool completed - send actual results if available
        if [[ -n "$RESULT_FILE" && -f "$RESULT_FILE" ]]; then
            # Read the actual tool JSON output and wrap it
            debug_log "Reading tool results from: $RESULT_FILE"
            
            # Check file size (warn if > 5MB, skip if > 10MB)
            FILE_SIZE=$(stat -f%z "$RESULT_FILE" 2>/dev/null || stat -c%s "$RESULT_FILE" 2>/dev/null || echo "0")
            if [[ "$FILE_SIZE" -gt 10485760 ]]; then
                debug_log "WARNING: Result file too large (${FILE_SIZE} bytes > 10MB), sending progress instead"
                JSON_PAYLOAD="{\"progress\":{\"layer\":${LAYER_NUM:-0},\"name\":\"$SIMPLE_TOOL\",\"total\":$TOTAL_LAYERS}}"
            elif [[ "$FILE_SIZE" -gt 5242880 ]]; then
                debug_log "WARNING: Large result file (${FILE_SIZE} bytes > 5MB), sending anyway but may be slow"
                TOOL_JSON=$(cat "$RESULT_FILE")
                # Validate it's valid JSON by checking first character
                if [[ "$TOOL_JSON" =~ ^[[:space:]]*[\{\[] ]]; then
                    JSON_PAYLOAD="{\"tool\":\"$SIMPLE_TOOL\",\"content\":$TOOL_JSON}"
                    debug_log "Payload: tool results for $SIMPLE_TOOL ($FILE_SIZE bytes)"
                else
                    debug_log "WARNING: Result file doesn't look like JSON, sending progress instead"
                    JSON_PAYLOAD="{\"progress\":{\"layer\":${LAYER_NUM:-0},\"name\":\"$SIMPLE_TOOL\",\"total\":$TOTAL_LAYERS}}"
                fi
            else
                TOOL_JSON=$(cat "$RESULT_FILE")
                # Validate it's valid JSON by checking first character
                if [[ "$TOOL_JSON" =~ ^[[:space:]]*[\{\[] ]]; then
                    JSON_PAYLOAD="{\"tool\":\"$SIMPLE_TOOL\",\"content\":$TOOL_JSON}"
                    debug_log "Payload: tool results for $SIMPLE_TOOL ($FILE_SIZE bytes)"
                else
                    debug_log "WARNING: Result file doesn't look like JSON, sending progress instead"
                    JSON_PAYLOAD="{\"progress\":{\"layer\":${LAYER_NUM:-0},\"name\":\"$SIMPLE_TOOL\",\"total\":$TOTAL_LAYERS}}"
                fi
            fi
        else
            # No results file - send progress update instead
            # This happens when tool completes but we don't have JSON to send yet
            if [[ -n "$LAYER_NUM" ]]; then
                JSON_PAYLOAD="{\"progress\":{\"layer\":$LAYER_NUM,\"name\":\"$SIMPLE_TOOL\",\"total\":$TOTAL_LAYERS}}"
                debug_log "Payload: progress layer $LAYER_NUM/$TOTAL_LAYERS - $SIMPLE_TOOL (no results file)"
            else
                ESCAPED_MSG=$(echo -n "$MESSAGE" | sed 's/"/\\"/g' | tr '\n' ' ')
                JSON_PAYLOAD="{\"progress\":{\"step\":\"$SIMPLE_TOOL\",\"label\":\"$ESCAPED_MSG\"}}"
                debug_log "Payload: progress step $SIMPLE_TOOL (no results file)"
            fi
        fi
        ;;
        
    scan_start|step)
        # Setup/teardown step or scan initialization
        ESCAPED_MSG=$(echo -n "$MESSAGE" | sed 's/"/\\"/g' | tr '\n' ' ')
        if [[ -n "$TOOL_NAME" ]]; then
            # If tool name provided, use it as step identifier
            JSON_PAYLOAD="{\"progress\":{\"step\":\"$SIMPLE_TOOL\",\"label\":\"$ESCAPED_MSG\"}}"
            debug_log "Payload: step $SIMPLE_TOOL - $ESCAPED_MSG"
        else
            # Generic step
            STEP_NAME=$(echo -n "$MESSAGE" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9]/-/g' | sed 's/^-*//; s/-*$//')
            JSON_PAYLOAD="{\"progress\":{\"step\":\"$STEP_NAME\",\"label\":\"$ESCAPED_MSG\"}}"
            debug_log "Payload: step $STEP_NAME"
        fi
        ;;
        
    *)
        # Unknown event - send as generic step
        ESCAPED_MSG=$(echo -n "$MESSAGE" | sed 's/"/\\"/g' | tr '\n' ' ')
        JSON_PAYLOAD="{\"progress\":{\"step\":\"unknown\",\"label\":\"$ESCAPED_MSG\"}}"
        debug_log "Payload: unknown event type $EVENT_TYPE, sending as step"
        ;;
esac

# Job ID is sent via header only (NOT in payload body per Barbatos API contract)
JOB_ID="${EPYON_JOB_ID:-unknown}"
HEADERS=(-H "Content-Type: application/json" -H "X-Epyon-Job-Id: $JOB_ID")

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
    
    HTTP_CODE=$(curl -s -o "$RESPONSE_FILE" -w "%{http_code}" \
        -X POST \
        "${HEADERS[@]}" \
        -d "$JSON_PAYLOAD" \
        "$EPYON_CALLBACK_URL" 2>&1 || echo "000")
    
    debug_log "HTTP response: $HTTP_CODE"
    
    if [[ "$HTTP_CODE" =~ ^2[0-9][0-9]$ ]]; then
        SUCCESS=true
        if [[ "${EPYON_WEBHOOK_DEBUG:-0}" == "1" ]]; then
            echo -e "${GREEN}✓${NC} Webhook delivered ($HTTP_CODE)" >&2
            echo -e "${GREEN}  Response:${NC} $(cat "$RESPONSE_FILE")" >&2
        fi
        break
    else
        # Log the failure
        if [[ "${EPYON_WEBHOOK_DEBUG:-0}" == "1" ]]; then
            echo -e "${YELLOW}⚠️  Webhook failed (HTTP $HTTP_CODE), attempt $i/$MAX_RETRIES${NC}" >&2
            echo -e "${YELLOW}  Response body:${NC} $(cat "$RESPONSE_FILE")" >&2
        fi
        
        # Retry with exponential backoff
        if [[ $i -lt $MAX_RETRIES ]]; then
            sleep $((RETRY_DELAY * i))
        fi
    fi
done

# Cleanup
rm -f "$RESPONSE_FILE"

# Always exit 0 - never block the scan due to webhook failures
if [[ "$SUCCESS" == "false" ]]; then
    if [[ "${EPYON_WEBHOOK_DEBUG:-0}" == "1" ]]; then
        echo -e "${RED}✗${NC} All webhook attempts failed - continuing scan anyway" >&2
    fi
fi

exit 0
