#!/bin/bash

# ══════════════════════════════════════════════════════════════════════════════
# Webhook Integration Test Script
# ══════════════════════════════════════════════════════════════════════════════
# Tests the full webhook flow from API call through to delivery
# ══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  Epyon Webhook Integration Test${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo ""

# Configuration
API_HOST="${API_HOST:-http://localhost:8056}"
WEBHOOK_URL="${WEBHOOK_URL:-https://srtm.dialtone.cc/api/security-scan-webhook}"
WEBHOOK_SECRET="${WEBHOOK_SECRET:-test-secret-123}"
TARGET_PATH="${TARGET_PATH:-$(pwd)}"

echo -e "${YELLOW}Test Configuration:${NC}"
echo "  API Host:       $API_HOST"
echo "  Webhook URL:    $WEBHOOK_URL"
echo "  Webhook Secret: ${WEBHOOK_SECRET:0:8}... (redacted)"
echo "  Target Path:    $TARGET_PATH"
echo ""

# Step 1: Check if API is running
echo -e "${YELLOW}Step 1: Checking if Epyon API is running...${NC}"
if curl -s -f "$API_HOST/api/health" > /dev/null 2>&1; then
    echo -e "${GREEN}✓ API is accessible${NC}"
else
    echo -e "${RED}✗ API is not accessible at $API_HOST${NC}"
    echo "  Start the API with: cd web && uvicorn api.main:app --reload"
    exit 1
fi
echo ""

# Step 2: Trigger a scan with webhook configuration
echo -e "${YELLOW}Step 2: Triggering scan with webhook configuration...${NC}"

PAYLOAD=$(cat <<EOF
{
  "target": "$TARGET_PATH",
  "scan_type": "quick",
  "webhook_url": "$WEBHOOK_URL",
  "webhook_secret": "$WEBHOOK_SECRET"
}
EOF
)

echo "Payload:"
echo "$PAYLOAD" | jq '.' 2>/dev/null || echo "$PAYLOAD"
echo ""

RESPONSE=$(curl -s -X POST "$API_HOST/api/scans" \
  -H "Content-Type: application/json" \
  -d "$PAYLOAD")

echo "Response:"
echo "$RESPONSE" | jq '.' 2>/dev/null || echo "$RESPONSE"
echo ""

JOB_ID=$(echo "$RESPONSE" | jq -r '.job_id' 2>/dev/null || echo "")

if [[ -z "$JOB_ID" || "$JOB_ID" == "null" ]]; then
    echo -e "${RED}✗ Failed to get job_id from response${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Scan triggered successfully${NC}"
echo "  Job ID: $JOB_ID"
echo ""

# Step 3: Monitor job progress
echo -e "${YELLOW}Step 3: Monitoring job progress (checking for webhook logs)...${NC}"
echo "  Checking job output every 5 seconds..."
echo "  Press Ctrl+C to stop monitoring"
echo ""

MAX_CHECKS=12  # 1 minute
CHECK_COUNT=0

while [[ $CHECK_COUNT -lt $MAX_CHECKS ]]; do
    sleep 5
    CHECK_COUNT=$((CHECK_COUNT + 1))
    
    JOB_STATUS=$(curl -s "$API_HOST/api/jobs/$JOB_ID" | jq -r '.status' 2>/dev/null || echo "unknown")
    
    echo -e "${BLUE}[$(date +%H:%M:%S)]${NC} Job status: $JOB_STATUS"
    
    # Get the last few lines of output
    OUTPUT=$(curl -s "$API_HOST/api/jobs/$JOB_ID" | jq -r '.output[-5:][]' 2>/dev/null || echo "")
    
    if [[ -n "$OUTPUT" ]]; then
        # Check for webhook-related logs
        if echo "$OUTPUT" | grep -q "Webhook configured"; then
            echo -e "${GREEN}✓ Found webhook configuration in job output:${NC}"
            echo "$OUTPUT" | grep "Webhook configured"
        fi
        
        if echo "$OUTPUT" | grep -q "webhook-debug"; then
            echo -e "${GREEN}✓ Found webhook debug logs:${NC}"
            echo "$OUTPUT" | grep "webhook-debug"
        fi
    fi
    
    if [[ "$JOB_STATUS" == "completed" || "$JOB_STATUS" == "failed" ]]; then
        echo -e "${GREEN}✓ Job finished with status: $JOB_STATUS${NC}"
        break
    fi
done

echo ""
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}Test Summary:${NC}"
echo ""
echo "To see full job output:"
echo "  curl -s $API_HOST/api/jobs/$JOB_ID | jq -r '.output[]'"
echo ""
echo "To check if webhooks were sent, look for:"
echo "  - '[web-ui] Webhook configured: $WEBHOOK_URL'"
echo "  - '[webhook-debug] Attempt X/3: POST to $WEBHOOK_URL'"
echo "  - '[webhook-debug] Response: HTTP XXX'"
echo ""
echo "If you don't see webhook logs, ensure:"
echo "  1. The API server was restarted after the code changes"
echo "  2. EPYON_WEBHOOK_DEBUG=1 is set when starting the API"
echo ""
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
