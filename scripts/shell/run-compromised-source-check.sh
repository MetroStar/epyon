#!/bin/bash

# Layer 21 — Compromised Source / Supply Chain Incident Detection
# Cross-references the target repository against configuration/compromised-sources.json
# (disclosed artifact-repository compromises) and flags references to known-compromised hosts.
# No Docker required — pure Python.

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

show_help() {
    echo -e "${WHITE}Layer 21 — Compromised Source / Supply Chain Incident Detection${NC}"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Scans package manager configs, container manifests, and SBOMs for references"
    echo "to artifact-repository hosts with disclosed compromises."
    echo ""
    echo "Options:"
    echo "  -h, --help          Show this help message and exit"
    echo ""
    echo "Environment Variables:"
    echo "  TARGET_DIR                    Directory to scan (default: current directory)"
    echo "  SCAN_ID                       Override auto-generated scan ID"
    echo "  SCAN_DIR                      Override output directory for scan results"
    echo "  COMPROMISED_SOURCES_PATH      Path to registry JSON (default: configuration/compromised-sources.json)"
    echo ""
    echo "Output:"
    echo "  Results are saved to: scans/{SCAN_ID}/compromised-source/"
    echo "  - compromised-source-results.json   Normalized scan summary"
    echo "  - compromised-source.log            Scan process log"
    echo ""
    echo "Examples:"
    echo "  $0                                               # Scan current directory"
    echo "  TARGET_DIR=/path/to/repo $0                      # Scan specific directory"
    echo "  COMPROMISED_SOURCES_PATH=/path/to/custom.json $0 # Use a custom incident registry"
    echo ""
    echo "Notes:"
    echo "  - Requires Python 3.8+"
    echo "  - Default registry: configuration/compromised-sources.json"
    exit 0
}

for arg in "$@"; do
    case $arg in
        -h|--help) show_help ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/scan-directory-template.sh"

init_scan_environment "compromised-source"

TARGET_SCAN_DIR="${TARGET_DIR:-$(pwd)}"
if [[ -z "$TARGET_SCAN_DIR" ]]; then
    echo "[INFO] TARGET_DIR is not set — skipping Layer 21 (compromised-source)" >&2
    mkdir -p "$OUTPUT_DIR"
    cat > "${OUTPUT_DIR}/compromised-source-results.json" <<EOF
{
  "tool": "compromised-source-check",
  "status": "skipped",
  "reason": "TARGET_DIR not set",
  "scan_id": "${SCAN_ID:-unknown}",
  "target": "",
  "generated_at": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "statistics": {"files_scanned": 0, "matches_found": 0},
  "findings": []
}
EOF
    exit 0
fi
TARGET_SCAN_DIR=$(realpath "${TARGET_SCAN_DIR}" 2>/dev/null) || {
    echo "[INFO] TARGET_DIR does not exist (${TARGET_DIR}) — skipping Layer 21 (compromised-source)" >&2
    mkdir -p "$OUTPUT_DIR"
    cat > "${OUTPUT_DIR}/compromised-source-results.json" <<EOF
{
  "tool": "compromised-source-check",
  "status": "skipped",
  "reason": "target directory does not exist: ${TARGET_DIR}",
  "scan_id": "${SCAN_ID:-unknown}",
  "target": "${TARGET_DIR}",
  "generated_at": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "statistics": {"files_scanned": 0, "matches_found": 0},
  "findings": []
}
EOF
    exit 0
}

if [[ -n "$SCAN_ID" ]]; then
    TARGET_NAME=$(echo "$SCAN_ID" | cut -d'_' -f1)
    TIMESTAMP=$(echo "$SCAN_ID" | cut -d'_' -f3-)
else
    TARGET_NAME=$(basename "$TARGET_SCAN_DIR")
    TIMESTAMP=$(date '+%Y-%m-%d_%H-%M-%S')
    SCAN_ID="${TARGET_NAME}_$(whoami)_${TIMESTAMP}"
fi

RESULTS_FILE="$OUTPUT_DIR/compromised-source-results.json"
SCAN_LOG="$OUTPUT_DIR/compromised-source.log"

mkdir -p "$OUTPUT_DIR"

echo -e "${WHITE}============================================${NC}"
echo -e "${WHITE}Layer 21 — Compromised Source Detection${NC}"
echo -e "${WHITE}============================================${NC}"
echo "Target Directory : $TARGET_SCAN_DIR"
echo "Output Directory : $OUTPUT_DIR"
echo "Timestamp        : $TIMESTAMP"
echo ""

echo -e "${CYAN}🔍 Checking for references to known-compromised artifact sources...${NC}"
echo ""

SCAN_EXIT=0
SCANNER_SCRIPT="$SCRIPT_DIR/run-compromised-source-check.py"

if [[ ! -f "$SCANNER_SCRIPT" ]]; then
    echo -e "${RED}❌ Compromised-source checker not found: $SCANNER_SCRIPT${NC}"
    cat > "$RESULTS_FILE" <<EOF
{
  "tool": "compromised-source-check",
  "status": "error",
  "reason": "Compromised-source checker script not found",
  "scan_id": "${SCAN_ID}",
  "target": "${TARGET_SCAN_DIR}",
  "generated_at": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "statistics": {"files_scanned": 0, "matches_found": 0},
  "findings": []
}
EOF
    record_scan_status "error" "Compromised-source checker script not found"
    exit 1
fi

CMD_ARGS=(
    --target "$TARGET_SCAN_DIR"
    --scan-dir "$OUTPUT_DIR"
    --app-name "${TARGET_NAME}"
)

if [[ -n "$COMPROMISED_SOURCES_PATH" ]]; then
    CMD_ARGS+=(--registry-path "$COMPROMISED_SOURCES_PATH")
fi

python3 "$SCANNER_SCRIPT" "${CMD_ARGS[@]}" \
    2>&1 | tee -a "$SCAN_LOG"
SCAN_EXIT="${PIPESTATUS[0]}"

echo ""

CRITICAL_COUNT=0
HIGH_COUNT=0
MATCHES_COUNT=0

if [[ -f "$RESULTS_FILE" ]] && python3 -c "import json,sys; json.load(open('$RESULTS_FILE'))" 2>/dev/null; then
    CRITICAL_COUNT=$(python3 -c "
import json
try:
    d = json.load(open('$RESULTS_FILE'))
    print(d.get('summary', {}).get('critical_findings', 0))
except Exception:
    print(0)
" 2>/dev/null)
    HIGH_COUNT=$(python3 -c "
import json
try:
    d = json.load(open('$RESULTS_FILE'))
    print(d.get('summary', {}).get('high_findings', 0))
except Exception:
    print(0)
" 2>/dev/null)
    MATCHES_COUNT=$(python3 -c "
import json
try:
    d = json.load(open('$RESULTS_FILE'))
    print(d.get('statistics', {}).get('matches_found', 0))
except Exception:
    print(0)
" 2>/dev/null)
else
    echo -e "${RED}❌ Failed to read scanner results${NC}"
    SCAN_EXIT=1
fi

CRITICAL_COUNT="${CRITICAL_COUNT:-0}"
HIGH_COUNT="${HIGH_COUNT:-0}"
MATCHES_COUNT="${MATCHES_COUNT:-0}"

if [[ "$CRITICAL_COUNT" -gt 0 ]] || [[ "$HIGH_COUNT" -gt 0 ]]; then
    STATUS="open"
    echo -e "${RED}🚨 ALERT: References to compromised artifact sources detected!${NC}"
    echo -e "${RED}   Critical: ${CRITICAL_COUNT}, High: ${HIGH_COUNT}, Total matches: ${MATCHES_COUNT}${NC}"
else
    STATUS="success"
    echo -e "${GREEN}✅ No references to known-compromised artifact sources detected${NC}"
fi

STATUS_MSG="Found ${CRITICAL_COUNT} critical and ${HIGH_COUNT} high compromised-source references (${MATCHES_COUNT} total matches)"

echo ""
echo "Results written to: $RESULTS_FILE"
echo ""

record_scan_status "$STATUS" "$STATUS_MSG"

exit $SCAN_EXIT
