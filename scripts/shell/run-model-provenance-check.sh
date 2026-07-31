#!/bin/bash

# Layer 18 — Model Provenance & Threat Intelligence Scanner
# Validates ML model provenance, checks signatures, and cross-references against threat intelligence.
# No Docker required — pure Python + optional GPG.

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

show_help() {
    echo -e "${WHITE}Layer 18 — Model Provenance & Threat Intelligence Scanner${NC}"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Validates ML model provenance and checks against threat intelligence."
    echo ""
    echo "Validates:"
    echo "  - Model file SHA256 hashes against expected values"
    echo "  - GPG/Sigstore signatures (if present)"
    echo "  - Hugging Face Hub download provenance"
    echo "  - Author reputation and account age"
    echo "  - Static blocklist (configuration/ml-blocklist.json)"
    echo "  - Dynamic threat feed (optional)"
    echo "  - Supply chain metadata (model cards)"
    echo ""
    echo "Options:"
    echo "  -h, --help          Show this help message and exit"
    echo ""
    echo "Environment Variables:"
    echo "  TARGET_DIR              Directory to scan (default: current directory)"
    echo "  SCAN_ID                 Override auto-generated scan ID"
    echo "  SCAN_DIR                Override output directory for scan results"
    echo "  ML_BLOCKLIST_PATH       Path to static blocklist JSON (default: configuration/ml-blocklist.json)"
    echo "  ML_THREAT_FEED_URL      URL to fetch dynamic threat intelligence"
    echo "  HF_TOKEN                Hugging Face API token for reputation checking"
    echo ""
    echo "Output:"
    echo "  Results are saved to: scans/{SCAN_ID}/model-provenance/"
    echo "  - model-provenance-results.json     Normalized scan summary"
    echo "  - model-provenance.log              Scan process log"
    echo ""
    echo "Scanned file types:"
    echo "  .pkl .pt .pth .bin .ckpt .onnx .pb .safetensors .h5 .hdf5"
    echo ""
    echo "Examples:"
    echo "  $0                                          # Scan current directory"
    echo "  TARGET_DIR=/path/to/model-repo $0           # Scan specific directory"
    echo "  HF_TOKEN=hf_xxx $0                          # Enable reputation checking"
    echo "  ML_THREAT_FEED_URL=https://... $0           # Use dynamic threat feed"
    echo ""
    echo "Notes:"
    echo "  - Requires Python 3.8+"
    echo "  - Optional: GPG for signature verification"
    echo "  - Default blocklist: configuration/ml-blocklist.json"
    exit 0
}

for arg in "$@"; do
    case $arg in
        -h|--help) show_help ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/scan-directory-template.sh"

init_scan_environment "model-provenance"

TARGET_SCAN_DIR="${TARGET_DIR:-$(pwd)}"
if [[ -z "$TARGET_SCAN_DIR" ]]; then
    echo "[INFO] TARGET_DIR is not set — skipping Layer 18 (model-provenance)" >&2
    mkdir -p "$OUTPUT_DIR"
    cat > "${OUTPUT_DIR}/model-provenance-results.json" <<EOF
{
  "tool": "model-provenance-check",
  "status": "skipped",
  "reason": "TARGET_DIR not set",
  "scan_id": "${SCAN_ID:-unknown}",
  "target": "",
  "generated_at": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "statistics": {"total_models": 0},
  "findings": []
}
EOF
    exit 0
fi
TARGET_SCAN_DIR=$(realpath "${TARGET_SCAN_DIR}" 2>/dev/null) || {
    echo "[INFO] TARGET_DIR does not exist (${TARGET_DIR}) — skipping Layer 18 (model-provenance)" >&2
    mkdir -p "$OUTPUT_DIR"
    cat > "${OUTPUT_DIR}/model-provenance-results.json" <<EOF
{
  "tool": "model-provenance-check",
  "status": "skipped",
  "reason": "target directory does not exist: ${TARGET_DIR}",
  "scan_id": "${SCAN_ID:-unknown}",
  "target": "${TARGET_DIR}",
  "generated_at": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "statistics": {"total_models": 0},
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

RESULTS_FILE="$OUTPUT_DIR/model-provenance-results.json"
SCAN_LOG="$OUTPUT_DIR/model-provenance.log"

mkdir -p "$OUTPUT_DIR"

echo -e "${WHITE}============================================${NC}"
echo -e "${WHITE}Layer 18 — Model Provenance & Threat Intel${NC}"
echo -e "${WHITE}============================================${NC}"
echo "Target Directory : $TARGET_SCAN_DIR"
echo "Output Directory : $OUTPUT_DIR"
echo "Timestamp        : $TIMESTAMP"
echo ""

# ── Run provenance checker ──────────────────────────────────────────────────
echo -e "${CYAN}🔍 Running model provenance checks...${NC}"
echo ""

SCAN_EXIT=0
SCANNER_SCRIPT="$SCRIPT_DIR/run-model-provenance-check.py"

if [[ ! -f "$SCANNER_SCRIPT" ]]; then
    echo -e "${RED}❌ Provenance checker not found: $SCANNER_SCRIPT${NC}"
    cat > "$RESULTS_FILE" <<EOF
{
  "tool": "model-provenance-check",
  "status": "error",
  "reason": "Provenance checker script not found",
  "scan_id": "${SCAN_ID}",
  "target": "${TARGET_SCAN_DIR}",
  "generated_at": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "statistics": {"total_models": 0},
  "findings": []
}
EOF
    record_scan_status "error" "Provenance checker script not found"
    exit 1
fi

# Build command with optional parameters
CMD_ARGS=(
    --target "$TARGET_SCAN_DIR"
    --scan-dir "$OUTPUT_DIR"
    --app-name "${TARGET_NAME}"
)

if [[ -n "$ML_BLOCKLIST_PATH" ]]; then
    CMD_ARGS+=(--blocklist-path "$ML_BLOCKLIST_PATH")
fi

if [[ -n "$ML_THREAT_FEED_URL" ]]; then
    CMD_ARGS+=(--threat-feed-url "$ML_THREAT_FEED_URL")
    echo -e "${CYAN}📡 Dynamic threat feed enabled: $ML_THREAT_FEED_URL${NC}"
fi

if [[ -n "$HF_TOKEN" ]]; then
    CMD_ARGS+=(--hf-token "$HF_TOKEN")
    echo -e "${CYAN}🔑 Hugging Face reputation checking enabled${NC}"
fi

# Run the provenance checker
python3 "$SCANNER_SCRIPT" "${CMD_ARGS[@]}" \
    2>&1 | tee -a "$SCAN_LOG" || SCAN_EXIT=$?

echo ""

# ── Parse results ────────────────────────────────────────────────────────────
BLOCKED_COUNT=0
CRITICAL_COUNT=0
HIGH_COUNT=0

if [[ -f "$RESULTS_FILE" ]] && python3 -c "import json,sys; json.load(open('$RESULTS_FILE'))" 2>/dev/null; then
    BLOCKED_COUNT=$(python3 -c "
import json, sys
try:
    d = json.load(open('$RESULTS_FILE'))
    print(d.get('statistics', {}).get('blocked_models', 0))
except Exception:
    print(0)
" 2>/dev/null)
    CRITICAL_COUNT=$(python3 -c "
import json, sys
try:
    d = json.load(open('$RESULTS_FILE'))
    print(d.get('summary', {}).get('critical_findings', 0))
except Exception:
    print(0)
" 2>/dev/null)
    HIGH_COUNT=$(python3 -c "
import json, sys
try:
    d = json.load(open('$RESULTS_FILE'))
    print(d.get('summary', {}).get('high_findings', 0))
except Exception:
    print(0)
" 2>/dev/null)
else
    echo -e "${RED}❌ Failed to read scanner results${NC}"
    SCAN_EXIT=1
fi

BLOCKED_COUNT="${BLOCKED_COUNT:-0}"
CRITICAL_COUNT="${CRITICAL_COUNT:-0}"
HIGH_COUNT="${HIGH_COUNT:-0}"

if [[ "$CRITICAL_COUNT" -gt 0 ]] || [[ "$HIGH_COUNT" -gt 0 ]]; then
    STATUS="open"
    echo -e "${RED}🚨 ALERT: Provenance issues detected!${NC}"
    echo -e "${RED}   Critical: ${CRITICAL_COUNT}, High: ${HIGH_COUNT}, Blocked: ${BLOCKED_COUNT}${NC}"
    echo -e "${RED}   Models may be from untrusted sources or threat actors.${NC}"
else
    STATUS="success"
    echo -e "${GREEN}✅ No critical provenance issues detected${NC}"
fi

# Status already recorded by Python scanner
STATUS_MSG="Found ${CRITICAL_COUNT} critical and ${HIGH_COUNT} high provenance issues (${BLOCKED_COUNT} blocked models)"

echo ""
echo "Results written to: $RESULTS_FILE"
echo ""

record_scan_status "$STATUS" "$STATUS_MSG"

exit $SCAN_EXIT
