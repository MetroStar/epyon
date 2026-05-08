#!/bin/bash

# Layer 14 — Pickle/Serialization Safety Scanner
# Scans ML model files for malicious pickle opcodes using picklescan.
# Targets: .pkl .pt .pth .bin .ckpt .npy .npz .joblib .h5 .hdf5
# No Docker required — uses pip-installed picklescan.

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

show_help() {
    echo -e "${WHITE}Layer 14 — Pickle/Serialization Safety Scanner${NC}"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Scans machine learning model files for malicious pickle opcodes"
    echo "that could execute arbitrary code when loaded."
    echo ""
    echo "Options:"
    echo "  -h, --help          Show this help message and exit"
    echo ""
    echo "Environment Variables:"
    echo "  TARGET_DIR              Directory to scan (default: current directory)"
    echo "  SCAN_ID                 Override auto-generated scan ID"
    echo "  SCAN_DIR                Override output directory for scan results"
    echo "  PICKLESCAN_AUTO_INSTALL Auto-install picklescan if missing: true/false (default: true)"
    echo "  PICKLESCAN_PIP_SPEC     pip package spec (default: picklescan)"
    echo ""
    echo "Output:"
    echo "  Results are saved to: scans/{SCAN_ID}/picklescan/"
    echo "  - picklescan-results.json     Normalized scan summary"
    echo "  - picklescan-raw.json         Raw picklescan output"
    echo "  - picklescan.log              Scan process log"
    echo ""
    echo "Scanned file types:"
    echo "  .pkl .pt .pth .bin .ckpt .npy .npz .joblib .h5 .hdf5"
    echo ""
    echo "Examples:"
    echo "  $0                                      # Scan current directory"
    echo "  TARGET_DIR=/path/to/model-repo $0       # Scan specific directory"
    echo ""
    echo "Notes:"
    echo "  - Requires Python 3.8+"
    echo "  - Common threat: HuggingFace model repos with malicious .pkl/.bin files"
    echo "  - Safe alternatives: .safetensors format does not use pickle"
    exit 0
}

for arg in "$@"; do
    case $arg in
        -h|--help) show_help ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/scan-directory-template.sh"

init_scan_environment "picklescan"

TARGET_SCAN_DIR="${TARGET_DIR:-$(pwd)}"
TARGET_SCAN_DIR=$(realpath "${TARGET_SCAN_DIR}" 2>/dev/null) || {
    echo "ERROR: Target path does not exist or is invalid: ${TARGET_SCAN_DIR}" >&2
    exit 1
}

if [[ -n "$SCAN_ID" ]]; then
    TARGET_NAME=$(echo "$SCAN_ID" | cut -d'_' -f1)
    TIMESTAMP=$(echo "$SCAN_ID" | cut -d'_' -f3-)
else
    TARGET_NAME=$(basename "$TARGET_SCAN_DIR")
    TIMESTAMP=$(date '+%Y-%m-%d_%H-%M-%S')
    SCAN_ID="${TARGET_NAME}_$(whoami)_${TIMESTAMP}"
fi

PICKLESCAN_AUTO_INSTALL="${PICKLESCAN_AUTO_INSTALL:-true}"
PICKLESCAN_PIP_SPEC="${PICKLESCAN_PIP_SPEC:-picklescan}"

RESULTS_FILE="$OUTPUT_DIR/picklescan-results.json"
RAW_FILE="$OUTPUT_DIR/picklescan-raw.json"
SCAN_LOG="$OUTPUT_DIR/picklescan.log"

mkdir -p "$OUTPUT_DIR"

echo -e "${WHITE}============================================${NC}"
echo -e "${WHITE}Layer 14 — Pickle/Serialization Safety${NC}"
echo -e "${WHITE}============================================${NC}"
echo "Target Directory : $TARGET_SCAN_DIR"
echo "Output Directory : $OUTPUT_DIR"
echo "Timestamp        : $TIMESTAMP"
echo ""

# ── Ensure picklescan is available ──────────────────────────────────────────
PICKLESCAN_CMD=""
if command -v picklescan >/dev/null 2>&1; then
    PICKLESCAN_CMD="picklescan"
elif python3 -m picklescan --help >/dev/null 2>&1; then
    PICKLESCAN_CMD="python3 -m picklescan"
fi

if [[ -z "$PICKLESCAN_CMD" ]]; then
    if [[ "$PICKLESCAN_AUTO_INSTALL" == "true" ]]; then
        echo -e "${CYAN}📦 picklescan not found — installing ${PICKLESCAN_PIP_SPEC}…${NC}"
        if python3 -m pip install --quiet "$PICKLESCAN_PIP_SPEC" 2>&1 | tee -a "$SCAN_LOG"; then
            if command -v picklescan >/dev/null 2>&1; then
                PICKLESCAN_CMD="picklescan"
            else
                PICKLESCAN_CMD="python3 -m picklescan"
            fi
            echo -e "${GREEN}✅ picklescan installed${NC}"
        else
            echo -e "${RED}❌ Failed to install picklescan${NC}"
            cat > "$RESULTS_FILE" <<EOF
{
  "tool": "picklescan",
  "status": "skipped",
  "reason": "picklescan installation failed",
  "scan_id": "${SCAN_ID}",
  "target": "${TARGET_SCAN_DIR}",
  "generated_at": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "file_count": 0,
  "flagged_count": 0,
  "findings": []
}
EOF
            record_scan_status "skipped" "picklescan installation failed"
            exit 0
        fi
    else
        echo -e "${YELLOW}⚠️  picklescan not available and auto-install is disabled — skipping${NC}"
        cat > "$RESULTS_FILE" <<EOF
{
  "tool": "picklescan",
  "status": "skipped",
  "reason": "picklescan not installed (PICKLESCAN_AUTO_INSTALL=false)",
  "scan_id": "${SCAN_ID}",
  "target": "${TARGET_SCAN_DIR}",
  "generated_at": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "file_count": 0,
  "flagged_count": 0,
  "findings": []
}
EOF
        record_scan_status "skipped" "picklescan not installed"
        exit 0
    fi
fi

echo -e "${CYAN}🔍 Scanning for serialized model files…${NC}"
echo "Scanning: $TARGET_SCAN_DIR"
echo ""

# ── Count files before scanning ─────────────────────────────────────────────
FILE_EXTENSIONS=("pkl" "pt" "pth" "bin" "ckpt" "npy" "npz" "joblib" "h5" "hdf5")
FILE_COUNT=0
for ext in "${FILE_EXTENSIONS[@]}"; do
    count=$(find "$TARGET_SCAN_DIR" -type f -name "*.${ext}" 2>/dev/null | wc -l | tr -d ' ')
    FILE_COUNT=$((FILE_COUNT + count))
done

echo "Files to scan : $FILE_COUNT serialized file(s) found"
echo ""

if [[ "$FILE_COUNT" -eq 0 ]]; then
    echo -e "${GREEN}✅ No serialized model files found — nothing to scan${NC}"
    cat > "$RESULTS_FILE" <<EOF
{
  "tool": "picklescan",
  "status": "success",
  "reason": "no serialized model files found",
  "scan_id": "${SCAN_ID}",
  "target": "${TARGET_SCAN_DIR}",
  "generated_at": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "file_count": 0,
  "flagged_count": 0,
  "findings": []
}
EOF
    record_scan_status "success" "no serialized model files found"
    exit 0
fi

# ── Run picklescan ───────────────────────────────────────────────────────────
echo -e "${CYAN}🔬 Running picklescan…${NC}"
SCAN_EXIT=0
$PICKLESCAN_CMD \
    --path "$TARGET_SCAN_DIR" \
    --json \
    2>&1 | tee "$RAW_FILE" | tee -a "$SCAN_LOG" || SCAN_EXIT=$?

echo ""

# ── Parse results ────────────────────────────────────────────────────────────
FLAGGED_COUNT=0
GLOBAL_IMPORTS="[]"
INFECTED_FILES="[]"

if [[ -f "$RAW_FILE" ]] && python3 -c "import json,sys; json.load(open('$RAW_FILE'))" 2>/dev/null; then
    FLAGGED_COUNT=$(python3 -c "
import json, sys
try:
    d = json.load(open('$RAW_FILE'))
    # picklescan outputs: {\"infected_files\": N, \"safe_files\": N, \"issues_by_severity\": {...}}
    print(d.get('infected_files', 0))
except Exception:
    print(0)
" 2>/dev/null)
    GLOBAL_IMPORTS=$(python3 -c "
import json
try:
    d = json.load(open('$RAW_FILE'))
    issues = d.get('issues_by_severity', {})
    all_issues = []
    for severity, items in issues.items():
        for item in (items if isinstance(items, list) else []):
            all_issues.append({'severity': severity, 'file': item.get('source', ''), 'globals': item.get('globals', []), 'details': str(item)})
    print(json.dumps(all_issues))
except Exception:
    print('[]')
" 2>/dev/null)
    INFECTED_FILES=$(python3 -c "
import json
try:
    d = json.load(open('$RAW_FILE'))
    issues = d.get('issues_by_severity', {})
    files = []
    for severity, items in issues.items():
        for item in (items if isinstance(items, list) else []):
            f = item.get('source', item.get('file', ''))
            if f and f not in files:
                files.append(f)
    print(json.dumps(files))
except Exception:
    print('[]')
" 2>/dev/null)
fi

FLAGGED_COUNT="${FLAGGED_COUNT:-0}"

if [[ "$FLAGGED_COUNT" -gt 0 ]]; then
    STATUS="open"
    echo -e "${RED}🚨 ALERT: ${FLAGGED_COUNT} malicious file(s) detected!${NC}"
    echo -e "${RED}   These files contain dangerous pickle opcodes that execute arbitrary code on load.${NC}"
else
    STATUS="success"
    echo -e "${GREEN}✅ No malicious serialized files detected (${FILE_COUNT} file(s) scanned)${NC}"
fi

# ── Write normalized results ─────────────────────────────────────────────────
GENERATED_AT="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
python3 - <<PYEOF
import json

findings_raw = ${GLOBAL_IMPORTS}
infected_files = ${INFECTED_FILES}

# Build a findings list compatible with the epyon findings format
findings = []
for item in findings_raw:
    findings.append({
        "severity":   item.get("severity", "high").lower(),
        "file":       item.get("file", ""),
        "globals":    item.get("globals", []),
        "details":    item.get("details", ""),
        "message":    "Malicious pickle opcode detected — arbitrary code execution risk",
    })

result = {
    "tool":           "picklescan",
    "status":         "${STATUS}",
    "scan_id":        "${SCAN_ID}",
    "target":         "${TARGET_SCAN_DIR}",
    "generated_at":   "${GENERATED_AT}",
    "file_count":     ${FILE_COUNT},
    "flagged_count":  ${FLAGGED_COUNT},
    "infected_files": infected_files,
    "findings":       findings,
}

with open("${RESULTS_FILE}", "w") as f:
    json.dump(result, f, indent=2)
print("Results written to ${RESULTS_FILE}")
PYEOF

PYEOF_EXIT=$?

if [[ $PYEOF_EXIT -ne 0 ]]; then
    # Fallback minimal output
    cat > "$RESULTS_FILE" <<EOF
{
  "tool": "picklescan",
  "status": "${STATUS}",
  "scan_id": "${SCAN_ID}",
  "target": "${TARGET_SCAN_DIR}",
  "generated_at": "${GENERATED_AT}",
  "file_count": ${FILE_COUNT},
  "flagged_count": ${FLAGGED_COUNT},
  "infected_files": [],
  "findings": []
}
EOF
fi

echo ""
echo "Results written to: $RESULTS_FILE"

if [[ "$STATUS" == "open" ]]; then
    record_scan_status "failed" "${FLAGGED_COUNT} malicious file(s) detected"
    echo -e "${RED}❌ Picklescan completed with findings — ${FLAGGED_COUNT} infected file(s)${NC}"
    exit 1
else
    record_scan_status "success" ""
    echo -e "${GREEN}✅ Picklescan completed — no threats detected${NC}"
    exit 0
fi
