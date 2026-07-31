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
if [[ -z "$TARGET_SCAN_DIR" ]]; then
    echo "[INFO] TARGET_DIR is not set — skipping Layer 14 (picklescan)" >&2
    mkdir -p "$OUTPUT_DIR"
    cat > "${OUTPUT_DIR}/picklescan-results.json" <<EOF
{
  "tool": "picklescan",
  "status": "skipped",
  "reason": "TARGET_DIR not set",
  "scan_id": "${SCAN_ID:-unknown}",
  "target": "",
  "generated_at": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "file_count": 0,
  "total_weight_files": 0,
  "flagged_count": 0,
  "weight_formats": [],
  "infected_files": [],
  "findings": []
}
EOF
    exit 0
fi
TARGET_SCAN_DIR=$(realpath "${TARGET_SCAN_DIR}" 2>/dev/null) || {
    echo "[INFO] TARGET_DIR does not exist (${TARGET_DIR}) — skipping Layer 14 (picklescan)" >&2
    mkdir -p "$OUTPUT_DIR"
    cat > "${OUTPUT_DIR}/picklescan-results.json" <<EOF
{
  "tool": "picklescan",
  "status": "skipped",
  "reason": "target directory does not exist: ${TARGET_DIR}",
  "scan_id": "${SCAN_ID:-unknown}",
  "target": "${TARGET_DIR}",
  "generated_at": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "file_count": 0,
  "total_weight_files": 0,
  "flagged_count": 0,
  "weight_formats": [],
  "infected_files": [],
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

# ── Inventory weight formats (risk-rated) ────────────────────────────────────
# Bash 3-compatible: use parallel indexed arrays instead of associative arrays.
# Columns: ext | risk | label | pickle_scannable | notes
_FMT_EXT=(     pkl       pickle    pt         pth        ckpt       bin        joblib     npy        npz        h5         hdf5       safetensors onnx       gguf       ggml       msgpack    )
_FMT_RISK=(    critical  critical  high       high       high       high       high       medium     medium     medium     medium     safe        low        low        low        low        )
_FMT_LABEL=(   .pkl      .pickle   .pt        .pth       .ckpt      .bin       .joblib    .npy       .npz       .h5        .hdf5      .safetensors .onnx     .gguf      .ggml      .msgpack   )
_FMT_PICKLE=(  true      true      true       true       true       true       true       true       true       true       true       false       false      false      false      false      )
_FMT_NOTES=(
    "Pure pickle — arbitrary code execution on load"
    "Pure pickle — arbitrary code execution on load"
    "PyTorch checkpoint — pickle-based, code execution risk"
    "PyTorch checkpoint — pickle-based, code execution risk"
    "PyTorch Lightning checkpoint — pickle-based"
    "HuggingFace model weights — pickle-based, code execution risk"
    "scikit-learn serialization — pickle-based"
    "NumPy array — risky if loaded with allow_pickle=True"
    "NumPy archive — risky if loaded with allow_pickle=True"
    "Keras/HDF5 — can embed pickled lambda layers"
    "HDF5 — can embed pickled lambda layers"
    "HuggingFace SafeTensors — immune to pickle code execution"
    "ONNX — protobuf-based, no pickle; custom ops may still be risky"
    "GGUF — llama.cpp format, custom binary, no pickle"
    "GGML — legacy llama.cpp format, no pickle"
    "MessagePack — binary serialization, no arbitrary code execution"
)

# Count files per format (and collect relative paths for UI display)
FILE_COUNT=0
TOTAL_FORMAT_COUNT=0
FORMATS_FOUND_JSON="["
_JSON_FIRST=1
declare -a _FMT_COUNT=()

for i in "${!_FMT_EXT[@]}"; do
    ext="${_FMT_EXT[$i]}"
    # Collect file paths and count via Python (handles spaces/special chars safely)
    _fmt_result=$(python3 - <<PYFMT 2>/dev/null
import os, json
target = ${TARGET_SCAN_DIR@Q}
ext = ${ext@Q}
found = []
for root, dirs, files in os.walk(target):
    dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ('__pycache__', '.git', 'node_modules')]
    for fname in files:
        if fname.lower().endswith('.' + ext):
            rel = os.path.relpath(os.path.join(root, fname), target)
            found.append(rel)
found.sort()
print(len(found))
print(json.dumps(found[:50]))
PYFMT
)
    cnt=$(echo "$_fmt_result" | head -1 | tr -d '[:space:]')
    files_json=$(echo "$_fmt_result" | tail -1)
    [[ -z "$cnt" || ! "$cnt" =~ ^[0-9]+$ ]] && cnt=0
    [[ -z "$files_json" ]] && files_json="[]"

    _FMT_COUNT[$i]=$cnt
    TOTAL_FORMAT_COUNT=$((TOTAL_FORMAT_COUNT + cnt))
    if [[ "$cnt" -gt 0 ]]; then
        risk="${_FMT_RISK[$i]}"
        label="${_FMT_LABEL[$i]}"
        notes="${_FMT_NOTES[$i]}"
        pickle="${_FMT_PICKLE[$i]}"
        [[ "$_JSON_FIRST" -eq 0 ]] && FORMATS_FOUND_JSON+=","
        FORMATS_FOUND_JSON+="{\"ext\":\"${ext}\",\"count\":${cnt},\"risk\":\"${risk}\",\"label\":\"${label}\",\"notes\":\"${notes}\",\"pickle_scannable\":${pickle},\"files\":${files_json}}"
        _JSON_FIRST=0
        if [[ "$pickle" == "true" ]]; then
            FILE_COUNT=$((FILE_COUNT + cnt))
        fi
    fi
done
FORMATS_FOUND_JSON+="]"

echo "Model weight formats found:"
for i in "${!_FMT_EXT[@]}"; do
    cnt=${_FMT_COUNT[$i]:-0}
    if [[ "$cnt" -gt 0 ]]; then
        echo "  ${_FMT_LABEL[$i]} (${_FMT_RISK[$i]}) : ${cnt} file(s) — ${_FMT_NOTES[$i]}"
    fi
done
echo ""
echo "Pickle-scannable : $FILE_COUNT file(s)"
echo "Total model files: $TOTAL_FORMAT_COUNT file(s)"
echo ""

if [[ "$FILE_COUNT" -eq 0 ]]; then
    if [[ "$TOTAL_FORMAT_COUNT" -gt 0 ]]; then
        echo -e "${GREEN}✅ Only safe-format model files found — no pickle-scannable files${NC}"
        STATUS_MSG="only safe format files found (e.g. .safetensors, .onnx)"
    else
        echo -e "${GREEN}✅ No model weight files found — nothing to scan${NC}"
        STATUS_MSG="no model weight files found"
    fi
    cat > "$RESULTS_FILE" <<EOF
{
  "tool": "picklescan",
  "status": "success",
  "reason": "${STATUS_MSG}",
  "scan_id": "${SCAN_ID}",
  "target": "${TARGET_SCAN_DIR}",
  "generated_at": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "file_count": 0,
  "total_weight_files": ${TOTAL_FORMAT_COUNT},
  "flagged_count": 0,
  "weight_formats": ${FORMATS_FOUND_JSON},
  "infected_files": [],
  "findings": []
}
EOF
    record_scan_status "success" "${STATUS_MSG}"
    exit 0
fi

# ── Run enhanced model exploit scanner ──────────────────────────────────────
echo -e "${CYAN}🔬 Running comprehensive model file analysis…${NC}"
echo "   Formats: pickle, PyTorch, ONNX, TensorFlow, config files"
echo ""

SCAN_EXIT=0
SCANNER_SCRIPT="$SCRIPT_DIR/run-picklescan.py"

if [[ ! -f "$SCANNER_SCRIPT" ]]; then
    echo -e "${RED}❌ Enhanced scanner not found: $SCANNER_SCRIPT${NC}"
    cat > "$RESULTS_FILE" <<EOF
{
  "tool": "picklescan",
  "status": "error",
  "reason": "Enhanced scanner script not found",
  "scan_id": "${SCAN_ID}",
  "target": "${TARGET_SCAN_DIR}",
  "generated_at": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "file_count": 0,
  "flagged_count": 0,
  "findings": []
}
EOF
    record_scan_status "error" "Enhanced scanner script not found"
    exit 1
fi

# Run the enhanced Python scanner
python3 "$SCANNER_SCRIPT" \
    --target "$TARGET_SCAN_DIR" \
    --scan-dir "$OUTPUT_DIR" \
    --app-name "${TARGET_NAME}" \
    --formats "pickle,pytorch,onnx,tf,config" \
    2>&1 | tee -a "$SCAN_LOG" || SCAN_EXIT=$?

echo ""

# ── Parse results from enhanced scanner ──────────────────────────────────────
FLAGGED_COUNT=0
CRITICAL_COUNT=0
HIGH_COUNT=0

if [[ -f "$RESULTS_FILE" ]] && python3 -c "import json,sys; json.load(open('$RESULTS_FILE'))" 2>/dev/null; then
    FLAGGED_COUNT=$(python3 -c "
import json, sys
try:
    d = json.load(open('$RESULTS_FILE'))
    print(d.get('statistics', {}).get('flagged_count', 0))
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

FLAGGED_COUNT="${FLAGGED_COUNT:-0}"
CRITICAL_COUNT="${CRITICAL_COUNT:-0}"
HIGH_COUNT="${HIGH_COUNT:-0}"

if [[ "$CRITICAL_COUNT" -gt 0 ]] || [[ "$HIGH_COUNT" -gt 0 ]]; then
    STATUS="open"
    echo -e "${RED}🚨 ALERT: ${FLAGGED_COUNT} suspicious file(s) detected!${NC}"
    echo -e "${RED}   Critical: ${CRITICAL_COUNT}, High: ${HIGH_COUNT}${NC}"
    echo -e "${RED}   These files may contain exploits or dangerous patterns.${NC}"
else
    STATUS="success"
    echo -e "${GREEN}✅ No critical security threats detected (${FILE_COUNT} file(s) scanned)${NC}"
fi

# Results are already written by the Python scanner, just need to update status
STATUS_MSG="Scanned ${FILE_COUNT} model files, found ${FLAGGED_COUNT} security issues (${CRITICAL_COUNT} critical, ${HIGH_COUNT} high)"

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
