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

# ── Inventory weight formats (risk-rated) ────────────────────────────────────
# Format: <ext>|<risk_level>|<risk_label>|<notes>
declare -A FMT_RISK      # ext → risk level (critical/high/medium/low/safe)
declare -A FMT_LABEL     # ext → display label
declare -A FMT_NOTES     # ext → short notes
declare -A FMT_COUNT     # ext → file count
declare -A FMT_PICKLE    # ext → true if picklescan should scan it

# Pickle-based formats (arbitrary code execution on load)
FMT_RISK[pkl]="critical"; FMT_LABEL[pkl]=".pkl"; FMT_NOTES[pkl]="Pure pickle — arbitrary code execution on load"; FMT_PICKLE[pkl]="true"
FMT_RISK[pickle]="critical"; FMT_LABEL[pickle]=".pickle"; FMT_NOTES[pickle]="Pure pickle — arbitrary code execution on load"; FMT_PICKLE[pickle]="true"
FMT_RISK[pt]="high"; FMT_LABEL[pt]=".pt"; FMT_NOTES[pt]="PyTorch checkpoint — pickle-based, code execution risk"; FMT_PICKLE[pt]="true"
FMT_RISK[pth]="high"; FMT_LABEL[pth]=".pth"; FMT_NOTES[pth]="PyTorch checkpoint — pickle-based, code execution risk"; FMT_PICKLE[pth]="true"
FMT_RISK[ckpt]="high"; FMT_LABEL[ckpt]=".ckpt"; FMT_NOTES[ckpt]="PyTorch Lightning checkpoint — pickle-based"; FMT_PICKLE[ckpt]="true"
FMT_RISK[bin]="high"; FMT_LABEL[bin]=".bin"; FMT_NOTES[bin]="HuggingFace model weights — pickle-based, code execution risk"; FMT_PICKLE[bin]="true"
FMT_RISK[joblib]="high"; FMT_LABEL[joblib]=".joblib"; FMT_NOTES[joblib]="scikit-learn serialization — pickle-based"; FMT_PICKLE[joblib]="true"
# NumPy formats (allow_pickle=True risk)
FMT_RISK[npy]="medium"; FMT_LABEL[npy]=".npy"; FMT_NOTES[npy]="NumPy array — risky if loaded with allow_pickle=True"; FMT_PICKLE[npy]="true"
FMT_RISK[npz]="medium"; FMT_LABEL[npz]=".npz"; FMT_NOTES[npz]="NumPy archive — risky if loaded with allow_pickle=True"; FMT_PICKLE[npz]="true"
# HDF5 / Keras (limited attack surface, but can embed pickled objects)
FMT_RISK[h5]="medium"; FMT_LABEL[h5]=".h5"; FMT_NOTES[h5]="Keras/HDF5 — can embed pickled lambda layers"; FMT_PICKLE[h5]="true"
FMT_RISK[hdf5]="medium"; FMT_LABEL[hdf5]=".hdf5"; FMT_NOTES[hdf5]="HDF5 — can embed pickled lambda layers"; FMT_PICKLE[hdf5]="true"
# Safer formats (no pickle)
FMT_RISK[safetensors]="safe"; FMT_LABEL[safetensors]=".safetensors"; FMT_NOTES[safetensors]="HuggingFace SafeTensors — immune to pickle code execution"; FMT_PICKLE[safetensors]="false"
FMT_RISK[onnx]="low"; FMT_LABEL[onnx]=".onnx"; FMT_NOTES[onnx]="ONNX — protobuf-based, no pickle; custom ops may still be risky"; FMT_PICKLE[onnx]="false"
FMT_RISK[gguf]="low"; FMT_LABEL[gguf]=".gguf"; FMT_NOTES[gguf]="GGUF — llama.cpp format, custom binary, no pickle"; FMT_PICKLE[gguf]="false"
FMT_RISK[ggml]="low"; FMT_LABEL[ggml]=".ggml"; FMT_NOTES[ggml]="GGML — legacy llama.cpp format, no pickle"; FMT_PICKLE[ggml]="false"
FMT_RISK[msgpack]="low"; FMT_LABEL[msgpack]=".msgpack"; FMT_NOTES[msgpack]="MessagePack — binary serialization, no arbitrary code execution"; FMT_PICKLE[msgpack]="false"

ALL_EXTENSIONS=("pkl" "pickle" "pt" "pth" "ckpt" "bin" "joblib" "npy" "npz" "h5" "hdf5" "safetensors" "onnx" "gguf" "ggml" "msgpack")

# Count files per extension
FILE_COUNT=0
FORMATS_FOUND_JSON="["
FIRST=1
for ext in "${ALL_EXTENSIONS[@]}"; do
    cnt=$(find "$TARGET_SCAN_DIR" -type f -name "*.${ext}" 2>/dev/null | wc -l | tr -d ' ')
    FMT_COUNT[$ext]=$cnt
    if [[ "$cnt" -gt 0 ]]; then
        risk="${FMT_RISK[$ext]}"
        label="${FMT_LABEL[$ext]}"
        notes="${FMT_NOTES[$ext]}"
        pickle="${FMT_PICKLE[$ext]}"
        [[ "$FIRST" -eq 0 ]] && FORMATS_FOUND_JSON+=","
        FORMATS_FOUND_JSON+="{\"ext\":\"${ext}\",\"count\":${cnt},\"risk\":\"${risk}\",\"label\":\"${label}\",\"notes\":\"${notes}\",\"pickle_scannable\":${pickle}}"
        FIRST=0
        if [[ "${FMT_PICKLE[$ext]}" == "true" ]]; then
            FILE_COUNT=$((FILE_COUNT + cnt))
        fi
    fi
done
FORMATS_FOUND_JSON+="]"

# Total including non-pickle formats for display
TOTAL_FORMAT_COUNT=0
for ext in "${ALL_EXTENSIONS[@]}"; do
    TOTAL_FORMAT_COUNT=$((TOTAL_FORMAT_COUNT + ${FMT_COUNT[$ext]:-0}))
done

echo "Model weight formats found:"
for ext in "${ALL_EXTENSIONS[@]}"; do
    cnt=${FMT_COUNT[$ext]:-0}
    if [[ "$cnt" -gt 0 ]]; then
        risk="${FMT_RISK[$ext]}"
        echo "  .${ext} (${risk}) : ${cnt} file(s) — ${FMT_NOTES[$ext]}"
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

# ── Run picklescan ───────────────────────────────────────────────────────────
echo -e "${CYAN}🔬 Running picklescan…${NC}"
SCAN_EXIT=0
$PICKLESCAN_CMD \
    --path "$TARGET_SCAN_DIR" \
    --json \
    > >(tee "$RAW_FILE" | tee -a "$SCAN_LOG") \
    2> >(tee -a "$SCAN_LOG" >&2) || SCAN_EXIT=$?

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
    "total_weight_files": ${TOTAL_FORMAT_COUNT},
    "flagged_count":  ${FLAGGED_COUNT},
    "infected_files": infected_files,
    "weight_formats": ${FORMATS_FOUND_JSON},
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
  "total_weight_files": ${TOTAL_FORMAT_COUNT},
  "flagged_count": ${FLAGGED_COUNT},
  "weight_formats": [],
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
