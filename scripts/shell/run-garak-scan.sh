#!/bin/bash

# Garak LLM Security Scanner
# Runs NVIDIA garak probes against a configured model endpoint

# Colors for help output
WHITE='\033[1;37m'
NC='\033[0m'

show_help() {
    echo -e "${WHITE}Garak LLM Security Scanner${NC}"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Runs NVIDIA garak to probe an LLM for jailbreak, prompt injection,"
    echo "hallucination, and other unsafe behaviors."
    echo ""
    echo "Options:"
    echo "  -h, --help          Show this help message and exit"
    echo ""
    echo "Environment Variables:"
    echo "  TARGET_DIR              Directory to scan (default: current directory)"
    echo "  SCAN_ID                 Override auto-generated scan ID"
    echo "  SCAN_DIR                Override output directory for scan results"
    echo "  GARAK_TARGET_TYPE       garak generator type (default: test)"
    echo "  GARAK_TARGET_NAME       Model name/target (default: test.Blank)"
    echo "  GARAK_PROBES            Probe set (default: promptinject)"
    echo "  GARAK_AUTO_INSTALL      Auto-install garak if missing: true/false (default: true)"
    echo "  GARAK_PIP_SPEC          pip package spec (default: garak)"
    echo ""
    echo "Output:"
    echo "  Results are saved to: scans/{SCAN_ID}/garak/"
    echo "  - garak-results.json              Normalized scan summary"
    echo "  - {SCAN_ID}_garak-results.json    Timestamped scan summary"
    echo "  - {SCAN_ID}_garak-console.log     Console output from garak"
    echo "  - {SCAN_ID}_garak-scan.log        Scanner process log"
    echo ""
    echo "Examples:"
    echo "  GARAK_TARGET_TYPE=openai GARAK_TARGET_NAME=gpt-5-nano OPENAI_API_KEY=... $0"
    echo "  GARAK_TARGET_TYPE=huggingface GARAK_TARGET_NAME=gpt2 GARAK_PROBES=dan $0"
    echo ""
    echo "Notes:"
    echo "  - Requires Python 3.10+"
    echo "  - Requires credentials for API-backed targets (OpenAI, Bedrock, etc.)"
    echo "  - Uses minimal probes by default for faster CI/runtime"
    exit 0
}

for arg in "$@"; do
    case $arg in
        -h|--help)
            show_help
            ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/scan-directory-template.sh"

init_scan_environment "garak"

TARGET_SCAN_DIR="${TARGET_DIR:-$(pwd)}"
if [[ -n "$SCAN_ID" ]]; then
    TARGET_NAME=$(echo "$SCAN_ID" | cut -d'_' -f1)
    USERNAME=$(echo "$SCAN_ID" | cut -d'_' -f2)
    TIMESTAMP=$(echo "$SCAN_ID" | cut -d'_' -f3-)
else
    TARGET_NAME=$(basename "$TARGET_SCAN_DIR")
    USERNAME=$(whoami)
    TIMESTAMP=$(date '+%Y-%m-%d_%H-%M-%S')
    SCAN_ID="${TARGET_NAME}_${USERNAME}_${TIMESTAMP}"
fi

GARAK_TARGET_TYPE_INPUT="${GARAK_TARGET_TYPE:-}"
GARAK_TARGET_NAME_INPUT="${GARAK_TARGET_NAME:-}"
GARAK_PROBES_INPUT="${GARAK_PROBES:-}"

if [[ -n "$GARAK_TARGET_TYPE_INPUT" ]]; then
    GARAK_TARGET_TYPE="$GARAK_TARGET_TYPE_INPUT"
    GARAK_TARGET_TYPE_SOURCE="provided"
else
    GARAK_TARGET_TYPE="test"
    GARAK_TARGET_TYPE_SOURCE="default"
fi

if [[ -n "$GARAK_TARGET_NAME_INPUT" ]]; then
    GARAK_TARGET_NAME="$GARAK_TARGET_NAME_INPUT"
    GARAK_TARGET_NAME_SOURCE="provided"
else
    GARAK_TARGET_NAME="test.Blank"
    GARAK_TARGET_NAME_SOURCE="default"
fi

if [[ -n "$GARAK_PROBES_INPUT" ]]; then
    GARAK_PROBES="$GARAK_PROBES_INPUT"
    GARAK_PROBES_SOURCE="provided"
else
    GARAK_PROBES="promptinject,dan,knownbadsignatures,encoding,continuation"
    GARAK_PROBES_SOURCE="default"
fi

if [[ "$GARAK_TARGET_TYPE_SOURCE" == "provided" && "$GARAK_TARGET_NAME_SOURCE" == "provided" ]]; then
    GARAK_TARGET_ORIGIN="provided"
elif [[ "$GARAK_TARGET_TYPE_SOURCE" == "default" && "$GARAK_TARGET_NAME_SOURCE" == "default" ]]; then
    GARAK_TARGET_ORIGIN="default"
else
    GARAK_TARGET_ORIGIN="mixed(type:${GARAK_TARGET_TYPE_SOURCE},name:${GARAK_TARGET_NAME_SOURCE})"
fi

GARAK_TARGET_TYPE_LC=$(printf '%s' "$GARAK_TARGET_TYPE" | tr '[:upper:]' '[:lower:]')
GARAK_RUNTIME_ENDPOINT="N/A"
GARAK_RUNTIME_CLASSIFICATION="custom"
case "$GARAK_TARGET_TYPE_LC" in
    openai)
        GARAK_RUNTIME_ENDPOINT="${OPENAI_BASE_URL:-https://api.openai.com/v1}"
        GARAK_RUNTIME_CLASSIFICATION="api-provider"
        ;;
    azure|azure_openai|azure-openai)
        GARAK_RUNTIME_ENDPOINT="${AZURE_OPENAI_ENDPOINT:-N/A}"
        GARAK_RUNTIME_CLASSIFICATION="api-provider"
        ;;
    anthropic)
        GARAK_RUNTIME_ENDPOINT="${ANTHROPIC_BASE_URL:-https://api.anthropic.com}"
        GARAK_RUNTIME_CLASSIFICATION="api-provider"
        ;;
    ollama)
        GARAK_RUNTIME_ENDPOINT="${OLLAMA_HOST:-http://localhost:11434}"
        GARAK_RUNTIME_CLASSIFICATION="local-runtime"
        ;;
    huggingface|hf)
        GARAK_RUNTIME_ENDPOINT="${HF_INFERENCE_ENDPOINT:-N/A}"
        GARAK_RUNTIME_CLASSIFICATION="provider-library"
        ;;
    test)
        GARAK_RUNTIME_ENDPOINT="local-test-generator"
        GARAK_RUNTIME_CLASSIFICATION="test-generator"
        ;;
esac

GARAK_RUNTIME_TARGET="${GARAK_TARGET_TYPE}:${GARAK_TARGET_NAME}"
if [[ -n "$GARAK_RUNTIME_ENDPOINT" && "$GARAK_RUNTIME_ENDPOINT" != "N/A" ]]; then
    GARAK_RUNTIME_TARGET="${GARAK_RUNTIME_TARGET} @ ${GARAK_RUNTIME_ENDPOINT}"
fi

GARAK_AUTO_INSTALL="${GARAK_AUTO_INSTALL:-true}"
GARAK_PIP_SPEC="${GARAK_PIP_SPEC:-garak}"

RESULTS_FILE="$OUTPUT_DIR/${SCAN_ID}_garak-results.json"
CURRENT_FILE="$OUTPUT_DIR/garak-results.json"
CONSOLE_LOG="$OUTPUT_DIR/${SCAN_ID}_garak-console.log"
SCAN_LOG="$OUTPUT_DIR/${SCAN_ID}_garak-scan.log"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'

echo -e "${WHITE}============================================${NC}"
echo -e "${WHITE}Garak LLM Security Scanner${NC}"
echo -e "${WHITE}============================================${NC}"
echo "Target Directory: $TARGET_SCAN_DIR"
echo "Output Directory: $OUTPUT_DIR"
echo "Target Type: $GARAK_TARGET_TYPE"
echo "Target Name: $GARAK_TARGET_NAME"
echo "Runtime Target: $GARAK_RUNTIME_TARGET"
echo "Runtime Classification: $GARAK_RUNTIME_CLASSIFICATION"
echo "Target Origin: $GARAK_TARGET_ORIGIN"
echo "Probes: $GARAK_PROBES"
echo "Timestamp: $TIMESTAMP"
echo ""

mkdir -p "$OUTPUT_DIR"

echo "Garak scan started: $TIMESTAMP" > "$SCAN_LOG"
echo "Target: $TARGET_SCAN_DIR" >> "$SCAN_LOG"
echo "Target type: $GARAK_TARGET_TYPE" >> "$SCAN_LOG"
echo "Target name: $GARAK_TARGET_NAME" >> "$SCAN_LOG"
echo "Runtime target: $GARAK_RUNTIME_TARGET" >> "$SCAN_LOG"
echo "Runtime classification: $GARAK_RUNTIME_CLASSIFICATION" >> "$SCAN_LOG"
echo "Target origin: $GARAK_TARGET_ORIGIN" >> "$SCAN_LOG"
echo "Probes: $GARAK_PROBES" >> "$SCAN_LOG"

if ! command -v python3 >/dev/null 2>&1; then
    echo -e "${RED}❌ python3 is required for garak${NC}"
    cat > "$RESULTS_FILE" << EOF
{
  "tool": "garak",
  "status": "skipped",
  "reason": "python3 not found",
  "scan_id": "$SCAN_ID",
  "generated_at": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
}
EOF
    cp "$RESULTS_FILE" "$CURRENT_FILE"
    record_scan_status "skipped" "python3 not found"
    exit 0
fi

GARAK_CMD=(python3 -m garak)
if command -v garak >/dev/null 2>&1; then
    GARAK_CMD=(garak)
fi

if ! "${GARAK_CMD[@]}" --version >/dev/null 2>&1; then
    if [[ "$GARAK_AUTO_INSTALL" == "true" ]]; then
        echo -e "${CYAN}📦 garak not found. Installing via pip...${NC}"

        # Free space before installing: garak pulls in torch (~1 GB uncompressed).
        # Purge pip cache so the wheel doesn't need to be held twice on disk.
        python3 -m pip cache purge >> "$SCAN_LOG" 2>&1 || true

        INSTALL_OK=0
        # PIP_NO_CACHE_DIR=1 avoids writing the wheel to cache during install,
        # halving peak disk usage for large wheels (torch, transformers, etc.).
        if PIP_NO_CACHE_DIR=1 python3 -m pip install -U "$GARAK_PIP_SPEC" >> "$SCAN_LOG" 2>&1; then
            INSTALL_OK=1
        # Ubuntu/Debian runners with externally-managed Python may require this flag.
        elif PIP_NO_CACHE_DIR=1 python3 -m pip install --break-system-packages -U "$GARAK_PIP_SPEC" >> "$SCAN_LOG" 2>&1; then
            INSTALL_OK=1
        # Fallback to user install in restrictive environments.
        elif PIP_NO_CACHE_DIR=1 python3 -m pip install --user -U "$GARAK_PIP_SPEC" >> "$SCAN_LOG" 2>&1; then
            export PATH="$HOME/.local/bin:$PATH"
            INSTALL_OK=1
        fi

        if [[ "$INSTALL_OK" -eq 1 ]]; then
            echo -e "${GREEN}✅ garak installed${NC}"
        else
            echo -e "${RED}❌ Failed to install garak${NC}"
            echo -e "${YELLOW}Last pip errors:${NC}"
            tail -n 25 "$SCAN_LOG" 2>/dev/null || true
            cat > "$RESULTS_FILE" << EOF
{
  "tool": "garak",
  "status": "failed",
  "reason": "garak install failed",
  "scan_id": "$SCAN_ID",
  "generated_at": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
}
EOF
            cp "$RESULTS_FILE" "$CURRENT_FILE"
            record_scan_status "failed" "garak install failed"
            exit 0
        fi
    else
        echo -e "${YELLOW}⚠️  garak not installed and auto-install disabled${NC}"
        cat > "$RESULTS_FILE" << EOF
{
  "tool": "garak",
  "status": "skipped",
  "reason": "garak not installed",
  "scan_id": "$SCAN_ID",
  "generated_at": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
}
EOF
        cp "$RESULTS_FILE" "$CURRENT_FILE"
        record_scan_status "skipped" "garak not installed"
        exit 0
    fi
fi

# Refresh command in case install added console entrypoint.
if command -v garak >/dev/null 2>&1; then
    GARAK_CMD=(garak)
else
    GARAK_CMD=(python3 -m garak)
fi

REPORT_PREFIX_ARGS=()
GARAK_HELP_TEXT=$("${GARAK_CMD[@]}" --help 2>/dev/null || true)

if echo "$GARAK_HELP_TEXT" | grep -q -- "--report_prefix"; then
    REPORT_PREFIX_ARGS=(--report_prefix "$OUTPUT_DIR/${SCAN_ID}_garak")
fi

# Garak CLI has changed over versions:
# - older: --target_type / --target_name
# - newer: --model_type / --model_name
MODEL_ARGS=()
if echo "$GARAK_HELP_TEXT" | grep -q -- "--target_type"; then
    MODEL_ARGS=(--target_type "$GARAK_TARGET_TYPE" --target_name "$GARAK_TARGET_NAME")
elif echo "$GARAK_HELP_TEXT" | grep -q -- "--model_type"; then
    MODEL_ARGS=(--model_type "$GARAK_TARGET_TYPE" --model_name "$GARAK_TARGET_NAME")
else
    # Fall back to target_* style for compatibility.
    MODEL_ARGS=(--target_type "$GARAK_TARGET_TYPE" --target_name "$GARAK_TARGET_NAME")
fi

echo -e "${BLUE}🔍 Running garak probe scan...${NC}"
echo "Command: ${GARAK_CMD[*]} ${MODEL_ARGS[*]} --probes $GARAK_PROBES ${REPORT_PREFIX_ARGS[*]}" | tee -a "$SCAN_LOG"

set +e
(
    cd "$TARGET_SCAN_DIR" || exit 1
    "${GARAK_CMD[@]}" \
        "${MODEL_ARGS[@]}" \
        --probes "$GARAK_PROBES" \
        "${REPORT_PREFIX_ARGS[@]}"
) > "$CONSOLE_LOG" 2>&1
GARAK_EXIT=$?
set -e

if [[ "$GARAK_EXIT" -eq 0 ]]; then
    SCAN_STATUS="success"
    STATUS_REASON="scan completed"
else
    # garak may return non-zero for runtime/model issues; keep artifacts and continue pipeline.
    SCAN_STATUS="failed"
    ERROR_PREVIEW=$(grep -m1 -E "error:|Exception|Traceback" "$CONSOLE_LOG" 2>/dev/null || true)
    if [[ -n "$ERROR_PREVIEW" ]]; then
        STATUS_REASON="garak exit code $GARAK_EXIT: ${ERROR_PREVIEW:0:180}"
    else
        STATUS_REASON="garak exit code $GARAK_EXIT"
    fi
fi

# Attempt to locate generated report artifacts.
REPORT_JSONL=$(find "$OUTPUT_DIR" -maxdepth 1 -type f -name "${SCAN_ID}_garak*.jsonl" | head -1)
if [[ -z "$REPORT_JSONL" ]]; then
    REPORT_JSONL=$(find "$TARGET_SCAN_DIR" -maxdepth 1 -type f -name "garak*.jsonl" | head -1)
    if [[ -n "$REPORT_JSONL" ]]; then
        cp "$REPORT_JSONL" "$OUTPUT_DIR/" 2>/dev/null || true
        REPORT_JSONL="$OUTPUT_DIR/$(basename "$REPORT_JSONL")"
    fi
fi

HIT_LOG=$(find "$OUTPUT_DIR" -maxdepth 1 -type f -name "${SCAN_ID}_garak*.hitlog.jsonl" | head -1)
if [[ -z "$HIT_LOG" ]]; then
    HIT_LOG=$(find "$TARGET_SCAN_DIR" -maxdepth 1 -type f -name "garak*.hitlog.jsonl" | head -1)
    if [[ -n "$HIT_LOG" ]]; then
        cp "$HIT_LOG" "$OUTPUT_DIR/" 2>/dev/null || true
        HIT_LOG="$OUTPUT_DIR/$(basename "$HIT_LOG")"
    fi
fi

if [[ -f "$TARGET_SCAN_DIR/garak.log" ]]; then
    cp "$TARGET_SCAN_DIR/garak.log" "$OUTPUT_DIR/garak.log" 2>/dev/null || true
fi

cat > "$RESULTS_FILE" << EOF
{
  "tool": "garak",
  "status": "$SCAN_STATUS",
  "reason": "$STATUS_REASON",
  "scan_id": "$SCAN_ID",
  "target_type": "$GARAK_TARGET_TYPE",
  "target_name": "$GARAK_TARGET_NAME",
    "runtime_target": "$GARAK_RUNTIME_TARGET",
    "runtime_classification": "$GARAK_RUNTIME_CLASSIFICATION",
    "runtime_endpoint": "$GARAK_RUNTIME_ENDPOINT",
    "target_origin": "$GARAK_TARGET_ORIGIN",
    "target_type_source": "$GARAK_TARGET_TYPE_SOURCE",
    "target_name_source": "$GARAK_TARGET_NAME_SOURCE",
    "probes_source": "$GARAK_PROBES_SOURCE",
  "probes": "$GARAK_PROBES",
  "exit_code": $GARAK_EXIT,
  "console_log": "$(basename "$CONSOLE_LOG")",
  "report_jsonl": "$(basename "${REPORT_JSONL:-}")",
  "hit_log": "$(basename "${HIT_LOG:-}")",
  "generated_at": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
}
EOF
cp "$RESULTS_FILE" "$CURRENT_FILE"

if [[ "$SCAN_STATUS" == "success" ]]; then
    echo -e "${GREEN}✅ Garak scan completed${NC}"
else
    echo -e "${YELLOW}⚠️  Garak scan finished with issues (exit code: $GARAK_EXIT)${NC}"
fi

echo "📄 Summary: $RESULTS_FILE"
echo "📝 Console log: $CONSOLE_LOG"
[[ -n "$REPORT_JSONL" ]] && echo "📊 Report JSONL: $REPORT_JSONL"
[[ -n "$HIT_LOG" ]] && echo "🚨 Hit log: $HIT_LOG"

record_scan_status "$SCAN_STATUS" "$STATUS_REASON"
finalize_scan_results "garak"
