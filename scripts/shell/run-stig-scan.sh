#!/bin/bash

# STIG Compliance Assessment Script
# Performs AI-assisted STIG assessment against a target application.
# Supports one or more STIG source files (.cklb JSON or XCCDF .xml).
#
# By default, all STIG files in configuration/stigs/ are processed.
# To add a new STIG, simply drop a .cklb or .xml file into that directory.
#
# Usage:
#   ./run-stig-scan.sh <TARGET_DIR>
#
# Environment variables:
#   OPENAI_API_KEY    Required. OpenAI API key for LLM assessment.
#   OPENAI_MODEL      OpenAI model to use (default: gpt-4.1).
#   STIGS_DIR         Directory of STIG files (default: configuration/stigs).
#                     Set STIGS_FILE instead to target a single file.
#   STIGS_FILE        Single STIG file path (overrides STIGS_DIR).
#   SCAN_DIR          Output directory for scan results (default: auto-derived).
#   APP_NAME          Application name for the report (default: basename of TARGET_DIR).
#   BATCH_SIZE        Controls per API call (default: 20).
#   BATCH_DELAY       Seconds between API calls (default: 1).
#   SKIP_STIG         Set to 'true' to skip this scan entirely.

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Display EPYON banner
echo -e "${CYAN}"
cat << "EOF"
███████╗██████╗ ██╗   ██╗ ██████╗ ███╗   ██╗
██╔════╝██╔══██╗╚██╗ ██╔╝██╔═══██╗████╗  ██║
█████╗  ██████╔╝ ╚████╔╝ ██║   ██║██╔██╗ ██║
██╔══╝  ██╔═══╝   ╚██╔╝  ██║   ██║██║╚██╗██║
███████╗██║        ██║   ╚██████╔╝██║ ╚████║
╚══════╝╚═╝        ╚═╝    ╚═════╝ ╚═╝  ╚═══╝
EOF
echo -e "${NC}"
echo -e "${GREEN}Absolute Security Control — Layer 13: STIG Compliance Assessment${NC}"
echo ""

# ── Help ─────────────────────────────────────────────────────────────────────
show_help() {
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}  STIG Compliance Assessment (multi-STIG support)${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo ""
    echo "Usage: $0 [OPTIONS] <TARGET_DIR>"
    echo ""
    echo "Performs AI-assisted DISA STIG compliance assessment against one or more"
    echo "STIGs using GPT-4.1. Processes all .cklb and .xml files in the stigs"
    echo "directory. Add more STIGs by dropping files into configuration/stigs/."
    echo ""
    echo "Arguments:"
    echo "  TARGET_DIR    Path to the application source directory (REQUIRED)"
    echo ""
    echo "Options:"
    echo "  -h, --help    Show this help message and exit"
    echo ""
    echo "Environment variables:"
    echo "  OPENAI_API_KEY    Required. OpenAI API key."
    echo "  OPENAI_MODEL      Model to use (default: gpt-4.1)."
    echo "  STIGS_DIR         Directory of STIG files (default: configuration/stigs)."
    echo "  STIGS_FILE        Single STIG file path (overrides STIGS_DIR)."
    echo "  SCAN_DIR          Output directory (default: auto-derived scan directory)."
    echo "  APP_NAME          Application name for the report header."
    echo "  BATCH_SIZE        Controls per API call (default: 20)."
    echo "  BATCH_DELAY       Seconds between API calls (default: 1)."
    echo "  SKIP_STIG         Set to 'true' to skip this layer."
    echo ""
    echo "Output (per STIG in stigs dir):"
    echo "  \$SCAN_DIR/findings.md              Primary report (first/only STIG)"
    echo "  \$SCAN_DIR/findings-{slug}.md       Per-STIG report when multiple present"
    echo "  \$SCAN_DIR/stig-controls-{slug}.json"
    echo "  \$SCAN_DIR/stig-results-{slug}.json"
    echo ""
    echo "Adding a new STIG:"
    echo "  Drop any .cklb or XCCDF .xml file into configuration/stigs/"
    echo "  It will be picked up automatically on the next scan."
    echo ""
    echo "Examples:"
    echo "  OPENAI_API_KEY=sk-... $0 /path/to/my-app"
    echo "  STIGS_FILE=configuration/stigs/U_ASD_STIG_V6R4_Manual-xccdf.xml $0 ./api"
    echo ""
    exit 0
}

for arg in "$@"; do
    case $arg in
        -h|--help) show_help ;;
    esac
done

# ── Skip check ───────────────────────────────────────────────────────────────
if [[ "${SKIP_STIG:-false}" == "true" ]]; then
    echo -e "${YELLOW}[SKIP] SKIP_STIG=true — skipping Layer 13${NC}"
    exit 0
fi

# ── Argument validation ───────────────────────────────────────────────────────
if [[ $# -lt 1 ]]; then
    echo -e "${RED}[ERROR] TARGET_DIR argument is required.${NC}"
    echo "Usage: $0 <TARGET_DIR>"
    exit 1
fi

TARGET_DIR="${1}"

if [[ ! -d "$TARGET_DIR" ]]; then
    echo -e "${RED}[ERROR] Target directory not found: ${TARGET_DIR}${NC}"
    exit 1
fi

# ── Resolve script directory (support invocation from any cwd) ───────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# ── Defaults ─────────────────────────────────────────────────────────────────
STIGS_DIR="${STIGS_DIR:-${PROJECT_ROOT}/configuration/stigs}"
STIGS_FILE="${STIGS_FILE:-}"
OPENAI_MODEL="${OPENAI_MODEL:-gpt-4.1}"
BATCH_SIZE="${BATCH_SIZE:-20}"
BATCH_DELAY="${BATCH_DELAY:-1}"
APP_NAME="${APP_NAME:-$(basename "$(realpath "$TARGET_DIR")")}"

# Auto-derive SCAN_DIR if not set (used when running standalone outside CI)
if [[ -z "${SCAN_DIR:-}" ]]; then
    TIMESTAMP="$(date +%Y-%m-%d_%H-%M-%S)"
    SCAN_ID="${APP_NAME}_${USER:-unknown}_${TIMESTAMP}"
    SCAN_DIR="${PROJECT_ROOT}/scans/${SCAN_ID}"
fi

# ── Pre-flight checks ─────────────────────────────────────────────────────────
if [[ -n "$STIGS_FILE" ]]; then
    echo -e "${BLUE}[INFO] STIG source     : ${STIGS_FILE} (single file)${NC}"
else
    echo -e "${BLUE}[INFO] STIG source dir : ${STIGS_DIR}${NC}"
fi
echo -e "${BLUE}[INFO] Target directory : ${TARGET_DIR}${NC}"
echo -e "${BLUE}[INFO] Scan output dir  : ${SCAN_DIR}${NC}"
echo -e "${BLUE}[INFO] Application name : ${APP_NAME}${NC}"
echo -e "${BLUE}[INFO] OpenAI model     : ${OPENAI_MODEL}${NC}"
echo ""

# Validate STIG source exists
if [[ -n "$STIGS_FILE" ]]; then
    if [[ ! -f "$STIGS_FILE" ]]; then
        echo -e "${RED}[ERROR] STIGS_FILE not found: ${STIGS_FILE}${NC}"
        exit 1
    fi
else
    if [[ ! -d "$STIGS_DIR" ]]; then
        echo -e "${RED}[ERROR] STIGS_DIR not found: ${STIGS_DIR}${NC}"
        echo "        Create it and place .cklb or XCCDF .xml files inside, or set STIGS_FILE."
        exit 1
    fi
    # Count supported files
    STIG_COUNT=$(find "$STIGS_DIR" -maxdepth 1 \( -name '*.cklb' -o -name '*.xml' \) -type f 2>/dev/null | wc -l | tr -d ' ')
    if [[ "$STIG_COUNT" -eq 0 ]]; then
        echo -e "${RED}[ERROR] No .cklb or .xml STIG files found in ${STIGS_DIR}${NC}"
        echo "        Drop DISA STIG files (.cklb or XCCDF .xml) into that directory."
        exit 1
    fi
    echo -e "${BLUE}[INFO] STIG files found : ${STIG_COUNT}${NC}"
    find "$STIGS_DIR" -maxdepth 1 \( -name '*.cklb' -o -name '*.xml' \) -type f | sort | while read -r f; do
        echo -e "${BLUE}         $(basename "$f")${NC}"
    done
    echo ""
fi

if ! command -v python3 &>/dev/null; then
    echo -e "${RED}[ERROR] python3 is not available on PATH.${NC}"
    exit 1
fi

# Check openai package is importable
if ! python3 -c "import openai" &>/dev/null 2>&1; then
    echo -e "${YELLOW}[WARNING] The 'openai' Python package is not installed.${NC}"
    echo "          Installing now: pip3 install --quiet openai"
    pip3 install --quiet openai || {
        echo -e "${RED}[ERROR] Failed to install openai package.${NC}"
        exit 1
    }
fi

# Warn (but do not abort) if API key is missing — assessment script handles gracefully
if [[ -z "${OPENAI_API_KEY:-}" ]]; then
    echo -e "${YELLOW}[WARNING] OPENAI_API_KEY is not set.${NC}"
    echo "          All controls will be marked 'Not Reviewed'."
    echo "          Set OPENAI_API_KEY to enable AI-powered assessment."
    echo ""
fi

mkdir -p "$SCAN_DIR"

# ── Run assessment ────────────────────────────────────────────────────────────
echo -e "${GREEN}[STIG] Starting STIG compliance assessment...${NC}"
echo ""

ASSESSMENT_SCRIPT="${SCRIPT_DIR}/run-stig-assessment.py"

if [[ ! -f "$ASSESSMENT_SCRIPT" ]]; then
    echo -e "${RED}[ERROR] Assessment script not found: ${ASSESSMENT_SCRIPT}${NC}"
    exit 1
fi

# Build the STIG source argument
if [[ -n "$STIGS_FILE" ]]; then
    STIG_ARG=("--cklb" "$STIGS_FILE")
else
    STIG_ARG=("--stigs-dir" "$STIGS_DIR")
fi

python3 "$ASSESSMENT_SCRIPT" \
    "${STIG_ARG[@]}"         \
    --target     "$TARGET_DIR"      \
    --scan-dir   "$SCAN_DIR"        \
    --app-name   "$APP_NAME"        \
    --model      "$OPENAI_MODEL"    \
    --batch-size "$BATCH_SIZE"      \
    --delay      "$BATCH_DELAY"

RC=$?
echo ""

if [[ $RC -eq 0 ]]; then
    if [[ -f "${SCAN_DIR}/findings.md" ]]; then
        OPEN_COUNT=$(grep -c "^Status: Open$"          "${SCAN_DIR}/findings.md" 2>/dev/null || true)
        NAF_COUNT=$(grep  -c "^Status: Not a Finding$" "${SCAN_DIR}/findings.md" 2>/dev/null || true)
        NA_COUNT=$(grep   -c "^Status: Not Applicable$" "${SCAN_DIR}/findings.md" 2>/dev/null || true)
        NR_COUNT=$(grep   -c "^Status: Not Reviewed$"  "${SCAN_DIR}/findings.md" 2>/dev/null || true)

        echo -e "${GREEN}[STIG] Assessment complete.${NC}"
        echo -e "${GREEN}       findings.md → ${SCAN_DIR}/findings.md${NC}"
        echo ""
        echo -e "       Open            : ${RED}${OPEN_COUNT}${NC}"
        echo -e "       Not a Finding   : ${GREEN}${NAF_COUNT}${NC}"
        echo -e "       Not Applicable  : ${BLUE}${NA_COUNT}${NC}"
        echo -e "       Not Reviewed    : ${YELLOW}${NR_COUNT}${NC}"
    else
        echo -e "${YELLOW}[STIG] Assessment finished but findings.md was not produced.${NC}"
    fi
else
    echo -e "${YELLOW}[STIG] Assessment completed with warnings (exit ${RC}).${NC}"
fi

exit 0
