#!/bin/bash

# Coverage Gate Check
# Reads coverage data from $SCAN_DIR/coverage/coverage-summary.json (produced by
# run-coverage-scan.sh) and enforces a minimum coverage threshold.
# Falls back to SonarQube metrics if the standalone coverage file is absent.

show_help() {
    cat <<'EOF'
Usage: check-coverage-gate.sh [--help]

Evaluates test coverage and fails the build if below threshold.

Environment:
    SCAN_DIR            Required. Scan directory to evaluate.
    COVERAGE_THRESHOLD  Minimum acceptable coverage % (default: 80).
    FAIL_ON_COVERAGE    true|false — fail build when below threshold (default: true).
    WARNING_ONLY        true|false — warn but always exit 0 (default: false).

Exit codes:
    0   Coverage meets threshold, or no coverage data found (not a failure).
    2   Coverage below threshold (when FAIL_ON_COVERAGE=true and WARNING_ONLY=false).
EOF
}

if [[ "${1:-}" == "--help" ]] || [[ "${1:-}" == "-h" ]]; then
    show_help
    exit 0
fi

# ── Colours ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
NC='\033[0m'

# ── Config ─────────────────────────────────────────────────────────────────────
SCAN_DIR="${SCAN_DIR:-}"
COVERAGE_THRESHOLD="${COVERAGE_THRESHOLD:-80}"
FAIL_ON_COVERAGE="${FAIL_ON_COVERAGE:-true}"
WARNING_ONLY="${WARNING_ONLY:-false}"

if [[ -z "$SCAN_DIR" || ! -d "$SCAN_DIR" ]]; then
    echo -e "${RED}❌ Error: SCAN_DIR not set or directory doesn't exist: '${SCAN_DIR}'${NC}"
    exit 1
fi

echo ""
echo -e "${CYAN}============================================${NC}"
echo -e "${CYAN}📊 Coverage Gate Check${NC}"
echo -e "${CYAN}============================================${NC}"
echo -e "${CYAN}Scan Directory : $SCAN_DIR${NC}"
echo -e "${CYAN}Threshold      : ${COVERAGE_THRESHOLD}%${NC}"
echo -e "${CYAN}Fail on low    : $FAIL_ON_COVERAGE${NC}"
echo -e "${CYAN}Warning only   : $WARNING_ONLY${NC}"
echo ""

# ── Source 1: standalone coverage-summary.json ────────────────────────────────
COVERAGE_PCT=""
COVERAGE_LANG=""
COVERAGE_FRAMEWORK=""
LINES_COVERED=0
LINES_TOTAL=0
BRANCHES_COVERED=0
BRANCHES_TOTAL=0
DATA_SOURCE=""

_summary="$SCAN_DIR/coverage/coverage-summary.json"
if [[ -f "$_summary" ]]; then
    _parsed=$(python3 - <<PYEOF
import json, sys
try:
    data = json.load(open("$_summary"))
    pct = data.get("percentage", 0)
    lang = data.get("language","unknown")
    fw = data.get("framework","unknown")
    lc = data.get("lines_covered",0)
    lt = data.get("lines_total",0)
    bc = data.get("branches_covered",0)
    bt = data.get("branches_total",0)
    status = data.get("status","unknown")
    print(f"{pct},{lang},{fw},{lc},{lt},{bc},{bt},{status}")
except Exception as e:
    print(f"error,,,0,0,0,0,error")
PYEOF
)
    IFS=',' read -r COVERAGE_PCT COVERAGE_LANG COVERAGE_FRAMEWORK LINES_COVERED LINES_TOTAL BRANCHES_COVERED BRANCHES_TOTAL _cov_status <<< "$_parsed"
    DATA_SOURCE="coverage-summary.json (${COVERAGE_LANG}/${COVERAGE_FRAMEWORK})"

    # If not_detected or error, treat as no data
    if [[ "$_cov_status" == "not_detected" ]]; then
        echo -e "${YELLOW}⚠️  No test framework was detected in the target repo — skipping gate${NC}"
        exit 0
    fi
fi

# ── Source 2: SonarQube API results (fallback) ────────────────────────────────
if [[ -z "$COVERAGE_PCT" || "$COVERAGE_PCT" == "0" ]]; then
    _sonar_results="$SCAN_DIR/sonar/sonar-analysis-results.json"
    if [[ -f "$_sonar_results" ]]; then
        _sonar_pct=$(python3 - <<PYEOF
import json, sys
try:
    data = json.load(open("$_sonar_results"))
    # SonarCloud API format: {"component": {"measures": [{"metric": "coverage", "value": "85.3"}]}}
    measures = (data.get("component") or {}).get("measures", [])
    for m in measures:
        if m.get("metric") == "coverage":
            print(m.get("value",""))
            sys.exit(0)
    # Flat format: {"coverage": "85.3"}
    cov = data.get("coverage","")
    print(cov)
except Exception:
    print("")
PYEOF
)
        if [[ -n "$_sonar_pct" ]] && python3 -c "float('$_sonar_pct')" &>/dev/null 2>&1; then
            COVERAGE_PCT="$_sonar_pct"
            DATA_SOURCE="SonarQube (sonar-analysis-results.json)"
        fi
    fi
fi

# ── No data ────────────────────────────────────────────────────────────────────
if [[ -z "$COVERAGE_PCT" ]]; then
    echo -e "${YELLOW}⚠️  No coverage data found — skipping coverage gate${NC}"
    echo -e "${YELLOW}   Run run-coverage-scan.sh to generate coverage data${NC}"
    exit 0
fi

# ── Evaluate threshold ─────────────────────────────────────────────────────────
echo -e "${CYAN}Data source    : $DATA_SOURCE${NC}"
if [[ -n "$COVERAGE_LANG" ]]; then
    echo -e "${CYAN}Language       : $COVERAGE_LANG${NC}"
fi
echo ""

_gate_result=$(python3 - <<PYEOF
import sys
pct = float("$COVERAGE_PCT")
threshold = float("$COVERAGE_THRESHOLD")
passed = pct >= threshold
delta = round(pct - threshold, 2)
print(f"{int(passed)},{round(pct,2)},{delta}")
PYEOF
)
IFS=',' read -r _passed _pct_display _delta <<< "$_gate_result"

echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
if [[ "$_passed" == "1" ]]; then
    echo -e "${GREEN}✅ Coverage PASSED: ${_pct_display}% >= ${COVERAGE_THRESHOLD}% (${_delta:+"+"}${_delta}pp)${NC}"
    if [[ "$LINES_TOTAL" -gt 0 ]]; then
        echo -e "${CYAN}   Lines  : ${LINES_COVERED}/${LINES_TOTAL} covered${NC}"
    fi
    if [[ "$BRANCHES_TOTAL" -gt 0 ]]; then
        echo -e "${CYAN}   Branches: ${BRANCHES_COVERED}/${BRANCHES_TOTAL} covered${NC}"
    fi
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    exit 0
else
    echo -e "${RED}❌ Coverage FAILED: ${_pct_display}% < ${COVERAGE_THRESHOLD}% (${_delta}pp below threshold)${NC}"
    if [[ "$LINES_TOTAL" -gt 0 ]]; then
        echo -e "${CYAN}   Lines  : ${LINES_COVERED}/${LINES_TOTAL} covered${NC}"
        _missing=$(python3 -c "print(int($LINES_TOTAL * $COVERAGE_THRESHOLD / 100) - int($LINES_COVERED))" 2>/dev/null || echo "?")
        echo -e "${YELLOW}   Need ~${_missing} more lines covered to reach ${COVERAGE_THRESHOLD}%${NC}"
    fi
    if [[ "$BRANCHES_TOTAL" -gt 0 ]]; then
        echo -e "${CYAN}   Branches: ${BRANCHES_COVERED}/${BRANCHES_TOTAL} covered${NC}"
    fi
    echo ""
    echo -e "${YELLOW}💡 To adjust the threshold:${NC}"
    echo -e "${YELLOW}   COVERAGE_THRESHOLD=70 SCAN_DIR=... check-coverage-gate.sh${NC}"
    echo -e "${YELLOW}   FAIL_ON_COVERAGE=false ... (warn-only)${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""

    if [[ "$WARNING_ONLY" == "true" ]]; then
        echo -e "${YELLOW}⚠️  WARNING_ONLY=true — not failing the build${NC}"
        exit 0
    fi

    if [[ "$FAIL_ON_COVERAGE" == "true" ]]; then
        exit 2
    else
        echo -e "${YELLOW}⚠️  FAIL_ON_COVERAGE=false — not failing the build${NC}"
        exit 0
    fi
fi
