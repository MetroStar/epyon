#!/bin/bash

# Test Coverage Scanner — Layer 16
# Auto-detects the test framework (pytest, Jest/Vitest, Go) in the target repo,
# runs tests with coverage enabled, and saves a normalized coverage-summary.json
# to $SCAN_DIR/coverage/.
#
# Supported frameworks (tried in order):
#   Python   — pytest with pytest-cov  (coverage.xml + .coverage)
#   JS/TS    — vitest --coverage / jest --coverage  (lcov.info + coverage-summary.json)
#   Go       — go test -coverprofile  (coverage.out + coverage.html)

show_help() {
    cat <<'EOF'
Usage: run-coverage-scan.sh [TARGET_DIR] [--help]

Runs test coverage analysis on a target repository.

Environment:
    TARGET_DIR              Required. Path to the repository to scan.
    SCAN_DIR                Required. Output directory for scan results.
    COVERAGE_TIMEOUT        Seconds to allow tests to run (default: 300).
    SKIP_COVERAGE_INSTALL   true|false — skip dep installation (default: false).

Output:
    $SCAN_DIR/coverage/coverage-summary.json   Normalized summary
    $SCAN_DIR/coverage/coverage.xml            Python XML report (if generated)
    $SCAN_DIR/coverage/lcov.info               JS/TS lcov report (if generated)
    $SCAN_DIR/coverage/coverage.out            Go coverage profile (if generated)

Exit codes:
    0   Coverage data collected (or no test suite found — not a failure).
    1   Hard error (missing required env vars, etc.).
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

# ── Resolve directories ────────────────────────────────────────────────────────
TARGET_DIR="${TARGET_DIR:-${1:-}}"
SCAN_DIR="${SCAN_DIR:-}"
COVERAGE_TIMEOUT="${COVERAGE_TIMEOUT:-300}"
SKIP_COVERAGE_INSTALL="${SKIP_COVERAGE_INSTALL:-false}"

if [[ -z "$TARGET_DIR" || ! -d "$TARGET_DIR" ]]; then
    echo -e "${RED}❌ Error: TARGET_DIR not set or does not exist: '${TARGET_DIR}'${NC}"
    exit 1
fi
if [[ -z "$SCAN_DIR" ]]; then
    echo -e "${RED}❌ Error: SCAN_DIR not set${NC}"
    exit 1
fi

TARGET_DIR="$(cd "$TARGET_DIR" && pwd)"
OUTPUT_DIR="$SCAN_DIR/coverage"
mkdir -p "$OUTPUT_DIR"

SCAN_LOG="$OUTPUT_DIR/coverage-scan.log"
SUMMARY_JSON="$OUTPUT_DIR/coverage-summary.json"

TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}📊 Test Coverage Analysis — $(basename "$TARGET_DIR")${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}Target     : $TARGET_DIR${NC}"
echo -e "${CYAN}Output Dir : $OUTPUT_DIR${NC}"
echo -e "${CYAN}Timeout    : ${COVERAGE_TIMEOUT}s${NC}"
echo ""

# ── Helper: write summary JSON ─────────────────────────────────────────────────
write_summary() {
    local lang="$1" framework="$2" pct="$3"
    local lines_covered="${4:-0}" lines_total="${5:-0}"
    local branches_covered="${6:-0}" branches_total="${7:-0}"
    local status="${8:-success}"

    python3 - <<PYEOF
import json, sys
data = {
    "language": "$lang",
    "framework": "$framework",
    "percentage": float("$pct") if "$pct" else 0.0,
    "lines_covered": int("$lines_covered"),
    "lines_total": int("$lines_total"),
    "branches_covered": int("$branches_covered"),
    "branches_total": int("$branches_total"),
    "status": "$status",
    "timestamp": "$TIMESTAMP",
}
print(json.dumps(data, indent=2))
PYEOF
}

# ── Helper: run command with timeout ───────────────────────────────────────────
run_with_timeout() {
    local timeout_secs="$1"
    shift
    if command -v timeout &>/dev/null; then
        timeout "$timeout_secs" "$@"
    elif command -v gtimeout &>/dev/null; then
        gtimeout "$timeout_secs" "$@"
    else
        # No timeout command (e.g. macOS without coreutils) — run directly
        "$@"
    fi
}

# ══════════════════════════════════════════════════════════════════════════════
# Framework detection + coverage collection
# ══════════════════════════════════════════════════════════════════════════════

DETECTED_LANG=""
DETECTED_FRAMEWORK=""
COVERAGE_PCT=""
LINES_COVERED=0
LINES_TOTAL=0
BRANCHES_COVERED=0
BRANCHES_TOTAL=0

cd "$TARGET_DIR"

# ─── 1. Python (pytest) ───────────────────────────────────────────────────────
_has_python_tests() {
    [[ -f "pyproject.toml" ]] || [[ -f "setup.py" ]] || [[ -f "setup.cfg" ]] || \
    [[ -f "pytest.ini" ]] || [[ -f "tox.ini" ]] || \
    (find . -maxdepth 4 -name "test_*.py" -o -name "*_test.py" 2>/dev/null | grep -q .)
}

if _has_python_tests && python3 -m pytest --version &>/dev/null 2>&1; then
    DETECTED_LANG="python"
    DETECTED_FRAMEWORK="pytest"
    echo -e "${CYAN}🐍 Detected Python/pytest project${NC}"

    # Install pytest-cov if needed
    if [[ "$SKIP_COVERAGE_INSTALL" != "true" ]]; then
        python3 -m pip install --quiet pytest-cov 2>&1 | tail -2 || true
    fi

    # Determine source root (prefer src/ layout, else repo root)
    _cov_src="."
    [[ -d "src" ]] && _cov_src="src"

    # Find project package name from pyproject.toml or setup.py
    _pkg_name=""
    if [[ -f "pyproject.toml" ]]; then
        _pkg_name=$(python3 -c "
import re, sys
text = open('pyproject.toml').read()
m = re.search(r'name\s*=\s*[\"\']([\w-]+)[\"\']\s', text)
print(m.group(1).replace('-','_') if m else '')
" 2>/dev/null) || true
    fi
    [[ -n "$_pkg_name" ]] && [[ -d "$_pkg_name" ]] && _cov_src="$_pkg_name"
    [[ -n "$_pkg_name" ]] && [[ -d "src/$_pkg_name" ]] && _cov_src="src/$_pkg_name"

    _xml_out="$OUTPUT_DIR/coverage.xml"

    echo -e "${CYAN}⏱  Running pytest --cov (timeout: ${COVERAGE_TIMEOUT}s)...${NC}"
    set +e
    run_with_timeout "$COVERAGE_TIMEOUT" python3 -m pytest \
        --cov="$_cov_src" \
        --cov-report="xml:$_xml_out" \
        --cov-report="term-missing" \
        --ignore=node_modules --ignore=.venv --ignore=venv \
        -q 2>&1 | tee "$SCAN_LOG" | tail -25
    _exit=$?
    set -e

    # Parse coverage % from XML
    if [[ -f "$_xml_out" ]]; then
        _parsed=$(python3 - <<PYEOF
import xml.etree.ElementTree as ET, sys
try:
    tree = ET.parse("$_xml_out")
    root = tree.getroot()
    lc = int(root.get("lines-covered","0"))
    lt = int(root.get("lines-valid","0"))
    bc = int(root.get("branches-covered","0"))
    bt = int(root.get("branches-valid","0"))
    pct = round(float(root.get("line-rate","0"))*100, 2)
    print(f"{pct},{lc},{lt},{bc},{bt}")
except Exception as e:
    print(f"0,0,0,0,0")
PYEOF
)
        IFS=',' read -r COVERAGE_PCT LINES_COVERED LINES_TOTAL BRANCHES_COVERED BRANCHES_TOTAL <<< "$_parsed"
    else
        # Fallback: parse terminal output
        COVERAGE_PCT=$(grep -E "^TOTAL\s+" "$SCAN_LOG" 2>/dev/null | awk '{print $NF}' | tr -d '%' | tail -1) || COVERAGE_PCT=""
    fi

fi

# ─── 2. JavaScript / TypeScript (Vitest or Jest) ──────────────────────────────
if [[ -z "$DETECTED_LANG" ]] && [[ -f "package.json" ]]; then
    # Detect vitest or jest
    _test_runner=""
    if python3 -c "import json,sys; p=json.load(open('package.json')); deps={**p.get('dependencies',{}),**p.get('devDependencies',{})}; sys.exit(0 if 'vitest' in deps else 1)" 2>/dev/null; then
        _test_runner="vitest"
    elif python3 -c "import json,sys; p=json.load(open('package.json')); deps={**p.get('dependencies',{}),**p.get('devDependencies',{})}; sys.exit(0 if 'jest' in deps else 1)" 2>/dev/null; then
        _test_runner="jest"
    fi

    # Also accept if package.json has a test:coverage or coverage script
    _cov_script=""
    for _s in "test:coverage" "coverage"; do
        if node -e "const p=require('./package.json');process.exit((p.scripts&&p.scripts['$_s'])?0:1)" 2>/dev/null; then
            _cov_script="$_s"
            break
        fi
    done

    if [[ -n "$_test_runner" ]] || [[ -n "$_cov_script" ]]; then
        DETECTED_LANG="javascript"
        DETECTED_FRAMEWORK="${_test_runner:-jest}"
        echo -e "${CYAN}📦 Detected JS/TS project (${DETECTED_FRAMEWORK})${NC}"

        # Install deps if needed
        if [[ "$SKIP_COVERAGE_INSTALL" != "true" ]] && [[ ! -d "node_modules" ]]; then
            echo -e "${CYAN}📥 Installing dependencies...${NC}"
            npm install --prefer-offline --no-audit --no-fund 2>&1 | tail -5 || true
        fi

        _lcov_out="$OUTPUT_DIR/lcov.info"
        _json_out="$OUTPUT_DIR/coverage-istanbul.json"

        echo -e "${CYAN}⏱  Running coverage (timeout: ${COVERAGE_TIMEOUT}s)...${NC}"
        set +e
        if [[ -n "$_cov_script" ]]; then
            run_with_timeout "$COVERAGE_TIMEOUT" npm run "$_cov_script" 2>&1 | tee "$SCAN_LOG" | tail -25
        elif [[ "$_test_runner" == "vitest" ]]; then
            run_with_timeout "$COVERAGE_TIMEOUT" npx vitest run --coverage 2>&1 | tee "$SCAN_LOG" | tail -25
        else
            run_with_timeout "$COVERAGE_TIMEOUT" npx jest --coverage --ci 2>&1 | tee "$SCAN_LOG" | tail -25
        fi
        _exit=$?
        set -e

        # Copy lcov.info if found
        for _lcov in coverage/lcov.info coverage/lcov-report/lcov.info; do
            [[ -f "$_lcov" ]] && cp "$_lcov" "$_lcov_out" && break
        done

        # Parse from coverage-summary.json (jest/vitest) if present
        for _cov_json in coverage/coverage-summary.json coverage-summary.json; do
            if [[ -f "$_cov_json" ]]; then
                _parsed=$(python3 - <<PYEOF
import json, sys
try:
    data = json.load(open("$_cov_json"))
    total = data.get("total", {})
    lc = total.get("lines",{}).get("covered",0)
    lt = total.get("lines",{}).get("total",0)
    bc = total.get("branches",{}).get("covered",0)
    bt = total.get("branches",{}).get("total",0)
    pct = round(total.get("lines",{}).get("pct",0), 2)
    print(f"{pct},{lc},{lt},{bc},{bt}")
except Exception:
    print("0,0,0,0,0")
PYEOF
)
                IFS=',' read -r COVERAGE_PCT LINES_COVERED LINES_TOTAL BRANCHES_COVERED BRANCHES_TOTAL <<< "$_parsed"
                cp "$_cov_json" "$_json_out" 2>/dev/null || true
                break
            fi
        done

        # Fallback: parse from lcov
        if [[ -z "$COVERAGE_PCT" || "$COVERAGE_PCT" == "0" ]] && [[ -f "$_lcov_out" ]]; then
            LINES_COVERED=$(grep -c "^DA:[0-9]*,[^0]" "$_lcov_out" 2>/dev/null || echo 0)
            LINES_TOTAL=$(grep -c "^DA:" "$_lcov_out" 2>/dev/null || echo 0)
            if [[ "$LINES_TOTAL" -gt 0 ]]; then
                COVERAGE_PCT=$(python3 -c "print(round($LINES_COVERED/$LINES_TOTAL*100,2))" 2>/dev/null || echo 0)
            fi
        fi
    fi
fi

# ─── 3. Go ────────────────────────────────────────────────────────────────────
if [[ -z "$DETECTED_LANG" ]] && [[ -f "go.mod" ]] && command -v go &>/dev/null; then
    DETECTED_LANG="go"
    DETECTED_FRAMEWORK="go test"
    echo -e "${CYAN}🐹 Detected Go project${NC}"

    _profile="$OUTPUT_DIR/coverage.out"
    _html_out="$OUTPUT_DIR/coverage.html"

    echo -e "${CYAN}⏱  Running go test -coverprofile (timeout: ${COVERAGE_TIMEOUT}s)...${NC}"
    set +e
    run_with_timeout "$COVERAGE_TIMEOUT" go test -coverprofile="$_profile" ./... 2>&1 | tee "$SCAN_LOG" | tail -25
    _exit=$?
    set -e

    if [[ -f "$_profile" ]]; then
        go tool cover -html="$_profile" -o "$_html_out" 2>/dev/null || true
        COVERAGE_PCT=$(go tool cover -func="$_profile" 2>/dev/null | grep "^total:" | awk '{print $NF}' | tr -d '%') || COVERAGE_PCT=""
        LINES_TOTAL=$(grep -c "^" "$_profile" 2>/dev/null || echo 0)
        LINES_COVERED=$(awk -F'[: ]' '$NF != "0" {count++} END {print count+0}' "$_profile" 2>/dev/null || echo 0)
    fi
fi

# ─── No test suite found ──────────────────────────────────────────────────────
if [[ -z "$DETECTED_LANG" ]]; then
    echo -e "${YELLOW}⚠️  No supported test framework detected (Python/pytest, JS/Vitest/Jest, Go)${NC}"
    echo -e "${YELLOW}   Skipping coverage collection.${NC}"
    write_summary "unknown" "none" "0" "0" "0" "0" "0" "not_detected" > "$SUMMARY_JSON"
    echo -e "${CYAN}📄 Coverage summary: $SUMMARY_JSON${NC}"
    exit 0
fi

# ─── Normalise and write summary ──────────────────────────────────────────────
COVERAGE_PCT="${COVERAGE_PCT:-0}"
# Strip trailing % if somehow present
COVERAGE_PCT="${COVERAGE_PCT//%/}"

if [[ -z "$COVERAGE_PCT" ]] || ! python3 -c "float('$COVERAGE_PCT')" &>/dev/null 2>&1; then
    COVERAGE_PCT="0"
    _status="error"
else
    _status="success"
fi

write_summary \
    "$DETECTED_LANG" \
    "$DETECTED_FRAMEWORK" \
    "$COVERAGE_PCT" \
    "$LINES_COVERED" \
    "$LINES_TOTAL" \
    "$BRANCHES_COVERED" \
    "$BRANCHES_TOTAL" \
    "$_status" > "$SUMMARY_JSON"

echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
if python3 -c "import sys; sys.exit(0 if float('$COVERAGE_PCT') >= 80 else 1)" 2>/dev/null; then
    echo -e "${GREEN}✅ Test Coverage: ${COVERAGE_PCT}% (${DETECTED_LANG}/${DETECTED_FRAMEWORK})${NC}"
else
    echo -e "${YELLOW}⚠️  Test Coverage: ${COVERAGE_PCT}% (${DETECTED_LANG}/${DETECTED_FRAMEWORK}) — below 80% threshold${NC}"
fi
echo -e "${CYAN}   Lines: ${LINES_COVERED}/${LINES_TOTAL}${NC}"
[[ "$BRANCHES_TOTAL" -gt 0 ]] && echo -e "${CYAN}   Branches: ${BRANCHES_COVERED}/${BRANCHES_TOTAL}${NC}"
echo -e "${CYAN}   Summary: $SUMMARY_JSON${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

exit 0
