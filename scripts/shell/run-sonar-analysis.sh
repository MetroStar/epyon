#!/bin/bash
# run-sonar-analysis.sh
# Minimal SonarCloud CI runner.
# Reads expected coverage paths from sonar-project.properties and generates
# any that are missing before invoking the scanner.
#
# Usage:
#   run-sonar-analysis.sh [TARGET_DIRECTORY]
#
# Environment variables (or values in .env.sonar):
#   SONAR_TOKEN           Required. SonarCloud authentication token.
#   SONAR_HOST_URL        SonarCloud URL (default: https://sonarcloud.io)
#   SONAR_PROJECT_KEY     Project key. Auto-derived from properties file if unset.
#   SONAR_ORGANIZATION    Organization slug. Auto-read from properties file if unset.

set -euo pipefail

# ---------------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_PATH="${1:-${TARGET_DIR:-$(pwd)}}"
REPO_PATH="$(cd "$REPO_PATH" && pwd)"

# Load .env.sonar (repo-level → home-level)
for _env in "$REPO_PATH/.env.sonar" "$HOME/.env.sonar"; do
  [ -f "$_env" ] && { set +u; source "$_env"; set -u; } && break
done

# Shared scan-directory setup (provides init_scan_environment, SCAN_DIR, etc.)
source "$SCRIPT_DIR/scan-directory-template.sh"

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
SONAR_HOST_URL="${SONAR_HOST_URL:-https://sonarcloud.io}"

if [ -z "${SONAR_TOKEN:-}" ]; then
  echo "[ERROR] SONAR_TOKEN is not set. Export it or add it to .env.sonar." >&2
  exit 1
fi

# Locate sonar-project.properties
PROPS_FILE=""
for _p in \
  "$REPO_PATH/sonar-project.properties" \
  "$REPO_PATH/sonar.properties"; do
  [ -f "$_p" ] && { PROPS_FILE="$_p"; break; }
done

# Read project key + org from properties file if not already set
if [ -n "$PROPS_FILE" ]; then
  _props_key=$(grep -E "^sonar\.projectKey\s*=" "$PROPS_FILE" 2>/dev/null \
               | head -1 | sed 's/^[^=]*=\s*//' | tr -d '[:space:]') || true
  _props_org=$(grep -E "^sonar\.organization\s*=" "$PROPS_FILE" 2>/dev/null \
               | head -1 | sed 's/^[^=]*=\s*//' | tr -d '[:space:]') || true
  [ -z "${SONAR_PROJECT_KEY:-}" ] && [ -n "${_props_key:-}" ] && SONAR_PROJECT_KEY="$_props_key"
  [ -z "${SONAR_ORGANIZATION:-}" ] && [ -n "${_props_org:-}" ] && SONAR_ORGANIZATION="$_props_org"
fi

# Derive a project key from directory name if still unset
if [ -z "${SONAR_PROJECT_KEY:-}" ]; then
  SONAR_PROJECT_KEY=$(basename "$REPO_PATH" | tr '[:upper:]' '[:lower:]' | tr ' /\\' '---' | tr -cd 'a-z0-9_.-')
  echo "[INFO] Derived project key: $SONAR_PROJECT_KEY"
fi

ORG_ARG=""
[ -n "${SONAR_ORGANIZATION:-}" ] && ORG_ARG="-Dsonar.organization=${SONAR_ORGANIZATION}"

# ---------------------------------------------------------------------------
# Scan directory
# ---------------------------------------------------------------------------
init_scan_environment "sonar"
SCAN_OUTPUT_DIR="$SCAN_DIR/sonar"
mkdir -p "$SCAN_OUTPUT_DIR"
SCANNER_LOG="$SCAN_OUTPUT_DIR/sonar-scan.log"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
TOKEN_DISPLAY="${SONAR_TOKEN:0:8}...(${#SONAR_TOKEN} chars total)"
echo ""
echo "============================================"
echo "SonarCloud Analysis"
echo "============================================"
echo "  Project Key : $SONAR_PROJECT_KEY"
echo "  Host        : $SONAR_HOST_URL"
echo "  Repo        : $REPO_PATH"
echo "  Token       : $TOKEN_DISPLAY"
[ -n "$PROPS_FILE" ] && echo "  Properties  : $(basename "$PROPS_FILE")"
echo "  Log         : $SCANNER_LOG"
echo "============================================"
echo ""

# ---------------------------------------------------------------------------
# Pre-scan: generate any missing coverage reports
# ---------------------------------------------------------------------------
# Read the JS/TS and Python coverage paths declared in sonar-project.properties
# and run the project's own test command for any that don't yet exist on disk.
# This keeps the script self-contained while staying minimal — no coverage
# generation logic is duplicated; we just delegate to the project's own tooling.

_PROPS_BASE="${PROPS_FILE:+$(dirname "$PROPS_FILE")}"
_PROPS_BASE="${_PROPS_BASE:-$REPO_PATH}"

# ---- JS/TS: sonar.javascript.lcov.reportPaths ----
if [ -n "$PROPS_FILE" ]; then
  _lcov_paths=$(grep -E "^sonar\.javascript\.lcov\.reportPaths\s*=" "$PROPS_FILE" 2>/dev/null \
                | head -1 | sed 's/^[^=]*=\s*//' | tr -d ' ') || true
  if [ -n "$_lcov_paths" ]; then
    IFS=',' read -ra _lcov_arr <<< "$_lcov_paths"
    for _lcov_rel in "${_lcov_arr[@]}"; do
      _lcov_abs="$_PROPS_BASE/$_lcov_rel"
      if [ ! -f "$_lcov_abs" ]; then
        echo "[INFO] Missing JS coverage: $_lcov_rel — searching for package.json to run tests..."
        # Walk up from the lcov path to find the nearest package.json
        _search_dir="$(dirname "$_lcov_abs")"
        _pkg_dir=""
        # Also check parent directories up to _PROPS_BASE
        _d="$_search_dir"
        while [[ "$_d" == "$_PROPS_BASE"* ]]; do
          if [ -f "$_d/package.json" ]; then
            _pkg_dir="$_d"
            break
          fi
          _d="$(dirname "$_d")"
        done
        if [ -n "$_pkg_dir" ]; then
          echo "[INFO] Running JS tests in: $_pkg_dir"
          cd "$_pkg_dir"
          # Try test:coverage, then coverage, then test -- vitest/jest both support these
          if node -e "const p=require('./package.json'); process.exit(p.scripts&&p.scripts['test:coverage']?0:1)" 2>/dev/null; then
            npm run test:coverage 2>&1 | tail -30 || true
          elif node -e "const p=require('./package.json'); process.exit(p.scripts&&p.scripts['coverage']?0:1)" 2>/dev/null; then
            npm run coverage 2>&1 | tail -30 || true
          else
            echo "[INFO] No test:coverage/coverage script found in $(basename "$_pkg_dir") — trying npx vitest run --coverage"
            npx vitest run --coverage 2>&1 | tail -30 || true
          fi
          cd "$REPO_PATH"
        else
          echo "[WARNING] Could not find a package.json near $_lcov_rel — skipping JS coverage generation"
        fi
      else
        echo "[INFO] JS coverage already present: $_lcov_rel"
      fi
    done
  fi
fi

# ---- Python: sonar.python.coverage.reportPaths ----
if [ -n "$PROPS_FILE" ]; then
  _py_cov_paths=$(grep -E "^sonar\.python\.coverage\.reportPaths\s*=" "$PROPS_FILE" 2>/dev/null \
                  | head -1 | sed 's/^[^=]*=\s*//' | tr -d ' ') || true
  if [ -n "$_py_cov_paths" ]; then
    _primary_cov=$(echo "$_py_cov_paths" | cut -d',' -f1)
    _primary_abs="$_PROPS_BASE/$_primary_cov"
    if [ ! -f "$_primary_abs" ]; then
      echo "[INFO] Missing Python coverage: $_primary_cov — attempting to generate..."
      cd "$_PROPS_BASE"
      if python3 -m pytest --version &>/dev/null 2>&1; then
        # Detect sonar.sources for --cov target
        _py_src=$(grep -E "^sonar\.sources\s*=" "$PROPS_FILE" 2>/dev/null \
                  | head -1 | sed 's/^[^=]*=\s*//' | tr -d ' ' | cut -d',' -f1) || true
        _cov_target="${_py_src:+$_PROPS_BASE/$_py_src}"
        _cov_target="${_cov_target:-$_PROPS_BASE}"
        mkdir -p "$(dirname "$_primary_abs")"
        python3 -m pip install --quiet pytest-cov 2>&1 | tail -1 || true
        python3 -m pytest \
          --cov="$_cov_target" \
          --cov-report="xml:${_primary_abs}" \
          --ignore=node_modules --ignore=.venv --ignore=venv \
          -q 2>&1 | tail -40 || true
      else
        echo "[WARNING] pytest not available — skipping Python coverage generation"
      fi
      cd "$REPO_PATH"
    else
      echo "[INFO] Python coverage already present: $_primary_cov"
    fi
  fi
fi

# ---------------------------------------------------------------------------
# Run scanner
# ---------------------------------------------------------------------------
if [ -n "$PROPS_FILE" ]; then
  # Properties file found — cd to its directory so relative paths inside it resolve
  cd "$(dirname "$PROPS_FILE")"
  npx sonarqube-scanner \
    -Dsonar.projectKey="$SONAR_PROJECT_KEY" \
    -Dsonar.host.url="$SONAR_HOST_URL" \
    -Dsonar.token="$SONAR_TOKEN" \
    $ORG_ARG \
    2>&1 | tee "$SCANNER_LOG"
else
  # No properties file — pass sources explicitly
  cd "$REPO_PATH"
  npx sonarqube-scanner \
    -Dsonar.projectKey="$SONAR_PROJECT_KEY" \
    -Dsonar.sources="$REPO_PATH" \
    -Dsonar.projectBaseDir="$REPO_PATH" \
    -Dsonar.host.url="$SONAR_HOST_URL" \
    -Dsonar.token="$SONAR_TOKEN" \
    $ORG_ARG \
    2>&1 | tee "$SCANNER_LOG"
fi
SCANNER_EXIT=${PIPESTATUS[0]}

cd "$REPO_PATH"

if [ "$SCANNER_EXIT" -ne 0 ]; then
  echo "[ERROR] SonarCloud scanner exited with code $SCANNER_EXIT" >&2
  exit "$SCANNER_EXIT"
fi
echo ""
echo "✅ SonarCloud scanner completed successfully"

# ---------------------------------------------------------------------------
# Fetch metrics from API and save results JSON
# ---------------------------------------------------------------------------
RESULTS_FILE="$SCAN_OUTPUT_DIR/sonar-analysis-results.json"
echo ""
echo "[INFO] Fetching metrics from SonarCloud API..."

_metrics="bugs,vulnerabilities,code_smells,security_hotspots,coverage,duplicated_lines_density,ncloc,sqale_index"
_api_url="${SONAR_HOST_URL}/api/measures/component?component=${SONAR_PROJECT_KEY}&metricKeys=${_metrics}"
_auth_header="Authorization: Bearer ${SONAR_TOKEN}"

if command -v curl &>/dev/null; then
  _api_response=$(curl -s -H "$_auth_header" "$_api_url" 2>/dev/null) || _api_response=""
else
  _api_response=""
fi

_coverage="n/a"
_bugs="n/a"
_vulns="n/a"
_smells="n/a"
_hotspots="n/a"

if [ -n "$_api_response" ] && echo "$_api_response" | grep -q '"component"'; then
  _extract() { echo "$_api_response" | grep -o "\"metric\":\"$1\"[^}]*\"value\":\"[^\"]*\"" | grep -o '"value":"[^"]*"' | cut -d'"' -f4 | head -1; }
  _coverage=$(_extract coverage || echo "n/a")
  _bugs=$(_extract bugs || echo "n/a")
  _vulns=$(_extract vulnerabilities || echo "n/a")
  _smells=$(_extract code_smells || echo "n/a")
  _hotspots=$(_extract security_hotspots || echo "n/a")
  echo "[OK] Metrics fetched:"
  echo "  • Bugs              : $_bugs"
  echo "  • Vulnerabilities   : $_vulns"
  echo "  • Code Smells       : $_smells"
  echo "  • Security Hotspots : $_hotspots"
  echo "  • Coverage          : ${_coverage}%"
else
  echo "[INFO] Could not fetch metrics (API unavailable or project not yet processed)"
fi

cat > "$RESULTS_FILE" <<JSON
{
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "project_key": "$SONAR_PROJECT_KEY",
  "host_url": "$SONAR_HOST_URL",
  "dashboard_url": "${SONAR_HOST_URL}/dashboard?id=${SONAR_PROJECT_KEY}",
  "metrics": {
    "bugs": "$_bugs",
    "vulnerabilities": "$_vulns",
    "code_smells": "$_smells",
    "security_hotspots": "$_hotspots",
    "coverage": "$_coverage"
  },
  "status": "ANALYSIS_COMPLETE"
}
JSON

echo ""
echo "[OK] Results saved: $RESULTS_FILE"
echo "📊 Dashboard: ${SONAR_HOST_URL}/dashboard?id=${SONAR_PROJECT_KEY}"
