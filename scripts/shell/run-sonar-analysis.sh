#!/bin/bash
# run-sonar-analysis.sh
# Minimal SonarCloud CI runner.
# Assumes coverage/test reports are already on disk; this script only
# invokes the SonarCloud scanner and saves the results JSON.
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
