#!/bin/bash

# Semgrep SAST Scanner
# Finds code-level vulnerabilities (SQL injection, hardcoded secrets, weak crypto,
# command injection, insecure JWT usage, ...) without needing a SonarQube server.

set -euo pipefail

WHITE='\033[1;37m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

show_help() {
    cat <<EOF
${WHITE}Semgrep SAST Scanner${NC}

Usage: $0 [OPTIONS] [TARGET_DIRECTORY]

Options:
  -h, --help          Show this help message and exit
  -t, --target PATH   Target directory to scan

Environment Variables:
  TARGET_DIR          Alternative way to specify target directory
  SCAN_DIR            Output directory root (required)
  SEMGREP_CONFIGS     Space-separated registry rulesets (default: "p/security-audit p/secrets");
                      Epyon's custom rules in configuration/semgrep-rules/ always run too
  SEMGREP_IMAGE       Container image used when semgrep is not installed

Output:
  \$SCAN_DIR/semgrep/semgrep-results.json
EOF
    exit 0
}

TARGET_ARG=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help) show_help ;;
        -t|--target)
            [[ -z "${2:-}" || "${2:-}" == -* ]] && { echo "❌ Error: $1 requires a value"; exit 1; }
            TARGET_ARG="$2"; shift 2 ;;
        -*) echo "❌ Error: Unknown option: $1"; exit 1 ;;
        *) [[ -z "$TARGET_ARG" ]] && TARGET_ARG="$1"; shift ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/scan-directory-template.sh"
if [[ -f "$SCRIPT_DIR/container-runtime.sh" ]]; then
    set +e; source "$SCRIPT_DIR/container-runtime.sh"; set -e
fi
CONTAINER_CLI="${CONTAINER_CLI:-docker}"
init_scan_environment "semgrep"

REPO_PATH="${TARGET_ARG:-${TARGET_DIR:-$(pwd)}}"
REPO_PATH=$(realpath "$REPO_PATH" 2>/dev/null) || { echo "ERROR: invalid target: $REPO_PATH" >&2; exit 1; }
RESULTS="$OUTPUT_DIR/semgrep-results.json"
SEMGREP_CONFIGS="${SEMGREP_CONFIGS:-p/security-audit p/secrets}"
SEMGREP_IMAGE="${SEMGREP_IMAGE:-semgrep/semgrep:latest}"

echo -e "${WHITE}Semgrep SAST Scanner${NC}"
echo "Target: $REPO_PATH"
echo "Rulesets: $SEMGREP_CONFIGS"

RULES_DIR="$(cd "$SCRIPT_DIR/../../configuration/semgrep-rules" && pwd)"
config_args=()
for c in $SEMGREP_CONFIGS; do config_args+=(--config "$c"); done
common_args=(scan "${config_args[@]}" --json --metrics=off --quiet
    --exclude node_modules --exclude .git --exclude dist --exclude build --exclude vendor --exclude __tests__ --exclude '*.test.*' --exclude '*.spec.*')

if command -v semgrep >/dev/null 2>&1; then
    (cd "$REPO_PATH" && semgrep "${common_args[@]}" --config "$RULES_DIR" . 2>>"$SCAN_LOG" > "$RESULTS") || true
elif command -v "$CONTAINER_CLI" >/dev/null 2>&1 && "$CONTAINER_CLI" info >/dev/null 2>&1; then
    target_host="$(to_host_path "$REPO_PATH" 2>/dev/null || echo "$REPO_PATH")"
    "$CONTAINER_CLI" run --rm -v "$target_host:/src:ro" -v "$(to_host_path "$RULES_DIR" 2>/dev/null || echo "$RULES_DIR"):/rules:ro" -w /src "$SEMGREP_IMAGE" \
        semgrep "${common_args[@]}" --config /rules . 2>>"$SCAN_LOG" > "$RESULTS" || true
else
    echo -e "${YELLOW}⚠️  Neither semgrep nor a container runtime is available — skipping${NC}"
    echo '{"results": [], "errors": []}' > "$RESULTS"
    record_scan_status "skipped" "semgrep unavailable" 2>/dev/null || true
    exit 0
fi

if ! jq -e '.results' "$RESULTS" >/dev/null 2>&1; then
    echo -e "${YELLOW}⚠️  Semgrep produced no usable output (see $SCAN_LOG)${NC}"
    echo '{"results": [], "errors": []}' > "$RESULTS"
    record_scan_status "failed" "no usable output" 2>/dev/null || true
    exit 0
fi

# "missing X" rules match once per statement; keep one finding per rule/location
jq '.results |= unique_by(if (.check_id | test("missing-")) then [.check_id, .path] else [.check_id, .path, .start.line] end)' "$RESULTS" > "$RESULTS.tmp" && mv "$RESULTS.tmp" "$RESULTS"
count=$(jq '.results | length' "$RESULTS")
echo -e "${GREEN}✅ Semgrep complete: $count findings${NC}"
record_scan_status "success" 2>/dev/null || true
