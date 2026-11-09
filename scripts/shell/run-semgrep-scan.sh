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
  SEMGREP_CONFIGS     Space-separated registry rulesets (default: security-audit, secrets, javascript, typescript,
                      nodejs, expressjs, owasp-top-ten, jwt, python);
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
SEMGREP_CONFIGS="${SEMGREP_CONFIGS:-p/security-audit p/secrets p/javascript p/typescript p/nodejs p/expressjs p/owasp-top-ten p/jwt p/python}"
SEMGREP_IMAGE="${SEMGREP_IMAGE:-semgrep/semgrep:latest}"

echo -e "${WHITE}Semgrep SAST Scanner${NC}"
echo "Target: $REPO_PATH"
echo "Rulesets: $SEMGREP_CONFIGS"

# docker-compose bind-mounts the host's ./configuration over /app/configuration, which
# can hide the bundled rules; fall back to the immutable image copy (see Dockerfile).
RULES_DIR=""
for candidate in "$SCRIPT_DIR/../../configuration/semgrep-rules" "${SEMGREP_RULES_DEFAULT_BACKUP:-/opt/epyon-defaults/configuration/semgrep-rules}"; do
    if [[ -n "$(ls "$candidate"/*.yml 2>/dev/null)" ]]; then RULES_DIR="$(cd "$candidate" && pwd)"; break; fi
done
if [[ -z "$RULES_DIR" ]]; then
    echo -e "${YELLOW}⚠️  Bundled Semgrep rules not found — using registry rulesets only${NC}"
fi
registry_args=()
for c in $SEMGREP_CONFIGS; do registry_args+=(--config "$c"); done
common_args=(scan --json --metrics=off --quiet
    --exclude node_modules --exclude .git --exclude dist --exclude build --exclude vendor --exclude __tests__ --exclude '*.test.*' --exclude '*.spec.*')

# Registry rulesets need to download rules from semgrep.dev; when that fails
# (air-gapped / egress-restricted deployments) semgrep aborts the whole run and
# emits nothing. Epyon's bundled rules are therefore run as their own pass so
# they always produce findings, and the registry pass is best-effort.
run_pass() {
    local out="$1"; shift
    if command -v semgrep >/dev/null 2>&1; then
        (cd "$REPO_PATH" && semgrep "${common_args[@]}" "$@" . 2>>"$SCAN_LOG" > "$out") || true
    else
        local target_host rules_host
        target_host="$(to_host_path "$REPO_PATH" 2>/dev/null || echo "$REPO_PATH")"
        rules_host="$(to_host_path "$RULES_DIR" 2>/dev/null || echo "$RULES_DIR")"
        "$CONTAINER_CLI" run --rm -v "$target_host:/src:ro" -v "$rules_host:/rules:ro" -w /src "$SEMGREP_IMAGE" \
            semgrep "${common_args[@]}" "$@" . 2>>"$SCAN_LOG" > "$out" || true
    fi
}

if command -v semgrep >/dev/null 2>&1; then
    rules_path="$RULES_DIR"
elif command -v "$CONTAINER_CLI" >/dev/null 2>&1 && "$CONTAINER_CLI" info >/dev/null 2>&1; then
    rules_path="/rules"
else
    echo -e "${YELLOW}⚠️  Neither semgrep nor a container runtime is available — skipping${NC}"
    echo '{"results": [], "errors": []}' > "$RESULTS"
    record_scan_status "skipped" "semgrep unavailable" 2>/dev/null || true
    exit 0
fi

if [[ -n "$RULES_DIR" ]]; then run_pass "$RESULTS.local" --config "$rules_path"; fi
run_pass "$RESULTS.registry" "${registry_args[@]}"

has_local=false; has_registry=false
jq -e '.results' "$RESULTS.local" >/dev/null 2>&1 && has_local=true
jq -e '.results' "$RESULTS.registry" >/dev/null 2>&1 && has_registry=true
if [[ "$has_registry" != "true" ]]; then
    echo -e "${YELLOW}⚠️  Semgrep registry rulesets unavailable (offline?) — using bundled rules only (see $SCAN_LOG)${NC}"
fi

if [[ "$has_local" == "true" || "$has_registry" == "true" ]]; then
    [[ "$has_local" == "true" ]] || echo '{"results": [], "errors": []}' > "$RESULTS.local"
    [[ "$has_registry" == "true" ]] || echo '{"results": [], "errors": []}' > "$RESULTS.registry"
    jq -s '{results: (map(.results) | add), errors: (map(.errors // []) | add)}' "$RESULTS.local" "$RESULTS.registry" > "$RESULTS"
else
    : > "$RESULTS"
fi
rm -f "$RESULTS.local" "$RESULTS.registry"

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
