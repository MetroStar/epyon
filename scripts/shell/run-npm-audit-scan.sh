#!/bin/bash

# npm audit Direct Dependency Scanner (lockfile-less aware)
# Scans Node.js projects that have a package.json. When no lockfile exists, a
# lockfile is resolved in a temporary copy (target is never modified) so that
# vulnerable dependency versions are still detected.

set -euo pipefail

WHITE='\033[1;37m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

show_help() {
    cat <<EOF
${WHITE}npm audit Dependency Scanner${NC}

Usage: $0 [OPTIONS] [TARGET_DIRECTORY]

Options:
  -h, --help          Show this help message and exit
  -t, --target PATH   Target directory to scan

Environment Variables:
  TARGET_DIR          Alternative way to specify target directory
  SCAN_DIR            Output directory root (required)

Output:
  \$SCAN_DIR/npm-audit/npm-audit-consolidated-results.json
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
init_scan_environment "npm-audit"

REPO_PATH="${TARGET_ARG:-${TARGET_DIR:-$(pwd)}}"
REPO_PATH=$(realpath "$REPO_PATH" 2>/dev/null) || { echo "ERROR: invalid target: $REPO_PATH" >&2; exit 1; }
CONSOLIDATED="$OUTPUT_DIR/npm-audit-consolidated-results.json"

echo -e "${WHITE}npm audit Dependency Scanner${NC}"
echo "Target: $REPO_PATH"

write_empty() {
    echo '{"scan_results": []}' > "$CONSOLIDATED"
}

if ! command -v npm >/dev/null 2>&1; then
    echo -e "${YELLOW}⚠️  npm not installed — skipping npm audit${NC}"
    write_empty
    record_scan_status "skipped" "npm not installed" 2>/dev/null || true
    exit 0
fi

PKG_FILES=()
while IFS= read -r f; do PKG_FILES+=("$f"); done < <(find "$REPO_PATH" -name package.json \
    -not -path '*/node_modules/*' -not -path '*/.git/*' -not -path '*/dist/*' \
    -not -path '*/build/*' 2>/dev/null | sort)

if [[ ${#PKG_FILES[@]} -eq 0 ]]; then
    echo -e "${CYAN}ℹ️  No package.json found — nothing to audit${NC}"
    write_empty
    record_scan_status "success" "no package.json" 2>/dev/null || true
    exit 0
fi

WORK_ROOT=$(mktemp -d)
trap 'rm -rf "$WORK_ROOT"' EXIT
echo '{"scan_results": []}' > "$CONSOLIDATED"

for pkg in "${PKG_FILES[@]}"; do
    pkg_dir="$(dirname "$pkg")"
    rel="${pkg_dir#"$REPO_PATH"}"; rel="${rel#/}"; rel="${rel:-.}"
    work="$WORK_ROOT/$(echo "$rel" | tr '/ ' '__')"
    mkdir -p "$work"
    cp "$pkg" "$work/package.json"
    for lock in package-lock.json npm-shrinkwrap.json; do
        [[ -f "$pkg_dir/$lock" ]] && cp "$pkg_dir/$lock" "$work/$lock"
    done

    echo -e "${CYAN}🔍 Auditing $rel/package.json${NC}"
    if [[ ! -f "$work/package-lock.json" && ! -f "$work/npm-shrinkwrap.json" ]]; then
        echo "   No lockfile — resolving dependency tree in a temporary copy"
        (cd "$work" && npm install --package-lock-only --ignore-scripts --no-audit --no-fund \
            >"$work/install.log" 2>&1) || { echo -e "${YELLOW}   ⚠️  Could not resolve dependencies for $rel${NC}"; continue; }
    fi

    cat "$work/install.log" >> "$SCAN_LOG" 2>/dev/null || true
    raw="$work/audit.json"
    # npm audit exits non-zero when vulnerabilities exist
    (cd "$work" && npm audit --json 2>>"$SCAN_LOG" > "$raw") || true
    jq -e '.vulnerabilities' "$raw" >/dev/null 2>&1 || { echo -e "${YELLOW}   ⚠️  No usable audit output for $rel${NC}"; continue; }

    lockfile="$work/package-lock.json"; [[ -f "$lockfile" ]] || lockfile="$work/npm-shrinkwrap.json"
    # Flatten: one entry per advisory (via[] objects) per package
    results=$(jq '[
        .vulnerabilities | to_entries[] | .key as $pkgname | .value as $v
        | ($v.via[]? | select(type == "object")) as $adv
        | {
            id: (($adv.url // "") | capture("(?<g>GHSA-[a-z0-9-]+)").g? // ($adv.source | tostring)),
            name: ($adv.name // $pkgname),
            v: ($v.range // ""),
            severity: ($adv.severity // $v.severity),
            title: ($adv.title // ""),
            advisory: ($adv.url // ""),
            fix_available: ($v.fixAvailable | if type == "object" then true else . end),
            direct: $v.isDirect
        }
    ] | unique_by(.id + "|" + .name)' "$raw")

    # Resolve installed versions from the generated lockfile
    results=$(jq --slurpfile lock "$lockfile" '
        map(. as $r | .v = (($lock[0].packages["node_modules/" + $r.name].version) // $r.v))' <<<"$results")

    # Deprecated packages are recorded in the lockfile by npm
    deprecated=$(jq '[.packages // {} | to_entries[] | select(.value.deprecated != null and .key != "")
        | {id: ("DEPRECATED-" + (.key | sub("^.*node_modules/"; ""))), name: (.key | sub("^.*node_modules/"; "")),
           v: .value.version, severity: "low", title: ("Deprecated: " + .value.deprecated), advisory: "", fix_available: false}]
        | unique_by(.id)' "$lockfile")
    results=$(jq --argjson d "${deprecated:-[]}" '. + $d' <<<"$results")
    count=$(jq 'length' <<<"$results")
    echo -e "${GREEN}   ✅ $count advisories${NC}"
    tmp=$(mktemp)
    jq --arg file "${rel}/package.json" --argjson res "$results" \
        '.scan_results += [{file: $file, results: $res}]' "$CONSOLIDATED" > "$tmp" && mv "$tmp" "$CONSOLIDATED"
done

record_scan_status "success" 2>/dev/null || true
echo -e "${GREEN}✅ npm audit complete: $CONSOLIDATED${NC}"
