#!/bin/bash

# Cross-Scan Metrics Aggregator
# Reads all scan directories and produces a time-series summary of findings.
# Works with the scan directory architecture: scans/{SCAN_ID}/scan-metadata.json
# and scans/{SCAN_ID}/security-findings-summary.json

set -o pipefail

# Colors
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
WHITE='\033[1;37m'
BOLD='\033[1m'
NC='\033[0m'

show_help() {
    echo -e "${WHITE}Cross-Scan Metrics Aggregator${NC}"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Reads completed scan directories — and optionally GitHub Actions artifacts — then"
    echo "produces a JSON time-series and terminal table of findings trends across all time."
    echo ""
    echo "Options:"
    echo "  -d, --scans-dir DIR       Root directory containing scan folders (default: auto-detect)"
    echo "  -t, --target NAME         Filter by target name (e.g. iris, comet-starter)"
    echo "  -u, --user NAME           Filter by scan user"
    echo "  -s, --since DATE          Only include scans on or after DATE (YYYY-MM-DD)"
    echo "  -o, --output FILE         Write JSON output to FILE (default: scan-history.json)"
    echo "  -q, --quiet               Suppress terminal table, emit only JSON"
    echo "  -h, --help                Show this help message and exit"
    echo ""
    echo "GitHub Options:"
    echo "  -g, --from-github [REPO]  Pull metrics from GitHub Actions artifacts."
    echo "                            REPO defaults to the current git remote origin."
    echo "                            Format: owner/repo  (e.g. MetroStar/epyon)"
    echo "  --github-only             Do not read local scan directories; use GitHub artifacts only"
    echo "  --no-cache                Re-download from GitHub even when a cached row exists"
    echo "  --fetch-legacy            Also scan full scan-artifact zips for runs that predate"
    echo "                            the lightweight metrics-{scan_id} artifact (slow)"
    echo "  --repos REPO1,REPO2,...   Comma-separated list of additional repos to include"
    echo ""
    echo "Output:"
    echo "  Terminal table — sorted by timestamp, one row per scan"
    echo "  scan-history.json (or --output path) — machine-readable time-series"
    echo ""
    echo "Sources (in order of precedence):"
    echo "  scans/                    Primary local scan output directory"
    echo "  baseline/scans/           Baseline scan directory"
    echo "  metrics/github-cache/     Cached rows from previously downloaded GitHub artifacts"
    echo "  GitHub Actions API        metrics-{scan_id} artifacts (requires gh CLI + auth)"
    echo ""
    echo "Examples:"
    echo "  $0                                         # Local scans only"
    echo "  $0 --from-github                           # Local + GitHub (auto-detect repo)"
    echo "  $0 --github-only --from-github MetroStar/epyon  # GitHub artifacts only"
    echo "  $0 --from-github MetroStar/epyon           # Explicit repo"
    echo "  $0 --from-github --since 2026-01-01        # GitHub runs since date"
    echo "  $0 --from-github --repos org/repo1,org/repo2  # Multiple repos"
    echo "  $0 --from-github --fetch-legacy            # Include pre-jsonl artifacts (slow)"
    exit 0
}

# ── Defaults ──────────────────────────────────────────────────────────────────
FILTER_TARGET=""
FILTER_USER=""
FILTER_SINCE=""
OUTPUT_FILE=""
QUIET=false
SCANS_DIR_OVERRIDE=""
FROM_GITHUB=false
GITHUB_REPOS=()
NO_CACHE=false
FETCH_LEGACY=false
GITHUB_ONLY=false

# ── Argument parsing ──────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)          show_help ;;
        -d|--scans-dir)     SCANS_DIR_OVERRIDE="$2"; shift 2 ;;
        -t|--target)        FILTER_TARGET="$2"; shift 2 ;;
        -u|--user)          FILTER_USER="$2"; shift 2 ;;
        -s|--since)         FILTER_SINCE="$2"; shift 2 ;;
        -o|--output)        OUTPUT_FILE="$2"; shift 2 ;;
        -q|--quiet)         QUIET=true; shift ;;
        -g|--from-github)
            FROM_GITHUB=true
            # Optional positional value: owner/repo (no leading dash)
            if [[ -n "${2:-}" && "${2}" != -* ]]; then
                GITHUB_REPOS+=("$2"); shift
            fi
            shift ;;
        --repos)
            IFS=',' read -r -a _EXTRA_REPOS <<< "$2"
            GITHUB_REPOS+=("${_EXTRA_REPOS[@]}")
            shift 2 ;;
        --github-only)
            GITHUB_ONLY=true
            FROM_GITHUB=true
            shift ;;
        --no-cache)         NO_CACHE=true; shift ;;
        --fetch-legacy)     FETCH_LEGACY=true; shift ;;
        *) echo -e "${RED}❌ Unknown option: $1${NC}" >&2; echo "Run with --help for usage." >&2; exit 1 ;;
    esac
done

# ── Locate workspace root ─────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
GH_CACHE_DIR="$WORKSPACE_ROOT/metrics/github-cache"

# ── Resolve scan search paths ─────────────────────────────────────────────────
if [[ -n "$SCANS_DIR_OVERRIDE" ]]; then
    SEARCH_DIRS=("$SCANS_DIR_OVERRIDE")
else
    SEARCH_DIRS=()
    [[ -d "$WORKSPACE_ROOT/scans" ]]          && SEARCH_DIRS+=("$WORKSPACE_ROOT/scans")
    [[ -d "$WORKSPACE_ROOT/baseline/scans" ]] && SEARCH_DIRS+=("$WORKSPACE_ROOT/baseline/scans")
fi

if [[ ${#SEARCH_DIRS[@]} -eq 0 && "$FROM_GITHUB" == false ]]; then
    echo -e "${RED}❌ No scan directories found under $WORKSPACE_ROOT${NC}"
    exit 1
fi

if [[ "$QUIET" == false ]]; then
    if [[ "$GITHUB_ONLY" == true ]]; then
        echo -e "${BLUE}🔍 GitHub-only mode enabled (skipping local scan directories)${NC}"
    else
        echo -e "${BLUE}🔍 Scanning for completed scans...${NC}"
    fi
fi

# Require jq
if ! command -v jq &>/dev/null; then
    echo -e "${RED}❌ jq is required but not installed.${NC}"
    echo "  Install: brew install jq  /  apt-get install jq"
    exit 1
fi

# ── Helper: build a SCAN_RECORD from parsed field variables ──────────────────
# Caller must set: SCAN_ID TARGET_NAME SCAN_TYPE SCAN_USER SCAN_TS SCAN_TS_LOCAL
#                  CRITICAL HIGH MEDIUM LOW TOOLS_ANALYZED HAS_FINDINGS
# Optional extras: REPOSITORY RUN_ID RUN_URL (empty string if absent)
build_record() {
    jq -cn \
        --arg  scan_id              "${SCAN_ID}" \
        --arg  target_name          "${TARGET_NAME}" \
        --arg  scan_type            "${SCAN_TYPE}" \
        --arg  scan_user            "${SCAN_USER}" \
        --arg  scan_timestamp       "${SCAN_TS}" \
        --arg  scan_timestamp_local "${SCAN_TS_LOCAL}" \
        --arg  repository           "${REPOSITORY:-}" \
        --arg  run_id               "${RUN_ID:-}" \
        --arg  run_url              "${RUN_URL:-}" \
        --argjson critical          "${CRITICAL}" \
        --argjson high              "${HIGH}" \
        --argjson medium            "${MEDIUM}" \
        --argjson low               "${LOW}" \
        --argjson tools             "${TOOLS_ANALYZED}" \
        --argjson has_findings      "${HAS_FINDINGS}" \
        '{
            scan_id:              $scan_id,
            target_name:          $target_name,
            scan_type:            $scan_type,
            scan_user:            $scan_user,
            scan_timestamp:       $scan_timestamp,
            scan_timestamp_local: $scan_timestamp_local,
            repository:           $repository,
            run_id:               $run_id,
            run_url:              $run_url,
            has_findings_summary: $has_findings,
            critical:             $critical,
            high:                 $high,
            medium:               $medium,
            low:                  $low,
            tools_analyzed:       $tools
        }'
}

# ── Helper: parse a security-findings-summary.json into severity vars ─────────
parse_findings_file() {
    local findings_file="$1"
    CRITICAL=0; HIGH=0; MEDIUM=0; LOW=0
    TOOLS_ANALYZED="[]"
    HAS_FINDINGS=false
    if [[ -f "$findings_file" ]]; then
        HAS_FINDINGS=true
        CRITICAL=$(jq -r '.summary.total_critical // 0' "$findings_file" 2>/dev/null || echo 0)
        HIGH=$(jq -r     '.summary.total_high     // 0' "$findings_file" 2>/dev/null || echo 0)
        MEDIUM=$(jq -r   '.summary.total_medium   // 0' "$findings_file" 2>/dev/null || echo 0)
        LOW=$(jq -r      '.summary.total_low      // 0' "$findings_file" 2>/dev/null || echo 0)
        local TOOLS_RAW
        TOOLS_RAW=$(jq '.summary.tools_analyzed // []' "$findings_file" 2>/dev/null || echo "[]")
        TOOLS_ANALYZED=$(echo "$TOOLS_RAW" | jq -c 'unique | sort' 2>/dev/null || echo "[]")
    fi
}

# ── GitHub fetch function ─────────────────────────────────────────────────────
# Populates SCAN_RECORDS with rows from GitHub Actions artifacts for REPO.
# Uses metrics/github-cache/{scan_id}.json to avoid re-downloading.
fetch_github_metrics() {
    local REPO="$1"

    [[ "$QUIET" == false ]] && echo -e "${CYAN}  ↳ GitHub: ${REPO}${NC}"

    # Validate gh is available and authenticated
    if ! command -v gh &>/dev/null; then
        echo -e "${RED}  ❌ gh CLI not found. Install from https://cli.github.com/${NC}"
        return 1
    fi
    if ! gh auth status &>/dev/null; then
        echo -e "${RED}  ❌ gh CLI not authenticated. Run: gh auth login${NC}"
        return 1
    fi

    mkdir -p "$GH_CACHE_DIR"

    local TMP_DIR
    TMP_DIR=$(mktemp -d)
    # shellcheck disable=SC2064
    trap "rm -rf '$TMP_DIR'" RETURN

    local PAGE=1
    local FETCHED=0
    local CACHED=0
    local SKIPPED_FILTER=0

    while true; do
        # List up to 100 artifacts per page
        local ARTIFACTS_JSON
        ARTIFACTS_JSON=$(gh api \
            "repos/${REPO}/actions/artifacts?per_page=100&page=${PAGE}" \
            --jq '.artifacts' 2>/dev/null) || {
            echo -e "${YELLOW}  ⚠️  Failed to list artifacts for ${REPO} (page ${PAGE})${NC}"
            break
        }

        local PAGE_COUNT
        PAGE_COUNT=$(echo "$ARTIFACTS_JSON" | jq 'length')
        [[ "$PAGE_COUNT" -eq 0 ]] && break

        # Process each artifact on this page
        while IFS= read -r ARTIFACT; do
            local ART_NAME ART_ID ART_EXPIRED ART_SIZE ART_RUN_ID
            ART_NAME=$(echo "$ARTIFACT"    | jq -r '.name')
            ART_ID=$(echo "$ARTIFACT"      | jq -r '.id')
            ART_EXPIRED=$(echo "$ARTIFACT" | jq -r '.expired')
            ART_SIZE=$(echo "$ARTIFACT"    | jq -r '.size_in_bytes // 0')
            ART_RUN_ID=$(echo "$ARTIFACT"  | jq -r '.workflow_run.id // ""')

            # Only process metrics-{scan_id} artifacts (lightweight)
            [[ "$ART_NAME" != metrics-* ]] && continue
            [[ "$ART_EXPIRED" == true ]]    && continue

            local SCAN_ID_FROM_ART
            SCAN_ID_FROM_ART="${ART_NAME#metrics-}"

            # Apply --since filter early (scan_id embeds the date)
            if [[ -n "$FILTER_SINCE" ]]; then
                # Extract date portion from the scan_id (format: name_user_YYYY-MM-DD_HH-MM-SS)
                local ART_DATE
                ART_DATE=$(echo "$SCAN_ID_FROM_ART" | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2}' | head -1)
                if [[ -n "$ART_DATE" && "$ART_DATE" < "$FILTER_SINCE" ]]; then
                    SKIPPED_FILTER=$(( SKIPPED_FILTER + 1 ))
                    continue
                fi
            fi

            local CACHE_FILE="$GH_CACHE_DIR/${SCAN_ID_FROM_ART}.json"

            # Skip if this scan ID was already collected locally
            _is_seen "$SCAN_ID_FROM_ART" && continue

            # Skip if already cached (unless --no-cache)
            if [[ "$NO_CACHE" == false && -f "$CACHE_FILE" ]]; then
                # Apply target/user filters to cached records before adding them
                local C_TARGET C_USER
                C_TARGET=$(jq -r '.target_name // ""' "$CACHE_FILE" 2>/dev/null)
                C_USER=$(jq -r   '.scan_user   // ""' "$CACHE_FILE" 2>/dev/null)
                if [[ -n "$FILTER_TARGET" && "$C_TARGET" != "$FILTER_TARGET" ]]; then continue; fi
                if [[ -n "$FILTER_USER"   && "$C_USER"   != "$FILTER_USER"   ]]; then continue; fi
                CACHED=$(( CACHED + 1 ))
                local CACHED_RECORD
                CACHED_RECORD=$(cat "$CACHE_FILE")
                SCAN_RECORDS+=("$CACHED_RECORD")
                _mark_seen "$SCAN_ID_FROM_ART"
                continue
            fi

            # Download the zip into a tmp subdir
            local ART_DIR="$TMP_DIR/$ART_ID"
            mkdir -p "$ART_DIR"
            local ZIP_FILE="$TMP_DIR/${ART_ID}.zip"

            [[ "$QUIET" == false ]] && \
                printf "  ${BLUE}  ↓ %-55s  %s bytes${NC}\n" \
                    "${ART_NAME:0:55}" "$ART_SIZE"

            local JSONL_CONTENT
            JSONL_CONTENT=""
            local DOWNLOAD_ERR
            DOWNLOAD_ERR="$TMP_DIR/download-${ART_ID}.err"
            if ! gh api "repos/${REPO}/actions/artifacts/${ART_ID}/zip" \
                    > "$ZIP_FILE" 2>"$DOWNLOAD_ERR"; then
                local ERR_MSG
                ERR_MSG=$(tr '\n' ' ' < "$DOWNLOAD_ERR" | sed -E 's/[[:space:]]+/ /g; s/^ //; s/ $//')
                [[ -z "$ERR_MSG" ]] && ERR_MSG="unknown error"
                echo -e "${YELLOW}    ⚠️  Download failed for artifact ${ART_ID}: ${ERR_MSG}${NC}"

                # Fallback path: gh run download is often more reliable in Actions context.
                if [[ -n "$ART_RUN_ID" ]]; then
                    rm -rf "$ART_DIR" && mkdir -p "$ART_DIR"
                    if gh run download "$ART_RUN_ID" \
                          --repo "$REPO" \
                          --name "$ART_NAME" \
                          --dir "$ART_DIR" 2>"$DOWNLOAD_ERR"; then
                        JSONL_CONTENT=$(head -1 "$ART_DIR/scan-metrics.json" 2>/dev/null || true)
                        if [[ -z "$JSONL_CONTENT" ]]; then
                            echo -e "${YELLOW}    ⚠️  Fallback download succeeded but scan-metrics.json was missing (${ART_NAME})${NC}"
                            continue
                        fi
                        rm -f "$DOWNLOAD_ERR"
                    else
                        ERR_MSG=$(tr '\n' ' ' < "$DOWNLOAD_ERR" | sed -E 's/[[:space:]]+/ /g; s/^ //; s/ $//')
                        [[ -z "$ERR_MSG" ]] && ERR_MSG="unknown error"
                        echo -e "${YELLOW}    ⚠️  Fallback gh run download failed for run ${ART_RUN_ID}: ${ERR_MSG}${NC}"
                        continue
                    fi
                else
                    continue
                fi
            fi

            # Extract scan-metrics.json from the zip
            if [[ -z "${JSONL_CONTENT:-}" ]]; then
                JSONL_CONTENT=$(unzip -p "$ZIP_FILE" 'scan-metrics.json' 2>/dev/null | head -1)
            fi
            rm -f "$ZIP_FILE"

            if [[ -z "$JSONL_CONTENT" ]]; then
                [[ "$QUIET" == false ]] && \
                    echo -e "${YELLOW}    ⚠️  No scan-metrics.json in artifact ${ART_NAME}${NC}"
                continue
            fi

            # Validate and enrich with repo/artifact URL
            local ENRICHED
            ENRICHED=$(echo "$JSONL_CONTENT" | jq -c \
                --arg repo "$REPO" \
                --arg art_id "$ART_ID" \
                --arg art_name "$ART_NAME" \
                'if .scan_id then
                    . + {source: "github", artifact_id: $art_id, artifact_name: $art_name}
                    | if (.repository == null or .repository == "") then . + {repository: $repo} else . end
                 else empty end' 2>/dev/null) || continue

            [[ -z "$ENRICHED" ]] && continue

            # Write to cache
            echo "$ENRICHED" > "$CACHE_FILE"
            SCAN_RECORDS+=("$ENRICHED")
            _mark_seen "$SCAN_ID_FROM_ART"
            FETCHED=$(( FETCHED + 1 ))

        done < <(echo "$ARTIFACTS_JSON" | jq -c '.[]')

        PAGE=$(( PAGE + 1 ))
    done

    # ── Legacy: also check full scan artifacts if requested ───────────────────
    if [[ "$FETCH_LEGACY" == true ]]; then
        [[ "$QUIET" == false ]] && \
            echo -e "${CYAN}  ↳ Checking legacy full-scan artifacts for ${REPO}...${NC}"

        PAGE=1
        while true; do
            local LEGACY_JSON
            LEGACY_JSON=$(gh api \
                "repos/${REPO}/actions/artifacts?per_page=100&page=${PAGE}" \
                --jq '.artifacts' 2>/dev/null) || break

            local LEGACY_COUNT
            LEGACY_COUNT=$(echo "$LEGACY_JSON" | jq 'length')
            [[ "$LEGACY_COUNT" -eq 0 ]] && break

            while IFS= read -r ARTIFACT; do
                local ART_NAME ART_ID ART_EXPIRED
                ART_NAME=$(echo "$ARTIFACT"    | jq -r '.name')
                ART_ID=$(echo "$ARTIFACT"      | jq -r '.id')
                ART_EXPIRED=$(echo "$ARTIFACT" | jq -r '.expired')

                # Skip metrics artifacts (already handled), expired, and already seen IDs
                [[ "$ART_NAME" == metrics-* ]] && continue
                [[ "$ART_EXPIRED" == true ]]    && continue
                # Scan artifact name IS the scan_id
                _is_seen "$ART_NAME" && continue

                # Must look like a scan_id (name_user_YYYY-MM-DD_HH-MM-SS)
                [[ ! "$ART_NAME" =~ ^[a-zA-Z0-9_-]+_[0-9]{4}-[0-9]{2}-[0-9]{2}_[0-9]{2}-[0-9]{2}-[0-9]{2}$ ]] && continue

                local LEGACY_CACHE="$GH_CACHE_DIR/${ART_NAME}.json"
                if [[ "$NO_CACHE" == false && -f "$LEGACY_CACHE" ]]; then
                    SCAN_RECORDS+=("$(cat "$LEGACY_CACHE")")
                    _mark_seen "$ART_NAME"
                    continue
                fi

                [[ "$QUIET" == false ]] && \
                    echo -e "${BLUE}  ↓ (legacy) ${ART_NAME}${NC}"

                local ZIP_FILE="$TMP_DIR/${ART_ID}.zip"
                gh api "repos/${REPO}/actions/artifacts/${ART_ID}/zip" \
                    --output "$ZIP_FILE" 2>/dev/null || continue

                # Try scan-metrics.json first, then fall back to individual files
                local JSONL_CONTENT
                JSONL_CONTENT=$(unzip -p "$ZIP_FILE" 'scan-metrics.json' 2>/dev/null | head -1)

                if [[ -z "$JSONL_CONTENT" ]]; then
                    # Fall back: extract scan-metadata.json + security-findings-summary.json
                    local META_CONTENT
                    META_CONTENT=$(unzip -p "$ZIP_FILE" 'scan-metadata.json' 2>/dev/null)
                    if [[ -z "$META_CONTENT" ]]; then
                        rm -f "$ZIP_FILE"; continue
                    fi
                    META_CONTENT=$(echo "$META_CONTENT" | sed 's/: *N\/A/: null/g')

                    local FINDINGS_CONTENT
                    FINDINGS_CONTENT=$(unzip -p "$ZIP_FILE" 'security-findings-summary.json' 2>/dev/null || echo '{}')

                    SCAN_ID=$(echo "$META_CONTENT"     | jq -r '.scan_id // ""'          2>/dev/null)
                    TARGET_NAME=$(echo "$META_CONTENT" | jq -r '.target_name // ""'     2>/dev/null)
                    SCAN_TYPE=$(echo "$META_CONTENT"   | jq -r '.scan_type // "unknown"' 2>/dev/null)
                    SCAN_USER=$(echo "$META_CONTENT"   | jq -r '.scan_user // ""'        2>/dev/null)
                    SCAN_TS=$(echo "$META_CONTENT"     | jq -r '.scan_timestamp // ""'   2>/dev/null)
                    SCAN_TS_LOCAL=$(echo "$META_CONTENT" | jq -r '.scan_timestamp_local // ""' 2>/dev/null)
                    REPOSITORY="$REPO"; RUN_ID=""; RUN_URL=""

                    [[ -z "$SCAN_ID" || -z "$SCAN_TS" ]] && { rm -f "$ZIP_FILE"; continue; }

                    # Write findings to temp file so parse_findings_file works
                    local TMP_FINDINGS="$TMP_DIR/findings_$$.json"
                    echo "$FINDINGS_CONTENT" > "$TMP_FINDINGS"
                    parse_findings_file "$TMP_FINDINGS"
                    rm -f "$TMP_FINDINGS"

                    JSONL_CONTENT=$(build_record)
                fi

                rm -f "$ZIP_FILE"
                [[ -z "$JSONL_CONTENT" ]] && continue

                local ENRICHED
                ENRICHED=$(echo "$JSONL_CONTENT" | jq -c \
                    --arg repo "$REPO" --arg art_id "$ART_ID" \
                    '. + {source: "github-legacy", artifact_id: $art_id}
                    | if (.repository == null or .repository == "") then . + {repository: $repo} else . end' \
                    2>/dev/null) || continue

                [[ -z "$ENRICHED" ]] && continue
                echo "$ENRICHED" > "$LEGACY_CACHE"
                SCAN_RECORDS+=("$ENRICHED")
                _mark_seen "$ART_NAME"
                FETCHED=$(( FETCHED + 1 ))

            done < <(echo "$LEGACY_JSON" | jq -c '.[]')
            PAGE=$(( PAGE + 1 ))
        done
    fi

    if [[ "$QUIET" == false ]]; then
        echo -e "  ${GREEN}✓ GitHub ${REPO}: ${FETCHED} new rows fetched, ${CACHED} from cache${NC}"
    fi
}

# ── Collect metadata from every scan directory ────────────────────────────────
declare -a SCAN_RECORDS            # JSON objects, one per scan
# Bash-3 compatible dedup: local scan IDs written to a temp file so GitHub fetch
# skips IDs that already exist locally (local always wins).
_SEEN_IDS_FILE=$(mktemp)
trap 'rm -f "$_SEEN_IDS_FILE"' EXIT
_is_seen()  { grep -qF "$1" "$_SEEN_IDS_FILE" 2>/dev/null; }
_mark_seen() { printf '%s\n' "$1" >> "$_SEEN_IDS_FILE"; }
TOTAL_DIRS=0
SKIPPED=0

if [[ "$GITHUB_ONLY" == false ]]; then
    for SEARCH_DIR in "${SEARCH_DIRS[@]}"; do
        while IFS= read -r -d '' SCAN_DIR; do
            META="$SCAN_DIR/scan-metadata.json"
            [[ -f "$META" ]] || continue

            TOTAL_DIRS=$(( TOTAL_DIRS + 1 ))

            # ── Parse metadata ────────────────────────────────────────────────
            # Sanitize non-standard JSON values (e.g. N/A without quotes) before parsing
            META_JSON=$(sed 's/: *N\/A/: null/g' "$META")
            SCAN_ID=$(echo "$META_JSON"       | jq -r '.scan_id // ""'           2>/dev/null)
            TARGET_NAME=$(echo "$META_JSON"   | jq -r '.target_name // ""'       2>/dev/null)
            SCAN_TYPE=$(echo "$META_JSON"     | jq -r '.scan_type // "unknown"'  2>/dev/null)
            SCAN_USER=$(echo "$META_JSON"     | jq -r '.scan_user // ""'         2>/dev/null)
            SCAN_TS=$(echo "$META_JSON"       | jq -r '.scan_timestamp // ""'    2>/dev/null)
            SCAN_TS_LOCAL=$(echo "$META_JSON" | jq -r '.scan_timestamp_local // ""' 2>/dev/null)
            REPOSITORY=""; RUN_ID=""; RUN_URL=""

            [[ -z "$SCAN_ID" || -z "$SCAN_TS" ]] && { SKIPPED=$(( SKIPPED + 1 )); continue; }

            # ── Apply filters ─────────────────────────────────────────────────
            if [[ -n "$FILTER_TARGET" && "$TARGET_NAME" != "$FILTER_TARGET" ]]; then
                SKIPPED=$(( SKIPPED + 1 )); continue
            fi
            if [[ -n "$FILTER_USER" && "$SCAN_USER" != "$FILTER_USER" ]]; then
                SKIPPED=$(( SKIPPED + 1 )); continue
            fi
            if [[ -n "$FILTER_SINCE" ]]; then
                SCAN_DATE="${SCAN_TS:0:10}"
                [[ "$SCAN_DATE" < "$FILTER_SINCE" ]] && { SKIPPED=$(( SKIPPED + 1 )); continue; }
            fi

            # ── Parse findings summary (optional) ────────────────────────────
            parse_findings_file "$SCAN_DIR/security-findings-summary.json"

            SCAN_RECORDS+=("$(build_record)")
            _mark_seen "$SCAN_ID"
        done < <(find "$SEARCH_DIR" -maxdepth 1 -mindepth 1 -type d -print0 2>/dev/null | sort -z)
    done
fi

# ── Fetch from GitHub Actions artifacts ───────────────────────────────────────
if [[ "$FROM_GITHUB" == true ]]; then
    [[ "$QUIET" == false ]] && echo -e "${BLUE}☁  Fetching from GitHub Actions...${NC}"

    # If no repos specified, auto-detect from git remote
    if [[ ${#GITHUB_REPOS[@]} -eq 0 ]]; then
        DETECTED_REPO=$(git -C "$WORKSPACE_ROOT" remote get-url origin 2>/dev/null \
            | sed -E 's|https://github.com/||; s|git@github.com:||; s|\.git$||')
        if [[ -n "$DETECTED_REPO" ]]; then
            GITHUB_REPOS+=("$DETECTED_REPO")
        else
            echo -e "${RED}  ❌ Could not detect GitHub repo from git remote. Use --from-github OWNER/REPO${NC}"
        fi
    fi

    for GH_REPO in "${GITHUB_REPOS[@]}"; do
        fetch_github_metrics "$GH_REPO"
    done
fi

FOUND=${#SCAN_RECORDS[@]}

if [[ $FOUND -eq 0 ]]; then
    echo -e "${YELLOW}⚠️  No scans found matching your criteria.${NC}"
    echo "  Local dirs examined: $TOTAL_DIRS  |  Skipped: $SKIPPED"
    exit 0
fi


# ── Build aggregated JSON ─────────────────────────────────────────────────────
# Merge all records into a sorted array and compute summary statistics
RECORDS_JSON=$(printf '%s\n' "${SCAN_RECORDS[@]}" | jq -s '
    sort_by(.scan_timestamp)
    | {
        generated_at:        (now | todate),
        total_scans:         length,
        scans_with_findings: ([.[] | select(.has_findings_summary)] | length),
        targets:             ([.[].target_name] | unique | sort),
        users:               ([.[].scan_user]   | unique | sort),
        scan_types:          ([.[].scan_type]   | unique | sort),
        totals: {
            critical: (([.[].critical] | add) // 0),
            high:     (([.[].high]     | add) // 0),
            medium:   (([.[].medium]   | add) // 0),
            low:      (([.[].low]      | add) // 0)
        },
        trend: .
      }
')

# ── Write JSON output ─────────────────────────────────────────────────────────
if [[ -z "$OUTPUT_FILE" ]]; then
    OUTPUT_FILE="$WORKSPACE_ROOT/scan-history.json"
fi

echo "$RECORDS_JSON" > "$OUTPUT_FILE"

# ── Terminal table ────────────────────────────────────────────────────────────
if [[ "$QUIET" == false ]]; then
    echo ""
    echo -e "${WHITE}${BOLD}═══════════════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${WHITE}${BOLD}  Epyon Scan Metrics  —  All Time                                              ${NC}"
    echo -e "${WHITE}${BOLD}═══════════════════════════════════════════════════════════════════════════════${NC}"
    echo ""

    # Summary box
    TOTAL_SCANS=$(echo "$RECORDS_JSON" | jq -r '.total_scans')
    TOTAL_C=$(echo "$RECORDS_JSON"     | jq -r '.totals.critical')
    TOTAL_H=$(echo "$RECORDS_JSON"     | jq -r '.totals.high')
    TOTAL_M=$(echo "$RECORDS_JSON"     | jq -r '.totals.medium')
    TOTAL_L=$(echo "$RECORDS_JSON"     | jq -r '.totals.low')
    TARGETS=$(echo "$RECORDS_JSON"     | jq -r '.targets | join(", ")')
    USERS=$(echo "$RECORDS_JSON"       | jq -r '.users   | join(", ")')
    WITH_FINDINGS=$(echo "$RECORDS_JSON" | jq -r '.scans_with_findings')

    echo -e "  Scans found     : ${CYAN}${TOTAL_SCANS}${NC}  (${WITH_FINDINGS} with findings summary)"
    echo -e "  Targets         : ${CYAN}${TARGETS}${NC}"
    echo -e "  Users           : ${CYAN}${USERS}${NC}"
    echo -e "  Cumulative      : ${RED}${TOTAL_C} CRITICAL${NC}  ${YELLOW}${TOTAL_H} HIGH${NC}  ${BLUE}${TOTAL_M} MEDIUM${NC}  ${GREEN}${TOTAL_L} LOW${NC}"
    echo ""

    # Column header
    printf "  ${BOLD}%-32s  %-15s  %-8s  %-5s  %-5s  %-5s  %-5s  %s${NC}\n" \
        "SCAN ID" "TARGET" "TYPE" "CRIT" "HIGH" "MED" "LOW" "USER"
    echo "  ────────────────────────────────────────────────────────────────────────────"

    # Rows — sorted oldest-first
    while IFS= read -r ROW; do
        SCAN_ID=$(echo "$ROW"   | jq -r '.scan_id')
        TARGET=$(echo "$ROW"    | jq -r '.target_name')
        TYPE=$(echo "$ROW"      | jq -r '.scan_type')
        USER=$(echo "$ROW"      | jq -r '.scan_user')
        C=$(echo "$ROW"         | jq -r '.critical')
        H=$(echo "$ROW"         | jq -r '.high')
        M=$(echo "$ROW"         | jq -r '.medium')
        L=$(echo "$ROW"         | jq -r '.low')
        HAS_F=$(echo "$ROW"     | jq -r '.has_findings_summary')
        SOURCE=$(echo "$ROW"    | jq -r '.source // "local"')
        RUN_URL_ROW=$(echo "$ROW" | jq -r '.run_url // ""')

        # Truncate scan_id for display
        DISPLAY_ID="${SCAN_ID:0:32}"

        # Source badge
        SRC_BADGE=""
        [[ "$SOURCE" == github* ]] && SRC_BADGE=" ${CYAN}[gh]${NC}"

        # Color severity numbers
        C_COL="${C}"; H_COL="${H}"; M_COL="${M}"; L_COL="${L}"
        [[ $HAS_F == false ]] && { C_COL="-"; H_COL="-"; M_COL="-"; L_COL="-"; }
        [[ "$C" != "0" && $HAS_F == true ]] && C_COL="${RED}${C}${NC}"
        [[ "$H" != "0" && $HAS_F == true ]] && H_COL="${YELLOW}${H}${NC}"

        printf "  %-32s  %-15s  %-8s  %-5b  %-5b  %-5b  %-5b  %-12s%b\n" \
            "$DISPLAY_ID" "${TARGET:0:15}" "${TYPE:0:8}" \
            "$C_COL" "$H_COL" "$M_COL" "$L_COL" "$USER" "$SRC_BADGE"
        # Print run URL on a second line when present (GitHub-sourced rows)
        if [[ -n "$RUN_URL_ROW" ]]; then
            printf "  %34s  %s\n" "" "$RUN_URL_ROW"
        fi
    done < <(echo "$RECORDS_JSON" | jq -c '.trend[]')

    echo ""
    echo -e "  ${GREEN}✅ JSON output written to: ${OUTPUT_FILE}${NC}"
    echo ""
fi

