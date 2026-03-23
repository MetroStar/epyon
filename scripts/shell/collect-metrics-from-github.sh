#!/usr/bin/env bash

# Collect Metrics from GitHub Actions Artifacts
# Pulls all metrics-{scan_id} artifacts from the last 90 days
# and aggregates them into a consolidated dashboard metrics file

set -euo pipefail

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

show_help() {
    cat << 'EOF'
Collect Metrics from GitHub Actions Artifacts

Usage: collect-metrics-from-github.sh [OPTIONS]

Pulls all metrics-{scan_id} artifacts from the last 90 days from GitHub Actions,
aggregates them into a time-series JSON, and prepares data for dashboard integration.

Options:
  -r, --repo OWNER/REPO      GitHub repository (defaults to git remote origin)
  -d, --days NUM             Number of days to collect (default: 90)
  -o, --output FILE          Output file for aggregated metrics (default: metrics-90d.json)
  --dashboard-dir DIR        Directory to store dashboard metrics (default: ./metrics/)
  --gh-token TOKEN           GitHub API token (defaults to gh CLI auth)
  -q, --quiet                Suppress progress output
  -h, --help                 Show this help message

Examples:
  collect-metrics-from-github.sh
  collect-metrics-from-github.sh --repo MetroStar/epyon --days 90
  collect-metrics-from-github.sh --dashboard-dir scans/metrics

Requirements:
  - GitHub CLI (gh) installed and authenticated
  - jq for JSON processing
  - git (to auto-detect repo)

Output:
  Creates metrics-90d.json with aggregated metrics from all runs
  Each scan includes: scan_id, timestamp, target, user, critical, high, medium, low counts

EOF
    exit 0
}

# ─── Defaults ────────────────────────────────────────────────────────
REPO=""
DAYS=90
OUTPUT_FILE=""
DASHBOARD_DIR="./metrics"
QUIET=false
GH_TOKEN=""

# ─── Parse Arguments ─────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        -r|--repo)          REPO="$2"; shift 2 ;;
        -d|--days)          DAYS="$2"; shift 2 ;;
        -o|--output)        OUTPUT_FILE="$2"; shift 2 ;;
        --dashboard-dir)    DASHBOARD_DIR="$2"; shift 2 ;;
        --gh-token)         GH_TOKEN="$2"; shift 2 ;;
        -q|--quiet)         QUIET=true; shift ;;
        -h|--help)          show_help ;;
        *)                  echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

# ─── Helper Functions ────────────────────────────────────────────────
log_info() {
    [[ "$QUIET" == false ]] && echo -e "${BLUE}ℹ️  $@${NC}" >&2
}

log_success() {
    [[ "$QUIET" == false ]] && echo -e "${GREEN}✅ $@${NC}" >&2
}

log_warn() {
    echo -e "${YELLOW}⚠️  $@${NC}" >&2
}

log_error() {
    echo -e "${RED}❌ $@${NC}" >&2
}

# ─── Auto-detect repo from git ────────────────────────────────────────
if [[ -z "$REPO" ]]; then
    if git rev-parse --git-dir > /dev/null 2>&1; then
        REPO=$(git config --get remote.origin.url | sed -E 's|.*[:/]([^/]+)/([^/]+?)(\.git)?$|\1/\2|')
        log_info "Auto-detected repo: $REPO"
    else
        log_error "Could not auto-detect repo. Use --repo OWNER/REPO"
        exit 1
    fi
fi

# ─── Validate repo format ────────────────────────────────────────────
if [[ ! "$REPO" =~ ^[a-zA-Z0-9._-]+/[a-zA-Z0-9._-]+$ ]]; then
    log_error "Invalid repo format: $REPO (expected: OWNER/REPO)"
    exit 1
fi

# ─── Set output file if not provided ──────────────────────────────────
if [[ -z "$OUTPUT_FILE" ]]; then
    OUTPUT_FILE="metrics-${DAYS}d.json"
fi

# ─── Create dashboard directory ───────────────────────────────────────
mkdir -p "$DASHBOARD_DIR"
log_info "Dashboard directory: $DASHBOARD_DIR"

# ─── Check that gh CLI is installed and authenticated ─────────────────
if ! command -v gh &> /dev/null; then
    log_error "GitHub CLI (gh) is not installed. Install it first: https://cli.github.com"
    exit 1
fi

if ! gh auth status > /dev/null 2>&1; then
    log_error "GitHub CLI is not authenticated. Run: gh auth login"
    exit 1
fi

log_info "Using repo: $REPO"
log_info "Collecting metrics from the last $DAYS days..."

# ─── Calculate date range ────────────────────────────────────────────
CUTOFF_DATE=$(date -u -d "$DAYS days ago" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || \
              date -u -v-${DAYS}d '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || echo "")

if [[ -z "$CUTOFF_DATE" ]]; then
    log_warn "Could not calculate date offset. Fetching last 50 runs..."
    RUN_FILTER=""
else
    log_info "Cutoff date: $CUTOFF_DATE"
    RUN_FILTER="created:>=$CUTOFF_DATE"
fi

# ─── Fetch all metrics artifacts ────────────────────────────────────
log_info "Fetching metrics artifacts from GitHub Actions..."

METRICS_JSON="[]"
ARTIFACT_COUNT=0
PROCESSED_COUNT=0

# Use gh to list all artifacts matching metrics-* pattern
if [[ -n "$RUN_FILTER" ]]; then
    RUNS=$(gh run list -R "$REPO" --json databaseId,createdAt --created "$RUN_FILTER" -L 500 2>/dev/null || echo "[]")
else
    RUNS=$(gh run list -R "$REPO" --json databaseId,createdAt -L 500 2>/dev/null || echo "[]")
fi

if [[ "$RUNS" == "[]" ]] || [[ -z "$RUNS" ]]; then
    log_warn "No runs found in the specified time range"
else
    # Parse run IDs
    RUN_IDS=$(echo "$RUNS" | jq -r '.[].databaseId' 2>/dev/null || echo "")
    
    if [[ -n "$RUN_IDS" ]]; then
        while read -r RUN_ID; do
            [[ -z "$RUN_ID" ]] && continue
            
            # List artifacts for this run
            ARTIFACTS=$(gh run download "$RUN_ID" -R "$REPO" --list 2>/dev/null | grep "metrics-" || true)
            
            if [[ -n "$ARTIFACTS" ]]; then
                while read -r ARTIFACT_NAME; do
                    [[ -z "$ARTIFACT_NAME" ]] && continue
                    
                    ARTIFACT_COUNT=$((ARTIFACT_COUNT + 1))
                    log_info "  [$ARTIFACT_COUNT] Downloading: $ARTIFACT_NAME from run $RUN_ID"
                    
                    # Create temp directory for artifact
                    TEMP_DIR=$(mktemp -d)
                    trap "rm -rf $TEMP_DIR" EXIT
                    
                    # Download artifact
                    if gh run download "$RUN_ID" -R "$REPO" -n "$ARTIFACT_NAME" -D "$TEMP_DIR" 2>/dev/null; then
                        # Find and read scan-metrics.json
                        METRICS_FILE=$(find "$TEMP_DIR" -name "scan-metrics.json" -type f | head -1)
                        if [[ -f "$METRICS_FILE" ]]; then
                            METRIC_DATA=$(cat "$METRICS_FILE")
                            
                            # Append to JSON array
                            METRICS_JSON=$(echo "$METRICS_JSON" | jq --argjson metric "$METRIC_DATA" '. += [$metric]')
                            PROCESSED_COUNT=$((PROCESSED_COUNT + 1))
                            log_success "  Processed: $ARTIFACT_NAME"
                        else
                            log_warn "  No scan-metrics.json found in artifact: $ARTIFACT_NAME"
                        fi
                    else
                        log_warn "  Failed to download: $ARTIFACT_NAME"
                    fi
                    
                    rm -rf "$TEMP_DIR"
                done < <(echo "$ARTIFACTS" | awk '{print $1}')
            fi
        done < <(echo "$RUN_IDS")
    fi
fi

# ─── Sort metrics by timestamp ──────────────────────────────────────
log_info "Aggregating and sorting $PROCESSED_COUNT metrics..."

AGGREGATED_JSON=$(echo "$METRICS_JSON" | jq '
    sort_by(.scan_timestamp) |
    {
        generated_at:        (now | todate),
        collected_from:      "github-actions",
        time_range_days:     '${DAYS}',
        total_scans:         length,
        scans_with_findings: ([.[] | select(.has_findings_summary)] | length),
        summary: {
            critical_total:  ([.[].critical // 0] | add),
            high_total:      ([.[].high // 0] | add),
            medium_total:    ([.[].medium // 0] | add),
            low_total:       ([.[].low // 0] | add)
        },
        targets:             ([.[].target_name] | unique | sort),
        users:               ([.[].scan_user] | unique | sort),
        metrics:             .
    }
')

# ─── Write output file ──────────────────────────────────────────────
OUTPUT_PATH="$DASHBOARD_DIR/$OUTPUT_FILE"
echo "$AGGREGATED_JSON" | jq '.' > "$OUTPUT_PATH"

log_success "Metrics written to: $OUTPUT_PATH"

# ─── Print summary ────────────────────────────────────────────────
if [[ "$QUIET" == false ]]; then
    echo ""
    echo -e "${CYAN}════════════════════════════════════${NC}"
    echo -e "${CYAN}Metrics Collection Summary${NC}"
    echo -e "${CYAN}════════════════════════════════════${NC}"
    
    TOTAL=$(echo "$AGGREGATED_JSON" | jq '.total_scans')
    WITH_FINDINGS=$(echo "$AGGREGATED_JSON" | jq '.scans_with_findings')
    CRIT=$(echo "$AGGREGATED_JSON" | jq '.summary.critical_total')
    HIGH=$(echo "$AGGREGATED_JSON" | jq '.summary.high_total')
    MED=$(echo "$AGGREGATED_JSON" | jq '.summary.medium_total')
    LOW=$(echo "$AGGREGATED_JSON" | jq '.summary.low_total')
    
    echo -e "  Total Scans:          ${GREEN}${TOTAL}${NC}"
    echo -e "  Scans w/ Findings:    ${GREEN}${WITH_FINDINGS}${NC}"
    echo -e "  Critical:             ${RED}${CRIT}${NC}"
    echo -e "  High:                 ${YELLOW}${HIGH}${NC}"
    echo -e "  Medium:               ${YELLOW}${MED}${NC}"
    echo -e "  Low:                  ${GREEN}${LOW}${NC}"
    echo -e "  Time Range:           Last ${DAYS} days"
    echo ""
fi

exit 0
