#!/usr/bin/env bash

# Quick Metrics Dashboard Update
# One-command wrapper to collect metrics and update dashboard

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

show_help() {
    cat << 'EOF'
Quick Metrics Dashboard Update

Usage: update-metrics-dashboard.sh [OPTIONS] [DASHBOARD_FILE]

Collects metrics and updates your dashboard in one command.

Options:
  -r, --repo OWNER/REPO      GitHub repository (auto-detected by default)
  -d, --days NUM             Days to collect (default: 90)
  --chart-type TYPE          Chart type: line, area, bar (default: line)
  --max-points NUM           Max chart points (default: 90)
  -q, --quiet                Suppress progress output
  -h, --help                 Show this help message

Positional Arguments:
  DASHBOARD_FILE             Path to dashboard HTML (or scans/ auto-detected)

Examples:
  # Update dashboard in scans/ directory (auto-detected)
  ./update-metrics-dashboard.sh

  # Update specific dashboard
  ./update-metrics-dashboard.sh scans/iris_*/consolidated-reports/dashboards/security-dashboard.html

  # Custom settings
  ./update-metrics-dashboard.sh -d 60 --chart-type area --dashboard-dir custom/

  # Just collect metrics, no embedding
  ./update-metrics-dashboard.sh -d 90 --collect-only

EOF
    exit 0
}

# ─── Defaults ────────────────────────────────────────────────────────
REPO=""
DAYS=90
CHART_TYPE="line"
MAX_POINTS=90
DASHBOARD_FILE=""
QUIET=false
COLLECT_ONLY=false
DASHBOARD_DIR="${PROJECT_ROOT}/metrics"

# ─── Parse Arguments ──────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        -r|--repo)          REPO="$2"; shift 2 ;;
        -d|--days)          DAYS="$2"; shift 2 ;;
        --chart-type)       CHART_TYPE="$2"; shift 2 ;;
        --max-points)       MAX_POINTS="$2"; shift 2 ;;
        --collect-only)     COLLECT_ONLY=true; shift ;;
        -q|--quiet)         QUIET=true; shift ;;
        -h|--help)          show_help ;;
        -*)                 echo "Unknown option: $1" >&2; exit 1 ;;
        *)                  DASHBOARD_FILE="$1"; shift ;;
    esac
done

# ─── Helper Functions ────────────────────────────────────────────────
log() {
    [[ "$QUIET" == false ]] && echo -e "${BLUE}→${NC} $@" >&2
}

success() {
    [[ "$QUIET" == false ]] && echo -e "${GREEN}✅${NC} $@" >&2
}

error() {
    echo -e "${RED}❌${NC} $@" >&2
    exit 1
}

# ─── Detect Dashboard File ───────────────────────────────────────────
if [[ -z "$DASHBOARD_FILE" ]]; then
    # Try to find latest dashboard in scans/
    DASHBOARD_FILE=$(find "$PROJECT_ROOT/scans" -name "security-dashboard.html" -type f 2>/dev/null | 
                     sort -r | 
                     head -1 || echo "")
    
    if [[ -z "$DASHBOARD_FILE" ]]; then
        log "No existing dashboard found. Will create minimal version."
        DASHBOARD_FILE="$DASHBOARD_DIR/security-dashboard.html"
    else
        log "Found dashboard: $(basename $(dirname "$DASHBOARD_FILE"))"
    fi
fi

# ─── Auto-detect repo if not provided ─────────────────────────────────
if [[ -z "$REPO" ]]; then
    if cd "$PROJECT_ROOT" && git rev-parse --git-dir > /dev/null 2>&1; then
        REPO=$(git config --get remote.origin.url | sed -E 's|.*[:/]([^/]+)/([^/]+?)(\.git)?$|\1/\2|')
        log "Detected repo: $REPO"
    fi
fi

# ─── Validate requirements ────────────────────────────────────────────
if ! command -v gh &> /dev/null; then
    error "GitHub CLI (gh) not found. Install from: https://cli.github.com"
fi

if ! command -v jq &> /dev/null; then
    error "jq is required. Install with: brew install jq (or apt-get install jq)"
fi

if ! gh auth status > /dev/null 2>&1; then
    error "GitHub CLI not authenticated. Run: gh auth login"
fi

# ─── Create working directory ─────────────────────────────────────────
mkdir -p "$DASHBOARD_DIR"
cd "$PROJECT_ROOT"

# ─── Step 1: Collect Metrics ──────────────────────────────────────────
log "Step 1/3: Collecting metrics from last $DAYS days..."

METRICS_FILE="$DASHBOARD_DIR/metrics-${DAYS}d.json"

if bash "$SCRIPT_DIR/collect-metrics-from-github.sh" \
    ${REPO:+--repo "$REPO"} \
    --days "$DAYS" \
    --dashboard-dir "$DASHBOARD_DIR" \
    --output "metrics-${DAYS}d.json" \
    ${QUIET:+--quiet}; then
    success "Metrics collected: $METRICS_FILE"
else
    error "Failed to collect metrics"
fi

# ─── Exit early if collect-only ──────────────────────────────────────
if [[ "$COLLECT_ONLY" == true ]]; then
    success "Done! Metrics saved to: $METRICS_FILE"
    exit 0
fi

# ─── Step 2: Generate/Ensure Dashboard ───────────────────────────────
log "Step 2/3: Preparing dashboard..."

if [[ ! -f "$DASHBOARD_FILE" ]]; then
    log "Creating minimal dashboard template..."
    mkdir -p "$(dirname "$DASHBOARD_FILE")"
    
    cat > "$DASHBOARD_FILE" << 'TEMPLATE'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Dashboard with Metrics</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #0F1F3D 0%, #1a2332 50%);
            min-height: 100vh;
            padding: 20px;
            color: #2d3748;
        }
        .container { max-width: 1400px; margin: 0 auto; }
        .header {
            background: white;
            border-radius: 16px;
            padding: 40px;
            margin-bottom: 30px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.15);
            text-align: center;
        }
        .header h1 { font-size: 2.5em; margin-bottom: 10px; color: #1f2937; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Security Dashboard</h1>
            <p style="color: #6b7280; font-size: 1.1em;">90-Day Metrics Report</p>
        </div>
        <!-- Metrics chart injected here -->
    </div>
</body>
</html>
TEMPLATE
    
    success "Dashboard template created"
fi

# ─── Step 3: Embed Metrics ────────────────────────────────────────
log "Step 3/3: Embedding metrics chart..."

if bash "$SCRIPT_DIR/embed-metrics-in-dashboard.sh" \
    --metrics "$METRICS_FILE" \
    --dashboard "$DASHBOARD_FILE" \
    --chart-type "$CHART_TYPE" \
    --max-points "$MAX_POINTS" \
    ${QUIET:+--quiet}; then
    success "Metrics embedded in dashboard"
else
    error "Failed to embed metrics"
fi

# ─── Final Summary ────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}════════════════════════════════════════════════${NC}"
echo -e "${GREEN}✅ Dashboard Update Complete${NC}"
echo -e "${CYAN}════════════════════════════════════════════════${NC}"
echo ""
echo -e "  📊 Metrics:   ${METRICS_FILE}"
echo -e "  📄 Dashboard: ${DASHBOARD_FILE}"
echo -e "  📈 Chart Type: ${CHART_TYPE}"
echo -e "  📅 Time Range: Last ${DAYS} days"
echo ""

# Print quick stats
if [[ -f "$METRICS_FILE" ]]; then
    TOTAL=$(jq '.total_scans' "$METRICS_FILE" 2>/dev/null || echo "?")
    CRIT=$(jq '.summary.critical_total' "$METRICS_FILE" 2>/dev/null || echo "?")
    HIGH=$(jq '.summary.high_total' "$METRICS_FILE" 2>/dev/null || echo "?")
    
    echo -e "  📌 Quick Stats:"
    echo -e "     Total Scans: ${TOTAL}"
    echo -e "     Critical: ${RED}${CRIT}${NC}"
    echo -e "     High: ${YELLOW}${HIGH}${NC}"
    echo ""
fi

if command -v open &> /dev/null; then
    echo -e "  💡 Tip: ${BLUE}open '${DASHBOARD_FILE}'${NC} to view dashboard"
elif command -v xdg-open &> /dev/null; then
    echo -e "  💡 Tip: ${BLUE}xdg-open '${DASHBOARD_FILE}'${NC} to view dashboard"
fi

echo ""
success "Ready to review!"

exit 0
