#!/bin/bash

# Open Latest Security Dashboard
# Automatically finds and opens the most recent scan's dashboard

# Color definitions
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
WHITE='\033[1;37m'
NC='\033[0m'

# Help function
show_help() {
    echo -e "${WHITE}Open Latest Security Dashboard${NC}"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Automatically finds and opens the most recent security scan dashboard"
    echo "in your default web browser."
    echo ""
    echo "Options:"
    echo "  -h, --help          Show this help message and exit"
    echo ""
    echo "Behavior:"
    echo "  1. Finds the most recent scan in scans/ directory"
    echo "  2. Checks if dashboard exists"
    echo "  3. Regenerates dashboard if missing"
    echo "  4. Opens in default browser"
    echo ""
    echo "Examples:"
    echo "  $0                              # Open latest dashboard"
    echo ""
    echo "Notes:"
    echo "  - Requires a completed scan in scans/ directory"
    echo "  - Uses 'open' command (macOS) for browser"
    exit 0
}

# Parse arguments
for arg in "$@"; do
    case $arg in
        -h|--help)
            show_help
            ;;
    esac
done

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Find latest scan
SCANS_DIR="$WORKSPACE_ROOT/scans"
LATEST_SCAN=$(find "$SCANS_DIR" -maxdepth 1 -type d -name "*_*_*" 2>/dev/null | sort -r | head -n 1)

if [[ -z "$LATEST_SCAN" ]]; then
    echo -e "${RED}❌ No scan directories found in $SCANS_DIR${NC}"
    echo -e "${YELLOW}Run a scan first using: ./run-target-security-scan.sh <target> <mode>${NC}"
    exit 1
fi

DASHBOARD_PATH="$LATEST_SCAN/consolidated-reports/dashboards/security-dashboard.html"

if [[ ! -f "$DASHBOARD_PATH" ]]; then
    echo -e "${YELLOW}⚠️  Dashboard not found. Regenerating...${NC}"
    SCAN_DIR="$LATEST_SCAN" "$SCRIPT_DIR/generate-security-dashboard.sh"
    
    if [[ ! -f "$DASHBOARD_PATH" ]]; then
        echo -e "${RED}❌ Failed to generate dashboard${NC}"
        exit 1
    fi
fi

echo -e "${GREEN}✅ Opening latest scan dashboard${NC}"
echo -e "${CYAN}📊 Scan: $(basename "$LATEST_SCAN")${NC}"
echo -e "${CYAN}📁 Path: $DASHBOARD_PATH${NC}"
echo ""

# Open in default browser
open "$DASHBOARD_PATH"
