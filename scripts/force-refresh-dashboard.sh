#!/bin/bash

# Force Refresh Dashboard - Clears cache and opens updated dashboard
# This script forces the browser to reload the dashboard with fresh data

# Color definitions
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
WHITE='\033[1;37m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DASHBOARD_PATH="$SCRIPT_DIR/../reports/security-reports/dashboards/security-dashboard.html"

echo -e "${WHITE}============================================${NC}"
echo -e "${WHITE}🔄 Force Dashboard Refresh${NC}"
echo -e "${WHITE}============================================${NC}"
echo

if [ -f "$DASHBOARD_PATH" ]; then
    # Show current file timestamp
    echo -e "${BLUE}📄 Dashboard file: $(basename "$DASHBOARD_PATH")${NC}"
    echo -e "${BLUE}🕒 Last modified: $(stat -f "%Sm" "$DASHBOARD_PATH")${NC}"
    echo
    
    # Create a unique timestamp for cache busting
    TIMESTAMP=$(date +%s)
    
    # Create file URL with cache busting parameters
    DASHBOARD_URL="file://$DASHBOARD_PATH?nocache=$TIMESTAMP&refresh=true"
    
    echo -e "${YELLOW}🧹 Using cache-busting parameters...${NC}"
    echo -e "${BLUE}🚀 Opening fresh dashboard...${NC}"
    
    # Open with cache busting
    if command -v open >/dev/null 2>&1; then
        # macOS - open in default browser
        open "$DASHBOARD_URL"
    elif command -v xdg-open >/dev/null 2>&1; then
        # Linux
        xdg-open "$DASHBOARD_URL"
    else
        echo -e "${YELLOW}⚠️  Could not detect browser opener${NC}"
        echo "Manual URL: $DASHBOARD_URL"
    fi
    
    echo
    echo -e "${GREEN}✅ Dashboard opened with fresh cache!${NC}"
    echo
    echo -e "${YELLOW}💡 If you still see old data:${NC}"
    echo "   1. Press Cmd+Shift+R (macOS) or Ctrl+Shift+R (Windows/Linux) to force refresh"
    echo "   2. Or close browser completely and reopen"
    echo "   3. Or use browser's Developer Tools > Network > Disable cache"
    
else
    echo -e "${YELLOW}❌ Dashboard file not found: $DASHBOARD_PATH${NC}"
    echo -e "${BLUE}💡 Try running: ./consolidate-security-reports.sh${NC}"
fi

echo
echo -e "${WHITE}============================================${NC}"