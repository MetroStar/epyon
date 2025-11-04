#!/bin/bash

# Security Dashboard Launcher
# Opens the comprehensive security dashboard from the new location

# Color definitions
GREEN='\033[0;32m'
BLUE='\033[0;34m'
WHITE='\033[1;37m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DASHBOARD_PATH="$SCRIPT_DIR/../reports/security-reports/dashboards/security-dashboard.html"

echo -e "${WHITE}============================================${NC}"
echo -e "${WHITE}🛡️  Security Dashboard Launcher${NC}"
echo -e "${WHITE}============================================${NC}"
echo

if [ -f "$DASHBOARD_PATH" ]; then
    echo -e "${GREEN}✅ Dashboard found: $DASHBOARD_PATH${NC}"
    echo -e "${BLUE}🚀 Opening security dashboard...${NC}"
    
    # Try different methods to open the dashboard
    # Add cache-busting parameter to force browser refresh
    TIMESTAMP=$(date +%s)
    DASHBOARD_URL="file://$DASHBOARD_PATH?v=$TIMESTAMP"
    
    if command -v open >/dev/null 2>&1; then
        # macOS
        open "$DASHBOARD_URL"
    elif command -v xdg-open >/dev/null 2>&1; then
        # Linux
        xdg-open "$DASHBOARD_URL"
    elif command -v start >/dev/null 2>&1; then
        # Windows
        start "$DASHBOARD_PATH"
    else
        echo -e "${BLUE}💡 Please open the following file in your browser:${NC}"
        echo "   file://$DASHBOARD_PATH"
    fi
    
    echo
    echo -e "${GREEN}✅ Security dashboard launched!${NC}"
    echo
    echo -e "${BLUE}📊 Dashboard Features:${NC}"
    echo "• Overview of all 8 security tools"
    echo "• Interactive status indicators"
    echo "• Direct links to detailed reports"
    echo "• Professional security summaries"
    
else
    echo -e "${RED}❌ Dashboard not found at: $DASHBOARD_PATH${NC}"
    echo -e "${BLUE}💡 To regenerate the dashboard, run:${NC}"
    echo "   ./consolidate-security-reports.sh"
fi

echo
echo -e "${WHITE}============================================${NC}"