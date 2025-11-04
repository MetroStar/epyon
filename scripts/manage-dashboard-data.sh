#!/bin/bash

# Security Dashboard Data Management Script
# Shows what scans are in the dashboard, when they were run, and provides options to clear/re-run

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SECURITY_REPORTS_DIR="$SCRIPT_DIR/../reports/security-reports"
INDIVIDUAL_REPORTS_DIR="$SCRIPT_DIR/../reports"

echo -e "${WHITE}============================================${NC}"
echo -e "${WHITE}🛡️  Security Dashboard Data Management${NC}"
echo -e "${WHITE}============================================${NC}"
echo

# Function to show scan timestamps and status
show_scan_status() {
    echo -e "${BLUE}📊 Current Dashboard Data Status:${NC}"
    echo
    
    local tools=("SonarQube" "TruffleHog" "ClamAV" "Helm" "Checkov" "Trivy" "Grype" "Xeol")
    local report_dirs=("sonar-reports" "trufflehog-reports" "clamav-reports" "helm-reports" "checkov-reports" "trivy-reports" "grype-reports" "xeol-reports")
    
    for i in "${!tools[@]}"; do
        local tool="${tools[i]}"
        local report_dir="$INDIVIDUAL_REPORTS_DIR/${report_dirs[i]}"
        
        echo -e "${CYAN}${tool}:${NC}"
        
        if [ -d "$report_dir" ]; then
            # Find the most recent scan log or result file
            local latest_file=$(find "$report_dir" -type f \( -name "*.log" -o -name "*.json" -o -name "*.txt" \) -exec stat -f "%m %N" {} \; 2>/dev/null | sort -rn | head -1 | cut -d' ' -f2-)
            
            if [ -n "$latest_file" ]; then
                local timestamp=$(stat -f "%Sm" -t "%Y-%m-%d %H:%M:%S" "$latest_file" 2>/dev/null || echo "Unknown")
                local file_count=$(find "$report_dir" -type f | wc -l)
                echo -e "  ✅ Last scan: ${GREEN}$timestamp${NC}"
                echo -e "  📁 Files: $file_count"
            else
                echo -e "  ❌ ${YELLOW}No scan data found${NC}"
            fi
        else
            echo -e "  ❌ ${RED}No reports directory${NC}"
        fi
        echo
    done
}

# Function to show dashboard generation status
show_dashboard_status() {
    echo -e "${PURPLE}📊 Dashboard Status:${NC}"
    
    if [ -f "$SECURITY_REPORTS_DIR/dashboards/security-dashboard.html" ]; then
        local dashboard_timestamp=$(stat -f "%Sm" -t "%Y-%m-%d %H:%M:%S" "$SECURITY_REPORTS_DIR/dashboards/security-dashboard.html" 2>/dev/null || echo "Unknown")
        echo -e "  ✅ Dashboard exists: ${GREEN}$dashboard_timestamp${NC}"
        echo -e "  📍 Location: $SECURITY_REPORTS_DIR/dashboards/security-dashboard.html"
    else
        echo -e "  ❌ ${RED}Dashboard not found${NC}"
        echo -e "  💡 Run './consolidate-security-reports.sh' to generate"
    fi
    
    echo
}

# Function to explain how the dashboard works
explain_dashboard() {
    echo -e "${WHITE}🔍 How the Dashboard Works:${NC}"
    echo
    echo -e "${BLUE}Data Sources:${NC}"
    echo "• The dashboard reads from individual tool report directories"
    echo "• Each tool (SonarQube, TruffleHog, etc.) has its own reports folder"
    echo "• Results are NOT cumulative - each scan overwrites previous results"
    echo
    echo -e "${BLUE}Dashboard Generation:${NC}"
    echo "• Running 'consolidate-security-reports.sh' creates the unified dashboard"
    echo "• It processes the LATEST results from each tool's directory"
    echo "• Generates HTML, Markdown, and navigation files"
    echo
    echo -e "${BLUE}Data Freshness:${NC}"
    echo "• Dashboard shows data from the most recent scan of each tool"
    echo "• If a tool hasn't been run recently, old data may be displayed"
    echo "• Check scan timestamps to verify data currency"
    echo
}

# Function to clear all scan results
clear_all_results() {
    echo -e "${RED}⚠️  Clear All Security Scan Results${NC}"
    echo "This will delete ALL scan results and the dashboard."
    echo -e "${YELLOW}Are you sure? This cannot be undone! (y/N)${NC}"
    read -r confirm
    
    if [[ $confirm =~ ^[Yy]$ ]]; then
        echo -e "${BLUE}🧹 Clearing all scan results...${NC}"
        
        # Remove individual tool reports
        rm -rf "$INDIVIDUAL_REPORTS_DIR"/sonar-reports 2>/dev/null
        rm -rf "$INDIVIDUAL_REPORTS_DIR"/trufflehog-reports 2>/dev/null
        rm -rf "$INDIVIDUAL_REPORTS_DIR"/clamav-reports 2>/dev/null
        rm -rf "$INDIVIDUAL_REPORTS_DIR"/helm-reports 2>/dev/null
        rm -rf "$INDIVIDUAL_REPORTS_DIR"/checkov-reports 2>/dev/null
        rm -rf "$INDIVIDUAL_REPORTS_DIR"/trivy-reports 2>/dev/null
        rm -rf "$INDIVIDUAL_REPORTS_DIR"/grype-reports 2>/dev/null
        rm -rf "$INDIVIDUAL_REPORTS_DIR"/xeol-reports 2>/dev/null
        
        # Remove consolidated reports
        rm -rf "$SECURITY_REPORTS_DIR" 2>/dev/null
        
        echo -e "${GREEN}✅ All scan results cleared!${NC}"
        echo -e "${BLUE}💡 To generate fresh scans, run individual tool scripts${NC}"
    else
        echo -e "${BLUE}ℹ️  Operation cancelled${NC}"
    fi
}

# Function to clear specific tool results
clear_tool_results() {
    echo -e "${BLUE}🔧 Clear Specific Tool Results${NC}"
    echo
    echo "Available tools to clear:"
    echo "1) SonarQube"
    echo "2) TruffleHog" 
    echo "3) ClamAV"
    echo "4) Helm"
    echo "5) Checkov"
    echo "6) Trivy"
    echo "7) Grype"
    echo "8) Xeol"
    echo "9) Consolidated Dashboard Only"
    echo "0) Cancel"
    echo
    read -p "Select tool to clear (1-9): " choice
    
    case $choice in
        1) rm -rf "$INDIVIDUAL_REPORTS_DIR/sonar-reports" && echo "✅ SonarQube results cleared" ;;
        2) rm -rf "$INDIVIDUAL_REPORTS_DIR/trufflehog-reports" && echo "✅ TruffleHog results cleared" ;;
        3) rm -rf "$INDIVIDUAL_REPORTS_DIR/clamav-reports" && echo "✅ ClamAV results cleared" ;;
        4) rm -rf "$INDIVIDUAL_REPORTS_DIR/helm-reports" && echo "✅ Helm results cleared" ;;
        5) rm -rf "$INDIVIDUAL_REPORTS_DIR/checkov-reports" && echo "✅ Checkov results cleared" ;;
        6) rm -rf "$INDIVIDUAL_REPORTS_DIR/trivy-reports" && echo "✅ Trivy results cleared" ;;
        7) rm -rf "$INDIVIDUAL_REPORTS_DIR/grype-reports" && echo "✅ Grype results cleared" ;;
        8) rm -rf "$INDIVIDUAL_REPORTS_DIR/xeol-reports" && echo "✅ Xeol results cleared" ;;
        9) rm -rf "$SECURITY_REPORTS_DIR" && echo "✅ Consolidated dashboard cleared" ;;
        0) echo "ℹ️  Operation cancelled" ;;
        *) echo "❌ Invalid selection" ;;
    esac
}

# Function to run fresh scans
run_fresh_scans() {
    echo -e "${GREEN}🚀 Run Fresh Security Scans${NC}"
    echo
    echo "Select scanning option:"
    echo "1) Quick Scan (TruffleHog + ClamAV + Grype)"
    echo "2) Full Scan (All 8 security tools)"
    echo "3) Custom Tool Selection"
    echo "4) Individual Tool Menu"
    echo "0) Cancel"
    echo
    read -p "Select option (1-4): " choice
    
    case $choice in
        1)
            echo -e "${BLUE}🔄 Running quick scan...${NC}"
            cd "$SCRIPT_DIR"
            ./run-trufflehog-scan.sh
            ./run-clamav-scan.sh  
            ./run-grype-scan.sh
            ./consolidate-security-reports.sh
            echo -e "${GREEN}✅ Quick scan completed!${NC}"
            ;;
        2)
            echo -e "${BLUE}🔄 Running full scan...${NC}"
            cd "$SCRIPT_DIR"
            ./run-sonar-analysis.sh
            ./run-trufflehog-scan.sh
            ./run-clamav-scan.sh
            ./run-helm-build.sh
            ./run-checkov-scan.sh
            ./run-trivy-scan.sh
            ./run-grype-scan.sh
            ./run-xeol-scan.sh
            ./consolidate-security-reports.sh
            echo -e "${GREEN}✅ Full scan completed!${NC}"
            ;;
        3)
            echo -e "${BLUE}🔧 Custom tool selection...${NC}"
            echo "Available tools: sonar, trufflehog, clamav, helm, checkov, trivy, grype, xeol"
            echo "Enter tools to run (space-separated): "
            read -r tools_to_run
            
            cd "$SCRIPT_DIR"
            for tool in $tools_to_run; do
                case $tool in
                    sonar) ./run-sonar-analysis.sh ;;
                    trufflehog) ./run-trufflehog-scan.sh ;;
                    clamav) ./run-clamav-scan.sh ;;
                    helm) ./run-helm-build.sh ;;
                    checkov) ./run-checkov-scan.sh ;;
                    trivy) ./run-trivy-scan.sh ;;
                    grype) ./run-grype-scan.sh ;;
                    xeol) ./run-xeol-scan.sh ;;
                    *) echo "❌ Unknown tool: $tool" ;;
                esac
            done
            ./consolidate-security-reports.sh
            echo -e "${GREEN}✅ Custom scan completed!${NC}"
            ;;
        4)
            show_individual_tool_menu
            ;;
        0)
            echo "ℹ️  Operation cancelled"
            ;;
        *)
            echo "❌ Invalid selection"
            ;;
    esac
}

# Function to show individual tool menu
show_individual_tool_menu() {
    while true; do
        echo -e "${CYAN}🔧 Individual Tool Menu${NC}"
        echo
        echo "1) Run SonarQube Analysis"
        echo "2) Run TruffleHog Secret Scan"
        echo "3) Run ClamAV Malware Scan"
        echo "4) Run Helm Chart Build"
        echo "5) Run Checkov IaC Scan"
        echo "6) Run Trivy Vulnerability Scan"
        echo "7) Run Grype Vulnerability Scan"
        echo "8) Run Xeol EOL Detection"
        echo "9) Regenerate Dashboard"
        echo "0) Back to Main Menu"
        echo
        read -p "Select tool (1-9): " tool_choice
        
        cd "$SCRIPT_DIR"
        case $tool_choice in
            1) ./run-sonar-analysis.sh ;;
            2) ./run-trufflehog-scan.sh ;;
            3) ./run-clamav-scan.sh ;;
            4) ./run-helm-build.sh ;;
            5) ./run-checkov-scan.sh ;;
            6) ./run-trivy-scan.sh ;;
            7) ./run-grype-scan.sh ;;
            8) ./run-xeol-scan.sh ;;
            9) ./consolidate-security-reports.sh && echo "✅ Dashboard regenerated!" ;;
            0) break ;;
            *) echo "❌ Invalid selection" ;;
        esac
        echo
    done
}

# Main menu
show_main_menu() {
    while true; do
        echo -e "${WHITE}============================================${NC}"
        echo -e "${WHITE}📊 Security Dashboard Management Menu${NC}"
        echo -e "${WHITE}============================================${NC}"
        echo
        echo "1) Show Current Scan Status"
        echo "2) Show Dashboard Status"
        echo "3) Explain How Dashboard Works"
        echo "4) Clear All Results"
        echo "5) Clear Specific Tool Results"
        echo "6) Run Fresh Scans"
        echo "7) Open Security Dashboard"
        echo "8) View Dashboard Location"
        echo "0) Exit"
        echo
        read -p "Select option (0-8): " main_choice
        
        case $main_choice in
            1) show_scan_status ;;
            2) show_dashboard_status ;;
            3) explain_dashboard ;;
            4) clear_all_results ;;
            5) clear_tool_results ;;
            6) run_fresh_scans ;;
            7) 
                if [ -f "$SECURITY_REPORTS_DIR/dashboards/security-dashboard.html" ]; then
                    open "$SECURITY_REPORTS_DIR/dashboards/security-dashboard.html"
                    echo -e "${GREEN}✅ Dashboard opened in browser${NC}"
                else
                    echo -e "${RED}❌ Dashboard not found. Run option 6 to generate scans first.${NC}"
                fi
                ;;
            8)
                echo -e "${BLUE}📍 Dashboard Location:${NC}"
                echo "$SECURITY_REPORTS_DIR/dashboards/security-dashboard.html"
                ;;
            0) 
                echo -e "${GREEN}👋 Goodbye!${NC}"
                exit 0 
                ;;
            *) 
                echo -e "${RED}❌ Invalid selection${NC}" 
                ;;
        esac
        echo
        read -p "Press Enter to continue..."
        clear
    done
}

# Start the interactive menu
clear
show_main_menu