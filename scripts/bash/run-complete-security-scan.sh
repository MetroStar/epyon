#!/bin/bash

# Complete Security Scan Orchestration Script
# Runs all eight security layers plus report consolidation (9 steps total) with multi-target scanning capabilities
# Usage: ./run-complete-security-scan.sh [quick|full|images|analysis]

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
REPO_ROOT=$(pwd)
TIMESTAMP=$(date '+%Y-%m-%d_%H-%M-%S')
SCAN_TYPE=${1:-full}

echo "============================================"
echo "🛡️  Complete Security Scan Orchestrator"
echo "============================================"
echo "Repository: $REPO_ROOT"
echo "Scan Type: $SCAN_TYPE"
echo "Timestamp: $(date)"
echo ""

# Function to print section headers
print_section() {
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}🔹 $1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

# Function to run security tools
run_security_tool() {
    local tool_name="$1"
    local script_path="$2"
    local args="$3"
    
    echo -e "${YELLOW}🔍 Running $tool_name...${NC}"
    echo "Command: $script_path $args"
    echo "Started: $(date)"
    echo ""
    
    if [[ -x "$script_path" ]]; then
        if [[ -n "$args" ]]; then
            $script_path $args
        else
            $script_path
        fi
        echo -e "${GREEN}✅ $tool_name completed successfully${NC}"
    else
        echo -e "${RED}❌ $tool_name script not found or not executable: $script_path${NC}"
        return 1
    fi
    echo ""
}

# Function to run npm security commands
run_npm_command() {
    local command_name="$1"
    local npm_command="$2"
    
    echo -e "${YELLOW}🔍 Running $command_name...${NC}"
    echo "Command: npm run $npm_command"
    echo "Started: $(date)"
    echo ""
    
    if npm run "$npm_command" > /dev/null 2>&1; then
        npm run "$npm_command"
        echo -e "${GREEN}✅ $command_name completed successfully${NC}"
    else
        echo -e "${RED}❌ $command_name failed or not available${NC}"
        return 1
    fi
    echo ""
}

# Main security scan execution
case "$SCAN_TYPE" in
    "quick")
        print_section "Quick Security Scan (Core Tools Only)"
        
        # Core security tools - filesystem only
        run_security_tool "SonarQube Code Quality" "./run-sonar-analysis.sh"
        run_security_tool "TruffleHog Secret Detection" "./run-trufflehog-scan.sh" "filesystem"
        run_security_tool "Grype Vulnerability Scanning" "./run-grype-scan.sh" "filesystem"
        run_security_tool "Trivy Security Analysis" "./run-trivy-scan.sh" "filesystem"
        run_security_tool "Report Consolidation" "./consolidate-security-reports.sh"
        ;;
        
    "images")
        print_section "Container Image Security Scan (All Image Types)"
        
        # Multi-target container image scanning
        run_security_tool "TruffleHog Container Images" "./run-trufflehog-scan.sh" "images"
        run_security_tool "Grype Container Images" "./run-grype-scan.sh" "images"
        run_security_tool "Grype Base Images" "./run-grype-scan.sh" "base"
        run_security_tool "Trivy Container Images" "./run-trivy-scan.sh" "images"
        run_security_tool "Trivy Base Images" "./run-trivy-scan.sh" "base"
        run_security_tool "Xeol End-of-Life Detection" "./run-xeol-scan.sh"
        run_security_tool "Report Consolidation" "./consolidate-security-reports.sh"
        ;;
        
    "analysis")
        print_section "Security Analysis & Reporting"
        
        # Analysis tools
        run_npm_command "Grype Analysis" "grype:analyze"
        run_npm_command "Trivy Analysis" "trivy:analyze"
        run_npm_command "TruffleHog Analysis" "trufflehog:analyze"
        run_npm_command "Xeol Analysis" "xeol:analyze"
        ;;
        
    "full")
        print_section "Complete Nine-Step Security Architecture Scan"
        
        echo -e "${PURPLE}🏗️  Layer 1: Code Quality & Test Coverage${NC}"
        run_security_tool "SonarQube Analysis" "./run-sonar-analysis.sh"
        
        echo -e "${PURPLE}🔐 Layer 2: Secret Detection (Multi-Target)${NC}"
        run_security_tool "TruffleHog Filesystem" "./run-trufflehog-scan.sh" "filesystem"
        run_security_tool "TruffleHog Container Images" "./run-trufflehog-scan.sh" "images"
        
        echo -e "${PURPLE}🦠 Layer 3: Malware Detection${NC}"
        run_security_tool "ClamAV Antivirus Scan" "./run-clamav-scan.sh"
        
        echo -e "${PURPLE}🏗️  Layer 4: Helm Chart Building${NC}"
        run_security_tool "Helm Chart Build" "./run-helm-build.sh"
        
        echo -e "${PURPLE}☸️  Layer 5: Infrastructure Security${NC}"
        run_security_tool "Checkov IaC Security" "./run-checkov-scan.sh"
        
        echo -e "${PURPLE}🔍 Layer 6: Vulnerability Detection (Multi-Target)${NC}"
        run_security_tool "Grype Filesystem" "./run-grype-scan.sh" "filesystem"
        run_security_tool "Grype Container Images" "./run-grype-scan.sh" "images"
        run_security_tool "Grype Base Images" "./run-grype-scan.sh" "base"
        
        echo -e "${PURPLE}🛡️  Layer 7: Container Security (Multi-Target)${NC}"
        run_security_tool "Trivy Filesystem" "./run-trivy-scan.sh" "filesystem"
        run_security_tool "Trivy Container Images" "./run-trivy-scan.sh" "images"
        run_security_tool "Trivy Base Images" "./run-trivy-scan.sh" "base"
        run_security_tool "Trivy Kubernetes" "./run-trivy-scan.sh" "kubernetes"
        
        echo -e "${PURPLE}⚰️  Layer 8: End-of-Life Detection${NC}"
        run_security_tool "Xeol EOL Detection" "./run-xeol-scan.sh"
        
        echo -e "${PURPLE}📊 Step 9: Security Report Consolidation${NC}"
        run_security_tool "Report Consolidation" "./consolidate-security-reports.sh"
        ;;
        
    *)
        echo -e "${RED}❌ Invalid scan type: $SCAN_TYPE${NC}"
        echo "Available options:"
        echo "  quick    - Core security tools (filesystem only)"
        echo "  images   - Container image security (all image types)"
        echo "  analysis - Security analysis and reporting"
        echo "  full     - Complete eight-layer security scan (default)"
        exit 1
        ;;
esac

# Generate summary report
print_section "Security Scan Summary Report"

echo -e "${CYAN}📊 Scan Completion Summary${NC}"
echo "Scan Type: $SCAN_TYPE"
echo "Timestamp: $(date)"
echo "Repository: $REPO_ROOT"
echo ""

echo -e "${CYAN}📁 Generated Reports:${NC}"
find . -name "*-reports" -type d 2>/dev/null | sort | while read -r dir; do
    if [[ -d "$dir" ]]; then
        report_count=$(find "$dir" -name "*.json" -o -name "*.html" -o -name "*.xml" | wc -l)
        echo "  📂 $dir ($report_count files)"
    fi
done
echo ""

echo -e "${CYAN}🔧 Available Analysis Commands:${NC}"
echo "  📊 npm run security:analyze    - Analyze all security results"
echo "  🔍 npm run grype:analyze       - Grype vulnerability analysis"
echo "  🛡️  npm run trivy:analyze       - Trivy security analysis"
echo "  🔐 npm run trufflehog:analyze  - TruffleHog secret analysis"
echo "  ⚰️  npm run xeol:analyze        - Xeol EOL analysis"
echo ""

echo -e "${CYAN}🚀 Quick Re-run Commands:${NC}"
echo "  🏃 ./run-complete-security-scan.sh quick    - Quick scan"
echo "  📦 ./run-complete-security-scan.sh images   - Image security"
echo "  📊 ./run-complete-security-scan.sh analysis - Analysis only"
echo "  🛡️  ./run-complete-security-scan.sh full     - Complete scan"
echo ""

# Enhanced Critical/High Security Alert System
echo -e "${CYAN}🚨 SECURITY ALERT SUMMARY${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
has_critical_issues=false
has_high_issues=false
total_critical=0
total_high=0
critical_details=()
high_details=()

# Function to add alert detail
add_alert() {
    local severity=$1
    local tool=$2
    local count=$3
    local message=$4
    
    if [[ "$severity" == "CRITICAL" ]]; then
        total_critical=$((total_critical + count))
        critical_details+=("${RED}🔴 $tool: $count $message${NC}")
        has_critical_issues=true
    elif [[ "$severity" == "HIGH" ]]; then
        total_high=$((total_high + count))
        high_details+=("${YELLOW}🟠 $tool: $count $message${NC}")
        has_high_issues=true
    fi
}

# Check ALL Grype results for high/critical vulnerabilities
echo -e "${CYAN}🔍 Analyzing Grype vulnerability reports...${NC}"
for grype_file in ./grype-reports/grype-*-results.json; do
    if [[ -f "$grype_file" ]]; then
        filename=$(basename "$grype_file")
        critical_count=$(jq -r '[.matches[] | select(.vulnerability.severity == "Critical")] | length' "$grype_file" 2>/dev/null || echo "0")
        high_count=$(jq -r '[.matches[] | select(.vulnerability.severity == "High")] | length' "$grype_file" 2>/dev/null || echo "0")
        
        if [[ "$critical_count" -gt 0 ]]; then
            add_alert "CRITICAL" "Grype ($filename)" "$critical_count" "CRITICAL vulnerabilities"
        fi
        if [[ "$high_count" -gt 0 ]]; then
            add_alert "HIGH" "Grype ($filename)" "$high_count" "HIGH vulnerabilities"
        fi
    fi
done

# Check ALL Trivy results for high/critical vulnerabilities
echo -e "${CYAN}🔍 Analyzing Trivy vulnerability reports...${NC}"
for trivy_file in ./trivy-reports/trivy-*-results.json; do
    if [[ -f "$trivy_file" ]]; then
        filename=$(basename "$trivy_file")
        critical_count=$(jq -r '[.Results[]?.Vulnerabilities[]? | select(.Severity == "CRITICAL")] | length' "$trivy_file" 2>/dev/null || echo "0")
        high_count=$(jq -r '[.Results[]?.Vulnerabilities[]? | select(.Severity == "HIGH")] | length' "$trivy_file" 2>/dev/null || echo "0")
        
        if [[ "$critical_count" -gt 0 ]]; then
            add_alert "CRITICAL" "Trivy ($filename)" "$critical_count" "CRITICAL vulnerabilities"
        fi
        if [[ "$high_count" -gt 0 ]]; then
            add_alert "HIGH" "Trivy ($filename)" "$high_count" "HIGH vulnerabilities"
        fi
    fi
done

# Check Checkov for high-severity configuration issues
echo -e "${CYAN}🔍 Analyzing Checkov configuration reports...${NC}"
if [[ -f "./checkov-reports/results_json.json" ]]; then
    checkov_critical=$(jq -r '[.results.failed_checks[] | select(.severity == "CRITICAL" or .severity == "HIGH")] | length' "./checkov-reports/results_json.json" 2>/dev/null || echo "0")
    if [[ "$checkov_critical" -gt 0 ]]; then
        add_alert "HIGH" "Checkov" "$checkov_critical" "HIGH/CRITICAL configuration issues"
    fi
fi

# Check TruffleHog for secrets (always high priority)
echo -e "${CYAN}🔍 Analyzing TruffleHog secret detection reports...${NC}"
for truffles_file in ./trufflehog-reports/trufflehog-*-results.json; do
    if [[ -f "$truffles_file" ]]; then
        filename=$(basename "$truffles_file")
        secrets_count=$(jq '. | length' "$truffles_file" 2>/dev/null || echo "0")
        if [[ "$secrets_count" -gt 0 ]]; then
            add_alert "HIGH" "TruffleHog ($filename)" "$secrets_count" "potential secrets detected"
        fi
    fi
done

# Display Critical Issues (Immediate Action Required)
if [[ "$has_critical_issues" == "true" ]]; then
    echo ""
    echo -e "${RED}🚨 CRITICAL SEVERITY ISSUES - IMMEDIATE ACTION REQUIRED! 🚨${NC}"
    echo -e "${RED}═══════════════════════════════════════════════════════════${NC}"
    for detail in "${critical_details[@]}"; do
        echo -e "  $detail"
    done
    echo -e "${RED}Total Critical Issues: $total_critical${NC}"
    echo ""
fi

# Display High Issues (Urgent Action Recommended)
if [[ "$has_high_issues" == "true" ]]; then
    echo -e "${YELLOW}⚠️  HIGH SEVERITY ISSUES - URGENT ACTION RECOMMENDED ⚠️${NC}"
    echo -e "${YELLOW}══════════════════════════════════════════════════════════${NC}"
    for detail in "${high_details[@]}"; do
        echo -e "  $detail"
    done
    echo -e "${YELLOW}Total High Issues: $total_high${NC}"
    echo ""
fi

# Check Xeol for EOL components (Medium priority)
eol_total=0
for xeol_file in ./xeol-reports/xeol-*-results.json; do
    if [[ -f "$xeol_file" ]]; then
        filename=$(basename "$xeol_file")
        eol_count=$(jq '[.matches[] | select(.eol == true)] | length' "$xeol_file" 2>/dev/null || echo "0")
        if [[ "$eol_count" -gt 0 ]]; then
            echo -e "  ${PURPLE}🟣 Xeol ($filename): $eol_count end-of-life components detected${NC}"
            eol_total=$((eol_total + eol_count))
        fi
    fi
done

if [[ "$eol_total" -gt 0 ]]; then
    echo -e "${PURPLE}Total EOL Components: $eol_total${NC}"
    echo ""
fi

# Overall Security Status
if [[ "$has_critical_issues" == "false" && "$has_high_issues" == "false" ]]; then
    echo -e "${GREEN}✅ SECURITY STATUS: GOOD - No critical or high severity issues detected${NC}"
else
    echo -e "${RED}❌ SECURITY STATUS: ATTENTION REQUIRED${NC}"
    if [[ "$SCAN_TYPE" == "full" ]]; then
        echo -e "${CYAN}📋 Next Steps for Full Target Scan:${NC}"
        echo -e "  1. Review detailed reports in each *-reports/ directory"
        echo -e "  2. Prioritize CRITICAL issues first, then HIGH severity"
        echo -e "  3. Update vulnerable components and fix configuration issues"
        echo -e "  4. Re-run scan to verify fixes: ./run-complete-security-scan.sh full"
        echo ""
        
        # Generate summary report for critical/high issues
        if [[ "$total_critical" -gt 0 || "$total_high" -gt 0 ]]; then
            echo -e "${CYAN}📄 Generating priority issues summary...${NC}"
            {
                echo "SECURITY SCAN PRIORITY ISSUES SUMMARY"
                echo "Generated: $(date)"
                echo "Scan Type: $SCAN_TYPE"
                echo "======================================"
                echo ""
                echo "CRITICAL ISSUES: $total_critical"
                for detail in "${critical_details[@]}"; do
                    echo "$detail" | sed 's/\x1b\[[0-9;]*m//g'  # Remove color codes
                done
                echo ""
                echo "HIGH ISSUES: $total_high"  
                for detail in "${high_details[@]}"; do
                    echo "$detail" | sed 's/\x1b\[[0-9;]*m//g'  # Remove color codes
                done
                echo ""
                echo "TOTAL PRIORITY ISSUES: $((total_critical + total_high))"
            } > "./priority-issues-summary.txt"
            echo -e "${GREEN}📄 Priority issues summary saved to: ./priority-issues-summary.txt${NC}"
        fi
    fi
fi

echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}🎯 Complete Security Scan Finished Successfully!${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""