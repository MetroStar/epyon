#!/bin/bash

# Complete Security Scan Orchestration Script
# Runs all eight security layers with multi-target scanning capabilities
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
        print_section "Complete Eight-Layer Security Architecture Scan"
        
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

# Check for high-priority issues
echo -e "${CYAN}🚨 High-Priority Security Issues:${NC}"
has_critical_issues=false

# Check Grype results for high/critical vulnerabilities
if [[ -f "./grype-reports/grype-filesystem-results.json" ]]; then
    high_count=$(jq -r '[.matches[] | select(.vulnerability.severity == "High" or .vulnerability.severity == "Critical")] | length' "./grype-reports/grype-filesystem-results.json" 2>/dev/null || echo "0")
    if [[ "$high_count" -gt 0 ]]; then
        echo -e "  ${RED}🔴 Grype: $high_count high/critical vulnerabilities found${NC}"
        has_critical_issues=true
    fi
fi

# Check Trivy results for high/critical vulnerabilities
if [[ -f "./trivy-reports/trivy-filesystem-results.json" ]]; then
    trivy_critical=$(jq -r '[.Results[]?.Vulnerabilities[]? | select(.Severity == "HIGH" or .Severity == "CRITICAL")] | length' "./trivy-reports/trivy-filesystem-results.json" 2>/dev/null || echo "0")
    if [[ "$trivy_critical" -gt 0 ]]; then
        echo -e "  ${RED}🔴 Trivy: $trivy_critical high/critical vulnerabilities found${NC}"
        has_critical_issues=true
    fi
fi

# Check TruffleHog for secrets
if [[ -f "./trufflehog-reports/trufflehog-filesystem-results.json" ]]; then
    secrets_count=$(jq '. | length' "./trufflehog-reports/trufflehog-filesystem-results.json" 2>/dev/null || echo "0")
    if [[ "$secrets_count" -gt 0 ]]; then
        echo -e "  ${YELLOW}🟡 TruffleHog: $secrets_count potential secrets detected${NC}"
    fi
fi

# Check Xeol for EOL components
if [[ -f "./xeol-reports/xeol-results.json" ]]; then
    eol_count=$(jq '[.matches[] | select(.eol == true)] | length' "./xeol-reports/xeol-results.json" 2>/dev/null || echo "0")
    if [[ "$eol_count" -gt 0 ]]; then
        echo -e "  ${YELLOW}🟡 Xeol: $eol_count end-of-life components detected${NC}"
    fi
fi

if [[ "$has_critical_issues" == "false" ]]; then
    echo -e "  ${GREEN}✅ No high/critical security issues detected${NC}"
fi

echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}🎯 Complete Security Scan Finished Successfully!${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""