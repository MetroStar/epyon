#!/bin/bash

# Target-Aware Complete Security Scan Orchestration Script
# Runs all eight security layers with multi-target scanning capabilities on external directories
# Usage: ./run-target-security-scan.sh <target_directory> [quick|full|images|analysis]

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
TARGET_DIR="$1"
SCAN_TYPE="${2:-full}"
# Get the script's directory to locate security tools
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
TIMESTAMP=$(date '+%Y-%m-%d_%H-%M-%S')

# Validate inputs
if [[ -z "$TARGET_DIR" ]]; then
    echo -e "${RED}❌ Error: Target directory is required${NC}"
    echo "Usage: $0 <target_directory> [quick|full|images|analysis]"
    echo ""
    echo "Examples:"
    echo "  $0 '/Users/rnelson/Desktop/CDAO Marketplace/advana-marketplace-monolith-node' full"
    echo "  $0 './my-project' quick"
    echo "  $0 '/path/to/project' images"
    exit 1
fi

# Resolve absolute path
if [[ ! -d "$TARGET_DIR" ]]; then
    echo -e "${RED}❌ Error: Target directory does not exist: $TARGET_DIR${NC}"
    exit 1
fi
TARGET_DIR=$(realpath "$TARGET_DIR" 2>/dev/null || (cd "$TARGET_DIR" && pwd))

echo "============================================"
echo "🛡️  Target-Aware Security Scan Orchestrator"
echo "============================================"
echo "Security Tools Dir: $REPO_ROOT"
echo "Target Directory: $TARGET_DIR"
echo "Scan Type: $SCAN_TYPE"
echo "Timestamp: $(date)"
echo ""

# Export TARGET_DIR for all child scripts
export TARGET_DIR

# Function to print section headers
print_section() {
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}🔹 $1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

# Function to run security tools with target directory
run_security_tool() {
    local tool_name="$1"
    local script_path="$2"
    local args="$3"
    
    echo -e "${YELLOW}🔍 Running $tool_name...${NC}"
    echo "Command: $script_path $args"
    echo "Target: $TARGET_DIR"
    echo "Started: $(date)"
    echo ""
    
    if [[ -x "$script_path" ]]; then
        # Change to security tools directory to run scripts
        cd "$REPO_ROOT"
        
        if [[ -n "$args" ]]; then
            env TARGET_DIR="$TARGET_DIR" "$script_path" $args
        else
            env TARGET_DIR="$TARGET_DIR" "$script_path"
        fi
        
        if [[ $? -eq 0 ]]; then
            echo -e "${GREEN}✅ $tool_name completed successfully${NC}"
        else
            echo -e "${YELLOW}⚠️  $tool_name completed with warnings${NC}"
        fi
    else
        echo -e "${RED}❌ $tool_name script not found or not executable: $script_path${NC}"
        return 1
    fi
    echo ""
}

# Function to run npm security commands with target
run_npm_command() {
    local command_name="$1"
    local npm_command="$2"
    
    echo -e "${YELLOW}🔍 Running $command_name...${NC}"
    echo "Command: npm run $npm_command"
    echo "Target: $TARGET_DIR"
    echo "Started: $(date)"
    echo ""
    
    cd "$REPO_ROOT"
    
    if TARGET_DIR="$TARGET_DIR" npm run "$npm_command"; then
        echo -e "${GREEN}✅ $command_name completed successfully${NC}"
    else
        echo -e "${RED}❌ $command_name failed or not available${NC}"
        return 1
    fi
    echo ""
}

# Validate target directory content
print_section "Target Directory Analysis"
echo -e "${CYAN}📂 Analyzing target directory...${NC}"
echo "Directory: $TARGET_DIR"
echo "Size: $(du -sh "$TARGET_DIR" | cut -f1)"
echo "Files: $(find "$TARGET_DIR" -type f | wc -l | xargs)"

if [[ -f "$TARGET_DIR/package.json" ]]; then
    echo -e "${GREEN}✅ Node.js project detected${NC}"
    echo "Package: $(cat "$TARGET_DIR/package.json" | jq -r '.name // "Unknown"' 2>/dev/null || echo "Unknown")"
    echo "Version: $(cat "$TARGET_DIR/package.json" | jq -r '.version // "Unknown"' 2>/dev/null || echo "Unknown")"
fi

if [[ -f "$TARGET_DIR/Dockerfile" ]]; then
    echo -e "${GREEN}✅ Docker project detected${NC}"
fi

if [[ -d "$TARGET_DIR/.git" ]]; then
    echo -e "${GREEN}✅ Git repository detected${NC}"
fi

echo ""

# Main security scan execution
case "$SCAN_TYPE" in
    "quick")
        print_section "Quick Security Scan (Core Tools Only) - Target: $(basename "$TARGET_DIR")"
        
        # Core security tools - filesystem only
        run_security_tool "TruffleHog Secret Detection" "$SCRIPT_DIR/run-trufflehog-scan.sh" "filesystem"
        run_security_tool "Grype Vulnerability Scanning" "$SCRIPT_DIR/run-grype-scan.sh" "filesystem"
        run_security_tool "Trivy Security Analysis" "$SCRIPT_DIR/run-trivy-scan.sh" "filesystem"
        run_security_tool "ClamAV Antivirus Scan" "$SCRIPT_DIR/run-clamav-scan.sh"
        ;;
        
    "images")
        print_section "Container Image Security Scan (All Image Types) - Target: $(basename "$TARGET_DIR")"
        
        # Multi-target container image scanning
        run_security_tool "TruffleHog Container Images" "$SCRIPT_DIR/run-trufflehog-scan.sh" "images"
        run_security_tool "Grype Container Images" "$SCRIPT_DIR/run-grype-scan.sh" "images"
        run_security_tool "Grype Base Images" "$SCRIPT_DIR/run-grype-scan.sh" "base"
        run_security_tool "Trivy Container Images" "$SCRIPT_DIR/run-trivy-scan.sh" "images"
        run_security_tool "Trivy Base Images" "$SCRIPT_DIR/run-trivy-scan.sh" "base"
        run_security_tool "Xeol End-of-Life Detection" "$SCRIPT_DIR/run-xeol-scan.sh"
        ;;
        
    "analysis")
        print_section "Security Analysis & Reporting - Target: $(basename "$TARGET_DIR")"
        
        # Analysis mode - process existing reports without running new scans
        echo -e "${BLUE}📊 Processing existing security reports for analysis...${NC}"
        echo -e "${YELLOW}ℹ️  Analysis mode processes existing scan results without running new scans${NC}"
        echo ""
        
        # Skip to analysis and consolidation section
        # The actual analysis will be done in the consolidation section at the end
        ;;
        
    "full")
        print_section "Complete Eight-Layer Security Architecture Scan - Target: $(basename "$TARGET_DIR")"
        
        echo -e "${PURPLE}🔐 Layer 1: Secret Detection (Multi-Target)${NC}"
        run_security_tool "TruffleHog Filesystem" "$SCRIPT_DIR/run-trufflehog-scan.sh" "filesystem"
        run_security_tool "TruffleHog Container Images" "$SCRIPT_DIR/run-trufflehog-scan.sh" "images"
        
        echo -e "${PURPLE}🦠 Layer 2: Malware Detection${NC}"
        run_security_tool "ClamAV Antivirus Scan" "$SCRIPT_DIR/run-clamav-scan.sh"
        
        echo -e "${PURPLE}☸️  Layer 3: Infrastructure Security${NC}"
        run_security_tool "Checkov IaC Security" "$SCRIPT_DIR/run-checkov-scan.sh"
        
        echo -e "${PURPLE}🔍 Layer 4: Vulnerability Detection (Multi-Target)${NC}"
        run_security_tool "Grype Filesystem" "$SCRIPT_DIR/run-grype-scan.sh" "filesystem"
        run_security_tool "Grype Container Images" "$SCRIPT_DIR/run-grype-scan.sh" "images"
        run_security_tool "Grype Base Images" "$SCRIPT_DIR/run-grype-scan.sh" "base"
        
        echo -e "${PURPLE}🛡️  Layer 5: Container Security (Multi-Target)${NC}"
        run_security_tool "Trivy Filesystem" "$SCRIPT_DIR/run-trivy-scan.sh" "filesystem"
        run_security_tool "Trivy Container Images" "$SCRIPT_DIR/run-trivy-scan.sh" "images"
        run_security_tool "Trivy Base Images" "$SCRIPT_DIR/run-trivy-scan.sh" "base"
        run_security_tool "Trivy Kubernetes" "$SCRIPT_DIR/run-trivy-scan.sh" "kubernetes"
        
        echo -e "${PURPLE}⚰️  Layer 6: End-of-Life Detection${NC}"
        run_security_tool "Xeol EOL Detection" "$SCRIPT_DIR/run-xeol-scan.sh"
        
        # Optional layers if specific files/configs exist
        if [[ -f "$TARGET_DIR/package.json" ]]; then
            echo -e "${PURPLE}📊 Layer 7: Code Quality Analysis (Node.js)${NC}"
            run_security_tool "SonarQube Analysis" "$SCRIPT_DIR/run-sonar-analysis.sh"
        fi
        
        if [[ -f "$TARGET_DIR/Chart.yaml" ]] || [[ -d "$TARGET_DIR/chart" ]] || [[ -d "$TARGET_DIR/charts" ]]; then
            echo -e "${PURPLE}🏗️  Layer 8: Helm Chart Building${NC}"
            run_security_tool "Helm Chart Build" "$SCRIPT_DIR/run-helm-build.sh"
        fi
        ;;
        
    *)
        echo -e "${RED}❌ Invalid scan type: $SCAN_TYPE${NC}"
        echo "Available options:"
        echo "  quick    - Core security tools (filesystem only)"
        echo "  images   - Container image security (all image types)"
        echo "  analysis - Security analysis and reporting"
        echo "  full     - Complete security scan (default)"
        exit 1
        ;;
esac

# Change back to security tools directory for report generation
cd "$REPO_ROOT"

# Generate summary report
print_section "Security Scan Summary Report"

echo -e "${CYAN}📊 Scan Completion Summary${NC}"
echo "Scan Type: $SCAN_TYPE"
echo "Target Directory: $TARGET_DIR"
echo "Security Tools Directory: $REPO_ROOT"
echo "Timestamp: $(date)"
echo ""

echo -e "${CYAN}📁 Generated Reports:${NC}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPORTS_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
find "$REPORTS_ROOT/reports" -name "*-reports" -type d 2>/dev/null | sort | while read -r dir; do
    if [[ -d "$dir" ]]; then
        report_count=$(find "$dir" -name "*.json" -o -name "*.html" -o -name "*.xml" | wc -l)
        echo "  📂 $dir ($report_count files)"
    fi
done
echo ""

echo -e "${CYAN}🔧 Available Analysis Commands:${NC}"
echo "  📊 TARGET_DIR=\"$TARGET_DIR\" npm run security:analyze    - Analyze all security results"
echo "  🔍 TARGET_DIR=\"$TARGET_DIR\" npm run grype:analyze       - Grype vulnerability analysis"
echo "  🛡️  TARGET_DIR=\"$TARGET_DIR\" npm run trivy:analyze       - Trivy security analysis"
echo "  🔐 TARGET_DIR=\"$TARGET_DIR\" npm run trufflehog:analyze  - TruffleHog secret analysis"
echo "  ⚰️  TARGET_DIR=\"$TARGET_DIR\" npm run xeol:analyze        - Xeol EOL analysis"
echo ""

echo -e "${CYAN}🚀 Quick Re-run Commands:${NC}"
echo "  🏃 ./run-target-security-scan.sh \"$TARGET_DIR\" quick    - Quick scan"
echo "  📦 ./run-target-security-scan.sh \"$TARGET_DIR\" images   - Image security"
echo "  📊 ./run-target-security-scan.sh \"$TARGET_DIR\" analysis - Analysis only"
echo "  🛡️  ./run-target-security-scan.sh \"$TARGET_DIR\" full     - Complete scan"
echo ""

# Check for high-priority issues
echo -e "${CYAN}🚨 High-Priority Security Issues:${NC}"
has_critical_issues=false

# Check Grype results for high/critical vulnerabilities
if [[ -f "$REPORTS_ROOT/reports/grype-reports/grype-filesystem-results.json" ]]; then
    high_count=$(jq -r '[.matches[] | select(.vulnerability.severity == "High" or .vulnerability.severity == "Critical")] | length' "$REPORTS_ROOT/reports/grype-reports/grype-filesystem-results.json" 2>/dev/null || echo "0")
    if [[ "$high_count" -gt 0 ]]; then
        echo -e "  ${RED}🔴 Grype: $high_count high/critical vulnerabilities found${NC}"
        has_critical_issues=true
    fi
fi

# Check Trivy results for high/critical vulnerabilities
if [[ -f "$REPORTS_ROOT/reports/trivy-reports/trivy-filesystem-results.json" ]]; then
    trivy_critical=$(jq -r '[.Results[]?.Vulnerabilities[]? | select(.Severity == "HIGH" or .Severity == "CRITICAL")] | length' "$REPORTS_ROOT/reports/trivy-reports/trivy-filesystem-results.json" 2>/dev/null || echo "0")
    if [[ "$trivy_critical" -gt 0 ]]; then
        echo -e "  ${RED}🔴 Trivy: $trivy_critical high/critical vulnerabilities found${NC}"
        has_critical_issues=true
    fi
fi

# Check TruffleHog for secrets
if [[ -f "$REPORTS_ROOT/reports/trufflehog-reports/trufflehog-filesystem-results.json" ]]; then
    secrets_count=$(jq '. | length' "$REPORTS_ROOT/reports/trufflehog-reports/trufflehog-filesystem-results.json" 2>/dev/null || echo "0")
    if [[ "$secrets_count" -gt 0 ]]; then
        echo -e "  ${YELLOW}🟡 TruffleHog: $secrets_count potential secrets detected${NC}"
    fi
fi

# Check Xeol for EOL components
if [[ -f "$REPORTS_ROOT/reports/xeol-reports/xeol-results.json" ]]; then
    eol_count=$(jq '[.matches[] | select(.eol == true)] | length' "$REPORTS_ROOT/reports/xeol-reports/xeol-results.json" 2>/dev/null || echo "0")
    if [[ "$eol_count" -gt 0 ]]; then
        echo -e "  ${YELLOW}🟡 Xeol: $eol_count end-of-life components detected${NC}"
    fi
fi

if [[ "$has_critical_issues" == "false" ]]; then
    echo -e "  ${GREEN}✅ No high/critical security issues detected${NC}"
fi

echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}🔹 Report Analysis & Consolidation${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

echo -e "${BLUE}📊 Analyzing security scan results...${NC}"

# Run individual analysis scripts for generated reports
analysis_success=true

# TruffleHog Analysis
if [[ -f "$REPO_ROOT/reports/trufflehog-reports/trufflehog-filesystem-results.json" ]]; then
    echo -e "${CYAN}🔍 Analyzing TruffleHog secret detection results...${NC}"
    if [[ -f "$SCRIPT_DIR/analyze-trufflehog-results.sh" ]]; then
        cd "$REPO_ROOT" && "$SCRIPT_DIR/analyze-trufflehog-results.sh" || analysis_success=false
    fi
fi

# ClamAV Analysis  
if [[ -f "$REPO_ROOT/reports/clamav-reports/clamav-scan.log" ]]; then
    echo -e "${CYAN}🦠 Analyzing ClamAV antivirus results...${NC}"
    if [[ -f "$SCRIPT_DIR/analyze-clamav-results.sh" ]]; then
        cd "$REPO_ROOT" && "$SCRIPT_DIR/analyze-clamav-results.sh" || analysis_success=false
    fi
fi

# Checkov Analysis
if [[ -f "$REPO_ROOT/reports/checkov-reports/checkov-results.json" ]]; then
    echo -e "${CYAN}🔒 Analyzing Checkov infrastructure security results...${NC}"
    if [[ -f "$SCRIPT_DIR/analyze-checkov-results.sh" ]]; then
        cd "$REPO_ROOT" && "$SCRIPT_DIR/analyze-checkov-results.sh" || analysis_success=false
    fi
fi

# Grype Analysis
if [[ -f "$REPO_ROOT/reports/grype-reports/grype-filesystem-results.json" ]]; then
    echo -e "${CYAN}🎯 Analyzing Grype vulnerability results...${NC}"
    if [[ -f "$SCRIPT_DIR/analyze-grype-results.sh" ]]; then
        cd "$REPO_ROOT" && "$SCRIPT_DIR/analyze-grype-results.sh" || analysis_success=false
    fi
fi

# Trivy Analysis
if [[ -f "$REPO_ROOT/reports/trivy-reports/trivy-filesystem-results.json" ]]; then
    echo -e "${CYAN}🐳 Analyzing Trivy security results...${NC}"
    if [[ -f "$SCRIPT_DIR/analyze-trivy-results.sh" ]]; then
        cd "$REPO_ROOT" && "$SCRIPT_DIR/analyze-trivy-results.sh" || analysis_success=false
    fi
fi

# Xeol Analysis
if [[ -f "$REPO_ROOT/reports/xeol-reports/xeol-filesystem-results.json" ]]; then
    echo -e "${CYAN}⏰ Analyzing Xeol EOL detection results...${NC}"
    if [[ -f "$SCRIPT_DIR/analyze-xeol-results.sh" ]]; then
        cd "$REPO_ROOT" && "$SCRIPT_DIR/analyze-xeol-results.sh" || analysis_success=false
    fi
fi

# Helm Analysis (if charts were built)
if [[ -f "$REPO_ROOT/reports/helm-packages/helm-build.log" ]]; then
    echo -e "${CYAN}⚓ Analyzing Helm build results...${NC}"
    if [[ -f "$SCRIPT_DIR/analyze-helm-results.sh" ]]; then
        cd "$REPO_ROOT" && "$SCRIPT_DIR/analyze-helm-results.sh" || analysis_success=false
    fi
fi

echo ""
echo -e "${BLUE}📋 Consolidating all security reports...${NC}"

# Run the unified report consolidation
if [[ -f "$SCRIPT_DIR/consolidate-security-reports.sh" ]]; then
    cd "$REPO_ROOT" && "$SCRIPT_DIR/consolidate-security-reports.sh"
    consolidation_result=$?
    
    if [[ $consolidation_result -eq 0 ]]; then
        echo -e "${GREEN}✅ Security reports consolidated successfully${NC}"
        
        # Display dashboard access information
        echo ""
        echo -e "${BLUE}📊 Security Dashboard Access:${NC}"
        if [[ -f "$REPO_ROOT/reports/security-reports/index.html" ]]; then
            echo -e "${CYAN}🎯 Main Dashboard: $REPO_ROOT/reports/security-reports/index.html${NC}"
        fi
        
        if [[ -f "$REPO_ROOT/reports/security-reports/dashboards/security-dashboard.html" ]]; then
            echo -e "${CYAN}📈 Executive Summary: $REPO_ROOT/reports/security-reports/dashboards/security-dashboard.html${NC}"
        fi
        
        echo ""
        echo -e "${BLUE}🔧 Quick Dashboard Access:${NC}"
        echo -e "${YELLOW}open $REPO_ROOT/reports/security-reports/index.html${NC}"
    else
        echo -e "${RED}❌ Report consolidation failed${NC}"
        analysis_success=false
    fi
    
    # Generate Critical & High Severity Findings Summary
    echo ""
    echo -e "${BLUE}🚨 Generating Critical & High Severity Findings Summary...${NC}"
    if [[ -f "$SCRIPT_DIR/generate-critical-high-summary.sh" ]]; then
        cd "$REPO_ROOT" && "$SCRIPT_DIR/generate-critical-high-summary.sh"
        summary_result=$?
        
        if [[ $summary_result -eq 0 ]]; then
            echo -e "${GREEN}✅ Critical & High severity summary generated successfully${NC}"
            
            # Display summary access information
            if [[ -f "$REPO_ROOT/reports/security-reports/critical-high-findings-summary.html" ]]; then
                echo -e "${CYAN}🎯 Critical/High Summary: $REPO_ROOT/reports/security-reports/critical-high-findings-summary.html${NC}"
            fi
            if [[ -f "$REPO_ROOT/reports/security-reports/critical-high-findings-summary.json" ]]; then
                echo -e "${CYAN}📊 JSON Summary: $REPO_ROOT/reports/security-reports/critical-high-findings-summary.json${NC}"
            fi
        else
            echo -e "${YELLOW}⚠️  Critical & High severity summary generation had issues${NC}"
        fi
    else
        echo -e "${YELLOW}⚠️  Critical & High severity summary script not found${NC}"
    fi
else
    echo -e "${YELLOW}⚠️  Report consolidation script not found${NC}"
fi

echo ""
if [[ "$analysis_success" == "true" ]]; then
    echo -e "${GREEN}✅ All security analysis and reporting completed successfully${NC}"
else
    echo -e "${YELLOW}⚠️  Some analysis steps had issues, but core scanning completed${NC}"
fi

echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}🎯 Target Security Scan Finished Successfully!${NC}"
echo -e "${CYAN}Target: $TARGET_DIR${NC}"
echo -e "${CYAN}Reports: $REPO_ROOT/reports${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""