#!/bin/bash

# Quick Scan Rollup Script
# Gets comprehensive summary of a specific scan ID

SCAN_ID="$1"
BASE_ROOT="${2:-$(dirname "$(dirname "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"))")}"
REPORTS_ROOT="$BASE_ROOT/reports"
SCANS_ROOT="$BASE_ROOT/scans"
SCAN_DIR="$SCANS_ROOT/$SCAN_ID"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

if [[ -z "$SCAN_ID" ]]; then
    echo "Usage: $0 <scan_id> [reports_root]"
    echo ""
    echo "Examples:"
    echo "  $0 'advana-marketplace-monolith-node_rnelson_2025-11-17_08-29-31'"
    echo "  $0 'myproject_user_2025-11-17_10-30-15'"
    exit 1
fi

echo -e "${WHITE}============================================${NC}"
echo -e "${WHITE}📊 Scan Rollup for: ${SCAN_ID}${NC}"
echo -e "${WHITE}============================================${NC}"
echo ""

# Check if security findings summary exists
SUMMARY_FILE="$REPORTS_ROOT/security-reports/${SCAN_ID}_security-findings-summary.json"
if [[ -f "$SUMMARY_FILE" ]]; then
    echo -e "${GREEN}✅ Security Findings Summary Found${NC}"
    echo -e "📄 File: $SUMMARY_FILE"
    echo ""
    
    # Extract key metrics
    critical=$(jq -r '.summary.total_critical // 0' "$SUMMARY_FILE" 2>/dev/null)
    high=$(jq -r '.summary.total_high // 0' "$SUMMARY_FILE" 2>/dev/null)
    medium=$(jq -r '.summary.total_medium // 0' "$SUMMARY_FILE" 2>/dev/null)
    low=$(jq -r '.summary.total_low // 0' "$SUMMARY_FILE" 2>/dev/null)
    tools=$(jq -r '.summary.tools_analyzed | length' "$SUMMARY_FILE" 2>/dev/null)
    
    echo -e "${CYAN}📈 Security Findings Overview:${NC}"
    echo -e "  ${RED}🔴 Critical: $critical${NC}"
    echo -e "  ${YELLOW}🟡 High: $high${NC}"
    echo -e "  ${BLUE}🔵 Medium: $medium${NC}"
    echo -e "  ${WHITE}⚪ Low: $low${NC}"
    echo -e "  ${PURPLE}🔧 Tools: $tools${NC}"
    echo ""
    
    # Show tools analyzed
    echo -e "${CYAN}🛠️  Tools Analyzed:${NC}"
    jq -r '.summary.tools_analyzed[]' "$SUMMARY_FILE" 2>/dev/null | while read tool; do
        echo -e "  • $tool"
    done
    echo ""
else
    echo -e "${YELLOW}⚠️  Security findings summary not found${NC}"
    echo -e "📄 Expected: $SUMMARY_FILE"
    echo ""
    
    # Try to generate it
    echo -e "${BLUE}🔄 Attempting to generate summary...${NC}"
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    if [[ -f "$SCRIPT_DIR/generate-scan-findings-summary.sh" ]]; then
        source "$SCRIPT_DIR/generate-scan-findings-summary.sh"
        # Extract target directory from scan ID pattern
        TARGET_NAME=$(echo "$SCAN_ID" | cut -d'_' -f1)
        generate_scan_findings_summary "$SCAN_ID" "$TARGET_NAME" "$REPORTS_ROOT"
    fi
fi

# Check if scan directory exists
if [[ -d "$SCAN_DIR" ]]; then
    echo -e "${GREEN}✅ Scan Directory Found: $SCAN_DIR${NC}"
    echo ""
    
    # List all files in scan directory
    echo -e "${CYAN}📁 Scan Directory Contents:${NC}"
    find "$SCAN_DIR" -type f 2>/dev/null | sort | while read file; do
        size=$(du -h "$file" | cut -f1)
        rel_path=$(echo "$file" | sed "s|$SCAN_DIR/||")
        echo -e "  📄 ${rel_path} (${size})"
    done
else
    echo -e "${YELLOW}⚠️  Scan directory not found: $SCAN_DIR${NC}"
    echo -e "${BLUE}🔍 Checking legacy reports structure...${NC}"
    
    # List all files for this scan ID in reports
    find "$REPORTS_ROOT" -name "*${SCAN_ID}*" -type f 2>/dev/null | sort | while read file; do
        size=$(du -h "$file" | cut -f1)
        tool_dir=$(basename "$(dirname "$file")")
        filename=$(basename "$file")
        echo -e "  📄 ${tool_dir}/${filename} (${size})"
    done
fi

echo ""

# Show individual tool summaries
echo -e "${CYAN}🔍 Individual Tool Results:${NC}"

# Grype
grype_files=($(find "$REPORTS_ROOT/grype-reports" -name "${SCAN_ID}_grype-*-results.json" 2>/dev/null))
if [[ ${#grype_files[@]} -gt 0 ]]; then
    echo -e "${PURPLE}  🎯 Grype Vulnerability Scanning:${NC}"
    for file in "${grype_files[@]}"; do
        scan_type=$(basename "$file" | sed "s/${SCAN_ID}_grype-//; s/-results.json//")
        vuln_count=$(jq -r '.matches | length' "$file" 2>/dev/null || echo "0")
        echo -e "    • $scan_type: $vuln_count vulnerabilities"
    done
fi

# Trivy
trivy_files=($(find "$REPORTS_ROOT/trivy-reports" -name "${SCAN_ID}_trivy-*-results.json" 2>/dev/null))
if [[ ${#trivy_files[@]} -gt 0 ]]; then
    echo -e "${BLUE}  🛡️  Trivy Security Analysis:${NC}"
    for file in "${trivy_files[@]}"; do
        scan_type=$(basename "$file" | sed "s/${SCAN_ID}_trivy-//; s/-results.json//")
        vuln_count=$(jq -r '[.Results[]?.Vulnerabilities[]?] | length' "$file" 2>/dev/null || echo "0")
        echo -e "    • $scan_type: $vuln_count issues"
    done
fi

# TruffleHog
trufflehog_files=($(find "$REPORTS_ROOT/trufflehog-reports" -name "${SCAN_ID}_trufflehog-*-results.json" 2>/dev/null))
if [[ ${#trufflehog_files[@]} -gt 0 ]]; then
    echo -e "${RED}  🔐 TruffleHog Secret Detection:${NC}"
    for file in "${trufflehog_files[@]}"; do
        scan_type=$(basename "$file" | sed "s/${SCAN_ID}_trufflehog-//; s/-results.json//")
        secret_count=$(jq -r '. | length' "$file" 2>/dev/null || echo "0")
        echo -e "    • $scan_type: $secret_count secrets"
    done
fi

# Checkov
checkov_file="$REPORTS_ROOT/checkov-reports/${SCAN_ID}_checkov-results.json"
if [[ -f "$checkov_file" ]]; then
    echo -e "${GREEN}  ☸️  Checkov Infrastructure Security:${NC}"
    failed_count=$(jq -r '.results.failed_checks | length' "$checkov_file" 2>/dev/null || echo "0")
    passed_count=$(jq -r '.results.passed_checks | length' "$checkov_file" 2>/dev/null || echo "0")
    echo -e "    • Failed: $failed_count, Passed: $passed_count"
fi

# SBOM
sbom_files=($(find "$REPORTS_ROOT/sbom-reports" -name "${SCAN_ID}_sbom-*.json" 2>/dev/null | grep -v summary))
if [[ ${#sbom_files[@]} -gt 0 ]]; then
    echo -e "${CYAN}  📋 SBOM Generation:${NC}"
    for file in "${sbom_files[@]}"; do
        scan_type=$(basename "$file" | sed "s/${SCAN_ID}_sbom-//; s/.json//")
        artifact_count=$(jq -r '.artifacts | length' "$file" 2>/dev/null || echo "0")
        echo -e "    • $scan_type: $artifact_count artifacts"
    done
fi

# Xeol
xeol_file="$REPORTS_ROOT/xeol-reports/${SCAN_ID}_xeol-results.json"
if [[ -f "$xeol_file" ]]; then
    echo -e "${YELLOW}  ⏰ Xeol EOL Detection:${NC}"
    eol_count=$(jq -r '[.matches[] | select(.eol == true)] | length' "$xeol_file" 2>/dev/null || echo "0")
    echo -e "    • EOL components: $eol_count"
fi

echo ""
echo -e "${WHITE}============================================${NC}"
echo -e "${GREEN}✅ Scan Rollup Complete${NC}"
echo -e "${WHITE}============================================${NC}"