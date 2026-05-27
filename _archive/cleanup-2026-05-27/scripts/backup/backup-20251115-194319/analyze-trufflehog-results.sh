#!/bin/bash

# Color definitions for enhanced output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

echo -e "${WHITE}============================================${NC}"
echo -e "${WHITE}TruffleHog Multi-Target Security Analysis${NC}"
echo -e "${WHITE}============================================${NC}"
echo

# Check for results files
FILESYSTEM_RESULTS="./trufflehog-reports/trufflehog-filesystem-results.json"
CONTAINER_RESULTS="./trufflehog-reports/trufflehog-container-results.json"
BASE_IMAGE_RESULTS="./trufflehog-reports/trufflehog-base-image-results.json"
REGISTRY_RESULTS="./trufflehog-reports/trufflehog-registry-results.json"
COMBINED_RESULTS="./trufflehog-reports/trufflehog-combined-results.json"

# Function to analyze a specific results file
analyze_results_file() {
    local file=$1
    local scan_type=$2
    local color=$3
    
    if [ ! -f "$file" ]; then
        echo -e "${YELLOW}⚠️  No results file found for $scan_type at $file${NC}"
        return 1
    fi
    
    local findings_count=$(grep -o '"DetectorName":"[^"]*"' "$file" | wc -l | tr -d ' ')
    
    echo -e "${color}📊 $scan_type Analysis (${findings_count} findings):${NC}"
    echo "========================================"
    
    if [ "$findings_count" -eq 0 ]; then
        echo -e "${GREEN}✅ No secrets found in $scan_type${NC}"
        echo
        return 0
    fi
    
    echo -e "${BLUE}🔍 Detector Types:${NC}"
    grep -o '"DetectorName":"[^"]*"' "$file" | sort | uniq -c | sort -nr | head -5
    
    echo
    echo -e "${PURPLE}🎯 Verification Status:${NC}"
    local verified=$(grep '"Verified":true' "$file" | wc -l | tr -d ' ')
    local unverified=$(grep '"Verified":false' "$file" | wc -l | tr -d ' ')
    echo "  Verified secrets: $verified"
    echo "  Unverified secrets: $unverified"
    
    echo
    if [[ "$scan_type" == "Filesystem" ]]; then
        echo -e "${RED}🚨 Files with findings (excluding node_modules):${NC}"
        grep '"file":' "$file" | grep -v 'node_modules' | sed 's/.*"file":"\([^"]*\)".*/\1/' | sort | uniq -c | sort -nr | head -5
    else
        echo -e "${RED}🐳 Container/Image findings:${NC}"
        grep '"SourceName":' "$file" | sed 's/.*"SourceName":"\([^"]*\)".*/\1/' | sort | uniq -c | sort -nr | head -5
    fi
    
    echo
    echo -e "${YELLOW}⚠️  High-priority findings (excluding false positives):${NC}"
    grep -v -E "(node_modules|\.git/|trufflehog-reports|README\.md|example\.com|localhost)" "$file" | \
    grep '"DetectorName"' | \
    sed 's/.*"DetectorName":"\([^"]*\)".*"SourceName":"\([^"]*\)".*/\2 - \1/' | \
    head -5
    
    echo
}

# Analyze individual scan results
analyze_results_file "$FILESYSTEM_RESULTS" "Filesystem" "$CYAN"
analyze_results_file "$CONTAINER_RESULTS" "Container Images" "$PURPLE"
analyze_results_file "$BASE_IMAGE_RESULTS" "Base Images" "$BLUE"
analyze_results_file "$REGISTRY_RESULTS" "Registry Images" "$GREEN"

# Create and analyze combined results
echo -e "${WHITE}🔄 Creating combined analysis...${NC}"
echo

# Combine all results into a single file
{
    echo "{"
    echo "  \"filesystem\": ["
    if [ -f "$FILESYSTEM_RESULTS" ]; then
        sed '1d;$d' "$FILESYSTEM_RESULTS" 2>/dev/null || echo ""
    fi
    echo "  ],"
    echo "  \"containers\": ["
    if [ -f "$CONTAINER_RESULTS" ]; then
        sed '1d;$d' "$CONTAINER_RESULTS" 2>/dev/null || echo ""
    fi
    echo "  ],"
    echo "  \"base_images\": ["
    if [ -f "$BASE_IMAGE_RESULTS" ]; then
        sed '1d;$d' "$BASE_IMAGE_RESULTS" 2>/dev/null || echo ""
    fi
    echo "  ],"
    echo "  \"registry_images\": ["
    if [ -f "$REGISTRY_RESULTS" ]; then
        sed '1d;$d' "$REGISTRY_RESULTS" 2>/dev/null || echo ""
    fi
    echo "  ]"
    echo "}"
} > "$COMBINED_RESULTS"

# Overall summary
echo -e "${WHITE}📈 OVERALL SECURITY SUMMARY${NC}"
echo "============================"

total_findings=0
for file in "$FILESYSTEM_RESULTS" "$CONTAINER_RESULTS" "$BASE_IMAGE_RESULTS" "$REGISTRY_RESULTS"; do
    if [ -f "$file" ]; then
        count=$(grep -o '"DetectorName":"[^"]*"' "$file" | wc -l | tr -d ' ')
        total_findings=$((total_findings + count))
    fi
done

if [ "$total_findings" -eq 0 ]; then
    echo -e "${GREEN}✅ SECURITY STATUS: CLEAN${NC}"
    echo -e "${GREEN}   No secrets detected across all scan targets${NC}"
else
    echo -e "${YELLOW}⚠️  SECURITY STATUS: REQUIRES REVIEW${NC}"
    echo -e "${YELLOW}   Total findings: $total_findings${NC}"
    echo -e "${YELLOW}   Review and verify each finding manually${NC}"
fi

echo
echo -e "${BLUE}🔗 Next Steps:${NC}"
echo "1. Review individual result files in ./trufflehog-reports/"
echo "2. Verify any unverified findings manually"
echo "3. Add false positives to exclude-paths.txt"
echo "4. Re-run scans after remediation"

echo
echo -e "${WHITE}============================================${NC}"
echo -e "${GREEN}✅ Multi-target analysis complete.${NC}"
echo -e "${WHITE}============================================${NC}"