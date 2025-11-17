#!/bin/bash

# Test script to verify timestamp consistency across all security tools

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
WHITE='\033[1;37m'
NC='\033[0m'

# Set up test environment
TARGET_DIR="${1:-/tmp/test-scan-consistency}"
mkdir -p "$TARGET_DIR"
echo '{"name": "test-project", "version": "1.0.0"}' > "$TARGET_DIR/package.json"

echo -e "${WHITE}============================================${NC}"
echo -e "${WHITE}🧪 Testing Scan ID Consistency${NC}"
echo -e "${WHITE}============================================${NC}"
echo ""

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"

# Generate a single scan ID that should be used by all tools
TARGET_NAME=$(basename "$TARGET_DIR")
USERNAME=$(whoami)
TIMESTAMP=$(date '+%Y-%m-%d_%H-%M-%S')
SCAN_ID="${TARGET_NAME}_${USERNAME}_${TIMESTAMP}"

echo -e "${BLUE}🎯 Master Scan ID: ${SCAN_ID}${NC}"
echo -e "${BLUE}📅 Master Timestamp: ${TIMESTAMP}${NC}"
echo ""

# Export the scan ID
export SCAN_ID
export TARGET_DIR

echo -e "${YELLOW}🔍 Testing individual tools with centralized SCAN_ID...${NC}"
echo ""

# Test a few key tools to verify they use the same SCAN_ID
echo -e "${GREEN}✅ Testing SBOM scan...${NC}"
cd "$SCRIPT_DIR"
./run-sbom-scan.sh "$TARGET_DIR" >/dev/null 2>&1
if [[ -f "$REPO_ROOT/reports/sbom-reports/${SCAN_ID}_sbom-summary.json" ]]; then
    echo -e "  📄 SBOM file created with correct SCAN_ID: ${SCAN_ID}_sbom-summary.json"
else
    echo -e "  ❌ SBOM file NOT found with expected SCAN_ID"
fi

# Test target scan to see if all files have the same timestamp
echo ""
echo -e "${GREEN}✅ Testing quick security scan...${NC}"
./run-target-security-scan.sh "$TARGET_DIR" quick >/dev/null 2>&1

echo ""
echo -e "${BLUE}📊 Checking file consistency...${NC}"

# Find all files with the master scan ID
files_with_scan_id=$(find "$REPO_ROOT/reports" -name "*${SCAN_ID}*" -type f 2>/dev/null)

if [[ -n "$files_with_scan_id" ]]; then
    echo -e "${GREEN}✅ Files found with consistent SCAN_ID:${NC}"
    echo "$files_with_scan_id" | while read file; do
        filename=$(basename "$file")
        dir_name=$(basename "$(dirname "$file")")
        echo -e "  📄 ${dir_name}/${filename}"
    done
    
    # Count unique SCAN_IDs in generated files
    unique_scan_ids=$(find "$REPO_ROOT/reports" -name "*${TARGET_NAME}_${USERNAME}_*" -type f 2>/dev/null | \
        sed -E "s/.*\/${TARGET_NAME}_${USERNAME}_([0-9]{4}-[0-9]{2}-[0-9]{2}_[0-9]{2}-[0-9]{2}-[0-9]{2}).*/\1/" | \
        sort | uniq | wc -l)
    
    echo ""
    if [[ "$unique_scan_ids" -eq 1 ]]; then
        echo -e "${GREEN}✅ SUCCESS: All files use the same timestamp (${unique_scan_ids} unique timestamp)${NC}"
    else
        echo -e "${YELLOW}⚠️  WARNING: Found ${unique_scan_ids} different timestamps${NC}"
        echo -e "${YELLOW}   This indicates timestamp inconsistency between tools${NC}"
        
        # Show the different timestamps
        echo -e "${BLUE}🕐 Different timestamps found:${NC}"
        find "$REPO_ROOT/reports" -name "*${TARGET_NAME}_${USERNAME}_*" -type f 2>/dev/null | \
            sed -E "s/.*\/${TARGET_NAME}_${USERNAME}_([0-9]{4}-[0-9]{2}-[0-9]{2}_[0-9]{2}-[0-9]{2}-[0-9]{2}).*/\1/" | \
            sort | uniq | while read ts; do
                echo -e "  📅 ${ts}"
            done
    fi
else
    echo -e "${YELLOW}⚠️  No files found with the expected SCAN_ID${NC}"
fi

# Cleanup test directory
rm -rf "$TARGET_DIR"

echo ""
echo -e "${WHITE}============================================${NC}"
echo -e "${WHITE}🧪 Test Complete${NC}"
echo -e "${WHITE}============================================${NC}"