#!/bin/bash

# Complete SBOM Scan with Python Manifest Preparation
# This script prepares Python manifest files for Syft, then generates a comprehensive SBOM
# 
# Syft's python-package-cataloger recognizes requirements.txt but not requirements.lock
# This script temporarily copies requirements.lock to requirements.txt for complete scanning

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

# Help function
show_help() {
    echo -e "${WHITE}Complete SBOM Scan with Python Manifest Preparation${NC}"
    echo ""
    echo "Usage: $0 [TARGET_DIRECTORY]"
    echo ""
    echo "This script:"
    echo "  1. Prepares Python manifest files (requirements.lock → requirements.txt if needed)"
    echo "  2. Runs Syft SBOM generation to catalog ALL dependencies"
    echo "  3. Cleans up temporary files"
    echo ""
    echo "Note: Syft recognizes requirements.txt but not requirements.lock"
    echo "      This script temporarily copies .lock files for complete scanning"
    echo ""
    echo "Arguments:"
    echo "  TARGET_DIRECTORY    Path to directory to scan (default: current directory)"
    echo ""
    echo "Examples:"
    echo "  $0                              # Scan current directory"
    echo "  $0 /path/to/python/project      # Scan specific Python project"
    echo ""
    exit 0
}

# Parse arguments
if [[ "$1" == "-h" ]] || [[ "$1" == "--help" ]]; then
    show_help
fi

# Support TARGET_DIR environment variable or command line argument
TARGET_DIR="${TARGET_DIR:-${1:-$(pwd)}}"
TARGET_DIR=$(realpath "${TARGET_DIR}" 2>/dev/null) || { echo "ERROR: Target path does not exist or is invalid: ${TARGET_DIR}" >&2; exit 1; }
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo -e "${WHITE}============================================${NC}"
echo -e "${WHITE}Complete SBOM Scan Pipeline${NC}"
echo -e "${WHITE}============================================${NC}"
echo "Target: $TARGET_DIR"
echo "Started: $(date)"
echo ""

# Step 1: Prepare Python manifest files for Syft
echo -e "${CYAN}Step 1: Preparing Python manifest files...${NC}"
TEMP_REQUIREMENTS_CREATED=false

# Check if requirements.lock exists but requirements.txt doesn't
# Syft's python-package-cataloger only recognizes requirements.txt, not .lock variants
if [[ -f "$TARGET_DIR/requirements.lock" ]] && [[ ! -f "$TARGET_DIR/requirements.txt" ]]; then
    echo -e "${YELLOW}⚠️  Found requirements.lock but no requirements.txt${NC}"
    echo -e "${CYAN}   Creating temporary requirements.txt from requirements.lock for Syft...${NC}"
    cp "$TARGET_DIR/requirements.lock" "$TARGET_DIR/requirements.txt"
    TEMP_REQUIREMENTS_CREATED=true
    echo -e "${GREEN}✅ Temporary requirements.txt created (will be cleaned up after scan)${NC}"
else
    echo -e "${GREEN}✅ Python manifest files ready for scanning${NC}"
fi
echo ""

# Step 2: Run SBOM scan
echo -e "${CYAN}Step 2: Generating SBOM with Syft...${NC}"
TARGET_DIR="$TARGET_DIR" "$SCRIPT_DIR/run-sbom-scan.sh"
echo ""

# Step 3: Cleanup
if [[ "$TEMP_REQUIREMENTS_CREATED" == "true" ]]; then
    echo -e "${CYAN}Step 3: Cleaning up temporary files...${NC}"
    rm -f "$TARGET_DIR/requirements.txt"
    echo -e "${GREEN}✅ Cleaned up temporary requirements.txt${NC}"
fi

echo ""
echo -e "${WHITE}============================================${NC}"
echo -e "${GREEN}✅ Complete SBOM Scan Finished${NC}"
echo -e "${WHITE}============================================${NC}"
echo "Completed: $(date)"
echo ""

# Find and display the latest scan results
LATEST_SCAN=$(ls -t "$SCRIPT_DIR/../../scans" | grep -v ".tmp-clones" | head -1)
if [[ -n "$LATEST_SCAN" ]]; then
    SBOM_DIR="$SCRIPT_DIR/../../scans/$LATEST_SCAN/sbom"
    if [[ -f "$SBOM_DIR/sbom-summary.json" ]]; then
        echo -e "${CYAN}📊 SBOM Results:${NC}"
        TOTAL_ARTIFACTS=$(jq -r '.total_artifacts // 0' "$SBOM_DIR/sbom-summary.json" 2>/dev/null)
        if [[ -z "$TOTAL_ARTIFACTS" || "$TOTAL_ARTIFACTS" == "null" ]]; then
            # Fallback: count from filesystem.json if available
            TOTAL_ARTIFACTS=$(jq -r '.artifacts | length' "$SBOM_DIR/filesystem.json" 2>/dev/null || echo "0")
        fi
        echo -e "   Total Artifacts: ${GREEN}$TOTAL_ARTIFACTS${NC}"
        echo -e "   Location: $SBOM_DIR"
        echo ""
    fi
fi

exit 0
