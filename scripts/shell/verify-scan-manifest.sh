#!/bin/bash

# Verify Scan Manifest Integrity
# Checks file hashes against manifest to detect tampering

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Detect hash command (cross-platform support)
if command -v sha256sum &> /dev/null; then
    HASH_CMD="sha256sum"
elif command -v shasum &> /dev/null; then
    HASH_CMD="shasum -a 256"
else
    echo -e "${RED}❌ Error: No SHA-256 command available (sha256sum or shasum)${NC}"
    exit 1
fi

# Usage
show_usage() {
    local exit_code="${1:-1}"
    echo "Usage: $0 <scan_directory>"
    echo ""
    echo "Arguments:"
    echo "  scan_directory    Absolute path to scan output directory"
    echo ""
    echo "Example:"
    echo "  $0 /path/to/scans/app_user_2026-02-06"
    exit "$exit_code"
}

if [[ "${1:-}" == "--help" ]] || [[ "${1:-}" == "-h" ]]; then
    show_usage 0
fi

# Validate arguments
if [[ $# -lt 1 ]]; then
    show_usage
fi

SCAN_DIR="$1"
MANIFEST_FILE="$SCAN_DIR/scan-manifest.json"

if [[ ! -d "$SCAN_DIR" ]]; then
    echo -e "${RED}❌ Error: Scan directory does not exist: $SCAN_DIR${NC}"
    exit 1
fi

if [[ ! -f "$MANIFEST_FILE" ]]; then
    echo -e "${RED}❌ Error: Manifest file not found: $MANIFEST_FILE${NC}"
    echo "   Generate manifest first with: ./scripts/shell/generate-scan-manifest.sh $SCAN_DIR"
    exit 1
fi

echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}  Verifying Scan Manifest${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Check if jq is available
if ! command -v jq &> /dev/null; then
    echo -e "${RED}❌ Error: jq is required but not installed${NC}"
    exit 1
fi

# Read manifest metadata
SCAN_ID=$(jq -r '.scan_metadata.scan_id' "$MANIFEST_FILE")
TIMESTAMP=$(jq -r '.scan_metadata.timestamp' "$MANIFEST_FILE")
USERNAME=$(jq -r '.scan_metadata.username' "$MANIFEST_FILE")
MANIFEST_VERSION=$(jq -r '.manifest_version' "$MANIFEST_FILE")

echo -e "${BLUE}📋 Manifest Information${NC}"
echo "   Scan ID: $SCAN_ID"
echo "   Generated: $TIMESTAMP"
echo "   User: $USERNAME"
echo "   Manifest Version: $MANIFEST_VERSION"
echo ""

# Verify manifest self-hash
echo -e "${BLUE}🔐 Verifying manifest integrity...${NC}"
STORED_MANIFEST_HASH=$(jq -r '.manifest_hash' "$MANIFEST_FILE")

# Remove manifest_hash field and recalculate using canonical JSON (compact, sorted keys)
# This ensures consistent formatting across platforms and after zip/unzip
TEMP_MANIFEST=$(jq -cS 'del(.manifest_hash)' "$MANIFEST_FILE")
CALCULATED_HASH=$(echo "$TEMP_MANIFEST" | $HASH_CMD | awk '{print $1}')

if [[ "sha256:$CALCULATED_HASH" == "$STORED_MANIFEST_HASH" ]]; then
    echo -e "${GREEN}   ✓ Manifest file integrity verified${NC}"
else
    echo -e "${RED}   ✗ Manifest file has been modified!${NC}"
    echo "   Expected: $STORED_MANIFEST_HASH"
    echo "   Calculated: sha256:$CALCULATED_HASH"
    exit 1
fi
echo ""

# Verify file hashes
echo -e "${BLUE}🔍 Verifying file hashes...${NC}"

declare -i VERIFIED=0
declare -i FAILED=0
declare -i MISSING=0

# Extract file hashes from manifest
while IFS= read -r file; do
    EXPECTED_HASH=$(jq -r --arg file "$file" '.file_hashes[$file]' "$MANIFEST_FILE")
    FILE_PATH="$SCAN_DIR/$file"
    
    if [[ ! -f "$FILE_PATH" ]]; then
        echo -e "${YELLOW}   ⚠ Missing: $file${NC}"
        (( MISSING += 1 ))
        continue
    fi
    
    # Calculate actual hash with cross-platform support
    ACTUAL_HASH=$($HASH_CMD "$FILE_PATH" | awk '{print $1}')
    
    if [[ "sha256:$ACTUAL_HASH" == "$EXPECTED_HASH" ]]; then
        echo -e "${GREEN}   ✓ $file${NC}"
        (( VERIFIED += 1 ))
    else
        echo -e "${RED}   ✗ $file${NC}"
        echo "     Expected: $EXPECTED_HASH"
        echo "     Actual:   sha256:$ACTUAL_HASH"
        (( FAILED += 1 ))
    fi
done < <(jq -r '.file_hashes | keys[]' "$MANIFEST_FILE")

echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}  Verification Summary${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "📊 Results:"
echo -e "   ${GREEN}Verified: $VERIFIED${NC}"
if [[ $FAILED -gt 0 ]]; then
    echo -e "   ${RED}Failed: $FAILED${NC}"
fi
if [[ $MISSING -gt 0 ]]; then
    echo -e "   ${YELLOW}Missing: $MISSING${NC}"
fi
echo ""

# Display target information
REPO_URL=$(jq -r '.target.repository // "N/A"' "$MANIFEST_FILE")
COMMIT_SHA=$(jq -r '.target.commit_sha // "N/A"' "$MANIFEST_FILE")
BRANCH=$(jq -r '.target.branch // "N/A"' "$MANIFEST_FILE")

if [[ "$REPO_URL" != "N/A" ]] && [[ "$REPO_URL" != "null" ]]; then
    echo "🎯 Target Information:"
    echo "   Repository: $REPO_URL"
    echo "   Commit: $COMMIT_SHA"
    echo "   Branch: $BRANCH"
    echo ""
fi

# Exit with appropriate code
if [[ $FAILED -gt 0 ]]; then
    echo -e "${RED}❌ Verification FAILED - Files have been modified!${NC}"
    exit 1
elif [[ $MISSING -gt 0 ]]; then
    echo -e "${YELLOW}⚠️  Verification WARNING - Some files are missing${NC}"
    exit 2
else
    echo -e "${GREEN}✅ All files verified successfully - Scan integrity intact${NC}"
    exit 0
fi
