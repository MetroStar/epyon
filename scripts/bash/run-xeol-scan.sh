#!/bin/bash

# Xeol End-of-Life Detection Script
# Detects End-of-Life packages and technologies using Xeol
# Updated to use absolute paths and handle directory names with spaces

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# Set up paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPORTS_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")/reports"
OUTPUT_DIR="$REPORTS_ROOT/xeol-reports"

# Add timestamp for historical preservation
TIMESTAMP=$(date '+%Y-%m-%d_%H-%M-%S')
SCAN_LOG="$OUTPUT_DIR/xeol-scan-$TIMESTAMP.log"

# Create output directory
mkdir -p "$OUTPUT_DIR"

echo
echo -e "${WHITE}============================================${NC}"
echo -e "${WHITE}Xeol End-of-Life Detection Scanner${NC}"
echo -e "${WHITE}============================================${NC}"
echo

# Function to scan a target
scan_target() {
    local scan_type="$1"
    local target="$2"
    local output_file="$3"
    
    if [ ! -z "$target" ] && [ ! -z "$output_file" ]; then
        echo -e "${BLUE}🔍 Scanning ${scan_type}: ${target}${NC}"
        
        # Run xeol scan with Docker
        docker run --rm -v "$PWD:/workspace" \
            -v "$OUTPUT_DIR:/output" \
            anchore/xeol:latest \
            "$target" \
            --output json \
            --file "/output/$(basename "$output_file")" 2>&1 | tee -a "$SCAN_LOG"
            
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}✅ Scan completed: $output_file${NC}"
        else
            echo -e "${RED}❌ Scan failed for $target${NC}"
        fi
        echo
    fi
}

# 1. End-of-Life Detection
echo -e "${CYAN}⚰️  Step 1: End-of-Life Package Detection${NC}"
echo "========================================"

# Scan common base images for EOL packages
BASE_IMAGES=(
    "alpine:latest"
    "ubuntu:22.04" 
    "node:18-alpine"
    "python:3.11-alpine"
    "nginx:alpine"
)

for image in "${BASE_IMAGES[@]}"; do
    if command -v docker &> /dev/null; then
        echo -e "${BLUE}📦 Scanning base image: $image${NC}"
        local image_name=$(echo $image | tr ':/' '-')
        scan_target "image" "$image" "xeol-base-$image_name-results-$TIMESTAMP.json"
        # Create current symlink
        ln -sf "xeol-base-$image_name-results-$TIMESTAMP.json" "$OUTPUT_DIR/xeol-base-$image_name-results.json"
    fi
done

# Scan filesystem if target directory provided
if [ ! -z "$1" ] && [ -d "$1" ]; then
    echo -e "${BLUE}📁 Scanning filesystem: $1${NC}"
    scan_target "dir" "$1" "xeol-filesystem-results-$TIMESTAMP.json"
    # Create current symlink
    ln -sf "xeol-filesystem-results-$TIMESTAMP.json" "$OUTPUT_DIR/xeol-filesystem-results.json"
fi

echo
echo -e "${CYAN}📊 Xeol End-of-Life Detection Summary${NC}"
echo "===================================="

RESULTS_COUNT=$(find "$OUTPUT_DIR" -name "xeol-*-results.json" 2>/dev/null | wc -l)
echo -e "⚰️  End-of-Life Package Summary:"
if [ $RESULTS_COUNT -gt 0 ]; then
    echo -e "${YELLOW}⚠️  $RESULTS_COUNT result files found - review recommended${NC}"
    
    # Count EOL packages across all files
    TOTAL_EOL=0
    
    for file in "$OUTPUT_DIR"/xeol-*-results.json; do
        if [ -f "$file" ]; then
            # Use jq to count EOL packages
            if command -v jq &> /dev/null; then
                EOL_COUNT=$(jq '[.matches[]?] | length' "$file" 2>/dev/null || echo 0)
                TOTAL_EOL=$((TOTAL_EOL + EOL_COUNT))
            fi
        fi
    done
    
    echo "  📊 Total End-of-Life Packages Found:"
    if [ $TOTAL_EOL -gt 0 ]; then
        echo -e "    ⚰️  EOL Packages: ${RED}$TOTAL_EOL${NC}"
    else
        echo -e "    ${GREEN}✅ No end-of-life packages detected${NC}"
    fi
else
    echo -e "${GREEN}✅ No end-of-life packages detected${NC}"
fi

echo
echo -e "${BLUE}📁 Output Files:${NC}"
echo "==============="
find "$OUTPUT_DIR" -name "xeol-*" -type f 2>/dev/null | while read file; do
    echo "📄 $(basename "$file")"
done
echo "📝 Scan log: $SCAN_LOG"
echo "📂 Reports directory: $OUTPUT_DIR"

echo
echo -e "${BLUE}🔧 Available Commands:${NC}"
echo "===================="
echo "📊 Analyze results:        npm run xeol:analyze"
echo "🔍 Run new scan:           npm run xeol:scan"
echo "🏗️  Filesystem only:        ./run-xeol-scan.sh filesystem"
echo "📦 Images only:            ./run-xeol-scan.sh images"
echo "🖼️  Base images only:       ./run-xeol-scan.sh base"
echo "🌐 Registry images only:   ./run-xeol-scan.sh registry"
echo "☸️  Kubernetes only:       ./run-xeol-scan.sh kubernetes"
echo "🛡️  Full security suite:    npm run security:scan && npm run virus:scan && npm run xeol:scan"
echo "📋 View specific results:   cat \$OUTPUT_DIR/xeol-*-results.json | jq ."

echo
echo -e "${BLUE}🔗 Additional Resources:${NC}"
echo "======================="
echo "• Xeol Documentation: https://github.com/anchore/xeol"
echo "• End-of-Life Package Detection: https://endoflife.date/"
echo "• NIST Software Security: https://csrc.nist.gov/projects/software-security"
echo "• Package Lifecycle Management: https://owasp.org/www-project-dependency-check/"

echo
echo "============================================"
echo -e "${GREEN}✅ Xeol end-of-life detection completed successfully!${NC}"
echo "============================================"
echo
echo "============================================"
echo "Xeol end-of-life detection complete."
echo "============================================"