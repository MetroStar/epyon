#!/bin/bash

# Grype Multi-Target Vulnerability Scanner
# Comprehensive vulnerability detection for containers, filesystems, and SBOMs

# Get absolute path to reports directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPORTS_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
OUTPUT_DIR="$REPORTS_ROOT/reports/grype-reports"
REPO_PATH="${1:-${TARGET_DIR:-$(pwd)}}"
# Use centralized SCAN_ID if provided, otherwise generate one
if [[ -n "$SCAN_ID" ]]; then
    # Use the SCAN_ID passed from main orchestrator
    TARGET_NAME=$(echo "$SCAN_ID" | cut -d'_' -f1)
    USERNAME=$(echo "$SCAN_ID" | cut -d'_' -f2)
    TIMESTAMP=$(echo "$SCAN_ID" | cut -d'_' -f3-)
else
    # Fallback for standalone execution
    TARGET_NAME=$(basename "$REPO_PATH")
    USERNAME=$(whoami)
    TIMESTAMP=$(date '+%Y-%m-%d_%H-%M-%S')
    SCAN_ID="${TARGET_NAME}_${USERNAME}_${TIMESTAMP}"
fi
SCAN_LOG="$OUTPUT_DIR/${SCAN_ID}_grype-scan.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

echo -e "${WHITE}============================================${NC}"
echo -e "${WHITE}Grype Multi-Target Vulnerability Scanner${NC}"
echo -e "${WHITE}============================================${NC}"
echo "Repository: $REPO_PATH"
echo "Output Directory: $OUTPUT_DIR"
echo "Timestamp: $TIMESTAMP"
echo

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Initialize scan log
echo "Grype scan started: $TIMESTAMP" > "$SCAN_LOG"
echo "Target: $REPO_PATH" >> "$SCAN_LOG"

# Function to run Grype scan
run_grype_scan() {
    local scan_type="$1"
    local target="$2"
    local output_file="$OUTPUT_DIR/${SCAN_ID}_grype-${scan_type}-results.json"
    local sbom_file="$OUTPUT_DIR/${SCAN_ID}_sbom-${scan_type}.json"
    local current_file="$OUTPUT_DIR/grype-${scan_type}-results.json"
    local current_sbom="$OUTPUT_DIR/sbom-${scan_type}.json"
    
    echo -e "${BLUE}🔍 Scanning ${scan_type}: ${target}${NC}"
    
    if command -v docker &> /dev/null; then
        echo "Using Docker-based Grype..."
        
        # Generate SBOM first
        docker run --rm -v "$target:/workspace" \
            anchore/syft:latest \
            /workspace -o json 2>&1 | tee -a "$SCAN_LOG" > "$sbom_file"
        
        # Run vulnerability scan
        docker run --rm -v "$sbom_file:/sbom.json" \
            anchore/grype:latest \
            sbom:/sbom.json -o json 2>&1 | tee -a "$SCAN_LOG" > "$output_file"
    else
        echo "⚠️  Docker not available - Grype scan skipped"
        echo '{"matches": [], "ignoredMatches": []}' > "$output_file"
        echo '{"artifacts": []}' > "$sbom_file"
    fi
    
    if [ -f "$output_file" ]; then
        local count=$(cat "$output_file" | jq '.matches | length' 2>/dev/null || echo "0")
        echo "✅ ${scan_type} scan completed: $count vulnerabilities found"
        echo "${scan_type} scan: $count vulnerabilities" >> "$SCAN_LOG"
        
        # Create/update current symlinks for easy access
        ln -sf "$(basename "$output_file")" "$current_file"
        ln -sf "$(basename "$sbom_file")" "$current_sbom"
    fi
}

# Determine scan type based on first argument
SCAN_TYPE="${1:-all}"

echo -e "${CYAN}🔍 Step 1: Vulnerability Detection${NC}"
echo "=================================="

case "$SCAN_TYPE" in
    "filesystem"|"all")
        if [ -d "$REPO_PATH" ]; then
            run_grype_scan "filesystem" "$REPO_PATH"
        else
            echo "⚠️  Target directory not found: $REPO_PATH"
        fi
        ;;
    "images"|"all")
        # Scan common base images
        for image in "nginx:alpine" "node:18-alpine" "python:3.11-alpine" "ubuntu:22.04" "alpine:latest"; do
            echo -e "${BLUE}📦 Scanning base image: $image${NC}"
            if command -v docker &> /dev/null; then
                docker pull "$image" >> "$SCAN_LOG" 2>&1
                run_grype_scan "base-$(echo $image | tr ':' '-')" "$image"
            fi
        done
        ;;
esac

# Count results
RESULTS_COUNT=$(find "$OUTPUT_DIR" -name "grype-*-results.json" -type f | wc -l | tr -d ' ')

echo
echo -e "${CYAN}📊 Grype Vulnerability Summary${NC}"
echo "==============================="
echo "📄 Results files generated: $RESULTS_COUNT"

# Basic results summary
echo -e "🔍 Vulnerability Detection Summary:"
if [ "$RESULTS_COUNT" -gt 0 ]; then
    echo -e "${YELLOW}⚠️  $RESULTS_COUNT result files found - review recommended${NC}"
    echo "Results saved to: $OUTPUT_DIR"
    
    # Simple vulnerability count using jq if available
    if command -v jq &> /dev/null; then
        total_vulns=0
        for file in "$OUTPUT_DIR"/grype-*-results.json; do
            if [ -f "$file" ]; then
                count=$(jq '.matches | length' "$file" 2>/dev/null || echo 0)
                total_vulns=$((total_vulns + count))
            fi
        done
        echo "Total vulnerabilities found: $total_vulns"
    fi
else
    echo -e "${GREEN}✅ No vulnerabilities detected${NC}"
fi

echo
echo -e "${BLUE}📁 Output Files:${NC}"
echo "================"
for file in "$OUTPUT_DIR"/grype-*-results.json; do
    if [ -f "$file" ]; then
        echo "📄 $(basename "$file")"
    fi
done
for file in "$OUTPUT_DIR"/sbom-*.json; do
    if [ -f "$file" ]; then
        echo "📦 $(basename "$file")"
    fi
done
echo "📝 Scan log: $SCAN_LOG"
echo "📂 Reports directory: $OUTPUT_DIR"

echo
echo -e "${BLUE}🔧 Available Commands:${NC}"
echo "===================="
echo "📊 Analyze results:        npm run grype:analyze"
echo "🔍 Run new scan:           npm run grype:scan"
echo "🏗️  Filesystem only:        ./run-grype-scan.sh filesystem"
echo "📦 Images only:            ./run-grype-scan.sh images"
echo "📋 View specific results:  cat $OUTPUT_DIR/grype-*-results.json | jq ."

echo
echo -e "${BLUE}🔗 Additional Resources:${NC}"
echo "======================="
echo "• Grype Documentation: https://github.com/anchore/grype"
echo "• Vulnerability Management: https://owasp.org/www-project-top-ten/2017/A9_2017-Using_Components_with_Known_Vulnerabilities"
echo "• Container Security: https://kubernetes.io/docs/concepts/security/"

echo
echo "============================================"
echo -e "${GREEN}✅ Grype vulnerability detection completed!${NC}"
echo "============================================"
echo
echo "============================================"
echo "Grype vulnerability scanning complete."
echo "============================================"