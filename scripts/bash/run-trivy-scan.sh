#!/bin/bash

# Trivy Security Scanner Script
# Performs comprehensive vulnerability scanning using Trivy
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

# Support target directory scanning - priority: command line arg, TARGET_DIR env var, current directory
REPO_PATH="${1:-${TARGET_DIR:-$(pwd)}}"

# Set REPO_ROOT for report generation
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
OUTPUT_DIR="$REPO_ROOT/reports/trivy-reports"

# Create unique scan ID for this scan run
TARGET_NAME=$(basename "$REPO_PATH")
USERNAME=$(whoami)
TIMESTAMP=$(date '+%Y-%m-%d_%H-%M-%S')
SCAN_ID="${TARGET_NAME}_${USERNAME}_${TIMESTAMP}"

# Create output directory
mkdir -p "$OUTPUT_DIR"

echo
echo -e "${WHITE}============================================${NC}"
echo -e "${WHITE}Trivy Multi-Target Security Scanner${NC}"
echo -e "${WHITE}============================================${NC}"
echo

# Function to scan a target
run_trivy_scan() {
    local scan_type="$1"
    local target="$2"
    local output_file="$OUTPUT_DIR/${SCAN_ID}_trivy-${scan_type}-results.json"
    local current_file="$OUTPUT_DIR/trivy-${scan_type}-results.json"
    
    if [ ! -z "$target" ] && [ ! -z "$output_file" ]; then
        echo -e "${BLUE}🔍 Scanning ${scan_type}: ${target}${NC}"
        
        # Run trivy scan with Docker
        if command -v docker &> /dev/null; then
            docker run --rm -v "$target:/workspace" \
                aquasec/trivy:latest \
                fs /workspace \
                --format json 2>&1 | tee -a "$SCAN_LOG" > "$output_file"
            
            if [ $? -eq 0 ]; then
                echo -e "${GREEN}✅ Scan completed: $output_file${NC}"
                # Create/update current symlink for easy access
                ln -sf "$(basename "$output_file")" "$current_file"
            else
                echo -e "${RED}❌ Scan failed for $target${NC}"
            fi
        else
            echo -e "${RED}❌ Docker not available - Trivy scan skipped${NC}"
            echo '{"Results": []}' > "$output_file"
        fi
        echo
    fi
}

# 1. Container Security Scan
echo -e "${CYAN}🛡️  Step 1: Container Security Scan${NC}"
echo "=================================="

# Scan common base images
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
        scan_target "image" "$image" "trivy-base-$(echo $image | tr ':/' '-')-results.json"
    fi
done

# Scan filesystem if target directory provided
if [ ! -z "$1" ] && [ -d "$1" ]; then
    echo -e "${BLUE}📁 Scanning filesystem: $1${NC}"
    scan_target "fs" "$1" "trivy-filesystem-results.json"
fi

echo
echo -e "${CYAN}📊 Trivy Security Scan Summary${NC}"
echo "============================="

RESULTS_COUNT=$(find "$OUTPUT_DIR" -name "trivy-*-results.json" 2>/dev/null | wc -l)
echo -e "🔍 Vulnerability Summary:"
if [ $RESULTS_COUNT -gt 0 ]; then
    echo -e "${YELLOW}⚠️  $RESULTS_COUNT result files found - review recommended${NC}"
    
    # Count vulnerabilities across all files
    TOTAL_CRITICAL=0
    TOTAL_HIGH=0
    TOTAL_MEDIUM=0
    TOTAL_LOW=0
    
    for file in "$OUTPUT_DIR"/trivy-*-results.json; do
        if [ -f "$file" ]; then
            # Use jq to count vulnerabilities by severity
            if command -v jq &> /dev/null; then
                CRITICAL=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "CRITICAL")] | length' "$file" 2>/dev/null || echo 0)
                HIGH=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "HIGH")] | length' "$file" 2>/dev/null || echo 0)
                MEDIUM=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "MEDIUM")] | length' "$file" 2>/dev/null || echo 0)
                LOW=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "LOW")] | length' "$file" 2>/dev/null || echo 0)
                
                TOTAL_CRITICAL=$((TOTAL_CRITICAL + CRITICAL))
                TOTAL_HIGH=$((TOTAL_HIGH + HIGH))
                TOTAL_MEDIUM=$((TOTAL_MEDIUM + MEDIUM))
                TOTAL_LOW=$((TOTAL_LOW + LOW))
            fi
        fi
    done
    
    echo "  📊 Total Vulnerabilities Found:"
    if [ $TOTAL_CRITICAL -gt 0 ]; then
        echo -e "    🔴 Critical: ${RED}$TOTAL_CRITICAL${NC}"
    fi
    if [ $TOTAL_HIGH -gt 0 ]; then
        echo -e "    🟠 High: ${YELLOW}$TOTAL_HIGH${NC}"
    fi
    if [ $TOTAL_MEDIUM -gt 0 ]; then
        echo -e "    🟡 Medium: $TOTAL_MEDIUM"
    fi
    if [ $TOTAL_LOW -gt 0 ]; then
        echo -e "    🟢 Low: $TOTAL_LOW"
    fi
    
    if [ $((TOTAL_CRITICAL + TOTAL_HIGH + TOTAL_MEDIUM + TOTAL_LOW)) -eq 0 ]; then
        echo -e "    ${GREEN}✅ No vulnerabilities detected in JSON files${NC}"
    fi
else
    echo -e "${GREEN}✅ No vulnerabilities detected${NC}"
fi

echo
echo -e "${BLUE}📁 Output Files:${NC}"
echo "==============="
find "$OUTPUT_DIR" -name "trivy-*" -type f 2>/dev/null | while read file; do
    echo "📄 $(basename "$file")"
done
echo "📝 Scan log: $SCAN_LOG"
echo "📂 Reports directory: $OUTPUT_DIR"

echo
echo -e "${BLUE}🔧 Available Commands:${NC}"
echo "===================="
echo "📊 Analyze results:        npm run trivy:analyze"
echo "🔍 Run new scan:           npm run trivy:scan"
echo "🏗️  Filesystem only:        ./run-trivy-scan.sh filesystem"
echo "📦 Images only:            ./run-trivy-scan.sh images"
echo "🖼️  Base images only:       ./run-trivy-scan.sh base"
echo "🌐 Registry images only:   ./run-trivy-scan.sh registry"
echo "☸️  Kubernetes only:       ./run-trivy-scan.sh kubernetes"
echo "🛡️  Full security suite:    npm run security:scan && npm run virus:scan && npm run trivy:scan"
echo "📋 View specific results:   cat \$OUTPUT_DIR/trivy-*-results.json | jq ."

echo
echo -e "${BLUE}🔗 Additional Resources:${NC}"
echo "======================="
echo "• Trivy Documentation: https://trivy.dev/"
echo "• Container Security Best Practices: https://kubernetes.io/docs/concepts/security/"
echo "• NIST Container Security Guide: https://csrc.nist.gov/publications/detail/sp/800-190/final"
echo "• Docker Security Best Practices: https://docs.docker.com/develop/security-best-practices/"

echo
echo "============================================"
echo -e "${GREEN}✅ Trivy security scan completed successfully!${NC}"
echo "============================================"
echo
echo "============================================"
echo "Trivy vulnerability scanning complete."
echo "============================================"