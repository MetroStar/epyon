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

# Help function
show_help() {
    echo -e "${WHITE}Trivy Security Scanner${NC}"
    echo ""
    echo "Usage: $0 [OPTIONS] [TARGET_DIRECTORY]"
    echo ""
    echo "Performs comprehensive vulnerability scanning using Trivy."
    echo "Scans containers, filesystems, and base images for security vulnerabilities."
    echo ""
    echo "Arguments:"
    echo "  TARGET_DIRECTORY    Path to directory to scan (default: current directory)"
    echo ""
    echo "Options:"
    echo "  -h, --help          Show this help message and exit"
    echo ""
    echo "Environment Variables:"
    echo "  TARGET_DIR          Alternative way to specify target directory"
    echo "  SCAN_ID             Override auto-generated scan ID"
    echo "  SCAN_DIR            Override output directory for scan results"
    echo ""
    echo "Output:"
    echo "  Results are saved to: scans/{SCAN_ID}/trivy/"
    echo "  - trivy-filesystem-results.json   Filesystem vulnerability scan"
    echo "  - trivy-base-*.json               Base image scans (if images found)"
    echo ""
    echo "Examples:"
    echo "  $0                              # Scan current directory"
    echo "  $0 /path/to/project             # Scan specific directory"
    echo "  TARGET_DIR=/app $0              # Scan via environment variable"
    echo ""
    echo "Notes:"
    echo "  - Requires Docker to be installed and running"
    echo "  - Automatically skips node_modules directories"
    echo "  - Uses aquasec/trivy:latest Docker image"
    exit 0
}

# Parse arguments
SCAN_MODE=""
for arg in "$@"; do
    case $arg in
        -h|--help)
            show_help
            ;;
        filesystem|images|base|registry|kubernetes|all)
            # This is a scan mode, not a path
            SCAN_MODE="$arg"
            ;;
    esac
done

# Initialize scan environment using scan directory approach
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_DIR="$(cd "$SCRIPT_DIR/../../configuration" && pwd)"

# Source the scan directory template
source "$SCRIPT_DIR/scan-directory-template.sh"

# Source container runtime detection utility if available
if [ -f "$SCRIPT_DIR/container-runtime.sh" ]; then
    # shellcheck source=/dev/null
    source "$SCRIPT_DIR/container-runtime.sh"
fi
# Fallback to docker CLI name if detection didn't find anything
if [ -z "${CONTAINER_CLI:-}" ]; then
    CONTAINER_CLI=docker
fi

# Source approved base images configuration only if PRIMARY_BASELINE_IMAGE is not already set
if [ -z "${PRIMARY_BASELINE_IMAGE:-}" ] && [ -f "$CONFIG_DIR/approved-base-images.conf" ]; then
    source "$CONFIG_DIR/approved-base-images.conf"
    echo "✅ Loaded approved base images configuration"
fi

# Initialize scan environment for Trivy
init_scan_environment "trivy"

# Set REPO_PATH - use TARGET_DIR from environment (preferred) or check if $1 is a valid directory
if [ -n "$TARGET_DIR" ] && [ -d "$TARGET_DIR" ]; then
    REPO_PATH="$TARGET_DIR"
elif [ -n "$1" ] && [ -d "$1" ]; then
    REPO_PATH="$1"
else
    REPO_PATH="$(pwd)"
fi

echo
echo -e "${WHITE}============================================${NC}"
echo -e "${WHITE}Trivy Multi-Target Security Scanner${NC}"
echo -e "${WHITE}============================================${NC}"
echo

# Display file count for transparency
if [ -d "$REPO_PATH" ]; then
    TOTAL_FILES=$(count_scannable_files "$REPO_PATH" "*")
    echo -e "${CYAN}📊 Target Analysis:${NC}"
    echo -e "   📁 Target Directory: $REPO_PATH"
    echo -e "   📄 Total Files to Scan: $TOTAL_FILES"
    get_file_breakdown "$REPO_PATH"
    echo
fi

# Create persistent volume for Trivy cache to speed up subsequent scans
TRIVY_CACHE_VOL="trivy-cache"
${CONTAINER_CLI} volume create "$TRIVY_CACHE_VOL" 2>/dev/null || true

# Update Trivy vulnerability database before scanning
echo -e "${CYAN}📥 Updating Trivy vulnerability database...${NC}"
echo "This ensures we have the latest CVE data (may take 1-2 minutes on first run)..."

${CONTAINER_CLI} run --rm \
    -v "$TRIVY_CACHE_VOL:/root/.cache" \
    aquasec/trivy:latest \
    image --download-db-only 2>&1 | tee -a "$SCAN_LOG"

DB_UPDATE_RESULT=$?
if [ $DB_UPDATE_RESULT -eq 0 ]; then
    echo -e "${GREEN}✅ Trivy vulnerability database updated successfully${NC}"
else
    echo -e "${YELLOW}⚠️  Database update had issues (exit code: $DB_UPDATE_RESULT)${NC}"
    echo "   Proceeding with cached database..."
fi

# Show database info
echo -e "${CYAN}📋 Checking Trivy database status...${NC}"
${CONTAINER_CLI} run --rm \
    -v "$TRIVY_CACHE_VOL:/root/.cache" \
    aquasec/trivy:latest \
    version 2>&1 | grep -E "(Version|VulnerabilityDB)" | tee -a "$SCAN_LOG"
echo

# Function to scan a target
run_trivy_scan() {
    local scan_type="$1"
    local target="$2"
    local output_file="$OUTPUT_DIR/${SCAN_ID}_trivy-${scan_type}-results.json"
    local current_file="$OUTPUT_DIR/trivy-${scan_type}-results.json"
    
    if [ ! -z "$target" ] && [ ! -z "$output_file" ]; then
        echo -e "${BLUE}🔍 Scanning ${scan_type}: ${target}${NC}"
        
        # Run trivy scan with Docker using cached/updated database
        if [ -n "${CONTAINER_CLI:-}" ]; then
            # Determine if this is an image scan or filesystem scan
            if [[ "$scan_type" == "base-"* ]] || [[ "$target" == *":"* ]]; then
                # Image scan - mount Docker socket to access host images
                # Try to use locally cached image first, fall back to remote scan
                echo "   Scanning container image: $target"
                ${CONTAINER_CLI} run --rm \
                    -v /var/run/docker.sock:/var/run/docker.sock \
                    -v "$TRIVY_CACHE_VOL:/root/.cache" \
                    aquasec/trivy:latest \
                    image "$target" \
                    --format json --quiet 2>> "$SCAN_LOG" > "$output_file"
            else
                # Filesystem scan - scan everything including node_modules for complete vulnerability detection
                ${CONTAINER_CLI} run --rm \
                    -v "${target}:/workspace:ro" \
                    -v "$TRIVY_CACHE_VOL:/root/.cache" \
                    aquasec/trivy:latest \
                    fs /workspace \
                    --format json 2>> "$SCAN_LOG" > "$output_file"
            fi
            
            local exit_code=$?
            if [ $exit_code -eq 0 ] && [ -f "$output_file" ] && [ -s "$output_file" ]; then
                echo -e "${GREEN}✅ Scan completed: $output_file${NC}"
                # Create/update current symlink for easy access
                ln -sf "$(basename "$output_file")" "$current_file" 2>/dev/null
            else
                echo -e "${RED}❌ Scan failed for $target${NC}"
                # Create empty result to prevent dashboard errors
                echo '{"Results": []}' > "$output_file"
            fi
        else
                echo -e "${RED}❌ Container runtime not available - Trivy scan skipped${NC}"
            echo '{"Results": []}' > "$output_file"
        fi
        echo
    fi
}

# 1. Container Security Scan (skip if mode is "filesystem" only)
if [ "$SCAN_MODE" != "filesystem" ]; then
    echo -e "${CYAN}🛡️  Step 1: Container Security Scan${NC}"
    echo "=================================="

    # Use PRIMARY_BASELINE_IMAGE if set by orchestrator, otherwise use configuration
    if [ -n "${PRIMARY_BASELINE_IMAGE:-}" ]; then
        BASE_IMAGES=("${PRIMARY_BASELINE_IMAGE}")
        echo "📋 Using user-selected baseline image"
    elif [ ${#APPROVED_BASE_IMAGES[@]} -gt 0 ]; then
        BASE_IMAGES=("${APPROVED_BASE_IMAGES[@]}")
        echo "📋 Using ${#BASE_IMAGES[@]} approved base images"
    else
        # Fallback to Docker Hardened Image
        BASE_IMAGES=(
            "dhi/caddy:debian-13-2-fips-dev@sha256:ba86d16733750c6fd7b8866981016d2479e234c842d77413f1bf41c4404e555c"
        )
    fi

    for image in "${BASE_IMAGES[@]}"; do
        if [ -n "${CONTAINER_CLI:-}" ]; then
            echo -e "${BLUE}📦 Scanning base image: $image${NC}"
            
            # Check if image exists locally first
            if $CONTAINER_CLI image inspect "$image" &>/dev/null; then
                echo "   ✅ Using cached image"
            else
                echo "   ⏬ Pulling image..."
                if ! $CONTAINER_CLI pull "$image" >> "$SCAN_LOG" 2>&1; then
                    echo "   ⚠️ Pull failed - skipping this image"
                    continue
                fi
            fi
            
            run_trivy_scan "base-$(echo $image | tr ':/' '-')" "$image"
        fi
    done
fi

# 2. Filesystem scan (skip if mode is "base" or "images" only)
if [ "$SCAN_MODE" != "base" ] && [ "$SCAN_MODE" != "images" ]; then
    if [ ! -z "$REPO_PATH" ] && [ -d "$REPO_PATH" ]; then
        echo -e "${CYAN}🛡️  Step 2: Filesystem Security Scan${NC}"
        echo "=================================="
        echo -e "${BLUE}📁 Scanning filesystem: $REPO_PATH${NC}"
        run_trivy_scan "filesystem" "$REPO_PATH"
    fi
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