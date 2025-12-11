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

# Help function
show_help() {
    echo -e "${WHITE}Xeol End-of-Life Detection Scanner${NC}"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Detects End-of-Life (EOL) packages and technologies in your project."
    echo "Identifies software that is no longer maintained or receiving security updates."
    echo ""
    echo "Options:"
    echo "  -h, --help          Show this help message and exit"
    echo ""
    echo "Environment Variables:"
    echo "  TARGET_DIR          Directory to scan (default: current directory)"
    echo "  SCAN_ID             Override auto-generated scan ID"
    echo "  SCAN_DIR            Override output directory for scan results"
    echo ""
    echo "Output:"
    echo "  Results are saved to: scans/{SCAN_ID}/xeol/"
    echo "  - xeol-filesystem-results.json    EOL software detected"
    echo "  - xeol-scan.log                   Scan process log"
    echo ""
    echo "Detection Capabilities:"
    echo "  - Operating system EOL detection"
    echo "  - Programming language runtime EOL (Node.js, Python, etc.)"
    echo "  - Framework and library EOL status"
    echo "  - Database EOL status"
    echo ""
    echo "Examples:"
    echo "  $0                              # Scan current directory"
    echo "  TARGET_DIR=/path/to/project $0  # Scan specific directory"
    echo ""
    echo "Notes:"
    echo "  - Requires Docker to be installed and running"
    echo "  - Uses xeol/xeol:latest Docker image"
    echo "  - EOL dates sourced from endoflife.date"
    exit 0
}

# Parse arguments
for arg in "$@"; do
    case $arg in
        -h|--help)
            show_help
            ;;
    esac
done

# Initialize scan environment using scan directory approach
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_DIR="$(cd "$SCRIPT_DIR/../../configuration" && pwd)"

# Source the scan directory template
source "$SCRIPT_DIR/scan-directory-template.sh"

# Source approved base images configuration
if [ -f "$CONFIG_DIR/approved-base-images.conf" ]; then
    source "$CONFIG_DIR/approved-base-images.conf"
fi

# Initialize scan environment for Xeol
init_scan_environment "xeol"

# Set REPO_PATH and extract scan information
REPO_PATH="${TARGET_DIR:-$(pwd)}"
if [[ -n "$SCAN_ID" ]]; then
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

# Set REPO_ROOT for compatibility
REPORTS_ROOT="$(dirname "$(dirname "$SCRIPT_DIR"))")"

# Create output directory
mkdir -p "$OUTPUT_DIR"

echo
echo -e "${WHITE}============================================${NC}"
echo -e "${WHITE}Xeol End-of-Life Detection Scanner${NC}"
echo -e "${WHITE}============================================${NC}"
echo "Target: $REPO_PATH"
echo "Output Directory: $OUTPUT_DIR"
echo "Timestamp: $TIMESTAMP"
echo

# Display target analysis for transparency
if [ -d "$REPO_PATH" ]; then
    TOTAL_FILES=$(count_scannable_files "$REPO_PATH" "*")
    echo -e "${CYAN}📊 EOL Detection Analysis:${NC}"
    echo -e "   📁 Target Directory: $REPO_PATH"
    echo -e "   📄 Total Files to Analyze: $TOTAL_FILES"
    echo -e "   🐳 Base Images to Check: ${#BASE_IMAGES[@]:-5}"
    echo
fi

# Create persistent volume for Xeol cache to speed up subsequent scans
XEOL_CACHE_VOL="xeol-cache"
docker volume create "$XEOL_CACHE_VOL" 2>/dev/null || true

# Update Xeol EOL database before scanning
echo -e "${CYAN}📥 Updating Xeol end-of-life database...${NC}"
echo "This ensures we have the latest EOL data..."

docker run --rm \
    -v "$XEOL_CACHE_VOL:/root/.cache" \
    xeol/xeol:latest \
    db update 2>&1 | tee -a "$SCAN_LOG"

DB_UPDATE_RESULT=$?
if [ $DB_UPDATE_RESULT -eq 0 ]; then
    echo -e "${GREEN}✅ Xeol EOL database updated successfully${NC}"
else
    echo -e "${YELLOW}⚠️  Database update had issues (exit code: $DB_UPDATE_RESULT)${NC}"
    echo "   Proceeding with cached database..."
fi

# Show database info
echo -e "${CYAN}📋 Checking Xeol database status...${NC}"
docker run --rm \
    -v "$XEOL_CACHE_VOL:/root/.cache" \
    xeol/xeol:latest \
    db status 2>&1 | tee -a "$SCAN_LOG"
echo

# Function to scan a target
scan_target() {
    local scan_type="$1"
    local target="$2"
    local output_file="$3"
    
    if [ ! -z "$target" ] && [ ! -z "$output_file" ]; then
        echo -e "${BLUE}🔍 Scanning ${scan_type}: ${target}${NC}"
        
        local full_output_path="$OUTPUT_DIR/$output_file"
        
        # Run xeol scan with Docker using cached/updated database
        if [ "$scan_type" = "dir" ]; then
            # For directory scans, mount the target directory
            docker run --rm \
                -v "$target:/workspace:ro" \
                -v "$XEOL_CACHE_VOL:/root/.cache" \
                xeol/xeol:latest \
                dir:/workspace \
                -o json 2>>"$SCAN_LOG" > "$full_output_path"
        else
            # For image scans, mount Docker socket to access host's Docker daemon
            docker run --rm \
                -v /var/run/docker.sock:/var/run/docker.sock \
                -v "$XEOL_CACHE_VOL:/root/.cache" \
                xeol/xeol:latest \
                "docker:$target" \
                -o json 2>>"$SCAN_LOG" > "$full_output_path"
        fi
        
        local exit_code=$?
        if [ $exit_code -eq 0 ] && [ -f "$full_output_path" ] && [ -s "$full_output_path" ]; then
            local eol_count=$(jq '.matches | length' "$full_output_path" 2>/dev/null || echo "0")
            echo -e "${GREEN}   ✅ Scan completed: $eol_count EOL components found${NC}"
            echo "${scan_type} scan ($target): $eol_count EOL components" >> "$SCAN_LOG"
        else
            echo -e "${RED}   ❌ Scan failed or no output for $target${NC}"
            echo "${scan_type} scan ($target): FAILED" >> "$SCAN_LOG"
            # Create empty result file
            echo '{"matches": [], "source": {"type": "'"$scan_type"'", "target": "'"$target"'"}}' > "$full_output_path"
        fi
        echo
    fi
}

# 1. End-of-Life Detection
echo -e "${CYAN}⚰️  Step 1: End-of-Life Package Detection${NC}"
echo "========================================"

# Scan common base images for EOL packages - use centralized config if available
if [ ${#APPROVED_BASE_IMAGES[@]} -gt 0 ]; then
    BASE_IMAGES=("${APPROVED_BASE_IMAGES[@]}")
    echo -e "${CYAN}📋 Using ${#BASE_IMAGES[@]} approved Bitnami hardened base images${NC}"
else
    # Fallback to minimal Bitnami images
    BASE_IMAGES=(
        "bitnami/nginx:latest"
        "bitnami/node:latest"
        "bitnami/python:latest"
        "bitnami/postgresql:latest"
    )
fi

IMAGES_SCANNED=0
for image in "${BASE_IMAGES[@]}"; do
    if command -v docker &> /dev/null; then
        echo -e "${BLUE}📦 Scanning base image: $image${NC}"
        
        # Check if image exists locally first
        if docker image inspect "$image" &>/dev/null; then
            echo "   ✅ Using cached image"
        else
            echo "   ⏬ Pulling image..."
            if ! docker pull "$image" >> "$SCAN_LOG" 2>&1; then
                echo "   ⚠️ Pull failed - skipping this image"
                continue
            fi
        fi
        
        image_name=$(echo $image | tr ':/' '-')
        output_file="${SCAN_ID}_xeol-base-${image_name}-results.json"
        scan_target "image" "$image" "$output_file"
        
        # Create current symlink for easy access
        ln -sf "$output_file" "$OUTPUT_DIR/xeol-base-$image_name-results.json" 2>/dev/null
        IMAGES_SCANNED=$((IMAGES_SCANNED + 1))
    fi
done

# Always scan the target filesystem
if [ -d "$REPO_PATH" ]; then
    echo -e "${BLUE}📁 Scanning filesystem for EOL components: $REPO_PATH${NC}"
    output_file="${SCAN_ID}_xeol-filesystem-results.json"
    scan_target "dir" "$REPO_PATH" "$output_file"
    # Create current symlink
    ln -sf "$output_file" "$OUTPUT_DIR/xeol-filesystem-results.json" 2>/dev/null
fi

echo
echo -e "${CYAN}📊 Xeol End-of-Life Detection Summary${NC}"
echo "===================================="
echo -e "🐳 Base images scanned: $IMAGES_SCANNED"

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
echo "• Xeol Documentation: https://github.com/xeol-io/xeol"
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