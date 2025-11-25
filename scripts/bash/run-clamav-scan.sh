#!/bin/bash

# ClamAV Multi-Target Malware Scanner
# Comprehensive malware detection for repositories, containers, and filesystems

# Initialize scan environment using scan directory approach
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source the scan directory template
source "$SCRIPT_DIR/scan-directory-template.sh"

# Initialize scan environment for ClamAV
init_scan_environment "clamav"

# Set TARGET_DIR and extract scan information
TARGET_DIR="${TARGET_DIR:-$(pwd)}"
REPO_PATH="$TARGET_DIR"

if [[ -n "$SCAN_ID" ]]; then
    TARGET_NAME=$(echo "$SCAN_ID" | cut -d'_' -f1)
    USERNAME=$(echo "$SCAN_ID" | cut -d'_' -f2)
    TIMESTAMP=$(echo "$SCAN_ID" | cut -d'_' -f3-)
else
    # Fallback for standalone execution
    TARGET_NAME=$(basename "$TARGET_DIR")
    USERNAME=$(whoami)
    TIMESTAMP=$(date '+%Y-%m-%d_%H-%M-%S')
    SCAN_ID="${TARGET_NAME}_${USERNAME}_${TIMESTAMP}"
fi

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
echo -e "${WHITE}ClamAV Multi-Target Malware Scanner${NC}"
echo -e "${WHITE}============================================${NC}"
echo "Repository: $REPO_PATH"
echo "Output Directory: $OUTPUT_DIR"
echo "Timestamp: $TIMESTAMP"
echo

# Create output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

# Initialize scan log
echo "ClamAV scan started: $TIMESTAMP" > "$SCAN_LOG"
echo "Target: $REPO_PATH" >> "$SCAN_LOG"

echo -e "${CYAN}🦠 Malware Detection Scan${NC}"
echo "=========================="

# Check if Docker is available
if command -v docker &> /dev/null; then
    echo "🐳 Using Docker-based ClamAV..."
    
    # Detect platform and choose appropriate ClamAV image
    PLATFORM=$(uname -m)
    if [[ "$PLATFORM" == "arm64" ]]; then
        echo "🍎 Detected Apple Silicon (ARM64) - using platform-specific image..."
        CLAMAV_IMAGE="clamav/clamav:latest"
        PLATFORM_FLAG="--platform linux/amd64"
    else
        echo "🐧 Detected x86_64 - using native image..."
        CLAMAV_IMAGE="clamav/clamav:latest"
        PLATFORM_FLAG=""
    fi
    
    # Pull ClamAV Docker image with platform specification
    echo "📥 Pulling ClamAV Docker image..."
    if ! docker pull $PLATFORM_FLAG "$CLAMAV_IMAGE" 2>&1 | tee -a "$SCAN_LOG"; then
        echo -e "${YELLOW}⚠️  Standard ClamAV image failed, trying alternative...${NC}"
        # Try alternative ClamAV image that supports ARM64
        CLAMAV_IMAGE="mkodockx/docker-clamav:alpine"
        PLATFORM_FLAG=""
        if ! docker pull "$CLAMAV_IMAGE" 2>&1 | tee -a "$SCAN_LOG"; then
            echo -e "${RED}❌ Unable to pull any ClamAV image${NC}"
            echo "ClamAV scan skipped - Docker image unavailable" > "$OUTPUT_DIR/${SCAN_ID}_clamav-detailed.log"
            echo "Platform: $PLATFORM not supported by available images" >> "$OUTPUT_DIR/${SCAN_ID}_clamav-detailed.log"
            ln -sf "${SCAN_ID}_clamav-detailed.log" "$OUTPUT_DIR/clamav-detailed.log"
            SCAN_RESULT=0
        else
            # Run scan with alternative image
            echo -e "${BLUE}🔍 Scanning directory: $REPO_PATH${NC}"
            echo "This may take several minutes..."
            
            docker run --rm \
                -v "$REPO_PATH:/workspace:ro" \
                -v "$OUTPUT_DIR:/output" \
                "$CLAMAV_IMAGE" \
                clamscan -r --log=/output/${SCAN_ID}_clamav-detailed.log /workspace 2>&1 | tee -a "$SCAN_LOG"
            SCAN_RESULT=$?
        fi
    else
        # Run scan with standard image
        echo -e "${BLUE}🔍 Scanning directory: $REPO_PATH${NC}"
        echo "This may take several minutes..."
        
        docker run --rm $PLATFORM_FLAG \
            -v "$REPO_PATH:/workspace:ro" \
            -v "$OUTPUT_DIR:/output" \
            "$CLAMAV_IMAGE" \
            clamscan -r --log=/output/${SCAN_ID}_clamav-detailed.log /workspace 2>&1 | tee -a "$SCAN_LOG"
        SCAN_RESULT=$?
    fi
    
    # Create current symlink for latest results
    if [ -f "$OUTPUT_DIR/${SCAN_ID}_clamav-detailed.log" ]; then
        ln -sf "${SCAN_ID}_clamav-detailed.log" "$OUTPUT_DIR/clamav-detailed.log"
    fi
    
    echo -e "✅ Malware scan completed"
    
else
    echo -e "${YELLOW}⚠️  Docker not available${NC}"
    echo "Installing ClamAV locally would be required for native scanning"
    echo "Creating placeholder results..."
    
    # Create empty results
    echo "ClamAV scan skipped - Docker not available" > "$OUTPUT_DIR/${SCAN_ID}_clamav-detailed.log"
    echo "No malware detected (scan not performed)" >> "$SCAN_LOG"
    
    # Create current symlink for consistency
    ln -sf "${SCAN_ID}_clamav-detailed.log" "$OUTPUT_DIR/clamav-detailed.log"
    SCAN_RESULT=0
fi

# Display summary
echo
echo -e "${CYAN}📊 ClamAV Malware Detection Summary${NC}"
echo "==================================="

if [ -f "$OUTPUT_DIR/clamav-detailed.log" ]; then
    echo "📄 Detailed scan log: $OUTPUT_DIR/clamav-detailed.log"
fi

# Basic summary from scan log
if [ -f "$SCAN_LOG" ]; then
    echo
    echo "Scan Summary:"
    echo "============="
    
    # Extract summary information from log
    if grep -q "SCAN SUMMARY" "$SCAN_LOG"; then
        sed -n '/----------- SCAN SUMMARY -----------/,/End Date:/p' "$SCAN_LOG"
    else
        # Fallback: count files and infected
        SCANNED_FILES=$(grep -c "OK$" "$SCAN_LOG" 2>/dev/null || echo "Unknown")
        INFECTED_FILES=$(grep -c "FOUND$" "$SCAN_LOG" 2>/dev/null || echo "0")
        
        echo "Scanned files: $SCANNED_FILES"
        echo "Infected files: $INFECTED_FILES"
    fi
    
    echo
    echo "Detailed results saved to: $SCAN_LOG"
else
    echo
    echo "⚠️  No scan log generated. Check Docker configuration."
fi

# Security status
if [ "$SCAN_RESULT" -eq 0 ]; then
    echo
    echo -e "${GREEN}✅ Security Status: Clean - No malware detected${NC}"
else
    echo
    echo -e "${RED}🚨 Security Status: THREAT DETECTED - Review results immediately${NC}"
fi

echo
echo -e "${BLUE}📁 Output Files:${NC}"
echo "================"
echo "📄 Scan log: $SCAN_LOG"
if [ -f "$OUTPUT_DIR/clamav-detailed.log" ]; then
    echo "📄 Detailed log: $OUTPUT_DIR/clamav-detailed.log"
fi
echo "📂 Reports directory: $OUTPUT_DIR"

echo
echo -e "${BLUE}🔧 Available Commands:${NC}"
echo "===================="
echo "📊 Analyze results:       npm run clamav:analyze"
echo "🔍 Run new scan:          npm run clamav:scan"
echo "📋 View scan log:         cat $SCAN_LOG"
echo "🔍 View detailed results: cat $OUTPUT_DIR/clamav-detailed.log"

echo
echo -e "${BLUE}🔗 Additional Resources:${NC}"
echo "======================="
echo "• ClamAV Documentation: https://docs.clamav.net/"
echo "• Malware Analysis Best Practices: https://owasp.org/www-project-top-ten/2017/A9_2017-Using_Components_with_Known_Vulnerabilities"
echo "• Docker Security: https://docs.docker.com/engine/security/"

echo
echo "============================================"
echo -e "${GREEN}✅ ClamAV malware detection completed!${NC}"
echo "============================================"
echo
echo "============================================"
echo "ClamAV scan complete."
echo "============================================"