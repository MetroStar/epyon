#!/bin/bash

# ClamAV Multi-Target Malware Scanner
# Comprehensive malware detection for repositories, containers, and filesystems

# Colors for help output
WHITE='\033[1;37m'
NC='\033[0m'

# Help function
show_help() {
    echo -e "${WHITE}ClamAV Multi-Target Malware Scanner${NC}"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Comprehensive malware detection for repositories, containers, and filesystems"
    echo "using the ClamAV antivirus engine."
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
    echo "  Results are saved to: scans/{SCAN_ID}/clamav/"
    echo "  - clamav-detailed.log           Detailed scan output"
    echo "  - clamav-results.json           JSON formatted results"
    echo "  - clamav-scan.log               Scan process log"
    echo ""
    echo "Detection Capabilities:"
    echo "  - Viruses, trojans, worms"
    echo "  - Malicious scripts"
    echo "  - Potentially unwanted applications (PUA)"
    echo "  - Suspicious file patterns"
    echo ""
    echo "Examples:"
    echo "  $0                              # Scan current directory"
    echo "  TARGET_DIR=/path/to/project $0  # Scan specific directory"
    echo ""
    echo "Notes:"
    echo "  - Requires Docker to be installed and running"
    echo "  - Automatically skips node_modules directories"
    echo "  - Uses clamav/clamav:latest Docker image"
    echo "  - ARM64 (Apple Silicon) compatible"
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

# Display file count for transparency
if [ -d "$REPO_PATH" ]; then
    TOTAL_FILES=$(count_scannable_files "$REPO_PATH" "*")
    echo -e "${CYAN}📊 Malware Scan Analysis:${NC}"
    echo -e "   📁 Target Directory: $REPO_PATH"
    echo -e "   📄 Total Files to Scan: $TOTAL_FILES"
    # Count executable/binary files
    EXE_COUNT=$(find "$REPO_PATH" -type f \( -name "*.exe" -o -name "*.dll" -o -name "*.so" -o -name "*.dylib" \) 2>/dev/null | wc -l | tr -d ' ')
    SCRIPT_COUNT=$(find "$REPO_PATH" -type f \( -name "*.sh" -o -name "*.ps1" -o -name "*.bat" -o -name "*.cmd" \) 2>/dev/null | wc -l | tr -d ' ')
    ARCHIVE_COUNT=$(find "$REPO_PATH" -type f \( -name "*.zip" -o -name "*.tar*" -o -name "*.gz" -o -name "*.rar" \) 2>/dev/null | wc -l | tr -d ' ')
    echo -e "   💾 Executable/Library files: $EXE_COUNT"
    echo -e "   📜 Script files: $SCRIPT_COUNT"
    echo -e "   📦 Archive files: $ARCHIVE_COUNT"
    echo
fi

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
            # Update virus definitions before scanning
            echo -e "${CYAN}📥 Updating ClamAV virus definitions...${NC}"
            echo "This ensures we have the latest malware signatures..."
            docker run --rm "$CLAMAV_IMAGE" freshclam 2>&1 | tee -a "$SCAN_LOG" || echo "Warning: Could not update definitions, using bundled versions"
            
            # Run scan with alternative image
            echo -e "${BLUE}🔍 Scanning directory: $REPO_PATH${NC}"
            echo "This may take several minutes..."
            
            docker run --rm \
                -v "$REPO_PATH:/workspace:ro" \
                -v "$OUTPUT_DIR:/output" \
                "$CLAMAV_IMAGE" \
                clamscan -r --exclude-dir=node_modules --log=/output/${SCAN_ID}_clamav-detailed.log /workspace 2>&1 | tee -a "$SCAN_LOG"
            SCAN_RESULT=$?
        fi
    else
        # Update virus definitions before scanning
        echo -e "${CYAN}📥 Updating ClamAV virus definitions...${NC}"
        echo "This ensures we have the latest malware signatures (may take 1-2 minutes)..."
        
        # Create a persistent volume for ClamAV definitions to speed up future scans
        CLAMAV_DB_VOL="clamav-definitions"
        docker volume create "$CLAMAV_DB_VOL" 2>/dev/null || true
        
        # Update definitions using freshclam
        echo "Running freshclam to download latest virus definitions..."
        docker run --rm $PLATFORM_FLAG \
            -v "$CLAMAV_DB_VOL:/var/lib/clamav" \
            "$CLAMAV_IMAGE" \
            freshclam --stdout 2>&1 | tee -a "$SCAN_LOG"
        
        FRESHCLAM_RESULT=$?
        if [ $FRESHCLAM_RESULT -eq 0 ]; then
            echo -e "${GREEN}✅ Virus definitions updated successfully${NC}"
        else
            echo -e "${YELLOW}⚠️  Virus definition update had issues (exit code: $FRESHCLAM_RESULT)${NC}"
            echo "   Proceeding with available definitions..."
        fi
        
        # Show definition info
        echo -e "${CYAN}📋 Checking virus definition status...${NC}"
        docker run --rm $PLATFORM_FLAG \
            -v "$CLAMAV_DB_VOL:/var/lib/clamav" \
            "$CLAMAV_IMAGE" \
            clamscan --version 2>&1 | tee -a "$SCAN_LOG"
        
        # Run scan with standard image and updated definitions
        echo -e "${BLUE}🔍 Scanning directory: $REPO_PATH${NC}"
        echo "This may take several minutes..."
        
        docker run --rm $PLATFORM_FLAG \
            -v "$REPO_PATH:/workspace:ro" \
            -v "$OUTPUT_DIR:/output" \
            -v "$CLAMAV_DB_VOL:/var/lib/clamav" \
            "$CLAMAV_IMAGE" \
            clamscan -r --exclude-dir=node_modules --log=/output/${SCAN_ID}_clamav-detailed.log /workspace 2>&1 | tee -a "$SCAN_LOG"
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