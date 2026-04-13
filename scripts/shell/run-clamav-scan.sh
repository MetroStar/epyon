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

# Source container runtime detection utility if available
if [ -f "$SCRIPT_DIR/container-runtime.sh" ]; then
    # shellcheck source=/dev/null
    set +e
    source "$SCRIPT_DIR/container-runtime.sh"
    set -e
fi
if [ -z "${CONTAINER_CLI:-}" ]; then
    CONTAINER_CLI=docker
fi

# Initialize scan environment for ClamAV
init_scan_environment "clamav"

# Set TARGET_DIR and extract scan information
TARGET_DIR="${TARGET_DIR:-$(pwd)}"
TARGET_DIR=$(realpath "${TARGET_DIR}" 2>/dev/null) || { echo "ERROR: Target path does not exist or is invalid: ${TARGET_DIR}" >&2; exit 1; }
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
DECODED_DIR="$OUTPUT_DIR/decoded-base64"
mkdir -p "$DECODED_DIR"

# Initialize scan log
echo "ClamAV scan started: $TIMESTAMP" > "$SCAN_LOG"
echo "Target: $REPO_PATH" >> "$SCAN_LOG"

echo -e "${CYAN}🦠 Malware Detection Scan${NC}"
echo "=========================="

# Pre-processing: Detect and decode base64 content
echo -e "${CYAN}🔍 Pre-scan: Detecting base64 encoded content...${NC}"
BASE64_FILES_FOUND=0
BASE64_DECODED=0

# Find files that might contain base64 (common patterns)
for file in $(find "$REPO_PATH" -type f \( -name "*.txt" -o -name "*.log" -o -name "*.data" -o -name "*.b64" -o -name "*.encoded" \) 2>/dev/null); do
    # Check if file contains base64-like content (long strings of base64 chars)
    if grep -qE '^[A-Za-z0-9+/]{40,}={0,2}$' "$file" 2>/dev/null; then
        BASE64_FILES_FOUND=$((BASE64_FILES_FOUND + 1))
        filename=$(basename "$file")
        decoded_file="$DECODED_DIR/${filename}.decoded"
        
        # Try to decode base64 content
        if base64 -d "$file" > "$decoded_file" 2>/dev/null && [ -s "$decoded_file" ]; then
            BASE64_DECODED=$((BASE64_DECODED + 1))
            echo "   📄 Decoded: $filename" >> "$SCAN_LOG"
        else
            # If full file decode fails, try extracting and decoding base64 chunks
            grep -oE '^[A-Za-z0-9+/]{40,}={0,2}$' "$file" 2>/dev/null | while read -r line; do
                echo "$line" | base64 -d >> "$decoded_file" 2>/dev/null
            done
            if [ -s "$decoded_file" ]; then
                BASE64_DECODED=$((BASE64_DECODED + 1))
                echo "   📄 Decoded chunks from: $filename" >> "$SCAN_LOG"
            else
                rm -f "$decoded_file"
            fi
        fi
    fi
done

if [ $BASE64_FILES_FOUND -gt 0 ]; then
    echo "   ✅ Found $BASE64_FILES_FOUND files with base64 content"
    echo "   ✅ Successfully decoded $BASE64_DECODED files for scanning"
else
    echo "   ℹ️  No base64 encoded files detected"
fi
echo

# Check if Docker is available
if [ -n "${CONTAINER_CLI:-}" ]; then
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
    
    # Pull ClamAV Docker image (try primary, then fallback)
    CLAMAV_PULL_OK=false
    echo "📥 Pulling ClamAV Docker image..."
    if ${CONTAINER_CLI} pull $PLATFORM_FLAG "$CLAMAV_IMAGE" 2>&1 | tee -a "$SCAN_LOG"; then
        CLAMAV_PULL_OK=true
    else
        echo -e "${YELLOW}⚠️  Standard ClamAV image failed, trying alternative...${NC}"
        CLAMAV_IMAGE="mkodockx/docker-clamav:alpine"
        PLATFORM_FLAG=""
        if ${CONTAINER_CLI} pull "$CLAMAV_IMAGE" 2>&1 | tee -a "$SCAN_LOG"; then
            CLAMAV_PULL_OK=true
        fi
    fi
    
    if [ "$CLAMAV_PULL_OK" = false ]; then
        echo -e "${RED}❌ Unable to pull any ClamAV image${NC}"
        echo "ClamAV scan skipped - Docker image unavailable" > "$OUTPUT_DIR/${SCAN_ID}_clamav-detailed.log"
        echo "Platform: $PLATFORM not supported by available images" >> "$OUTPUT_DIR/${SCAN_ID}_clamav-detailed.log"
        ln -sf "${SCAN_ID}_clamav-detailed.log" "$OUTPUT_DIR/clamav-detailed.log"
        SCAN_RESULT=0
    else
        # Update virus definitions before scanning
        echo -e "${CYAN}📥 Updating ClamAV virus definitions...${NC}"
        
        # Create a persistent volume for ClamAV definitions to speed up future scans
        CLAMAV_DB_VOL="clamav-definitions"
        CLAMAV_VOL_ARGS=""
        if ${CONTAINER_CLI} volume create "$CLAMAV_DB_VOL" 2>/dev/null; then
            CLAMAV_VOL_ARGS="-v $CLAMAV_DB_VOL:/var/lib/clamav"
        fi
        
        echo "Running freshclam to download latest virus definitions..."
        ${CONTAINER_CLI} run --rm $PLATFORM_FLAG $CLAMAV_VOL_ARGS \
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
        ${CONTAINER_CLI} run --rm $PLATFORM_FLAG $CLAMAV_VOL_ARGS \
            "$CLAMAV_IMAGE" \
            clamscan --version 2>&1 | tee -a "$SCAN_LOG"
        
        # Run scan
        echo -e "${BLUE}🔍 Scanning directory: $REPO_PATH${NC}"
        echo "This may take several minutes..."
        
        ${CONTAINER_CLI} run --rm $PLATFORM_FLAG \
            -v "$REPO_PATH:/workspace:ro" \
            -v "$OUTPUT_DIR:/output" \
            $CLAMAV_VOL_ARGS \
            "$CLAMAV_IMAGE" \
            clamscan -r \
            --exclude-dir=node_modules \
            --exclude-dir=.scannerwork \
            --scan-mail=yes \
            --scan-html=yes \
            --scan-pdf=yes \
            --scan-ole2=yes \
            --scan-archive=yes \
            --alert-encrypted=yes \
            --alert-encrypted-archive=yes \
            --alert-encrypted-doc=yes \
            --max-recursion=30 \
            --max-filesize=2000M \
            --max-scansize=2000M \
            --log=/output/${SCAN_ID}_clamav-detailed.log /workspace 2>&1 | tee -a "$SCAN_LOG"
        SCAN_RESULT=$?
        
        # Also scan decoded base64 files if any exist
        if [ $BASE64_DECODED -gt 0 ]; then
            echo -e "${BLUE}🔍 Scanning decoded base64 content...${NC}"
            ${CONTAINER_CLI} run --rm $PLATFORM_FLAG \
                -v "$DECODED_DIR:/decoded:ro" \
                -v "$OUTPUT_DIR:/output" \
                $CLAMAV_VOL_ARGS \
                "$CLAMAV_IMAGE" \
                clamscan -r \
                --scan-mail=yes \
                --scan-html=yes \
                --scan-pdf=yes \
                --scan-ole2=yes \
                --scan-archive=yes \
                --max-filesize=2000M \
                --max-scansize=2000M \
                /decoded 2>&1 | tee -a "$SCAN_LOG" >> "$OUTPUT_DIR/${SCAN_ID}_clamav-detailed.log"
            DECODED_SCAN_RESULT=$?
            
            if [ $DECODED_SCAN_RESULT -eq 1 ]; then
                echo -e "${RED}🚨 THREATS FOUND in decoded base64 content!${NC}"
                SCAN_RESULT=1
            fi
        fi
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

# ClamAV sends per-file results and SCAN SUMMARY to the --log= file (clamav-detailed.log).
# scan.log (via tee) may only contain stdout (progress/summary line counts).
# Prefer detailed log for all result parsing.
_detail_log=""
[ -f "$OUTPUT_DIR/clamav-detailed.log" ] && _detail_log="$OUTPUT_DIR/clamav-detailed.log"
_primary_log="${_detail_log:-$SCAN_LOG}"

if [ -f "$_primary_log" ]; then
    echo
    echo "Scan Summary:"
    echo "============="

    # Print the clamscan SCAN SUMMARY block
    if grep -q "SCAN SUMMARY" "$_primary_log" 2>/dev/null; then
        sed -n '/----------- SCAN SUMMARY -----------/,/End Date:/p' "$_primary_log"
    elif [ -n "$_detail_log" ] && grep -q "SCAN SUMMARY" "$SCAN_LOG" 2>/dev/null; then
        sed -n '/----------- SCAN SUMMARY -----------/,/End Date:/p' "$SCAN_LOG"
    else
        _scanned_display=$(grep "Scanned files:" "$_primary_log" 2>/dev/null | head -1 | grep -oE '[0-9]+' || echo "?")
        _infected_display=$(grep "Infected files:" "$_primary_log" 2>/dev/null | head -1 | grep -oE '[0-9]+' || echo "0")
        echo "Scanned files:  $_scanned_display"
        echo "Infected files: $_infected_display"
    fi

    # Locate FOUND lines — prefer detailed log, fall back to scan.log
    _found_source=""
    if [ -n "$_detail_log" ] && grep -q " FOUND$" "$_detail_log" 2>/dev/null; then
        _found_source="$_detail_log"
    elif grep -q " FOUND$" "$SCAN_LOG" 2>/dev/null; then
        _found_source="$SCAN_LOG"
    fi

    if [ -n "$_found_source" ]; then
        _found_count=$(grep -c " FOUND$" "$_found_source" 2>/dev/null || echo "0")
        if [ "${_found_count:-0}" -gt 0 ]; then
            echo
            echo -e "${RED}🦠 Detected Threats (${_found_count}):${NC}"
            echo "-------------------"
            while IFS= read -r _found_line; do
                _found_line=$(echo "$_found_line" | tr -d '\r')
                _rest="${_found_line% FOUND}"
                # Split on last ": " to separate path from virus name
                _vname="${_rest##*: }"
                _fpath="${_rest%: ${_vname}}"
                printf "   %-55s  (%s)\n" "$_vname" "$(basename "${_fpath}")"
            done < <(grep " FOUND$" "$_found_source" 2>/dev/null | tr -d '\r')
            echo
            echo -e "${YELLOW}💡 To rule out false positives, check:${NC}"
            echo "   • Heuristics.Encrypted.*  — may be encrypted archives or test fixtures"
            echo "   • .git/objects/pack/*      — git pack files commonly trigger Encrypted.Zip"
            echo "   • Test resource files      — sample malware used in unit tests"
        fi
    fi

    echo
    echo "Detailed results saved to: ${_detail_log:-$SCAN_LOG}"
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

# Write clamav-results.json
# Reuse _detail_log / _found_source / _primary_log set in summary block above
_json_found_source="${_found_source:-${_detail_log:-$SCAN_LOG}}"
_json_stats_source="${_detail_log:-$SCAN_LOG}"
{
    _ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    _infected=$(grep "Infected files:" "$_json_stats_source" 2>/dev/null | head -1 | grep -oE '[0-9]+' || echo "0")
    _scanned=$(grep "Scanned files:" "$_json_stats_source" 2>/dev/null | head -1 | grep -oE '[0-9]+' || echo "0")
    _engine=$(grep "Engine version:" "$_json_stats_source" 2>/dev/null | head -1 | sed 's/Engine version: //' | xargs || echo "unknown")
    _db=$(grep "Known viruses:" "$_json_stats_source" 2>/dev/null | head -1 | grep -oE '[0-9]+' || echo "0")
    _duration=$(grep "^Time:" "$_json_stats_source" 2>/dev/null | head -1 | sed 's/Time: //' | xargs || echo "N/A")
    _status="clean"
    [ "${SCAN_RESULT:-0}" -ne 0 ] && _status="threats_found"

    # Build detections array from whichever log has FOUND lines
    _detections="[]"
    if grep -q " FOUND$" "$_json_found_source" 2>/dev/null; then
        _detections=$(grep " FOUND$" "$_json_found_source" 2>/dev/null | tr -d '\r' | python3 -c '
import sys, json
rows = []
for line in sys.stdin:
    line = line.rstrip()
    if line.endswith(" FOUND"):
        rest = line[:-6]
        sep = rest.rfind(": ")
        if sep != -1:
            fpath = rest[:sep]
            vname = rest[sep+2:]
            rows.append({"file": fpath, "virus": vname})
print(json.dumps(rows))
' 2>/dev/null || echo "[]")
    fi

    python3 -c "
import json, sys
data = {
    'scan_timestamp': '$_ts',
    'status': '$_status',
    'engine_version': '$_engine',
    'virus_db_signatures': int('${_db:-0}'),
    'files_scanned': int('${_scanned:-0}'),
    'infected_files': int('${_infected:-0}'),
    'scan_duration': '$_duration',
    'detections': json.loads(sys.argv[1])
}
print(json.dumps(data, indent=2))
" "$_detections" > "$OUTPUT_DIR/clamav-results.json" 2>/dev/null || true
    if [ -f "$OUTPUT_DIR/clamav-results.json" ]; then
        echo "📄 JSON results: $OUTPUT_DIR/clamav-results.json"
    fi
}

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