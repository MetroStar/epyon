#!/bin/bash

# SBOM Export Script
# Exports SBOM data in multiple standard formats for compliance and tooling integration

# Colors for output
WHITE='\033[1;37m'
CYAN='\033[0;36m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# Help function
show_help() {
    echo -e "${WHITE}SBOM Export Utility${NC}"
    echo ""
    echo "Usage: $0 [OPTIONS] [SCAN_ID]"
    echo ""
    echo "Exports SBOM data in multiple standard formats for compliance and integration."
    echo "Supports CycloneDX and SPDX formats (JSON and XML variants)."
    echo ""
    echo "Arguments:"
    echo "  SCAN_ID             Specific scan ID to export (default: latest scan)"
    echo ""
    echo "Options:"
    echo "  -f, --format FORMAT Export specific format: cyclonedx-json, cyclonedx-xml,"
    echo "                      spdx-json, spdx-xml, or all (default: all)"
    echo "  -o, --output DIR    Output directory (default: scan's sbom/exports/)"
    echo "  -d, --desktop       Copy exports to ~/Desktop/sboms/ for easy access"
    echo "  -h, --help          Show this help message"
    echo ""
    echo "Supported Formats:"
    echo "  cyclonedx-json      CycloneDX 1.5 JSON format (widely supported)"
    echo "  cyclonedx-xml       CycloneDX 1.5 XML format"
    echo "  spdx-json           SPDX 2.3 JSON format"
    echo "  spdx-tag-value      SPDX 2.3 Tag-Value format"
    echo ""
    echo "Tool Integration:"
    echo "  • Dependency-Track  - Import cyclonedx-json or cyclonedx-xml"
    echo "  • OWASP OSS Index   - Import cyclonedx-json"
    echo "  • Snyk              - Import cyclonedx-json or spdx-json"
    echo "  • JFrog Xray        - Import cyclonedx-json or spdx-json"
    echo "  • GitHub Dependency - Import spdx-json"
    echo "  • GitLab Security   - Import cyclonedx-json"
    echo ""
    echo "Examples:"
    echo "  $0                                    # Export latest scan (all formats)"
    echo "  $0 midas_rnelson_2026-01-22_07-44-58 # Export specific scan"
    echo "  $0 -f cyclonedx-json                  # Export only CycloneDX JSON"
    echo "  $0 -o /tmp/exports                    # Export to custom directory"
    echo ""
    exit 0
}

# Parse arguments
FORMAT="all"
OUTPUT_DIR=""
SCAN_ID=""
COPY_TO_DESKTOP=false

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_help
            ;;
        -f|--format)
            FORMAT="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        -d|--desktop)
            COPY_TO_DESKTOP=true
            shift
            ;;
        -*)
            echo -e "${RED}❌ Unknown option: $1${NC}"
            echo "Use -h or --help for usage information"
            exit 1
            ;;
        *)
            SCAN_ID="$1"
            shift
            ;;
    esac
done

# Determine script and repository paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
SCANS_DIR="$REPO_ROOT/scans"
BASELINE_SCANS_DIR="$REPO_ROOT/baseline/scans"

# Find scan directory
if [[ -z "$SCAN_ID" ]]; then
    # Use latest scan (check both scans/ and baseline/scans/)
    SCAN_DIR=$(find "$SCANS_DIR" "$BASELINE_SCANS_DIR" -maxdepth 1 -type d -name "*_rnelson_*" 2>/dev/null | sort -r | head -1)
    if [[ -z "$SCAN_DIR" ]]; then
        echo -e "${RED}❌ No scans found in $SCANS_DIR or $BASELINE_SCANS_DIR${NC}"
        exit 1
    fi
    SCAN_ID=$(basename "$SCAN_DIR")
    echo -e "${CYAN}📋 Using latest scan: $SCAN_ID${NC}"
else
    # Check both scans/ and baseline/scans/ directories
    if [[ -d "$SCANS_DIR/$SCAN_ID" ]]; then
        SCAN_DIR="$SCANS_DIR/$SCAN_ID"
    elif [[ -d "$BASELINE_SCANS_DIR/$SCAN_ID" ]]; then
        SCAN_DIR="$BASELINE_SCANS_DIR/$SCAN_ID"
    else
        echo -e "${RED}❌ Scan directory not found in $SCANS_DIR or $BASELINE_SCANS_DIR${NC}"
        exit 1
    fi
fi

# Find SBOM directory
SBOM_DIR="$SCAN_DIR/sbom"
if [[ ! -d "$SBOM_DIR" ]]; then
    echo -e "${RED}❌ SBOM directory not found: $SBOM_DIR${NC}"
    echo "Run an SBOM scan first using run-sbom-scan.sh"
    exit 1
fi

# Find filesystem.json (Syft's native format)
SBOM_FILE="$SBOM_DIR/filesystem.json"
if [[ ! -f "$SBOM_FILE" ]]; then
    echo -e "${RED}❌ SBOM file not found: $SBOM_FILE${NC}"
    exit 1
fi

# Set output directory
if [[ -z "$OUTPUT_DIR" ]]; then
    OUTPUT_DIR="$SBOM_DIR/exports"
fi
mkdir -p "$OUTPUT_DIR"

echo -e "${WHITE}============================================${NC}"
echo -e "${WHITE}SBOM Export${NC}"
echo -e "${WHITE}============================================${NC}"
echo -e "${CYAN}📦 Scan ID:       $SCAN_ID${NC}"
echo -e "${CYAN}📁 Source SBOM:   $(basename "$SBOM_FILE")${NC}"
echo -e "${CYAN}💾 Export Dir:    $OUTPUT_DIR${NC}"
echo -e "${CYAN}🔧 Format:        $FORMAT${NC}"
echo ""

# Check if Syft is available
if ! command -v syft >/dev/null 2>&1 && ! command -v docker >/dev/null 2>&1; then
    echo -e "${RED}❌ Neither Syft nor Docker available for export${NC}"
    echo "Install Syft: brew install syft (macOS) or see https://github.com/anchore/syft"
    exit 1
fi

# Function to export using Syft
export_format() {
    local format="$1"
    local extension="$2"
    local output_file="$OUTPUT_DIR/sbom-$SCAN_ID.$extension"
    
    echo -e "${BLUE}📤 Exporting $format format...${NC}"
    
    # Check if Syft is available
    if command -v syft >/dev/null 2>&1; then
        # Use local Syft to convert from existing SBOM
        if syft convert "$SBOM_FILE" -o "$format" > "$output_file" 2>/dev/null; then
            local size=$(du -h "$output_file" | cut -f1)
            echo -e "${GREEN}✅ Exported: $(basename "$output_file") ($size)${NC}"
            return 0
        else
            echo -e "${YELLOW}⚠️  Failed to export $format${NC}"
            return 1
        fi
    elif command -v docker >/dev/null 2>&1; then
        # Use Docker version - convert from existing SBOM
        local sbom_dir=$(dirname "$SBOM_FILE")
        local sbom_name=$(basename "$SBOM_FILE")
        
        if docker run --rm \
            -v "$sbom_dir":/sbom:ro \
            -v "$OUTPUT_DIR":/output \
            anchore/syft:latest \
            convert "/sbom/$sbom_name" -o "$format" > "$output_file" 2>/dev/null; then
            local size=$(du -h "$output_file" | cut -f1)
            echo -e "${GREEN}✅ Exported: $(basename "$output_file") ($size)${NC}"
            return 0
        else
            echo -e "${YELLOW}⚠️  Failed to export $format using Docker${NC}"
            return 1
        fi
    else
        echo -e "${RED}❌ Neither Syft nor Docker available${NC}"
        return 1
    fi
}

# Export formats
SUCCESS_COUNT=0
TOTAL_COUNT=0

case "$FORMAT" in
    cyclonedx-json)
        export_format "cyclonedx-json" "cyclonedx.json" && SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
        TOTAL_COUNT=1
        ;;
    cyclonedx-xml)
        export_format "cyclonedx-xml" "cyclonedx.xml" && SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
        TOTAL_COUNT=1
        ;;
    spdx-json)
        export_format "spdx-json" "spdx.json" && SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
        TOTAL_COUNT=1
        ;;
    spdx-tag-value)
        export_format "spdx-tag-value" "spdx" && SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
        TOTAL_COUNT=1
        ;;
    all)
        export_format "cyclonedx-json" "cyclonedx.json" && SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
        export_format "cyclonedx-xml" "cyclonedx.xml" && SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
        export_format "spdx-json" "spdx.json" && SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
        export_format "spdx-tag-value" "spdx" && SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
        TOTAL_COUNT=4
        ;;
    *)
        echo -e "${RED}❌ Invalid format: $FORMAT${NC}"
        echo "Valid formats: cyclonedx-json, cyclonedx-xml, spdx-json, spdx-tag-value, all"
        exit 1
        ;;
esac

echo ""
echo -e "${WHITE}============================================${NC}"
echo -e "${WHITE}Export Summary${NC}"
echo -e "${WHITE}============================================${NC}"
echo -e "${GREEN}✅ Exported $SUCCESS_COUNT of $TOTAL_COUNT formats${NC}"
echo ""
echo -e "${CYAN}📁 Export Location:${NC}"
echo -e "   $OUTPUT_DIR"
echo ""
echo -e "${CYAN}📋 Exported Files:${NC}"
find "$OUTPUT_DIR" -type f -name "sbom-$SCAN_ID.*" | while read file; do
    size=$(du -h "$file" | cut -f1)
    echo -e "   📄 $(basename "$file") ($size)"
done

# Copy to Desktop if requested
if [ "$COPY_TO_DESKTOP" = true ]; then
    DESKTOP_DIR="$HOME/Desktop/sboms"
    mkdir -p "$DESKTOP_DIR"
    
    echo ""
    echo -e "${CYAN}📥 Copying exports to Desktop...${NC}"
    
    COPIED_COUNT=0
    find "$OUTPUT_DIR" -type f -name "sbom-$SCAN_ID.*" | while read file; do
        cp "$file" "$DESKTOP_DIR/"
        if [ $? -eq 0 ]; then
            COPIED_COUNT=$((COPIED_COUNT + 1))
            echo -e "   ${GREEN}✓${NC} Copied $(basename "$file")"
        fi
    done
    
    echo ""
    echo -e "${GREEN}✅ SBOM files copied to: $DESKTOP_DIR${NC}"
    echo -e "${CYAN}📂 Open folder: open $DESKTOP_DIR${NC}"
fi

echo ""
echo -e "${CYAN}🔧 Integration Examples:${NC}"
echo ""
echo -e "${BLUE}Dependency-Track (CycloneDX):${NC}"
echo -e "   curl -X POST http://your-server/api/v1/bom \\"
echo -e "     -H 'X-Api-Key: YOUR_API_KEY' \\"
echo -e "     -F 'project=PROJECT_UUID' \\"
echo -e "     -F 'bom=@$OUTPUT_DIR/sbom-$SCAN_ID.cyclonedx.json'"
echo ""
echo -e "${BLUE}GitHub Dependency Submission (SPDX):${NC}"
echo -e "   gh api /repos/OWNER/REPO/dependency-graph/snapshots \\"
echo -e "     --method POST \\"
echo -e "     --input $OUTPUT_DIR/sbom-$SCAN_ID.spdx.json"
echo ""
echo -e "${BLUE}Snyk (CycloneDX):${NC}"
echo -e "   snyk test --file=$OUTPUT_DIR/sbom-$SCAN_ID.cyclonedx.json"
echo ""

exit 0
