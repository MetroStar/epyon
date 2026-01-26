#!/bin/bash

# API Discovery Export Script
# Exports API discovery data for integration with external applications

# Colors for output
WHITE='\033[1;37m'
CYAN='\033[0;36m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
MAGENTA='\033[0;35m'
NC='\033[0m'

# Help function
show_help() {
    echo -e "${WHITE}API Discovery Export Utility${NC}"
    echo ""
    echo "Usage: $0 [OPTIONS] [SCAN_ID]"
    echo ""
    echo "Exports API discovery data in JSON format for integration with external applications."
    echo ""
    echo "Arguments:"
    echo "  SCAN_ID             Specific scan ID to export (default: latest scan)"
    echo ""
    echo "Options:"
    echo "  -o, --output DIR    Output directory (default: scan's api-discovery-exports/)"
    echo "  -d, --desktop       Copy exports to ~/Desktop/api-discovery/ for easy access"
    echo "  -h, --help          Show this help message"
    echo ""
    echo "Export Format:"
    echo "  api-discovery-{scan_id}.json    Complete API discovery results with:"
    echo "    • OpenAPI/Swagger specifications"
    echo "    • Code-level route detection (Python, Node.js, Java)"
    echo "    • GraphQL schema detection"
    echo "    • Documentation endpoints"
    echo "    • Framework detection"
    echo "    • Endpoint summaries and recommendations"
    echo ""
    echo "Integration Examples:"
    echo "  • Postman: Import endpoints from JSON"
    echo "  • Swagger UI: Load OpenAPI specifications"
    echo "  • API Management Platforms: Import discovered APIs"
    echo "  • Security Testing Tools: Feed discovered endpoints"
    echo ""
    echo "Examples:"
    echo "  $0                                    # Export latest scan"
    echo "  $0 midas_rnelson_2026-01-23_10-28-22  # Export specific scan"
    echo "  $0 --desktop                          # Export and copy to Desktop"
    echo "  $0 -o /tmp/api-exports                # Export to custom directory"
    echo ""
    exit 0
}

# Parse arguments
OUTPUT_DIR=""
SCAN_ID=""
COPY_TO_DESKTOP=false

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_help
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

# Find API discovery file
API_FILE="$SCAN_DIR/api-discovery.json"
if [[ ! -f "$API_FILE" ]]; then
    echo -e "${RED}❌ API discovery file not found: $API_FILE${NC}"
    echo "Run API discovery scan first using run-api-discovery.sh"
    exit 1
fi

# Set output directory
if [[ -z "$OUTPUT_DIR" ]]; then
    OUTPUT_DIR="$SCAN_DIR/api-discovery-exports"
fi
mkdir -p "$OUTPUT_DIR"

echo -e "${WHITE}============================================${NC}"
echo -e "${WHITE}API Discovery Export${NC}"
echo -e "${WHITE}============================================${NC}"
echo -e "${CYAN}📦 Scan ID:       $SCAN_ID${NC}"
echo -e "${CYAN}📁 Source File:   $(basename "$API_FILE")${NC}"
echo -e "${CYAN}💾 Export Dir:    $OUTPUT_DIR${NC}"
echo ""

# Export API discovery data
OUTPUT_FILE="$OUTPUT_DIR/api-discovery-$SCAN_ID.json"
echo -e "${BLUE}📤 Exporting API discovery data...${NC}"

if cp "$API_FILE" "$OUTPUT_FILE" 2>/dev/null; then
    FILE_SIZE=$(du -h "$OUTPUT_FILE" | cut -f1)
    echo -e "${GREEN}✅ Exported: $(basename "$OUTPUT_FILE") ($FILE_SIZE)${NC}"
    
    # Parse JSON to show summary
    if command -v jq >/dev/null 2>&1; then
        TOTAL_ENDPOINTS=$(jq -r '.summary.total_endpoints_discovered // 0' "$API_FILE" 2>/dev/null)
        TOTAL_SPECS=$(jq -r '.summary.total_specs_found // 0' "$API_FILE" 2>/dev/null)
        TOTAL_ROUTES=$(jq -r '.summary.total_routes_found // 0' "$API_FILE" 2>/dev/null)
        FRAMEWORKS=$(jq -r '.summary.frameworks_detected[]? // empty' "$API_FILE" 2>/dev/null | tr '\n' ', ' | sed 's/,$//')
        
        echo ""
        echo -e "${MAGENTA}📊 API Discovery Summary:${NC}"
        echo -e "   ${CYAN}Total Endpoints:${NC} $TOTAL_ENDPOINTS"
        echo -e "   ${CYAN}OpenAPI Specs:${NC} $TOTAL_SPECS"
        echo -e "   ${CYAN}Code Routes:${NC} $TOTAL_ROUTES"
        if [[ -n "$FRAMEWORKS" ]]; then
            echo -e "   ${CYAN}Frameworks:${NC} $FRAMEWORKS"
        fi
    fi
else
    echo -e "${RED}❌ Failed to export API discovery data${NC}"
    exit 1
fi

echo ""
echo -e "${WHITE}============================================${NC}"
echo -e "${WHITE}Export Summary${NC}"
echo -e "${WHITE}============================================${NC}"
echo -e "${GREEN}✅ API discovery data exported${NC}"
echo ""
echo -e "${CYAN}📁 Export Location:${NC}"
echo -e "   $OUTPUT_DIR"
echo ""
echo -e "${CYAN}📋 Exported Files:${NC}"
echo -e "   📄 $(basename "$OUTPUT_FILE") ($FILE_SIZE)"

# Copy to Desktop if requested
if [ "$COPY_TO_DESKTOP" = true ]; then
    DESKTOP_DIR="$HOME/Desktop/api-discovery"
    mkdir -p "$DESKTOP_DIR"
    
    echo ""
    echo -e "${CYAN}📥 Copying exports to Desktop...${NC}"
    
    if cp "$OUTPUT_FILE" "$DESKTOP_DIR/" 2>/dev/null; then
        echo -e "   ${GREEN}✓${NC} Copied $(basename "$OUTPUT_FILE")"
        echo ""
        echo -e "${GREEN}✅ API discovery files copied to: $DESKTOP_DIR${NC}"
        echo -e "${CYAN}📂 Open folder: open $DESKTOP_DIR${NC}"
    else
        echo -e "${RED}❌ Failed to copy to Desktop${NC}"
    fi
fi

echo ""
echo -e "${CYAN}🔧 Integration Examples:${NC}"
echo ""
echo -e "${BLUE}Postman Collection:${NC}"
echo -e "   1. Open Postman → Import"
echo -e "   2. Select '$OUTPUT_FILE'"
echo -e "   3. Postman will auto-detect API format"
echo ""
echo -e "${BLUE}Swagger UI:${NC}"
echo -e "   # If OpenAPI specs are found, extract and serve"
echo -e "   jq '.discovery_methods.openapi_specs[]' $OUTPUT_FILE"
echo ""
echo -e "${BLUE}Custom Integration:${NC}"
echo -e "   # Parse JSON with jq"
echo -e "   jq '.discovery_methods.code_routes' $OUTPUT_FILE"
echo -e "   jq '.summary' $OUTPUT_FILE"
echo ""
echo -e "${BLUE}API Security Testing:${NC}"
echo -e "   # Extract endpoints for security scanning"
echo -e "   jq -r '.discovery_methods.code_routes[][] | .endpoint' $OUTPUT_FILE"
echo ""

exit 0
