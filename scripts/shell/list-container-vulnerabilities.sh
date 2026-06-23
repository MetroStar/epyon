#!/usr/bin/env bash
# list-container-vulnerabilities.sh
# Show which container images have which vulnerabilities
#
# Usage:
#   ./list-container-vulnerabilities.sh [SCAN_DIR]
#   ./list-container-vulnerabilities.sh scans/myapp_2026-06-22_14-30-45
#
# Output:
#   Container-specific vulnerability breakdown with CVE IDs, severity, and package names

set -euo pipefail

# Colors
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# Resolve scan directory
if [[ $# -gt 0 ]]; then
    SCAN_DIR="$1"
elif [[ -n "${SCAN_DIR:-}" ]]; then
    : # use env var
else
    # Auto-detect latest scan
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
    LATEST=$(ls -td "$REPO_ROOT"/scans/*/ 2>/dev/null | head -1 || true)
    if [[ -z "$LATEST" ]]; then
        echo -e "${RED}ERROR: No scan directory found${NC}" >&2
        echo "Usage: $0 [SCAN_DIR]" >&2
        exit 1
    fi
    SCAN_DIR="${LATEST%/}"
fi

SCAN_DIR=$(realpath "$SCAN_DIR" 2>/dev/null) || {
    echo -e "${RED}ERROR: Scan directory does not exist: ${SCAN_DIR}${NC}" >&2
    exit 1
}

ANCHORE_DIR="$SCAN_DIR/anchore"
if [[ ! -d "$ANCHORE_DIR" ]]; then
    echo -e "${RED}ERROR: No Anchore results found in $SCAN_DIR${NC}" >&2
    exit 1
fi

IMAGE_RESULTS_DIR="$ANCHORE_DIR/images"

echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}   Container Vulnerability Breakdown${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}Scan: $(basename "$SCAN_DIR")${NC}"
echo ""

# Check if jq is available
if ! command -v jq &>/dev/null; then
    echo -e "${RED}ERROR: jq is required but not installed${NC}" >&2
    exit 1
fi

# Function to display vulnerabilities for a single image
show_image_vulns() {
    local image_file="$1"
    local image_name
    image_name=$(basename "$image_file" .json)
    
    # Decode image name (replace _ with / and :)
    local display_name
    display_name=$(echo "$image_name" | sed 's/_/:/2' | sed 's/_/\//g')
    
    # Skip if file doesn't exist or is empty
    if [[ ! -f "$image_file" ]] || [[ ! -s "$image_file" ]]; then
        return
    fi
    
    # Get vulnerability counts
    local total critical high medium low
    total=$(jq -r '.matches | length' "$image_file" 2>/dev/null || echo "0")
    
    if [[ "$total" -eq 0 ]]; then
        echo -e "${GREEN}✅ $display_name${NC}"
        echo -e "   No vulnerabilities found"
        echo ""
        return
    fi
    
    critical=$(jq -r '[.matches[] | select(.vulnerability.severity=="Critical")] | length' "$image_file" 2>/dev/null || echo "0")
    high=$(jq -r '[.matches[] | select(.vulnerability.severity=="High")] | length' "$image_file" 2>/dev/null || echo "0")
    medium=$(jq -r '[.matches[] | select(.vulnerability.severity=="Medium")] | length' "$image_file" 2>/dev/null || echo "0")
    low=$(jq -r '[.matches[] | select(.vulnerability.severity=="Low")] | length' "$image_file" 2>/dev/null || echo "0")
    
    # Get detected OS
    local detected_os
    detected_os=$(jq -r '.distro.name // .distro.type // "unknown"' "$image_file" 2>/dev/null || echo "unknown")
    local detected_version
    detected_version=$(jq -r '.distro.version // ""' "$image_file" 2>/dev/null || echo "")
    
    # Color code based on severity
    if [[ "$critical" -gt 0 ]]; then
        echo -e "${RED}🚨 $display_name${NC}"
    elif [[ "$high" -gt 0 ]]; then
        echo -e "${YELLOW}⚠️  $display_name${NC}"
    else
        echo -e "${GREEN}ℹ️  $display_name${NC}"
    fi
    
    echo -e "   ${BOLD}OS:${NC} $detected_os $detected_version"
    echo -e "   ${BOLD}Total:${NC} $total vulnerabilities"
    
    if [[ "$critical" -gt 0 ]]; then
        echo -e "   ${RED}Critical: $critical${NC}"
    fi
    if [[ "$high" -gt 0 ]]; then
        echo -e "   ${YELLOW}High: $high${NC}"
    fi
    if [[ "$medium" -gt 0 ]]; then
        echo -e "   Medium: $medium"
    fi
    if [[ "$low" -gt 0 ]]; then
        echo -e "   Low: $low"
    fi
    
    echo ""
    echo -e "   ${BOLD}Top Critical/High CVEs:${NC}"
    
    # Show top 10 critical/high CVEs
    jq -r '.matches[] | select(.vulnerability.severity=="Critical" or .vulnerability.severity=="High") | 
           "   • \(.vulnerability.id) [\(.vulnerability.severity)] in \(.artifact.name)@\(.artifact.version)"' \
        "$image_file" 2>/dev/null | head -10 || true
    
    local remaining
    remaining=$(jq -r '[.matches[] | select(.vulnerability.severity=="Critical" or .vulnerability.severity=="High")] | length' "$image_file" 2>/dev/null || echo "0")
    if [[ "$remaining" -gt 10 ]]; then
        echo -e "   ${CYAN}... and $((remaining - 10)) more critical/high vulnerabilities${NC}"
    fi
    
    echo ""
}

# Process filesystem results (if present)
if [[ -f "$ANCHORE_DIR/anchore-filesystem-results.json" ]]; then
    echo -e "${BOLD}━━━ Filesystem Scan Results ━━━${NC}"
    echo ""
    show_image_vulns "$ANCHORE_DIR/anchore-filesystem-results.json"
fi

# Process SBOM results (if present)
if [[ -f "$ANCHORE_DIR/anchore-sbom-results.json" ]]; then
    echo -e "${BOLD}━━━ SBOM Scan Results ━━━${NC}"
    echo ""
    show_image_vulns "$ANCHORE_DIR/anchore-sbom-results.json"
fi

# Process container image results
if [[ -d "$IMAGE_RESULTS_DIR" ]]; then
    IMAGE_COUNT=$(find "$IMAGE_RESULTS_DIR" -name "*.json" -type f 2>/dev/null | wc -l | tr -d ' ')
    
    if [[ "$IMAGE_COUNT" -gt 0 ]]; then
        echo -e "${BOLD}━━━ Container Image Scan Results ($IMAGE_COUNT images) ━━━${NC}"
        echo ""
        
        for image_file in "$IMAGE_RESULTS_DIR"/*.json; do
            [[ -f "$image_file" ]] || continue
            show_image_vulns "$image_file"
        done
    fi
fi

# Summary statistics
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}   Summary${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"

# Calculate totals
TOTAL_IMAGES=$(find "$IMAGE_RESULTS_DIR" -name "*.json" -type f 2>/dev/null | wc -l | tr -d ' ')
TOTAL_CRITICAL=0
TOTAL_HIGH=0
TOTAL_MEDIUM=0
TOTAL_LOW=0

for image_file in "$IMAGE_RESULTS_DIR"/*.json; do
    [[ -f "$image_file" ]] || continue
    TOTAL_CRITICAL=$((TOTAL_CRITICAL + $(jq -r '[.matches[] | select(.vulnerability.severity=="Critical")] | length' "$image_file" 2>/dev/null || echo "0")))
    TOTAL_HIGH=$((TOTAL_HIGH + $(jq -r '[.matches[] | select(.vulnerability.severity=="High")] | length' "$image_file" 2>/dev/null || echo "0")))
    TOTAL_MEDIUM=$((TOTAL_MEDIUM + $(jq -r '[.matches[] | select(.vulnerability.severity=="Medium")] | length' "$image_file" 2>/dev/null || echo "0")))
    TOTAL_LOW=$((TOTAL_LOW + $(jq -r '[.matches[] | select(.vulnerability.severity=="Low")] | length' "$image_file" 2>/dev/null || echo "0")))
done

echo "Scanned Images: $TOTAL_IMAGES"
echo -e "${RED}Critical Vulnerabilities: $TOTAL_CRITICAL${NC}"
echo -e "${YELLOW}High Vulnerabilities: $TOTAL_HIGH${NC}"
echo "Medium Vulnerabilities: $TOTAL_MEDIUM"
echo "Low Vulnerabilities: $TOTAL_LOW"
echo ""

# Export functionality
echo -e "${BOLD}Export Options:${NC}"
echo "  • View full JSON for an image: jq . $IMAGE_RESULTS_DIR/<image_name>.json"
echo "  • Export CVEs to CSV: See documentation/ANCHORE_CONFIGURATION_GUIDE.md"
echo "  • View in Web UI: Open http://127.0.0.1:8000 (see README.md)"
echo ""
