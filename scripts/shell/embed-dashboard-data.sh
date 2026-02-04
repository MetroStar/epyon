#!/bin/bash

# Embed SBOM and API Discovery data into dashboard HTML for offline downloads
# This is a post-processing script that runs after dashboard generation

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCAN_DIR="${SCAN_DIR:-}"
DASHBOARD_FILE="${1:-}"

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

print_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

print_success() {
    echo -e "${GREEN}✅${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠️${NC} $1"
}

print_error() {
    echo -e "${RED}❌${NC} $1"
}

# Show help
if [[ "${1:-}" == "--help" ]] || [[ "${1:-}" == "-h" ]]; then
    cat << EOF
Embed Dashboard Data - Post-process dashboard to enable offline downloads

USAGE:
    ./embed-dashboard-data.sh [DASHBOARD_FILE]

ARGUMENTS:
    DASHBOARD_FILE    Path to the dashboard HTML file (optional if SCAN_DIR is set)

ENVIRONMENT VARIABLES:
    SCAN_DIR          Scan directory containing SBOM and API data

EXAMPLES:
    # With explicit dashboard path
    ./embed-dashboard-data.sh /path/to/dashboard.html

    # With SCAN_DIR environment variable
    SCAN_DIR=/path/to/scan ./embed-dashboard-data.sh

DESCRIPTION:
    This script embeds SBOM and API discovery data directly into the dashboard
    HTML using base64 encoding. This allows downloads to work even when viewing
    the dashboard from a local file:// URL (e.g., downloaded GitHub Actions artifacts).

EOF
    exit 0
fi

# Determine dashboard file and scan directory
if [ -n "$DASHBOARD_FILE" ]; then
    # Dashboard file provided
    if [ ! -f "$DASHBOARD_FILE" ]; then
        print_error "Dashboard file not found: $DASHBOARD_FILE"
        exit 1
    fi
    
    # If SCAN_DIR not set, derive it from dashboard location
    if [ -z "$SCAN_DIR" ]; then
        SCAN_DIR=$(dirname "$(dirname "$DASHBOARD_FILE")")
    fi
else
    # No dashboard file provided, try to find it in SCAN_DIR
    if [ -z "$SCAN_DIR" ]; then
        print_error "Either DASHBOARD_FILE or SCAN_DIR must be provided"
        exit 1
    fi
    
    DASHBOARD_FILE="$SCAN_DIR/consolidated-reports/dashboards/security-dashboard.html"
    
    if [ ! -f "$DASHBOARD_FILE" ]; then
        print_error "Dashboard file not found: $DASHBOARD_FILE"
        exit 1
    fi
fi

print_info "Dashboard file: $DASHBOARD_FILE"
print_info "Scan directory: $SCAN_DIR"

# Extract scan name from directory
SCAN_NAME=$(basename "$SCAN_DIR")

# Create temp file for processing
TEMP_FILE="${DASHBOARD_FILE}.tmp"

print_info "Embedding SBOM and API data..."

# Read the HTML file and find the placeholder
if ! grep -q "const embeddedSBOMs = {};" "$DASHBOARD_FILE"; then
    print_error "Dashboard placeholder not found. Make sure the dashboard was generated correctly."
    exit 1
fi

# Copy original file to temp
cp "$DASHBOARD_FILE" "$TEMP_FILE"

# Function to embed base64 data
embed_data() {
    local file_path="$1"
    local var_name="$2"
    local key="$3"
    
    if [ -f "$file_path" ]; then
        print_info "Embedding: $(basename "$file_path")"
        
        # Encode file to base64
        local encoded=$(cat "$file_path" | base64 | tr -d '\n')
        
        # Create the JavaScript line
        if [ "$key" == "null" ]; then
            local js_line="        const ${var_name} = atob('${encoded}');"
        else
            local js_line="        embeddedSBOMs['${key}'] = atob('${encoded}');"
        fi
        
        # Insert after the placeholder
        if [ "$key" == "null" ]; then
            sed -i.bak "s|const ${var_name} = null;|${js_line}|g" "$TEMP_FILE"
        else
            # Add after embeddedSBOMs declaration
            sed -i.bak "/const embeddedSBOMs = {};/a\\
${js_line}" "$TEMP_FILE"
        fi
        
        rm -f "${TEMP_FILE}.bak"
        return 0
    else
        print_warning "File not found: $file_path"
        return 1
    fi
}

# Embed CycloneDX JSON
SBOM_CYCLONE_JSON="$SCAN_DIR/sbom/exports/sbom-${SCAN_NAME}.cyclonedx.json"
embed_data "$SBOM_CYCLONE_JSON" "embeddedSBOMs" "cyclonedx-json"

# Embed SPDX JSON
SBOM_SPDX_JSON="$SCAN_DIR/sbom/exports/sbom-${SCAN_NAME}.spdx.json"
embed_data "$SBOM_SPDX_JSON" "embeddedSBOMs" "spdx-json"

# Embed API Discovery data
API_DISC_JSON="$SCAN_DIR/api/api-discovery.json"
embed_data "$API_DISC_JSON" "embeddedAPIDiscovery" "null"

# Replace original file with processed version
mv "$TEMP_FILE" "$DASHBOARD_FILE"

print_success "Data embedding complete!"
echo ""
print_info "Dashboard now supports offline downloads"
print_info "File size: $(du -h "$DASHBOARD_FILE" | cut -f1)"
echo ""
