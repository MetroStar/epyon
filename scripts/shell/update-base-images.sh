#!/bin/bash
# update-base-images.sh
# Automatically pulls and validates latest hardened base images

set -euo pipefail

show_help() {
        cat <<'EOF'
Usage: update-base-images.sh [--help]

Interactive utility to pull and validate approved hardened base images.

Options:
    -h, --help    Show this help text and exit.
EOF
}

if [[ "${1:-}" == "--help" ]] || [[ "${1:-}" == "-h" ]]; then
        show_help
        exit 0
fi

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_DIR="$SCRIPT_DIR/../configuration"

echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}     Base Image Security Update Utility${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}"
echo ""

# Source the approved images configuration
if [ -f "$CONFIG_DIR/approved-base-images.conf" ]; then
    source "$CONFIG_DIR/approved-base-images.conf"
    echo -e "${GREEN}✅ Loaded approved images configuration${NC}"
else
    echo -e "${RED}❌ Configuration file not found: $CONFIG_DIR/approved-base-images.conf${NC}"
    exit 1
fi

# Function to get image metadata
get_image_info() {
    local image="$1"
    local version created digest
    
    version=$(docker image inspect "$image" --format='{{index .Config.Labels "org.opencontainers.image.version"}}' 2>/dev/null || echo "unknown")
    created=$(docker image inspect "$image" --format='{{index .Config.Labels "org.opencontainers.image.created"}}' 2>/dev/null || echo "unknown")
    digest=$(docker image inspect "$image" --format='{{index .RepoDigests 0}}' 2>/dev/null | cut -d'@' -f2 | cut -c1-19 || echo "unknown")
    
    echo "$version|$created|$digest"
}

# Function to pull and compare image
update_image() {
    local image="$1"
    
    echo ""
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}📦 Processing: $image${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    # Check if image exists locally
    if docker image inspect "$image" >/dev/null 2>&1; then
        local old_info=$(get_image_info "$image")
        local old_version=$(echo "$old_info" | cut -d'|' -f1)
        local old_date=$(echo "$old_info" | cut -d'|' -f2)
        local old_digest=$(echo "$old_info" | cut -d'|' -f3)
        
        echo -e "${YELLOW}📋 Current version:${NC}"
        echo "   Version: $old_version"
        echo "   Created: $old_date"
        echo "   Digest:  ${old_digest}..."
    else
        echo -e "${YELLOW}⚠️  Image not found locally${NC}"
        old_version="none"
    fi
    
    # Pull latest
    echo ""
    echo -e "${BLUE}📥 Pulling latest version...${NC}"
    if docker pull "$image" 2>&1 | grep -q "up to date"; then
        echo -e "${GREEN}✅ Already up to date${NC}"
        return 0
    fi
    
    # Get new version info
    local new_info=$(get_image_info "$image")
    local new_version=$(echo "$new_info" | cut -d'|' -f1)
    local new_date=$(echo "$new_info" | cut -d'|' -f2)
    local new_digest=$(echo "$new_info" | cut -d'|' -f3)
    
    echo ""
    echo -e "${GREEN}✅ Updated successfully!${NC}"
    echo -e "${GREEN}📋 New version:${NC}"
    echo "   Version: $new_version"
    echo "   Created: $new_date"
    echo "   Digest:  ${new_digest}..."
    
    # Show upgrade if version changed
    if [ "$old_version" != "none" ] && [ "$old_version" != "$new_version" ]; then
        echo ""
        echo -e "${GREEN}🎉 UPGRADED: $old_version → $new_version${NC}"
    fi
}

# Main execution
echo -e "${YELLOW}🔍 Mode Selection:${NC}"
echo "  1. Update core images only (recommended)"
echo "  2. Update all extended images"
echo "  3. Update specific image"
echo ""
read -p "Choose option [1-3]: " mode

case $mode in
    1)
        echo ""
        echo -e "${BLUE}🔄 Updating core images...${NC}"
        for image in "${APPROVED_BASE_IMAGES[@]}"; do
            update_image "$image"
        done
        ;;
    2)
        echo ""
        echo -e "${BLUE}🔄 Updating all extended images (this may take a while)...${NC}"
        for image in "${APPROVED_BASE_IMAGES_EXTENDED[@]}"; do
            update_image "$image"
        done
        ;;
    3)
        echo ""
        read -p "Enter image name (e.g., bitnami/node:latest): " custom_image
        update_image "$custom_image"
        ;;
    *)
        echo -e "${RED}❌ Invalid option${NC}"
        exit 1
        ;;
esac

# Summary
echo ""
echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}✅ Update process completed${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${YELLOW}📊 Next Steps:${NC}"
echo "  1. Review updated images:"
echo "     docker images | grep bitnami"
echo ""
echo "  2. Run security scans:"
echo "     ./scripts/shell/run-trivy-scan.sh base"
echo ""
echo "  3. Review scan results in:"
echo "     scans/<latest-scan-dir>/security-findings-summary.json"
echo ""
echo -e "${YELLOW}📅 Recommended: Set a weekly reminder to run this script${NC}"
echo ""
