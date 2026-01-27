#!/usr/bin/env bash
# ============================================================================
# check-docker-runtime.sh - Docker Runtime Detection Utility
# ============================================================================
# Purpose: Detect and display information about the current Docker runtime
# Usage: ./check-docker-runtime.sh
# ============================================================================

set -euo pipefail

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
RED='\033[0;31m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

echo -e "${CYAN}🐳 Docker Runtime Detection${NC}"
echo ""
# Source container runtime detection utility when available
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$SCRIPT_DIR/container-runtime.sh" ]; then
    # shellcheck source=/dev/null
    set +e  # Temporarily disable exit on error
    source "$SCRIPT_DIR/container-runtime.sh"
    set -e  # Re-enable
fi

if [ -z "${CONTAINER_CLI:-}" ]; then
    echo -e "${RED}❌ No container runtime CLI found (docker/podman/nerdctl)${NC}"
    echo ""
    echo -e "${YELLOW}Install options:${NC}"
    echo -e "  - Docker Engine: https://docs.docker.com/engine/install/"
    echo -e "  - Podman: https://podman.io/getting-started/"
    echo -e "  - nerdctl (containerd): https://github.com/containerd/nerdctl"
    exit 1
fi

echo -e "${GREEN}✅ Container CLI detected:${NC} $CONTAINER_CLI"
echo -e "   Version: $($CONTAINER_CLI --version 2>/dev/null || echo 'N/A')"
echo ""

# Check if runtime is responsive
if ! container_info 2>/dev/null; then
    # Check if it works with sudo (permission issue)
    if sudo $CONTAINER_CLI info &>/dev/null; then
        echo -e "${YELLOW}⚠️  Container runtime requires elevated permissions${NC}"
        echo ""
        echo -e "${CYAN}Your user was added to the 'docker' group, but you need to:${NC}"
        echo -e "  1️⃣  Log out and log back in, OR"
        echo -e "  2️⃣  Open a new terminal session, OR"
        echo -e "  3️⃣  Run: ${WHITE}exec su -l \$USER${NC}"
        echo ""
        echo -e "${GREEN}Temporary workaround:${NC} Prefix commands with 'sudo'"
        exit 1
    else
        echo -e "${RED}❌ Container runtime not responding (${CONTAINER_CLI})${NC}"
        echo ""
        echo -e "${YELLOW}Start your container runtime:${NC}"
        echo -e "  - Docker Engine: sudo systemctl start docker"
        echo -e "  - Docker Desktop: open -a Docker"
        echo -e "  - Podman (rootless): podman system service --time=0 &"
        echo -e "  - Colima: colima start"
        echo -e "  - Rancher Desktop: open -a 'Rancher Desktop'"
        exit 1
    fi
fi

echo -e "${GREEN}✅ Container runtime is responsive${NC}"
echo ""

# Detect Docker runtime
echo -e "${CYAN}📊 Runtime Information:${NC}"
echo ""

DOCKER_RUNTIME="Unknown"
CURRENT_CONTEXT="$($CONTAINER_CLI context show 2>/dev/null || echo "default")"

if [ "$CONTAINER_CLI" = "podman" ]; then
    DOCKER_RUNTIME="Podman"
elif $CONTAINER_CLI context ls 2>/dev/null | grep -q "colima"; then
    DOCKER_RUNTIME="Colima"
elif $CONTAINER_CLI context ls 2>/dev/null | grep -q "desktop-linux"; then
    DOCKER_RUNTIME="Docker Desktop"
elif $CONTAINER_CLI context ls 2>/dev/null | grep -q "rancher-desktop"; then
    DOCKER_RUNTIME="Rancher Desktop"
elif $CONTAINER_CLI context ls 2>/dev/null | grep -q "orbstack"; then
    DOCKER_RUNTIME="OrbStack"
elif command -v systemctl &>/dev/null && systemctl is-active docker &>/dev/null 2>&1; then
    DOCKER_RUNTIME="Docker Engine (systemd)"
else
    DOCKER_RUNTIME="$CONTAINER_CLI (compatible runtime)"
fi

echo -e "  ${GREEN}Runtime:${NC} $DOCKER_RUNTIME"
echo -e "  ${GREEN}Context:${NC} $CURRENT_CONTEXT"

# Get Docker info
DOCKER_VERSION=$($CONTAINER_CLI version --format '{{.Server.Version}}' 2>/dev/null || $CONTAINER_CLI --version 2>/dev/null || echo "N/A")
DOCKER_ENDPOINT=$($CONTAINER_CLI context inspect --format '{{.Endpoints.docker.Host}}' 2>/dev/null || echo "N/A")
DOCKER_OS=$($CONTAINER_CLI version --format '{{.Server.Os}}' 2>/dev/null || echo "N/A")
DOCKER_ARCH=$($CONTAINER_CLI version --format '{{.Server.Arch}}' 2>/dev/null || echo "N/A")

echo -e "  ${GREEN}Server Version:${NC} $DOCKER_VERSION"
echo -e "  ${GREEN}Endpoint:${NC} $DOCKER_ENDPOINT"
echo -e "  ${GREEN}OS/Arch:${NC} $DOCKER_OS/$DOCKER_ARCH"

# Check for alternative runtimes installed
echo ""
echo -e "${CYAN}📦 Available Docker Runtimes:${NC}"
echo ""

if command -v colima &>/dev/null; then
    COLIMA_STATUS=$(colima status 2>/dev/null | head -1 || echo "stopped")
    echo -e "  ${GREEN}✓${NC} Colima: $(colima version 2>/dev/null | head -1) - Status: $COLIMA_STATUS"
fi

if [[ -d "/Applications/Docker.app" ]]; then
    echo -e "  ${GREEN}✓${NC} Docker Desktop: Installed"
fi

if [[ -d "/Applications/Rancher Desktop.app" ]]; then
    echo -e "  ${GREEN}✓${NC} Rancher Desktop: Installed"
fi

if [[ -d "/Applications/OrbStack.app" ]]; then
    echo -e "  ${GREEN}✓${NC} OrbStack: Installed"
fi

if command -v systemctl &>/dev/null && systemctl list-unit-files docker.service &>/dev/null; then
    DOCKER_SERVICE_STATUS=$(systemctl is-active docker 2>/dev/null || echo "inactive")
    echo -e "  ${GREEN}✓${NC} Docker Engine (systemd): Status: $DOCKER_SERVICE_STATUS"
fi

# Test Docker functionality
echo ""
echo -e "${CYAN}🧪 Testing Docker Functionality:${NC}"
echo ""

echo -n "  Testing image pull... "
if $CONTAINER_CLI pull hello-world:latest &>/dev/null; then
    echo -e "${GREEN}✓${NC}"
else
    echo -e "${RED}✗${NC}"
fi

echo -n "  Testing container run... "
if $CONTAINER_CLI run --rm hello-world &>/dev/null; then
    echo -e "${GREEN}✓${NC}"
else
    echo -e "${RED}✗${NC}"
fi

# Cleanup
$CONTAINER_CLI rmi hello-world:latest &>/dev/null || true

echo ""
echo -e "${GREEN}✅ Docker runtime check complete!${NC}"
echo ""
echo -e "${CYAN}💡 Tip:${NC} All Epyon security scanners support any Docker-compatible runtime"
