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
NC='\033[0m' # No Color

echo -e "${CYAN}🐳 Docker Runtime Detection${NC}"
echo ""

# Check if Docker is installed
if ! command -v docker &>/dev/null; then
    echo -e "${RED}❌ Docker is not installed${NC}"
    echo ""
    echo -e "${YELLOW}Install options:${NC}"
    echo -e "  - Docker Engine: https://docs.docker.com/engine/install/"
    echo -e "  - Docker Desktop: https://docker.com"
    echo -e "  - Colima (macOS): brew install colima docker"
    echo -e "  - Rancher Desktop: https://rancherdesktop.io/"
    echo -e "  - OrbStack (macOS): https://orbstack.dev/"
    exit 1
fi

echo -e "${GREEN}✅ Docker CLI installed${NC}"
echo -e "   Version: $(docker --version)"
echo ""

# Check if Docker daemon is running
if ! docker info &>/dev/null; then
    echo -e "${RED}❌ Docker daemon is not running${NC}"
    echo ""
    echo -e "${YELLOW}Start your Docker runtime:${NC}"
    echo -e "  - Docker Engine: sudo systemctl start docker"
    echo -e "  - Docker Desktop: open -a Docker"
    echo -e "  - Colima: colima start"
    echo -e "  - Rancher Desktop: open -a 'Rancher Desktop'"
    echo -e "  - OrbStack: open -a OrbStack"
    exit 1
fi

echo -e "${GREEN}✅ Docker daemon is running${NC}"
echo ""

# Detect Docker runtime
echo -e "${CYAN}📊 Runtime Information:${NC}"
echo ""

# Check context
DOCKER_RUNTIME="Unknown"
CURRENT_CONTEXT=$(docker context show 2>/dev/null || echo "default")

if docker context ls 2>/dev/null | grep -q "colima"; then
    DOCKER_RUNTIME="Colima"
    if [[ "$CURRENT_CONTEXT" == *"colima"* ]]; then
        DOCKER_RUNTIME="$DOCKER_RUNTIME (active)"
    fi
elif docker context ls 2>/dev/null | grep -q "desktop-linux"; then
    DOCKER_RUNTIME="Docker Desktop"
    if [[ "$CURRENT_CONTEXT" == *"desktop"* ]]; then
        DOCKER_RUNTIME="$DOCKER_RUNTIME (active)"
    fi
elif docker context ls 2>/dev/null | grep -q "rancher-desktop"; then
    DOCKER_RUNTIME="Rancher Desktop"
    if [[ "$CURRENT_CONTEXT" == *"rancher"* ]]; then
        DOCKER_RUNTIME="$DOCKER_RUNTIME (active)"
    fi
elif docker context ls 2>/dev/null | grep -q "orbstack"; then
    DOCKER_RUNTIME="OrbStack"
    if [[ "$CURRENT_CONTEXT" == *"orbstack"* ]]; then
        DOCKER_RUNTIME="$DOCKER_RUNTIME (active)"
    fi
elif command -v systemctl &>/dev/null && systemctl is-active docker &>/dev/null 2>&1; then
    DOCKER_RUNTIME="Docker Engine (systemd)"
else
    DOCKER_RUNTIME="Docker Engine or compatible runtime"
fi

echo -e "  ${GREEN}Runtime:${NC} $DOCKER_RUNTIME"
echo -e "  ${GREEN}Context:${NC} $CURRENT_CONTEXT"

# Get Docker info
DOCKER_VERSION=$(docker version --format '{{.Server.Version}}' 2>/dev/null || echo "N/A")
DOCKER_ENDPOINT=$(docker context inspect --format '{{.Endpoints.docker.Host}}' 2>/dev/null || echo "N/A")
DOCKER_OS=$(docker version --format '{{.Server.Os}}' 2>/dev/null || echo "N/A")
DOCKER_ARCH=$(docker version --format '{{.Server.Arch}}' 2>/dev/null || echo "N/A")

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

# Test image pull
echo -n "  Testing image pull... "
if docker pull hello-world:latest &>/dev/null; then
    echo -e "${GREEN}✓${NC}"
else
    echo -e "${RED}✗${NC}"
fi

# Test container run
echo -n "  Testing container run... "
if docker run --rm hello-world &>/dev/null; then
    echo -e "${GREEN}✓${NC}"
else
    echo -e "${RED}✗${NC}"
fi

# Cleanup
docker rmi hello-world:latest &>/dev/null || true

echo ""
echo -e "${GREEN}✅ Docker runtime check complete!${NC}"
echo ""
echo -e "${CYAN}💡 Tip:${NC} All Epyon security scanners support any Docker-compatible runtime"
