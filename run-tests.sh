#!/bin/bash

# BATS Test Runner for Security Architecture
# Automatically installs BATS locally if not available

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BATS_DIR="$SCRIPT_DIR/.bats"
TESTS_DIR="$SCRIPT_DIR/tests/shell"

echo -e "${GREEN}================================${NC}"
echo -e "${GREEN}Security Architecture Test Suite${NC}"
echo -e "${GREEN}================================${NC}"
echo ""

# Check if BATS is available globally
if command -v bats &> /dev/null; then
    BATS_CMD="bats"
    echo -e "${GREEN}✓ Using system BATS installation${NC}"
else
    # Check if local BATS exists
    if [ -f "$BATS_DIR/bin/bats" ]; then
        BATS_CMD="$BATS_DIR/bin/bats"
        echo -e "${GREEN}✓ Using local BATS installation${NC}"
    else
        # Install BATS locally
        echo -e "${YELLOW}⚙ BATS not found - installing locally...${NC}"
        mkdir -p "$BATS_DIR"
        
        # Clone BATS
        echo "Cloning BATS repository..."
        git clone --depth 1 https://github.com/bats-core/bats-core.git "$BATS_DIR/bats-core" 2>/dev/null || {
            echo -e "${RED}✗ Failed to clone BATS${NC}"
            echo ""
            echo "Manual installation options:"
            echo "1. Install via Homebrew (requires admin): brew install bats-core"
            echo "2. Clone manually: git clone https://github.com/bats-core/bats-core.git .bats/bats-core"
            exit 1
        }
        
        # Install BATS to local directory
        cd "$BATS_DIR/bats-core"
        ./install.sh "$BATS_DIR" >/dev/null
        cd "$SCRIPT_DIR"
        
        BATS_CMD="$BATS_DIR/bin/bats"
        echo -e "${GREEN}✓ BATS installed successfully to .bats/${NC}"
    fi
fi

echo ""
echo -e "${GREEN}Running tests...${NC}"
echo ""

# Run all tests or specific test if provided
if [ -n "$1" ]; then
    TEST_FILE="$TESTS_DIR/$1"
    if [ ! -f "$TEST_FILE" ]; then
        TEST_FILE="$TESTS_DIR/test-$1.bats"
    fi
    
    if [ -f "$TEST_FILE" ]; then
        echo "Running: $(basename "$TEST_FILE")"
        "$BATS_CMD" "$TEST_FILE"
    else
        echo -e "${RED}✗ Test file not found: $1${NC}"
        echo ""
        echo "Available tests:"
        ls -1 "$TESTS_DIR"/*.bats | xargs -n 1 basename
        exit 1
    fi
else
    # Run all tests
    echo "Running all tests in $TESTS_DIR"
    "$BATS_CMD" "$TESTS_DIR"/*.bats
fi

echo ""
echo -e "${GREEN}================================${NC}"
echo -e "${GREEN}Tests Complete${NC}"
echo -e "${GREEN}================================${NC}"
