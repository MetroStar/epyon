#!/bin/bash
# Test if model provenance and inference security layers can run

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo "=== Testing ML Security Layers 18 & 19 ==="
echo ""

# Create a test target directory with some dummy files
TEST_TARGET="/tmp/epyon-ml-layer-test-$$"
mkdir -p "$TEST_TARGET"

# Create dummy files
touch "$TEST_TARGET/README.md"
echo "FROM python:3.11" > "$TEST_TARGET/Dockerfile"
echo "version: '3'" > "$TEST_TARGET/docker-compose.yml"
mkdir -p "$TEST_TARGET/models"
touch "$TEST_TARGET/models/model.pkl"

echo "Test target created: $TEST_TARGET"
echo ""

# Set up environment
export TARGET_DIR="$TEST_TARGET"
export SCAN_ID="test_ml_layers_$(date +%Y%m%d_%H%M%S)"
export SCAN_DIR="/tmp/epyon-test-scan-$SCAN_ID"
mkdir -p "$SCAN_DIR"

echo "Environment:"
echo "  TARGET_DIR=$TARGET_DIR"
echo "  SCAN_ID=$SCAN_ID"
echo "  SCAN_DIR=$SCAN_DIR"
echo ""

# Test Layer 18 - Model Provenance
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Testing Layer 18: Model Provenance"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

LAYER18_SCRIPT="$BASE_DIR/scripts/shell/run-model-provenance-check.sh"
if [[ -x "$LAYER18_SCRIPT" ]]; then
    echo "Script found: $LAYER18_SCRIPT"
    echo "Running..."
    if "$LAYER18_SCRIPT"; then
        echo "✓ Layer 18 completed"
        
        # Check outputs
        if [[ -d "$SCAN_DIR/model-provenance" ]]; then
            echo "✓ Output directory created"
            ls -la "$SCAN_DIR/model-provenance/"
        else
            echo "✗ Output directory NOT created"
        fi
    else
        echo "✗ Layer 18 failed with exit code $?"
    fi
else
    echo "✗ Script not found or not executable: $LAYER18_SCRIPT"
fi
echo ""

# Test Layer 19 - Inference Security
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Testing Layer 19: Inference Security"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

LAYER19_SCRIPT="$BASE_DIR/scripts/shell/run-inference-security-scan.sh"
if [[ -x "$LAYER19_SCRIPT" ]]; then
    echo "Script found: $LAYER19_SCRIPT"
    echo "Running..."
    if "$LAYER19_SCRIPT"; then
        echo "✓ Layer 19 completed"
        
        # Check outputs
        if [[ -d "$SCAN_DIR/inference-security" ]]; then
            echo "✓ Output directory created"
            ls -la "$SCAN_DIR/inference-security/"
        else
            echo "✗ Output directory NOT created"
        fi
    else
        echo "✗ Layer 19 failed with exit code $?"
    fi
else
    echo "✗ Script not found or not executable: $LAYER19_SCRIPT"
fi
echo ""

# Clean up
echo "Cleaning up test files..."
rm -rf "$TEST_TARGET"
rm -rf "$SCAN_DIR"

echo ""
echo "=== Test Complete ==="
