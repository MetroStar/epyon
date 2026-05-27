#!/bin/bash

# Simple test script to verify path resolution
echo "Testing path resolution..."

# Get absolute path to reports directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPORTS_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
OUTPUT_DIR="$REPORTS_ROOT/reports/test-reports"

echo "Script directory: $SCRIPT_DIR"
echo "Reports root: $REPORTS_ROOT"
echo "Output directory: $OUTPUT_DIR"

# Create the directory
mkdir -p "$OUTPUT_DIR"

# Create a test file
echo "Test file created at $(date)" > "$OUTPUT_DIR/test-file.txt"

echo "✅ Test completed - check $OUTPUT_DIR for test file"