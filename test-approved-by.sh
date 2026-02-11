#!/bin/bash

# Test script to verify approved_by field extraction and display

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Set TARGET_DIR so parse_ignore_rules can find the ignore file
export TARGET_DIR="$SCRIPT_DIR"

# Source the filter-ignored-findings.sh
source scripts/shell/filter-ignored-findings.sh
source scripts/shell/parse-epyon-ignore.sh

# Create a temp suppressed log
export SUPPRESSED_LOG="/tmp/test-suppressed.md"
rm -f "$SUPPRESSED_LOG"

# Parse ignore rules
parse_ignore_rules

echo "=== Testing approved_by extraction ===="
echo

# Test with a known path from .epyon-ignore.yml
test_path="/.github/workflows/scan-public-repo.yml"
echo "Testing path: $test_path"
echo

# Check if path is ignored (this should call log_suppressed with approved_by)
if is_path_ignored "$test_path" "Checkov"; then
    echo "✅ Path was identified as ignored"
else
    echo "❌ Path was NOT ignored (unexpected)"
fi

echo
echo "=== Suppressed Log Content ==="
cat "$SUPPRESSED_LOG"

echo
echo "=== Checking for Approved By field ==="
if grep -q "Approved By" "$SUPPRESSED_LOG"; then
    echo "✅ 'Approved By' field found in suppressed log"
    grep "Approved By" "$SUPPRESSED_LOG"
else
    echo "❌ 'Approved By' field NOT found in suppressed log"
fi

# Cleanup
rm -f "$SUPPRESSED_LOG"
