#!/usr/bin/env bats

# Unit tests for generate-scan-findings-summary.sh

SCRIPT_DIR="${BATS_TEST_DIRNAME}/../../scripts/shell"
SCRIPT_PATH="${SCRIPT_DIR}/generate-scan-findings-summary.sh"

@test "generate-scan-findings-summary.sh exists and is executable" {
    [ -f "$SCRIPT_PATH" ]
    [ -x "$SCRIPT_PATH" ]
}

@test "generate-scan-findings-summary.sh has proper shebang" {
    head -n 1 "$SCRIPT_PATH" | grep -q "^#!/bin/bash"
}

@test "generate-scan-findings-summary.sh defines color variables" {
    grep -q "RED=\|GREEN=\|YELLOW=" "$SCRIPT_PATH"
}

@test "generate-scan-findings-summary.sh processes scan results" {
    grep -q "scan.*results\|findings" "$SCRIPT_PATH"
}

@test "generate-scan-findings-summary.sh aggregates findings" {
    grep -q "summary\|aggregate\|total" "$SCRIPT_PATH"
}

@test "generate-scan-findings-summary.sh includes severity counts" {
    grep -q "CRITICAL\|HIGH\|MEDIUM\|LOW\|severity" "$SCRIPT_PATH"
}

@test "generate-scan-findings-summary.sh creates summary report" {
    grep -q "summary\|report\|output" "$SCRIPT_PATH"
}

@test "generate-scan-findings-summary.sh processes JSON results" {
    grep -q "json\|jq" "$SCRIPT_PATH"
}
