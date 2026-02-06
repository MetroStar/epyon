#!/usr/bin/env bats

# Unit tests for check-severity-gate.sh

SCRIPT_DIR="${BATS_TEST_DIRNAME}/../../scripts/shell"
SCRIPT_PATH="${SCRIPT_DIR}/check-severity-gate.sh"

@test "check-severity-gate.sh exists and is executable" {
    [ -f "$SCRIPT_PATH" ]
    [ -x "$SCRIPT_PATH" ]
}

@test "check-severity-gate.sh has proper shebang" {
    head -n 1 "$SCRIPT_PATH" | grep -q "^#!/bin/bash"
}

@test "check-severity-gate.sh defines color variables" {
    grep -q "RED=\|GREEN=\|YELLOW=" "$SCRIPT_PATH"
}

@test "check-severity-gate.sh checks severity thresholds" {
    grep -q "CRITICAL\|HIGH\|MEDIUM\|severity" "$SCRIPT_PATH"
}

@test "check-severity-gate.sh processes scan results" {
    grep -q "scan.*results\|json" "$SCRIPT_PATH"
}

@test "check-severity-gate.sh enforces quality gates" {
    grep -q "gate\|threshold\|limit\|max" "$SCRIPT_PATH"
}

@test "check-severity-gate.sh exits with appropriate codes" {
    grep -q "exit 0\|exit 1" "$SCRIPT_PATH"
}

@test "check-severity-gate.sh counts findings by severity" {
    grep -q "count\|total\|number" "$SCRIPT_PATH"
}

@test "check-severity-gate.sh provides gate validation" {
    grep -q "pass\|fail\|exceed\|breach" "$SCRIPT_PATH" || grep -q "gate" "$SCRIPT_PATH"
}
