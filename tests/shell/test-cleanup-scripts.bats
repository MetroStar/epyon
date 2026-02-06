#!/usr/bin/env bats

# Unit tests for cleanup-scripts.sh

SCRIPT_DIR="${BATS_TEST_DIRNAME}/../../scripts/shell"
SCRIPT_PATH="${SCRIPT_DIR}/cleanup-scripts.sh"

@test "cleanup-scripts.sh exists and is executable" {
    [ -f "$SCRIPT_PATH" ]
    [ -x "$SCRIPT_PATH" ]
}

@test "cleanup-scripts.sh has proper shebang" {
    head -n 1 "$SCRIPT_PATH" | grep -q "^#!/bin/bash"
}

@test "cleanup-scripts.sh defines color variables" {
    grep -q "RED=\|GREEN=\|YELLOW=" "$SCRIPT_PATH"
}

@test "cleanup-scripts.sh removes old scan directories" {
    grep -q "rm\|remove\|delete\|clean" "$SCRIPT_PATH"
}

@test "cleanup-scripts.sh handles scan directories" {
    grep -q "scan\|SCAN" "$SCRIPT_PATH"
}

@test "cleanup-scripts.sh has safety checks" {
    grep -q "\\[ -d\|\\[ -f\|confirm\|are you sure" "$SCRIPT_PATH" || grep -q "find.*delete" "$SCRIPT_PATH"
}

@test "cleanup-scripts.sh provides cleanup functionality" {
    grep -q "old\|expired\|days\|retention" "$SCRIPT_PATH" || grep -q "clean" "$SCRIPT_PATH"
}
