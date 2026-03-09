#!/usr/bin/env bats

# Unit tests for run-garak-scan.sh

SCRIPT_DIR="${BATS_TEST_DIRNAME}/../../scripts/shell"
SCRIPT_PATH="${SCRIPT_DIR}/run-garak-scan.sh"

@test "run-garak-scan.sh exists and is executable" {
    [ -f "$SCRIPT_PATH" ]
    [ -x "$SCRIPT_PATH" ]
}

@test "run-garak-scan.sh has proper shebang" {
    head -n 1 "$SCRIPT_PATH" | grep -q "^#!/bin/bash"
}

@test "run-garak-scan.sh sources scan-directory-template.sh" {
    grep -q "source.*scan-directory-template.sh" "$SCRIPT_PATH"
}

@test "run-garak-scan.sh calls init_scan_environment" {
    grep -q "init_scan_environment" "$SCRIPT_PATH"
}

@test "run-garak-scan.sh references garak command" {
    grep -q "garak" "$SCRIPT_PATH"
}

@test "run-garak-scan.sh supports target type environment variable" {
    grep -q "GARAK_TARGET_TYPE" "$SCRIPT_PATH"
}
