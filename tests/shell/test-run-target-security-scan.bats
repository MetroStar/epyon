#!/usr/bin/env bats

# Unit tests for run-target-security-scan.sh

SCRIPT_DIR="${BATS_TEST_DIRNAME}/../../scripts/shell"
SCRIPT_PATH="${SCRIPT_DIR}/run-target-security-scan.sh"

@test "run-target-security-scan.sh exists and is executable" {
    [ -f "$SCRIPT_PATH" ]
    [ -x "$SCRIPT_PATH" ]
}

@test "run-target-security-scan.sh has proper shebang" {
    head -n 1 "$SCRIPT_PATH" | grep -q "^#!/bin/bash"
}

@test "run-target-security-scan.sh defines color variables" {
    grep -q "RED=" "$SCRIPT_PATH"
    grep -q "GREEN=" "$SCRIPT_PATH"
    grep -q "NC=" "$SCRIPT_PATH"
}

@test "run-target-security-scan.sh orchestrates multiple scans" {
    grep -q "run-trivy-scan\|run-grype-scan\|run-checkov-scan" "$SCRIPT_PATH"
}

@test "run-target-security-scan.sh accepts target directory parameter" {
    grep -q "TARGET_DIR" "$SCRIPT_PATH"
}

@test "run-target-security-scan.sh creates scan directory" {
    grep -q "SCAN_DIR\|SCAN_ID" "$SCRIPT_PATH"
}

@test "run-target-security-scan.sh exports SCAN_DIR environment variable" {
    grep -q "export SCAN_DIR" "$SCRIPT_PATH"
}

@test "run-target-security-scan.sh generates scan ID" {
    grep -q "SCAN_ID" "$SCRIPT_PATH"
}
