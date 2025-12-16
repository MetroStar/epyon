#!/usr/bin/env bats

# Unit tests for run-trivy-scan.sh

SCRIPT_DIR="${BATS_TEST_DIRNAME}/../../scripts/shell"
SCRIPT_PATH="${SCRIPT_DIR}/run-trivy-scan.sh"

@test "run-trivy-scan.sh exists and is executable" {
    [ -f "$SCRIPT_PATH" ]
    [ -x "$SCRIPT_PATH" ]
}

@test "run-trivy-scan.sh shows help with --help flag" {
    run bash "$SCRIPT_PATH" --help
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Trivy Security Scanner" ]]
    [[ "$output" =~ "Usage:" ]]
}

@test "run-trivy-scan.sh shows help with -h flag" {
    run bash "$SCRIPT_PATH" -h
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Trivy Security Scanner" ]]
}

@test "run-trivy-scan.sh sources scan-directory-template.sh" {
    # Verify the script sources the template
    grep -q "source.*scan-directory-template.sh" "$SCRIPT_PATH"
}

@test "run-trivy-scan.sh contains init_scan_environment function call" {
    # Verify the script initializes scan environment
    grep -q "init_scan_environment" "$SCRIPT_PATH"
}

@test "run-trivy-scan.sh has proper shebang" {
    head -n 1 "$SCRIPT_PATH" | grep -q "^#!/bin/bash"
}

@test "run-trivy-scan.sh defines color variables" {
    grep -q "^RED=" "$SCRIPT_PATH"
    grep -q "^GREEN=" "$SCRIPT_PATH"
    grep -q "^NC=" "$SCRIPT_PATH"
}

@test "run-trivy-scan.sh contains run_trivy_scan function" {
    grep -q "run_trivy_scan()" "$SCRIPT_PATH"
}

@test "run-trivy-scan.sh uses Docker for scanning" {
    grep -q "docker run" "$SCRIPT_PATH"
}

@test "run-trivy-scan.sh checks for Docker availability" {
    grep -q "command -v docker" "$SCRIPT_PATH"
}
