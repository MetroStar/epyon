#!/usr/bin/env bats

# Unit tests for run-grype-scan.sh

SCRIPT_DIR="${BATS_TEST_DIRNAME}/../../scripts/shell"
SCRIPT_PATH="${SCRIPT_DIR}/run-grype-scan.sh"

@test "run-grype-scan.sh exists and is executable" {
    [ -f "$SCRIPT_PATH" ]
    [ -x "$SCRIPT_PATH" ]
}

@test "run-grype-scan.sh shows help with --help flag" {
    run bash "$SCRIPT_PATH" --help
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Grype Multi-Target Vulnerability Scanner" ]]
    [[ "$output" =~ "Usage:" ]]
}

@test "run-grype-scan.sh shows help with -h flag" {
    run bash "$SCRIPT_PATH" -h
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Grype" ]]
}

@test "run-grype-scan.sh sources scan-directory-template.sh" {
    grep -q "source.*scan-directory-template.sh" "$SCRIPT_PATH"
}

@test "run-grype-scan.sh contains init_scan_environment function call" {
    grep -q "init_scan_environment" "$SCRIPT_PATH"
}

@test "run-grype-scan.sh has proper shebang" {
    head -n 1 "$SCRIPT_PATH" | grep -q "^#!/bin/bash"
}

@test "run-grype-scan.sh defines color variables" {
    grep -q "^RED=" "$SCRIPT_PATH"
    grep -q "^GREEN=" "$SCRIPT_PATH"
    grep -q "^NC=" "$SCRIPT_PATH"
}

@test "run-grype-scan.sh contains run_grype_scan function" {
    grep -q "run_grype_scan()" "$SCRIPT_PATH"
}

@test "run-grype-scan.sh uses Docker for scanning" {
    grep -q "docker run" "$SCRIPT_PATH"
}

@test "run-grype-scan.sh checks for Docker availability" {
    grep -q "command -v docker" "$SCRIPT_PATH"
}

@test "run-grype-scan.sh supports filesystem scan mode" {
    grep -q "filesystem" "$SCRIPT_PATH"
}

@test "run-grype-scan.sh supports images scan mode" {
    grep -q "images" "$SCRIPT_PATH"
}
