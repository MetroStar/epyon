#!/usr/bin/env bats

# Unit tests for run-checkov-scan.sh

SCRIPT_DIR="${BATS_TEST_DIRNAME}/../../scripts/shell"
SCRIPT_PATH="${SCRIPT_DIR}/run-checkov-scan.sh"

@test "run-checkov-scan.sh exists and is executable" {
    [ -f "$SCRIPT_PATH" ]
    [ -x "$SCRIPT_PATH" ]
}

@test "run-checkov-scan.sh shows help with --help flag" {
    run bash "$SCRIPT_PATH" --help
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Checkov Infrastructure-as-Code Security Scanner" ]]
    [[ "$output" =~ "Usage:" ]]
}

@test "run-checkov-scan.sh shows help with -h flag" {
    run bash "$SCRIPT_PATH" -h
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Checkov" ]]
}

@test "run-checkov-scan.sh sources scan-directory-template.sh" {
    grep -q "source.*scan-directory-template.sh" "$SCRIPT_PATH"
}

@test "run-checkov-scan.sh contains init_scan_environment function call" {
    grep -q "init_scan_environment" "$SCRIPT_PATH"
}

@test "run-checkov-scan.sh has proper shebang" {
    head -n 1 "$SCRIPT_PATH" | grep -q "^#!/bin/bash"
}

@test "run-checkov-scan.sh defines color variables" {
    grep -q "^RED=" "$SCRIPT_PATH"
    grep -q "^GREEN=" "$SCRIPT_PATH"
    grep -q "^NC=" "$SCRIPT_PATH"
}

@test "run-checkov-scan.sh uses Docker for scanning" {
    grep -q "docker run" "$SCRIPT_PATH"
}

@test "run-checkov-scan.sh checks for Docker availability" {
    grep -q "command -v docker" "$SCRIPT_PATH"
}

@test "run-checkov-scan.sh supports AWS credentials" {
    grep -q "AWS_ACCESS_KEY_ID" "$SCRIPT_PATH"
    grep -q "AWS_SECRET_ACCESS_KEY" "$SCRIPT_PATH"
}

@test "run-checkov-scan.sh scans infrastructure files" {
    grep -q "bridgecrew/checkov" "$SCRIPT_PATH"
}

@test "run-checkov-scan.sh skips node_modules" {
    grep -q "skip-path node_modules" "$SCRIPT_PATH"
}
