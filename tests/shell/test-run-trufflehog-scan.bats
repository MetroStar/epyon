#!/usr/bin/env bats

# Unit tests for run-trufflehog-scan.sh

SCRIPT_DIR="${BATS_TEST_DIRNAME}/../../scripts/shell"
SCRIPT_PATH="${SCRIPT_DIR}/run-trufflehog-scan.sh"

@test "run-trufflehog-scan.sh exists and is executable" {
    [ -f "$SCRIPT_PATH" ]
    [ -x "$SCRIPT_PATH" ]
}

@test "run-trufflehog-scan.sh has proper shebang" {
    head -n 1 "$SCRIPT_PATH" | grep -q "^#!/bin/bash"
}

@test "run-trufflehog-scan.sh sources scan-directory-template.sh" {
    grep -q "source.*scan-directory-template.sh" "$SCRIPT_PATH"
}

@test "run-trufflehog-scan.sh contains init_scan_environment function call" {
    grep -q "init_scan_environment" "$SCRIPT_PATH"
}

@test "run-trufflehog-scan.sh defines color variables" {
    grep -q "RED=" "$SCRIPT_PATH"
    grep -q "GREEN=" "$SCRIPT_PATH"
    grep -q "NC=" "$SCRIPT_PATH"
}

@test "run-trufflehog-scan.sh uses Docker for scanning" {
    grep -q "docker run" "$SCRIPT_PATH"
}

@test "run-trufflehog-scan.sh checks for Docker availability" {
    grep -q "command -v docker" "$SCRIPT_PATH"
}

@test "run-trufflehog-scan.sh uses trufflehog image" {
    grep -q "trufflesecurity/trufflehog" "$SCRIPT_PATH"
}
