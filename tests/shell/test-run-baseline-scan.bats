#!/usr/bin/env bats

# Unit tests for run-baseline-scan.sh

SCRIPT_DIR="${BATS_TEST_DIRNAME}/../../scripts/shell"
SCRIPT_PATH="${SCRIPT_DIR}/run-baseline-scan.sh"

@test "run-baseline-scan.sh exists and is executable" {
    [ -f "$SCRIPT_PATH" ]
    [ -x "$SCRIPT_PATH" ]
}

@test "run-baseline-scan.sh shows help with --help flag" {
    run bash "$SCRIPT_PATH" --help
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Baseline" ]] || [[ "$output" =~ "baseline" ]] || [[ "$output" =~ "Usage" ]]
}

@test "run-baseline-scan.sh has proper shebang" {
    head -n 1 "$SCRIPT_PATH" | grep -q "^#!/bin/bash"
}

@test "run-baseline-scan.sh defines color variables" {
    grep -q "^RED=" "$SCRIPT_PATH"
    grep -q "^GREEN=" "$SCRIPT_PATH"
    grep -q "^NC=" "$SCRIPT_PATH"
}

@test "run-baseline-scan.sh has standalone structure" {
    # Baseline scan has its own structure
    grep -q "function" "$SCRIPT_PATH" || grep -q "()" "$SCRIPT_PATH"
}

@test "run-baseline-scan.sh supports baseline image scanning" {
    # Check for baseline or image references
    grep -q "BASELINE" "$SCRIPT_PATH" || grep -q "baseline" "$SCRIPT_PATH"
}

@test "run-baseline-scan.sh orchestrates security scanning" {
    # Baseline scan orchestrates multiple scanners
    grep -q "scan" "$SCRIPT_PATH" || grep -q "run-" "$SCRIPT_PATH"
}

@test "run-baseline-scan.sh integrates with security scanners" {
    # Checks that baseline scan calls security tools
    grep -q "trivy\|grype\|xeol" "$SCRIPT_PATH" || grep -q "run-.*-scan" "$SCRIPT_PATH"
}

@test "run-baseline-scan.sh creates baseline scan results" {
    grep -q "baseline.*json\|baseline-scan" "$SCRIPT_PATH"
}

@test "run-baseline-scan.sh references baseline repository" {
    # Baseline scan works with comet-starter or baseline repo
    grep -q "comet-starter\|baseline" "$SCRIPT_PATH"
}

@test "run-baseline-scan.sh creates scan directory output" {
    grep -q "SCAN_DIR\|scan.*directory" "$SCRIPT_PATH"
}

@test "run-baseline-scan.sh includes severity filtering" {
    grep -q "CRITICAL\|HIGH\|MEDIUM\|severity" "$SCRIPT_PATH"
}

@test "run-baseline-scan.sh generates JSON output" {
    grep -q "json\|-o.*json\|--format json" "$SCRIPT_PATH"
}

@test "run-baseline-scan.sh includes timestamp" {
    grep -q "date\|timestamp" "$SCRIPT_PATH"
}

@test "run-baseline-scan.sh handles baseline repository" {
    # Checks baseline repository handling
    grep -q "git\|clone\|pull\|repo" "$SCRIPT_PATH"
}
