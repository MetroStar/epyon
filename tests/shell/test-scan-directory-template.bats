#!/usr/bin/env bats

# Unit tests for scan-directory-template.sh

SCRIPT_DIR="${BATS_TEST_DIRNAME}/../../scripts/shell"
SCRIPT_PATH="${SCRIPT_DIR}/scan-directory-template.sh"

@test "scan-directory-template.sh exists and is executable" {
    [ -f "$SCRIPT_PATH" ]
    [ -x "$SCRIPT_PATH" ]
}

@test "scan-directory-template.sh has proper shebang" {
    head -n 1 "$SCRIPT_PATH" | grep -q "^#!/bin/bash"
}

@test "scan-directory-template.sh defines init_scan_environment function" {
    grep -q "^init_scan_environment()" "$SCRIPT_PATH"
}

@test "scan-directory-template.sh defines create_result_file function" {
    grep -q "^create_result_file()" "$SCRIPT_PATH"
}

@test "scan-directory-template.sh defines count_scannable_files function" {
    grep -q "^count_scannable_files()" "$SCRIPT_PATH"
}

@test "scan-directory-template.sh defines get_file_breakdown function" {
    grep -q "^get_file_breakdown()" "$SCRIPT_PATH"
}

@test "scan-directory-template.sh defines finalize_scan_results function" {
    grep -q "^finalize_scan_results()" "$SCRIPT_PATH"
}

@test "scan-directory-template.sh can be sourced without errors" {
    run bash -c "source '$SCRIPT_PATH' && echo 'OK'"
    [ "$status" -eq 0 ]
    [[ "$output" =~ "OK" ]]
}

@test "scan-directory-template.sh count_scannable_files excludes node_modules" {
    grep -A 20 "^count_scannable_files()" "$SCRIPT_PATH" | grep -q "node_modules"
}

@test "scan-directory-template.sh count_scannable_files excludes .git" {
    grep -A 20 "^count_scannable_files()" "$SCRIPT_PATH" | grep -q "\.git"
}
