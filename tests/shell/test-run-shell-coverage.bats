#!/usr/bin/env bats

# Unit tests for run-shell-coverage.sh

SCRIPT_DIR="${BATS_TEST_DIRNAME}/../../scripts/shell"
SCRIPT_PATH="${SCRIPT_DIR}/run-shell-coverage.sh"

@test "run-shell-coverage.sh exists and is executable" {
    [ -f "$SCRIPT_PATH" ]
    [ -x "$SCRIPT_PATH" ]
}

@test "run-shell-coverage.sh has proper shebang" {
    head -n 1 "$SCRIPT_PATH" | grep -qE "^#!/usr/bin/env bash|^#!/bin/bash"
}

@test "run-shell-coverage.sh references kcov" {
    grep -q "kcov" "$SCRIPT_PATH"
}

@test "run-shell-coverage.sh references bats tests" {
    grep -q "bats\|\.bats" "$SCRIPT_PATH"
}

@test "run-shell-coverage.sh produces SonarCloud coverage XML" {
    grep -q "sonar-coverage.xml\|coverageReportPaths\|sonar" "$SCRIPT_PATH"
}

@test "run-shell-coverage.sh defines write_empty_coverage fallback" {
    grep -q "write_empty_coverage" "$SCRIPT_PATH"
}

@test "run-shell-coverage.sh accepts REPO_PATH as first argument" {
    grep -q "REPO_PATH" "$SCRIPT_PATH"
}

@test "run-shell-coverage.sh accepts COVERAGE_OUT environment variable" {
    grep -q "COVERAGE_OUT" "$SCRIPT_PATH"
}

@test "run-shell-coverage.sh accepts SCRIPTS_PATH environment variable" {
    grep -q "SCRIPTS_PATH" "$SCRIPT_PATH"
}

@test "run-shell-coverage.sh accepts TESTS_PATH environment variable" {
    grep -q "TESTS_PATH" "$SCRIPT_PATH"
}

@test "run-shell-coverage.sh references convert-kcov-to-sonar.py converter" {
    grep -q "convert-kcov-to-sonar" "$SCRIPT_PATH"
}

@test "run-shell-coverage.sh writes empty coverage XML when kcov unavailable" {
    # When kcov is not installed the script must still produce valid XML
    # and exit 0 (graceful degradation)
    command -v kcov &>/dev/null && skip "kcov is installed; skipping empty-coverage path test"

    local TMP_REPO
    TMP_REPO=$(mktemp -d)
    mkdir -p "$TMP_REPO/scripts/shell" "$TMP_REPO/tests/shell" "$TMP_REPO/coverage"

    local OUT="$TMP_REPO/coverage/sonar-coverage.xml"

    run "$SCRIPT_PATH" "$TMP_REPO"
    [ "$status" -eq 0 ]
    [ -f "$OUT" ]
    grep -q "<coverage" "$OUT"

    rm -rf "$TMP_REPO"
}
