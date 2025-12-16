#!/usr/bin/env bats

# Unit tests for run-sonar-analysis.sh

SCRIPT_DIR="${BATS_TEST_DIRNAME}/../../scripts/shell"
SCRIPT_PATH="${SCRIPT_DIR}/run-sonar-analysis.sh"

@test "run-sonar-analysis.sh exists and is executable" {
    [ -f "$SCRIPT_PATH" ]
    [ -x "$SCRIPT_PATH" ]
}

@test "run-sonar-analysis.sh has proper shebang" {
    head -n 1 "$SCRIPT_PATH" | grep -q "^#!/bin/bash"
}

@test "run-sonar-analysis.sh sources scan-directory-template.sh" {
    grep -q "source.*scan-directory-template.sh" "$SCRIPT_PATH"
}

@test "run-sonar-analysis.sh contains init_scan_environment function call" {
    grep -q "init_scan_environment" "$SCRIPT_PATH"
}

@test "run-sonar-analysis.sh defines color variables" {
    grep -q "WHITE=" "$SCRIPT_PATH"
    grep -q "NC=" "$SCRIPT_PATH"
}

@test "run-sonar-analysis.sh uses Docker or sonar-scanner" {
    grep -q "docker run\|sonar-scanner" "$SCRIPT_PATH"
}

@test "run-sonar-analysis.sh references SonarQube" {
    grep -q -i "sonar" "$SCRIPT_PATH"
}

@test "run-sonar-analysis.sh checks for sonar configuration" {
    grep -q "SONAR_HOST_URL\|SONAR_TOKEN" "$SCRIPT_PATH"
}
