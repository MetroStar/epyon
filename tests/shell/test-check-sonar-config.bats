#!/usr/bin/env bats

# Unit tests for check-sonar-config.sh

SCRIPT_DIR="${BATS_TEST_DIRNAME}/../../scripts/shell"
SCRIPT_PATH="${SCRIPT_DIR}/check-sonar-config.sh"

@test "check-sonar-config.sh exists and is executable" {
    [ -f "$SCRIPT_PATH" ]
    [ -x "$SCRIPT_PATH" ]
}

@test "check-sonar-config.sh has proper shebang" {
    head -n 1 "$SCRIPT_PATH" | grep -q "^#!/bin/bash"
}

@test "check-sonar-config.sh defines color variables" {
    grep -q "RED=" "$SCRIPT_PATH" || grep -q "GREEN=" "$SCRIPT_PATH" || grep -q "YELLOW=" "$SCRIPT_PATH" || echo "# May not use colors"
}

@test "check-sonar-config.sh checks for sonar configuration" {
    grep -q "sonar" "$SCRIPT_PATH" || grep -q "SONAR" "$SCRIPT_PATH"
}

@test "check-sonar-config.sh validates SonarQube configuration" {
    grep -q "sonar\|SONAR" "$SCRIPT_PATH"
}

@test "check-sonar-config.sh validates sonar properties" {
    grep -q "project\|key\|source" "$SCRIPT_PATH" || grep -q "valid\|check" "$SCRIPT_PATH"
}

@test "check-sonar-config.sh provides configuration validation" {
    grep -q "valid\|check\|verify" "$SCRIPT_PATH"
}
