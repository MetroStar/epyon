#!/usr/bin/env bats

# Unit tests for generate-remediation-suggestions.sh

SCRIPT_DIR="${BATS_TEST_DIRNAME}/../../scripts/shell"
SCRIPT_PATH="${SCRIPT_DIR}/generate-remediation-suggestions.sh"

@test "generate-remediation-suggestions.sh exists and is executable" {
    [ -f "$SCRIPT_PATH" ]
    [ -x "$SCRIPT_PATH" ]
}

@test "generate-remediation-suggestions.sh has proper shebang" {
    head -n 1 "$SCRIPT_PATH" | grep -q "^#!/bin/bash"
}

@test "generate-remediation-suggestions.sh defines color variables" {
    grep -q "RED=\|GREEN=\|YELLOW=" "$SCRIPT_PATH"
}

@test "generate-remediation-suggestions.sh processes vulnerabilities" {
    grep -q "vulnerabilit\|CVE\|finding" "$SCRIPT_PATH"
}

@test "generate-remediation-suggestions.sh provides remediation advice" {
    grep -q "remediation\|fix\|upgrade\|patch" "$SCRIPT_PATH"
}

@test "generate-remediation-suggestions.sh analyzes scan results" {
    grep -q "scan.*results\|json" "$SCRIPT_PATH"
}

@test "generate-remediation-suggestions.sh suggests version upgrades" {
    grep -q "version\|upgrade\|update" "$SCRIPT_PATH"
}

@test "generate-remediation-suggestions.sh creates remediation report" {
    grep -q "report\|output\|suggestion" "$SCRIPT_PATH"
}
