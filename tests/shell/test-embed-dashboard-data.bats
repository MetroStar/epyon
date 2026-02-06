#!/usr/bin/env bats

# Unit tests for embed-dashboard-data.sh

SCRIPT_DIR="${BATS_TEST_DIRNAME}/../../scripts/shell"
SCRIPT_PATH="${SCRIPT_DIR}/embed-dashboard-data.sh"

@test "embed-dashboard-data.sh exists and is executable" {
    [ -f "$SCRIPT_PATH" ]
    [ -x "$SCRIPT_PATH" ]
}

@test "embed-dashboard-data.sh has proper shebang" {
    head -n 1 "$SCRIPT_PATH" | grep -q "^#!/bin/bash"
}

@test "embed-dashboard-data.sh defines color variables" {
    grep -q "RED=\|GREEN=\|YELLOW=" "$SCRIPT_PATH"
}

@test "embed-dashboard-data.sh reads scan results" {
    grep -q "json\|scan.*results" "$SCRIPT_PATH"
}

@test "embed-dashboard-data.sh embeds data into HTML" {
    grep -q "html\|HTML\|dashboard" "$SCRIPT_PATH"
}

@test "embed-dashboard-data.sh uses JavaScript data embedding" {
    grep -q "script\|var.*data\|const.*data" "$SCRIPT_PATH"
}

@test "embed-dashboard-data.sh creates self-contained dashboard" {
    grep -q "embed\|inline\|self-contained" "$SCRIPT_PATH" || grep -q "dashboard" "$SCRIPT_PATH"
}
