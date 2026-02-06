#!/usr/bin/env bats

# Unit tests for open-latest-dashboard.sh

SCRIPT_DIR="${BATS_TEST_DIRNAME}/../../scripts/shell"
SCRIPT_PATH="${SCRIPT_DIR}/open-latest-dashboard.sh"

@test "open-latest-dashboard.sh exists and is executable" {
    [ -f "$SCRIPT_PATH" ]
    [ -x "$SCRIPT_PATH" ]
}

@test "open-latest-dashboard.sh has proper shebang" {
    head -n 1 "$SCRIPT_PATH" | grep -q "^#!/bin/bash"
}

@test "open-latest-dashboard.sh defines color variables" {
    grep -q "RED=\|GREEN=\|YELLOW=\|CYAN=" "$SCRIPT_PATH"
}

@test "open-latest-dashboard.sh finds latest scan directory" {
    grep -q "find.*scan\|ls.*scan\|latest" "$SCRIPT_PATH"
}

@test "open-latest-dashboard.sh locates dashboard file" {
    grep -q "dashboard.*html\|security-dashboard\\.html" "$SCRIPT_PATH"
}

@test "open-latest-dashboard.sh opens dashboard in browser" {
    grep -q "open\|xdg-open\|start" "$SCRIPT_PATH"
}

@test "open-latest-dashboard.sh handles missing dashboard" {
    grep -q "not found\|does not exist\|No dashboard" "$SCRIPT_PATH" || grep -q "\\[ -f" "$SCRIPT_PATH"
}
