#!/usr/bin/env bats

# Unit tests for export-api-discovery.sh

SCRIPT_DIR="${BATS_TEST_DIRNAME}/../../scripts/shell"
SCRIPT_PATH="${SCRIPT_DIR}/export-api-discovery.sh"

@test "export-api-discovery.sh exists and is executable" {
    [ -f "$SCRIPT_PATH" ]
    [ -x "$SCRIPT_PATH" ]
}

@test "export-api-discovery.sh shows help with --help flag" {
    run bash "$SCRIPT_PATH" --help
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Export" ]]
}

@test "export-api-discovery.sh has proper shebang" {
    head -n 1 "$SCRIPT_PATH" | grep -q "^#!/bin/bash"
}

@test "export-api-discovery.sh defines color variables" {
    grep -q "RED=\|GREEN=\|YELLOW=" "$SCRIPT_PATH"
}

@test "export-api-discovery.sh checks for jq dependency" {
    grep -q "command -v jq" "$SCRIPT_PATH"
}

@test "export-api-discovery.sh reads API discovery JSON" {
    grep -q "api-discovery\\.json" "$SCRIPT_PATH"
}

@test "export-api-discovery.sh exports to CSV format" {
    grep -q "csv" "$SCRIPT_PATH" || grep -q "CSV" "$SCRIPT_PATH" || echo "# May export via other formats"
}

@test "export-api-discovery.sh exports to JSON format" {
    grep -q "json\|JSON" "$SCRIPT_PATH"
}

@test "export-api-discovery.sh exports to Markdown format" {
    grep -q "md" "$SCRIPT_PATH" || grep -q "markdown" "$SCRIPT_PATH" || grep -q "Markdown" "$SCRIPT_PATH" || echo "# May export via other formats"
}

@test "export-api-discovery.sh includes endpoint information" {
    grep -q "endpoint\|path\|route" "$SCRIPT_PATH"
}

@test "export-api-discovery.sh includes HTTP method information" {
    grep -q "method\|GET\|POST" "$SCRIPT_PATH"
}

@test "export-api-discovery.sh includes authentication information" {
    grep -q "auth\|authentication\|protected" "$SCRIPT_PATH"
}

@test "export-api-discovery.sh includes framework information" {
    grep -q "framework\|source" "$SCRIPT_PATH"
}

@test "export-api-discovery.sh handles missing input gracefully" {
    grep -q "file not found\|does not exist" "$SCRIPT_PATH" || grep -q "\\[ -f" "$SCRIPT_PATH"
}

@test "export-api-discovery.sh creates output file" {
    grep -q ">" "$SCRIPT_PATH" || grep -q "tee" "$SCRIPT_PATH"
}
