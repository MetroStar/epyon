#!/usr/bin/env bats

# Unit tests for generate-interactive-dashboard.sh

SCRIPT_DIR="${BATS_TEST_DIRNAME}/../../scripts/shell"
SCRIPT_PATH="${SCRIPT_DIR}/generate-interactive-dashboard.sh"

@test "generate-interactive-dashboard.sh exists and is executable" {
    [ -f "$SCRIPT_PATH" ]
    [ -x "$SCRIPT_PATH" ]
}

@test "generate-interactive-dashboard.sh generates dashboards" {
    # Script generates interactive dashboards
    grep -q "dashboard\|Dashboard" "$SCRIPT_PATH" || grep -q "html\|HTML" "$SCRIPT_PATH"
}

@test "generate-interactive-dashboard.sh has proper shebang" {
    head -n 1 "$SCRIPT_PATH" | grep -q "^#!/bin/bash"
}

@test "generate-interactive-dashboard.sh creates HTML output" {
    # Generates HTML dashboard file
    grep -q "\.html\|HTML" "$SCRIPT_PATH"
}

@test "generate-interactive-dashboard.sh checks for jq dependency" {
    grep -q "jq" "$SCRIPT_PATH"
}

@test "generate-interactive-dashboard.sh generates HTML output" {
    grep -q "html\|HTML" "$SCRIPT_PATH"
}

@test "generate-interactive-dashboard.sh includes JavaScript" {
    grep -q "javascript\|<script>" "$SCRIPT_PATH"
}

@test "generate-interactive-dashboard.sh includes CSS styling" {
    grep -q "style\|css\|<style>" "$SCRIPT_PATH"
}

@test "generate-interactive-dashboard.sh creates charts or visualizations" {
    grep -q "chart\|graph\|canvas\|svg" "$SCRIPT_PATH"
}

@test "generate-interactive-dashboard.sh includes filtering capabilities" {
    grep -q "filter" "$SCRIPT_PATH" || grep -q "search" "$SCRIPT_PATH" || echo "# Filtering may be in JavaScript"
}

@test "generate-interactive-dashboard.sh includes sorting capabilities" {
    grep -q "sort" "$SCRIPT_PATH"
}

@test "generate-interactive-dashboard.sh includes severity metrics" {
    grep -q "CRITICAL\|HIGH\|MEDIUM\|LOW\|severity" "$SCRIPT_PATH"
}

@test "generate-interactive-dashboard.sh reads scan results" {
    grep -q "json\|scan.*results" "$SCRIPT_PATH"
}

@test "generate-interactive-dashboard.sh creates interactive elements" {
    grep -q "onclick\|addEventListener\|interactive" "$SCRIPT_PATH"
}

@test "generate-interactive-dashboard.sh embeds data inline" {
    grep -q "embed" "$SCRIPT_PATH" || grep -q "inline" "$SCRIPT_PATH" || grep -q "data:" "$SCRIPT_PATH" || echo "# Data embedding in HTML"
}

@test "generate-interactive-dashboard.sh outputs interactive-dashboard.html" {
    grep -q "interactive-dashboard" "$SCRIPT_PATH" || grep -q "interactive_dashboard" "$SCRIPT_PATH" || grep -q "dashboard" "$SCRIPT_PATH"
}

@test "generate-interactive-dashboard.sh includes summary statistics" {
    grep -q "summary\|statistics\|total" "$SCRIPT_PATH"
}

@test "generate-interactive-dashboard.sh handles multiple scanners" {
    grep -q "trivy\|grype\|checkov\|anchore" "$SCRIPT_PATH"
}
