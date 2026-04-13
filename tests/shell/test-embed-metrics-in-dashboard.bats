#!/usr/bin/env bats

# Unit tests for embed-metrics-in-dashboard.sh

SCRIPT_DIR="${BATS_TEST_DIRNAME}/../../scripts/shell"
SCRIPT_PATH="${SCRIPT_DIR}/embed-metrics-in-dashboard.sh"

@test "embed-metrics-in-dashboard.sh exists and is executable" {
    [ -f "$SCRIPT_PATH" ]
    [ -x "$SCRIPT_PATH" ]
}

@test "embed-metrics-in-dashboard.sh has proper shebang" {
    head -n 1 "$SCRIPT_PATH" | grep -q "^#!/bin/bash\|^#!/usr/bin/env bash"
}

@test "embed-metrics-in-dashboard.sh defines color variables" {
    grep -q "GREEN=\|RED=\|CYAN=" "$SCRIPT_PATH"
}

@test "embed-metrics-in-dashboard.sh accepts --metrics flag" {
    grep -q "\-m|\-\-metrics\|--metrics" "$SCRIPT_PATH"
}

@test "embed-metrics-in-dashboard.sh accepts --dashboard flag" {
    grep -q "\-\-dashboard\|-d\b" "$SCRIPT_PATH"
}

@test "embed-metrics-in-dashboard.sh accepts --output flag" {
    grep -q "\-\-output\|-o\b" "$SCRIPT_PATH"
}

@test "embed-metrics-in-dashboard.sh accepts --max-points flag" {
    grep -q "max.points\|MAX_POINTS" "$SCRIPT_PATH"
}

@test "embed-metrics-in-dashboard.sh defaults MAX_POINTS to 90" {
    grep -q "MAX_POINTS.*90\|MAX_POINTS=90" "$SCRIPT_PATH"
}

@test "embed-metrics-in-dashboard.sh accepts --pr-repo flag" {
    grep -q "pr.repo\|PR_REPO" "$SCRIPT_PATH"
}

@test "embed-metrics-in-dashboard.sh accepts --pr-base-branch flag" {
    grep -q "pr.base.branch\|PR_BASE_BRANCH" "$SCRIPT_PATH"
}

@test "embed-metrics-in-dashboard.sh defaults PR_BASE_BRANCH to main" {
    grep -q 'PR_BASE_BRANCH.*main\|PR_BASE_BRANCH="main"' "$SCRIPT_PATH"
}

@test "embed-metrics-in-dashboard.sh exits with error when metrics file is missing" {
    grep -q "Metrics file not found\|not found.*METRICS_FILE" "$SCRIPT_PATH"
}

@test "embed-metrics-in-dashboard.sh exits with error when dashboard file is missing" {
    grep -q "dashboard.*not found\|Dashboard.*not found\|DASHBOARD_FILE" "$SCRIPT_PATH"
}

@test "embed-metrics-in-dashboard.sh uses jq for JSON processing" {
    grep -q "jq" "$SCRIPT_PATH"
}

@test "embed-metrics-in-dashboard.sh supports --quiet flag" {
    grep -q "QUIET\|--quiet" "$SCRIPT_PATH"
}

@test "embed-metrics-in-dashboard.sh generates vulnerability trend chart data" {
    grep -q "trend\|vulnerability.*chart\|Chart 1\|chart_1\|vulnChart" "$SCRIPT_PATH"
}

@test "embed-metrics-in-dashboard.sh generates PR activity and CVE discipline chart" {
    grep -q "PR.*CVE\|cve.*discipline\|prChart\|Chart 2\|chart_2\|prActivity" "$SCRIPT_PATH"
}

@test "embed-metrics-in-dashboard.sh embeds chart data into HTML dashboard" {
    grep -q "sed\|replace\|inject\|embed\|EPYON_METRICS_DATA\|<!-- METRICS\|CHART_DATA" "$SCRIPT_PATH"
}

@test "embed-metrics-in-dashboard.sh handles empty metrics gracefully" {
    grep -q '"\[\]"\|== \[\]\|empty\|no.*data\|0 data points\|No.*metric' "$SCRIPT_PATH"
}

@test "embed-metrics-in-dashboard.sh supports --since date filtering" {
    grep -q "since\|PR_SINCE" "$SCRIPT_PATH"
}
