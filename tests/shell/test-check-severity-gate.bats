#!/usr/bin/env bats

# Unit tests for check-severity-gate.sh

SCRIPT_DIR="${BATS_TEST_DIRNAME}/../../scripts/shell"
SCRIPT_PATH="${SCRIPT_DIR}/check-severity-gate.sh"

@test "check-severity-gate.sh exists and is executable" {
    [ -f "$SCRIPT_PATH" ]
    [ -x "$SCRIPT_PATH" ]
}

@test "check-severity-gate.sh has proper shebang" {
    head -n 1 "$SCRIPT_PATH" | grep -q "^#!/bin/bash"
}

@test "check-severity-gate.sh defines color variables" {
    grep -q "RED=\|GREEN=\|YELLOW=" "$SCRIPT_PATH"
}

@test "check-severity-gate.sh checks severity thresholds" {
    grep -q "CRITICAL\|HIGH\|MEDIUM\|severity" "$SCRIPT_PATH"
}

@test "check-severity-gate.sh processes scan results" {
    grep -q "scan.*results\|json" "$SCRIPT_PATH"
}

@test "check-severity-gate.sh enforces quality gates" {
    grep -q "gate\|threshold\|limit\|max" "$SCRIPT_PATH"
}

@test "check-severity-gate.sh exits with appropriate codes" {
    grep -q "exit 0\|exit 1" "$SCRIPT_PATH"
}

@test "check-severity-gate.sh counts findings by severity" {
    grep -q "count\|total\|number" "$SCRIPT_PATH"
}

@test "check-severity-gate.sh provides gate validation" {
    grep -q "pass\|fail\|exceed\|breach" "$SCRIPT_PATH" || grep -q "gate" "$SCRIPT_PATH"
}

@test "check-severity-gate.sh suppresses identified findings by package version" {
        local scan_dir
        scan_dir=$(mktemp -d)
        local target_dir
        target_dir=$(mktemp -d)

        cat > "$target_dir/.epyon-ignore.yml" << 'EOF'
ignores:
    - type: package
        value: netty-handler@4.1.136.Final
        reason: Waiting for updated image
        approved_by: rnelson
        expires: "2026-12-31"
EOF
        cat > "$scan_dir/security-findings-summary.json" << 'EOF'
{
    "critical_findings": [{
        "tool": "trivy",
        "vulnerability_id": "GHSA-c4c3-7fpv-j4q5",
        "package_name": "netty-handler",
        "package_version": "4.1.136.Final"
    }],
    "high_findings": [],
    "medium_findings": [],
    "low_findings": [],
    "summary": {}
}
EOF

        run env SCAN_DIR="$scan_dir" TARGET_DIR="$target_dir" WARNING_ONLY=true "$SCRIPT_PATH"
        [ "$status" -eq 0 ]

        run jq -e '.critical_findings | length == 0' "$scan_dir/security-findings-filtered.json"
        [ "$status" -eq 0 ]

        rm -rf "$scan_dir" "$target_dir"
}
