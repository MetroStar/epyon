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

        printf '%s\n' \
            'ignores:' \
            '  - type: package' \
            '    value: netty-handler@4.1.136.Final' \
            '    reason: Waiting for updated image' \
            '    approved_by: rnelson' \
            '    expires: "2026-12-31"' \
            > "$target_dir/.epyon-ignore.yml"
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

@test "check-severity-gate.sh step summary lists every tool that detected a deduplicated CVE, not just the first" {
        # generate-scan-findings-summary.sh's dedup pass keeps only .[0] as the
        # surviving finding but records ALL contributing tools in .detected_by.
        # The step-summary CVE list must render .detected_by (falling back to
        # .tool for older summaries), not just the single surviving .tool,
        # otherwise a tool whose findings fully overlap another tool's appears
        # to have found nothing even though it ran and agreed on the CVE.
        local scan_dir
        scan_dir=$(mktemp -d)
        local target_dir
        target_dir=$(mktemp -d)
        local summary_file
        summary_file=$(mktemp)

        cat > "$scan_dir/security-findings-summary.json" << 'EOF'
{
    "critical_findings": [{
        "tool": "grype-sbom",
        "detected_by": ["grype-sbom", "trivy-filesystem"],
        "vulnerability_id": "GHSA-ffc3-869f-jxw9",
        "package_name": "pyjwt",
        "package_version": "2.13.0",
        "package_path": "api/requirements-pyproject.txt"
    }],
    "high_findings": [{
        "tool": "grype-sbom",
        "detected_by": ["grype-sbom", "trivy-filesystem"],
        "vulnerability_id": "GHSA-9j54-fg26-wv3r",
        "package_name": "pyjwt",
        "package_version": "2.13.0",
        "package_path": "api/requirements-pyproject.txt"
    }],
    "medium_findings": [],
    "low_findings": [],
    "summary": {}
}
EOF

        run env SCAN_DIR="$scan_dir" TARGET_DIR="$target_dir" GITHUB_STEP_SUMMARY="$summary_file" WARNING_ONLY=true "$SCRIPT_PATH"

        grep -q "trivy-filesystem" "$summary_file"
        grep -q "grype-sbom" "$summary_file"
        grep -q "GHSA-ffc3-869f-jxw9" "$summary_file"
        grep -q "GHSA-9j54-fg26-wv3r" "$summary_file"

        rm -rf "$scan_dir" "$target_dir"
        rm -f "$summary_file"
}
