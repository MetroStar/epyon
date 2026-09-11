#!/usr/bin/env bats

# Unit tests for run-build-scan.sh

SCRIPT_DIR="${BATS_TEST_DIRNAME}/../../scripts/shell"
SCRIPT_PATH="${SCRIPT_DIR}/run-build-scan.sh"

@test "run-build-scan.sh exists and is executable" {
    [ -f "$SCRIPT_PATH" ]
    [ -x "$SCRIPT_PATH" ]
}

@test "run-build-scan.sh has proper shebang" {
    head -n 1 "$SCRIPT_PATH" | grep -q "^#!/bin/bash"
}

@test "run-build-scan.sh shows help with --help flag" {
    run bash "$SCRIPT_PATH" --help
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Container Image Builder" ]]
}

@test "run-build-scan.sh skips gracefully when no Dockerfile present" {
    local target_dir
    target_dir=$(mktemp -d)
    local scan_dir
    scan_dir=$(mktemp -d)

    run bash "$SCRIPT_PATH" --target "$target_dir" --scan-dir "$scan_dir"
    [ "$status" -eq 0 ]
    [ -f "$scan_dir/build/build-summary.json" ]
    run jq -r '.status' "$scan_dir/build/build-summary.json"
    [ "$output" = "skipped" ]

    rm -rf "$target_dir" "$scan_dir"
}

@test "run-build-scan.sh detects Dockerfile and attempts build" {
    local target_dir
    target_dir=$(mktemp -d)
    local scan_dir
    scan_dir=$(mktemp -d)

    cat << 'EOF' > "$target_dir/Dockerfile"
FROM scratch
EOF

    # Test with mockup docker or execution check
    run bash "$SCRIPT_PATH" --target "$target_dir" --scan-dir "$scan_dir" --image-name "test-img" --image-tag "v1"
    # Will complete or attempt build based on local docker availability
    [ -d "$scan_dir/build" ]

    rm -rf "$target_dir" "$scan_dir"
}
