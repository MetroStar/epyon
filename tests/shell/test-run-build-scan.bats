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

@test "run-build-scan.sh generates target manifest when no Dockerfile present" {
    local target_dir
    target_dir=$(mktemp -d)
    local scan_dir
    scan_dir=$(mktemp -d)

    run bash "$SCRIPT_PATH" --target "$target_dir" --scan-dir "$scan_dir"
    [ "$status" -eq 0 ]
    [ -f "$scan_dir/build/build-summary.json" ]
    [ -f "$scan_dir/build/image-digest.txt" ]
    [ -f "$scan_dir/build/oci-manifest.json" ]
    [ -f "$scan_dir/build/Dockerfile" ]
    run jq -r '.status' "$scan_dir/build/build-summary.json"
    [ "$output" = "success" ]

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

@test "run-build-scan.sh writes mode=container_build in build-summary.json on a successful build" {
    # Regression: build-summary.json's success path never set a "mode" field,
    # so run-epyon-scan-ci.sh / run-target-security-scan.sh's
    # `build_mode == "container_build"` check could never be true for a real
    # build — PRIMARY_BASELINE_IMAGE was never routed to downstream scanners,
    # which silently fell back to pulling the raw, unpatched upstream base
    # image instead of scanning the actual built artifact.
    local target_dir
    target_dir=$(mktemp -d)
    local scan_dir
    scan_dir=$(mktemp -d)

    cat << 'EOF' > "$target_dir/Dockerfile"
FROM scratch
EOF

    run bash "$SCRIPT_PATH" --target "$target_dir" --scan-dir "$scan_dir" --image-name "test-img" --image-tag "v1"

    run jq -r '.status' "$scan_dir/build/build-summary.json"
    local build_status="$output"
    if [[ "$build_status" == "success" ]]; then
        run jq -r '.mode' "$scan_dir/build/build-summary.json"
        [ "$output" = "container_build" ]
    else
        skip "no container build runtime available in this environment"
    fi

    rm -rf "$target_dir" "$scan_dir"
}

@test "run-build-scan.sh auto-discovers a nested Dockerfile when none exists at the target root" {
    # Regression: monorepo-style targets (e.g. ui/Dockerfile, no root
    # Dockerfile) used to fall through to the no-Dockerfile "target_source_manifest"
    # branch, never building the real artifact.
    local target_dir
    target_dir=$(mktemp -d)
    local scan_dir
    scan_dir=$(mktemp -d)
    mkdir -p "$target_dir/ui"

    cat << 'EOF' > "$target_dir/ui/Dockerfile"
FROM scratch
EOF

    run bash "$SCRIPT_PATH" --target "$target_dir" --scan-dir "$scan_dir" --image-name "test-img" --image-tag "v1"
    [[ "$output" =~ "auto-discovered" ]]
    [[ "$output" =~ "ui/Dockerfile" ]]

    run jq -r '.status' "$scan_dir/build/build-summary.json"
    [ "$output" != "" ]
    [ "$output" != "null" ]

    rm -rf "$target_dir" "$scan_dir"
}

@test "run-build-scan.sh --dockerfile override takes precedence over auto-discovery" {
    local target_dir
    target_dir=$(mktemp -d)
    local scan_dir
    scan_dir=$(mktemp -d)
    mkdir -p "$target_dir/ui" "$target_dir/api"

    cat << 'EOF' > "$target_dir/ui/Dockerfile"
FROM scratch
EOF
    cat << 'EOF' > "$target_dir/api/Dockerfile"
FROM scratch
LABEL service=api
EOF

    run bash "$SCRIPT_PATH" --target "$target_dir" --scan-dir "$scan_dir" --dockerfile "api/Dockerfile" --image-name "test-img" --image-tag "v1"
    [[ ! "$output" =~ "auto-discovered" ]]
    run jq -r '.dockerfile' "$scan_dir/build/build-summary.json"
    [ "$output" = "Dockerfile" ]
    grep -q "service=api" "$scan_dir/build/Dockerfile"

    rm -rf "$target_dir" "$scan_dir"
}

@test "run-build-scan.sh fails clearly when --dockerfile points to a non-existent file" {
    local target_dir
    target_dir=$(mktemp -d)
    local scan_dir
    scan_dir=$(mktemp -d)

    run bash "$SCRIPT_PATH" --target "$target_dir" --scan-dir "$scan_dir" --dockerfile "does/not/exist/Dockerfile"
    [ "$status" -ne 0 ]
    [[ "$output" =~ "no such file" ]]

    rm -rf "$target_dir" "$scan_dir"
}
