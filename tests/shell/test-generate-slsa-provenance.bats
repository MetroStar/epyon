#!/usr/bin/env bats

# Unit tests for generate-slsa-provenance.sh

SCRIPT_DIR="${BATS_TEST_DIRNAME}/../../scripts/shell"
SCRIPT_PATH="${SCRIPT_DIR}/generate-slsa-provenance.sh"

@test "generate-slsa-provenance.sh exists and is executable" {
    [ -f "$SCRIPT_PATH" ]
    [ -x "$SCRIPT_PATH" ]
}

@test "generate-slsa-provenance.sh has proper shebang" {
    head -n 1 "$SCRIPT_PATH" | grep -q "^#!/bin/bash"
}

@test "generate-slsa-provenance.sh generates in-toto SLSA v1.0 provenance" {
    local scan_dir
    scan_dir=$(mktemp -d)
    mkdir -p "$scan_dir/build"
    echo "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef" > "$scan_dir/build/image-digest.txt"

    run bash "$SCRIPT_PATH" --scan-dir "$scan_dir" --image-name "my-app" --image-tag "v1.0.0"
    [ "$status" -eq 0 ]
    [ -f "$scan_dir/provenance.jsonl" ]
    [ -f "$scan_dir/provenance.json" ]

    run jq -r '.predicateType' "$scan_dir/provenance.json"
    [ "$output" = "https://slsa.dev/provenance/v1" ]

    rm -rf "$scan_dir"
}

@test "generate-slsa-provenance.sh safely serializes special characters in metadata" {
    local target_dir scan_dir
    target_dir=$(mktemp -d)
    scan_dir="${BATS_TEST_TMPDIR}/scan-\"quote\\slash"

    mkdir -p "$scan_dir/build"
    git -C "$target_dir" init
    git -C "$target_dir" config user.name "Test User"
    git -C "$target_dir" config user.email "test@example.com"
    printf 'content\n' > "$target_dir/file.txt"
    git -C "$target_dir" add file.txt
    git -C "$target_dir" commit -m "init"
    git -C "$target_dir" remote add origin 'https://example.com/org/repo"quoted".git'
    echo "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef" > "$scan_dir/build/image-digest.txt"

    run bash "$SCRIPT_PATH" --scan-dir "$scan_dir" --target "$target_dir" --image-name 'my"app\name' --image-tag "v1.0.0"
    [ "$status" -eq 0 ]

    run jq -r '.subject[0].name' "$scan_dir/provenance.json"
    [ "$output" = 'my"app\name:v1.0.0' ]

    run jq -r '.predicate.buildDefinition.externalParameters.repository' "$scan_dir/provenance.json"
    [ "$output" = 'https://example.com/org/repo"quoted".git' ]

    run jq -r '.predicate.runDetails.metadata.invocationId' "$scan_dir/provenance.json"
    [ "$output" = 'scan-"quote\slash' ]

    rm -rf "$target_dir" "$scan_dir"
}
