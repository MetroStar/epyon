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
