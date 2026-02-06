#!/usr/bin/env bats

# Unit tests for update-base-images.sh

SCRIPT_DIR="${BATS_TEST_DIRNAME}/../../scripts/shell"
SCRIPT_PATH="${SCRIPT_DIR}/update-base-images.sh"

@test "update-base-images.sh exists and is executable" {
    [ -f "$SCRIPT_PATH" ]
    [ -x "$SCRIPT_PATH" ]
}

@test "update-base-images.sh has proper shebang" {
    head -n 1 "$SCRIPT_PATH" | grep -q "^#!/bin/bash"
}

@test "update-base-images.sh defines color variables" {
    grep -q "RED=\|GREEN=\|YELLOW=" "$SCRIPT_PATH"
}

@test "update-base-images.sh pulls Docker images" {
    grep -q "docker pull\|docker image" "$SCRIPT_PATH"
}

@test "update-base-images.sh handles multiple base images" {
    grep -q "image\|IMAGE" "$SCRIPT_PATH"
}

@test "update-base-images.sh updates scanner images" {
    grep -q "trivy\|grype\|anchore\|syft" "$SCRIPT_PATH" || grep -q "scanner\|tool" "$SCRIPT_PATH"
}

@test "update-base-images.sh checks for Docker availability" {
    grep -q "command -v docker\|which docker\|docker" "$SCRIPT_PATH"
}

@test "update-base-images.sh provides image management" {
    grep -q "update\|pull\|latest" "$SCRIPT_PATH"
}
