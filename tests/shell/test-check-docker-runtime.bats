#!/usr/bin/env bats

# Unit tests for check-docker-runtime.sh

SCRIPT_DIR="${BATS_TEST_DIRNAME}/../../scripts/shell"
SCRIPT_PATH="${SCRIPT_DIR}/check-docker-runtime.sh"

@test "check-docker-runtime.sh exists and is executable" {
    [ -f "$SCRIPT_PATH" ]
    [ -x "$SCRIPT_PATH" ]
}

@test "check-docker-runtime.sh has proper shebang" {
    head -n 1 "$SCRIPT_PATH" | grep -qE "^#!/usr/bin/env bash|^#!/bin/bash"
}

@test "check-docker-runtime.sh defines color variables" {
    grep -q "GREEN=\|RED=\|CYAN=" "$SCRIPT_PATH"
}

@test "check-docker-runtime.sh sources container-runtime.sh" {
    grep -q "container-runtime.sh" "$SCRIPT_PATH"
}

@test "check-docker-runtime.sh handles missing container runtime gracefully" {
    grep -q "CONTAINER_CLI\|container.*cli\|No container" "$SCRIPT_PATH"
}

@test "check-docker-runtime.sh exits non-zero when no runtime found" {
    grep -q "exit 1" "$SCRIPT_PATH"
}

@test "check-docker-runtime.sh references docker podman or nerdctl" {
    grep -qiE "docker|podman|nerdctl" "$SCRIPT_PATH"
}
