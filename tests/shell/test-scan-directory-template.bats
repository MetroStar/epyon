#!/usr/bin/env bats

# Unit tests for scan-directory-template.sh

SCRIPT_DIR="${BATS_TEST_DIRNAME}/../../scripts/shell"
SCRIPT_PATH="${SCRIPT_DIR}/scan-directory-template.sh"

@test "scan-directory-template.sh exists and is executable" {
    [ -f "$SCRIPT_PATH" ]
    [ -x "$SCRIPT_PATH" ]
}

@test "scan-directory-template.sh has proper shebang" {
    head -n 1 "$SCRIPT_PATH" | grep -q "^#!/bin/bash"
}

@test "scan-directory-template.sh defines init_scan_environment function" {
    grep -q "^init_scan_environment()" "$SCRIPT_PATH"
}

@test "scan-directory-template.sh defines create_result_file function" {
    grep -q "^create_result_file()" "$SCRIPT_PATH"
}

@test "scan-directory-template.sh defines count_scannable_files function" {
    grep -q "^count_scannable_files()" "$SCRIPT_PATH"
}

@test "scan-directory-template.sh defines get_file_breakdown function" {
    grep -q "^get_file_breakdown()" "$SCRIPT_PATH"
}

@test "scan-directory-template.sh defines finalize_scan_results function" {
    grep -q "^finalize_scan_results()" "$SCRIPT_PATH"
}

@test "scan-directory-template.sh can be sourced without errors" {
    run bash -c "source '$SCRIPT_PATH' && echo 'OK'"
    [ "$status" -eq 0 ]
    [[ "$output" =~ "OK" ]]
}

@test "scan-directory-template.sh count_scannable_files excludes node_modules" {
    grep -A 20 "^count_scannable_files()" "$SCRIPT_PATH" | grep -q "node_modules"
}

@test "scan-directory-template.sh count_scannable_files excludes .git" {
    grep -A 20 "^count_scannable_files()" "$SCRIPT_PATH" | grep -q "\.git"
}

@test "scan-directory-template.sh defines to_host_path function" {
    grep -q "^to_host_path()" "$SCRIPT_PATH"
}

@test "to_host_path returns the path unchanged when HOST_PROJECT_DIR is unset" {
    run bash -c "source '$SCRIPT_PATH' && unset HOST_PROJECT_DIR && to_host_path '/app/tmp/clone-123'"
    [ "$status" -eq 0 ]
    [ "$output" = "/app/tmp/clone-123" ]
}

@test "to_host_path returns non-/app paths unchanged even when HOST_PROJECT_DIR is set" {
    run bash -c "source '$SCRIPT_PATH' && HOST_PROJECT_DIR=/srv/epyon && to_host_path '/tmp/foo-1234'"
    [ "$status" -eq 0 ]
    [ "$output" = "/tmp/foo-1234" ]
}

@test "to_host_path translates an /app path to HOST_PROJECT_DIR when set" {
    run bash -c "source '$SCRIPT_PATH' && HOST_PROJECT_DIR=/srv/epyon && to_host_path '/app/tmp/clone-123'"
    [ "$status" -eq 0 ]
    [ "$output" = "/srv/epyon/tmp/clone-123" ]
}

@test "to_host_path handles a trailing slash on HOST_PROJECT_DIR without doubling it" {
    run bash -c "source '$SCRIPT_PATH' && HOST_PROJECT_DIR=/srv/epyon/ && to_host_path '/app/scans/foo_2026-01-01'"
    [ "$status" -eq 0 ]
    [ "$output" = "/srv/epyon/scans/foo_2026-01-01" ]
}

@test "to_host_path leaves a bare /app (no subpath) unchanged" {
    # Real callers always pass a subpath (e.g. /app/tmp/clone-123); a bare
    # "/app" has no trailing slash to strip and is left as-is rather than
    # guessed at.
    run bash -c "source '$SCRIPT_PATH' && HOST_PROJECT_DIR=/srv/epyon && to_host_path '/app'"
    [ "$status" -eq 0 ]
    [ "$output" = "/app" ]
}

# ── discover_dockerfile_base_images() ────────────────────────────────────────

@test "discover_dockerfile_base_images only reports the final stage of a multi-stage Dockerfile" {
    local tmp_target
    tmp_target="$(mktemp -d)"
    cat > "${tmp_target}/Dockerfile" <<'DOCKERFILE'
FROM golang:1.24.13-alpine AS builder
FROM python:3.12-slim-bookworm AS runtime
DOCKERFILE
    run bash -c "source '$SCRIPT_PATH' && mapfile -t images < <(discover_dockerfile_base_images '$tmp_target') && printf '%s\n' \"\${images[@]}\""
    rm -rf "$tmp_target"
    [ "$status" -eq 0 ]
    [[ "$output" == "python:3.12-slim-bookworm" ]]
    [[ "$output" != *"golang"* ]]
}

@test "discover_dockerfile_base_images skips the whole Dockerfile when the final stage is an unresolved build-arg" {
    local tmp_target
    tmp_target="$(mktemp -d)"
    cat > "${tmp_target}/Dockerfile" <<'DOCKERFILE'
FROM reg.internal.example/python:3.12-dev AS builder
FROM ${RUNTIME_IMAGE}
DOCKERFILE
    run bash -c "source '$SCRIPT_PATH' && mapfile -t images < <(discover_dockerfile_base_images '$tmp_target') && printf '%s\n' \"\${images[@]}\""
    rm -rf "$tmp_target"
    [ "$status" -eq 0 ]
    [ -z "$output" ]
}

@test "discover_dockerfile_base_images resolves a final FROM that references an earlier named stage" {
    local tmp_target
    tmp_target="$(mktemp -d)"
    cat > "${tmp_target}/Dockerfile" <<'DOCKERFILE'
FROM ubuntu:22.04 AS base
FROM base AS runtime
DOCKERFILE
    run bash -c "source '$SCRIPT_PATH' && mapfile -t images < <(discover_dockerfile_base_images '$tmp_target') && printf '%s\n' \"\${images[@]}\""
    rm -rf "$tmp_target"
    [ "$status" -eq 0 ]
    [[ "$output" == "ubuntu:22.04" ]]
}

@test "discover_dockerfile_base_images still reports a single-stage Dockerfile's only image" {
    local tmp_target
    tmp_target="$(mktemp -d)"
    cat > "${tmp_target}/Dockerfile" <<'DOCKERFILE'
FROM ubuntu:24.04
DOCKERFILE
    run bash -c "source '$SCRIPT_PATH' && mapfile -t images < <(discover_dockerfile_base_images '$tmp_target') && printf '%s\n' \"\${images[@]}\""
    rm -rf "$tmp_target"
    [ "$status" -eq 0 ]
    [[ "$output" == "ubuntu:24.04" ]]
}

@test "discover_dockerfile_base_images skips FROM scratch final stages" {
    local tmp_target
    tmp_target="$(mktemp -d)"
    cat > "${tmp_target}/Dockerfile" <<'DOCKERFILE'
FROM golang:1.24.13-alpine AS src
FROM scratch
DOCKERFILE
    run bash -c "source '$SCRIPT_PATH' && mapfile -t images < <(discover_dockerfile_base_images '$tmp_target') && printf '%s\n' \"\${images[@]}\""
    rm -rf "$tmp_target"
    [ "$status" -eq 0 ]
    [ -z "$output" ]
}
