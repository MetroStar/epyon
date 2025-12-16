#!/usr/bin/env bats

# Unit tests for run-helm-build.sh

SCRIPT_DIR="${BATS_TEST_DIRNAME}/../../scripts/shell"
SCRIPT_PATH="${SCRIPT_DIR}/run-helm-build.sh"

@test "run-helm-build.sh exists and is executable" {
    [ -f "$SCRIPT_PATH" ]
    [ -x "$SCRIPT_PATH" ]
}

@test "run-helm-build.sh has proper shebang" {
    head -n 1 "$SCRIPT_PATH" | grep -q "^#!/bin/bash"
}

@test "run-helm-build.sh sources scan-directory-template.sh" {
    grep -q "source.*scan-directory-template.sh" "$SCRIPT_PATH"
}

@test "run-helm-build.sh contains init_scan_environment function call" {
    grep -q "init_scan_environment" "$SCRIPT_PATH"
}

@test "run-helm-build.sh defines color variables" {
    grep -q "RED=" "$SCRIPT_PATH"
    grep -q "GREEN=" "$SCRIPT_PATH"
    grep -q "NC=" "$SCRIPT_PATH"
}

@test "run-helm-build.sh uses helm commands" {
    grep -q "helm lint\|helm template\|helm package" "$SCRIPT_PATH"
}

@test "run-helm-build.sh has build_helm_chart function" {
    grep -q "build_helm_chart()" "$SCRIPT_PATH"
}

@test "run-helm-build.sh supports AWS ECR authentication" {
    grep -q "aws ecr\|ECR_REGISTRY" "$SCRIPT_PATH"
}
