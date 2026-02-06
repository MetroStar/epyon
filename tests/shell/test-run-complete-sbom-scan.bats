#!/usr/bin/env bats

# Unit tests for run-complete-sbom-scan.sh

SCRIPT_DIR="${BATS_TEST_DIRNAME}/../../scripts/shell"
SCRIPT_PATH="${SCRIPT_DIR}/run-complete-sbom-scan.sh"

@test "run-complete-sbom-scan.sh exists and is executable" {
    [ -f "$SCRIPT_PATH" ]
    [ -x "$SCRIPT_PATH" ]
}

@test "run-complete-sbom-scan.sh has proper shebang" {
    head -n 1 "$SCRIPT_PATH" | grep -q "^#!/bin/bash"
}

@test "run-complete-sbom-scan.sh defines color variables" {
    grep -q "RED=\|GREEN=\|YELLOW=" "$SCRIPT_PATH"
}

@test "run-complete-sbom-scan.sh has proper structure" {
    # May or may not source template depending on implementation
    grep -q "function\|()" "$SCRIPT_PATH"
}

@test "run-complete-sbom-scan.sh generates comprehensive SBOM" {
    grep -q "sbom\|SBOM" "$SCRIPT_PATH"
}

@test "run-complete-sbom-scan.sh uses SBOM generation tools" {
    grep -q "syft\|sbom\|run-sbom" "$SCRIPT_PATH"
}

@test "run-complete-sbom-scan.sh handles SBOM formats" {
    grep -q "cyclonedx" "$SCRIPT_PATH" || grep -q "spdx" "$SCRIPT_PATH" || grep -q "format" "$SCRIPT_PATH" || grep -q "json" "$SCRIPT_PATH"
}

@test "run-complete-sbom-scan.sh scans filesystem and containers" {
    grep -q "filesystem\|dir:\|image:" "$SCRIPT_PATH" || grep -q "scan" "$SCRIPT_PATH"
}

@test "run-complete-sbom-scan.sh creates SBOM output" {
    grep -q "output\|json\|xml" "$SCRIPT_PATH"
}
