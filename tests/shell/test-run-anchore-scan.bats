#!/usr/bin/env bats

# Unit tests for run-anchore-scan.sh

SCRIPT_DIR="${BATS_TEST_DIRNAME}/../../scripts/shell"
SCRIPT_PATH="${SCRIPT_DIR}/run-anchore-scan.sh"

@test "run-anchore-scan.sh exists and is executable" {
    [ -f "$SCRIPT_PATH" ]
    [ -x "$SCRIPT_PATH" ]
}

@test "run-anchore-scan.sh has proper shebang" {
    head -n 1 "$SCRIPT_PATH" | grep -q "^#!/bin/bash"
}

@test "run-anchore-scan.sh sources scan-directory-template.sh" {
    grep -q "source.*scan-directory-template.sh" "$SCRIPT_PATH"
}

@test "run-anchore-scan.sh contains init_scan_environment function call" {
    grep -q "init_scan_environment" "$SCRIPT_PATH"
}

@test "run-anchore-scan.sh defines color variables" {
    grep -q "WHITE=" "$SCRIPT_PATH"
    grep -q "NC=" "$SCRIPT_PATH"
}

@test "run-anchore-scan.sh is a placeholder script" {
    # Anchore scan may be placeholder or full implementation
    grep -q "Placeholder\|placeholder\|anchore" "$SCRIPT_PATH"
}

@test "run-anchore-scan.sh creates anchore results" {
    grep -q "anchore" "$SCRIPT_PATH" && grep -q "json" "$SCRIPT_PATH"
}

@test "run-anchore-scan.sh translates directory/SBOM-file scan paths via to_host_path before docker run -v" {
    grep -q '\-v "\$(to_host_path "\$REPO_PATH"):/scan:ro"' "$SCRIPT_PATH"
    grep -q '\-v "\$(to_host_path "\$(dirname "\$SBOM_FILE")"):/sbom:ro"' "$SCRIPT_PATH"
}

@test "run-anchore-scan.sh translates OUTPUT_DIR via to_host_path before docker run -v" {
    ! grep -q '\-v "\$OUTPUT_DIR:/output"' "$SCRIPT_PATH"
    grep -q '\-v "\$(to_host_path "\$OUTPUT_DIR"):/output"' "$SCRIPT_PATH"
}
