#!/usr/bin/env bats

# Unit tests for run-athena-sbom.sh

SCRIPT_DIR="${BATS_TEST_DIRNAME}/../../scripts/shell"
SCRIPT_PATH="${SCRIPT_DIR}/run-athena-sbom.sh"

@test "run-athena-sbom.sh exists and is executable" {
    [ -f "$SCRIPT_PATH" ]
    [ -x "$SCRIPT_PATH" ]
}

@test "run-athena-sbom.sh has proper shebang" {
    head -n 1 "$SCRIPT_PATH" | grep -q "^#!/bin/bash\|^#!/usr/bin/env bash"
}

@test "run-athena-sbom.sh defines color variables" {
    grep -q "RED=\|GREEN=\|CYAN=" "$SCRIPT_PATH"
}

@test "run-athena-sbom.sh requires SCAN_DIR environment variable" {
    grep -q 'SCAN_DIR.*:?\|SCAN_DIR.*must be set\|SCAN_DIR:?' "$SCRIPT_PATH"
}

@test "run-athena-sbom.sh requires TARGET_DIR environment variable" {
    grep -q 'TARGET_DIR.*:?\|TARGET_DIR.*must be set\|TARGET_DIR:?' "$SCRIPT_PATH"
}

@test "run-athena-sbom.sh supports SKIP_ATHENA flag to bypass layer" {
    grep -q "SKIP_ATHENA" "$SCRIPT_PATH"
}

@test "run-athena-sbom.sh skips when SKIP_ATHENA is true" {
    grep -q 'SKIP_ATHENA.*true\|== "true"' "$SCRIPT_PATH"
}

@test "run-athena-sbom.sh references the MetroStar Athena repository" {
    grep -q "MetroStar/athena\|ATHENA_REPO" "$SCRIPT_PATH"
}

@test "run-athena-sbom.sh supports configurable ATHENA_REPO source" {
    grep -q "ATHENA_REPO" "$SCRIPT_PATH"
}

@test "run-athena-sbom.sh supports configurable ATHENA_INSTALL_DIR" {
    grep -q "ATHENA_INSTALL_DIR" "$SCRIPT_PATH"
}

@test "run-athena-sbom.sh detects Python dependency artifacts before running" {
    grep -q "has_python_artifacts\|requirements.txt\|Pipfile\|poetry.lock\|setup.py" "$SCRIPT_PATH"
}

@test "run-athena-sbom.sh skips when no Python artifacts are found" {
    grep -q "No Python dependency artifacts\|skipping Athena\|skip.*athena" "$SCRIPT_PATH"
}

@test "run-athena-sbom.sh writes CycloneDX output to sbom directory" {
    grep -q "cyclonedx\|\.cyclonedx\.json\|SBOM_DIR" "$SCRIPT_PATH"
}

@test "run-athena-sbom.sh generates athena-sbom output file" {
    grep -q "athena-sbom" "$SCRIPT_PATH"
}

@test "run-athena-sbom.sh generates athena-licenses.json output file" {
    grep -q "athena-licenses.json\|LICENSE_FILE" "$SCRIPT_PATH"
}

@test "run-athena-sbom.sh detects Python binary across common paths" {
    grep -q "PYTHON_BIN\|python3\|python\b" "$SCRIPT_PATH"
}

@test "run-athena-sbom.sh exits gracefully when no Python binary is found" {
    grep -q "No.*python\|python.*not found\|PYTHON_BIN.*-z" "$SCRIPT_PATH"
}

@test "run-athena-sbom.sh includes SPDX license identifiers in output" {
    grep -q "SPDX\|license\|LICENSE" "$SCRIPT_PATH"
}

@test "run-athena-sbom.sh names output file using SCAN_ID" {
    grep -q "SCAN_ID\|scan_id\|basename.*SCAN_DIR" "$SCRIPT_PATH"
}
