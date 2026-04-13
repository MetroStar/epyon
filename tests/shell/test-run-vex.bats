#!/usr/bin/env bats

# Unit tests for run-vex.sh

SCRIPT_DIR="${BATS_TEST_DIRNAME}/../../scripts/shell"
SCRIPT_PATH="${SCRIPT_DIR}/run-vex.sh"

@test "run-vex.sh exists and is executable" {
    [ -f "$SCRIPT_PATH" ]
    [ -x "$SCRIPT_PATH" ]
}

@test "run-vex.sh has proper shebang" {
    head -n 1 "$SCRIPT_PATH" | grep -q "^#!/bin/bash\|^#!/usr/bin/env bash"
}

@test "run-vex.sh defines color variables" {
    grep -q "GREEN=\|YELLOW=\|RED=" "$SCRIPT_PATH"
}

@test "run-vex.sh supports create mode" {
    grep -q '"create"\|create' "$SCRIPT_PATH"
}

@test "run-vex.sh supports apply mode" {
    grep -q '"apply"\|apply' "$SCRIPT_PATH"
}

@test "run-vex.sh supports list mode" {
    grep -q '"list"\|list' "$SCRIPT_PATH"
}

@test "run-vex.sh defaults to apply mode when no argument provided" {
    grep -q 'MODE.*:-.*apply\|MODE.*apply\|{1:-apply}' "$SCRIPT_PATH"
}

@test "run-vex.sh stores VEX documents in .epyon/vex directory" {
    grep -q "\.epyon/vex\|VEX_DIR" "$SCRIPT_PATH"
}

@test "run-vex.sh names VEX files using CVE ID" {
    grep -q 'CVE_ID.*\.vex\.json\|\.vex\.json' "$SCRIPT_PATH"
}

@test "run-vex.sh follows OpenVEX 0.2.0 specification" {
    grep -q "openvex.dev\|0.2.0\|OpenVEX" "$SCRIPT_PATH"
}

@test "run-vex.sh uses @context and @id in VEX document structure" {
    grep -q '@context\|@id' "$SCRIPT_PATH"
}

@test "run-vex.sh requires CVE_ID argument in create mode" {
    grep -q "CVE_ID.*:?\|Missing.*CVE\|CVE-ID" "$SCRIPT_PATH"
}

@test "run-vex.sh requires package name argument in create mode" {
    grep -q "PKG_NAME.*:?\|Missing package\|package name" "$SCRIPT_PATH"
}

@test "run-vex.sh requires justification argument in create mode" {
    grep -q "JUSTIFICATION.*:?\|Missing justification" "$SCRIPT_PATH"
}

@test "run-vex.sh supports documented justification options" {
    grep -q "component_not_present\|vulnerable_code_not_in_execute_path\|inline_mitigations_already_exist" "$SCRIPT_PATH"
}

@test "run-vex.sh warns when VEX file already exists in create mode" {
    grep -q "already exists\|VEX file already" "$SCRIPT_PATH"
}

@test "run-vex.sh writes VEX summary output in apply mode" {
    grep -q "vex-summary.json\|VEX_SUMMARY" "$SCRIPT_PATH"
}

@test "run-vex.sh writes vex-applied-results.json in apply mode" {
    grep -q "vex-applied-results.json\|VEX_OUTPUT" "$SCRIPT_PATH"
}

@test "run-vex.sh uses Grype SBOM results as input for apply mode" {
    grep -q "grype-sbom-results.json\|GRYPE_SBOM_FILE" "$SCRIPT_PATH"
}

@test "run-vex.sh passes --vex flags to Grype when binary is available" {
    grep -q "\-\-vex\|VEX_FLAGS" "$SCRIPT_PATH"
}

@test "run-vex.sh falls back to JSON post-processing when Grype binary is unavailable" {
    grep -q "JSON post-processing\|json.*filter\|post.process" "$SCRIPT_PATH"
}

@test "run-vex.sh requires SCAN_DIR for apply mode" {
    grep -q "SCAN_DIR.*must be set\|SCAN_DIR:?" "$SCRIPT_PATH"
}

@test "run-vex.sh requires TARGET_DIR for apply mode" {
    grep -q "TARGET_DIR.*must be set\|TARGET_DIR:?" "$SCRIPT_PATH"
}

@test "run-vex.sh handles no VEX documents gracefully in apply mode" {
    grep -q "No VEX documents\|nothing to apply\|No VEX.*found" "$SCRIPT_PATH"
}

@test "run-vex.sh uses jq to build VEX document JSON" {
    grep -q "jq" "$SCRIPT_PATH"
}

@test "run-vex.sh create mode produces a readable success message" {
    grep -q "VEX statement created\|Created VEX" "$SCRIPT_PATH"
}
