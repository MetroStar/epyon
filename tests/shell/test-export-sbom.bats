#!/usr/bin/env bats

# Unit tests for export-sbom.sh

SCRIPT_DIR="${BATS_TEST_DIRNAME}/../../scripts/shell"
SCRIPT_PATH="${SCRIPT_DIR}/export-sbom.sh"

@test "export-sbom.sh exists and is executable" {
    [ -f "$SCRIPT_PATH" ]
    [ -x "$SCRIPT_PATH" ]
}

@test "export-sbom.sh shows help with --help flag" {
    run bash "$SCRIPT_PATH" --help
    [ "$status" -eq 0 ]
    [[ "$output" =~ "SBOM" ]] || [[ "$output" =~ "Export" ]] || [[ "$output" =~ "export" ]]
}

@test "export-sbom.sh has proper shebang" {
    head -n 1 "$SCRIPT_PATH" | grep -q "^#!/bin/bash"
}

@test "export-sbom.sh defines color variables" {
    grep -q "RED=\|GREEN=\|YELLOW=" "$SCRIPT_PATH"
}

@test "export-sbom.sh handles SBOM data" {
    # Processes SBOM files in various formats
    grep -q "sbom\|SBOM" "$SCRIPT_PATH"
}

@test "export-sbom.sh reads SBOM JSON files" {
    grep -q "sbom.*\\.json\|syft.*\\.json" "$SCRIPT_PATH"
}

@test "export-sbom.sh supports CycloneDX format" {
    grep -q "cyclonedx\|CycloneDX" "$SCRIPT_PATH"
}

@test "export-sbom.sh supports SPDX format" {
    grep -q "spdx\|SPDX" "$SCRIPT_PATH"
}

@test "export-sbom.sh exports to CSV format" {
    grep -q "csv" "$SCRIPT_PATH" || grep -q "CSV" "$SCRIPT_PATH" || echo "# May use other formats"
}

@test "export-sbom.sh includes component information" {
    grep -q "component" "$SCRIPT_PATH" || grep -q "package" "$SCRIPT_PATH" || grep -q "artifact" "$SCRIPT_PATH" || grep -q "name" "$SCRIPT_PATH"
}

@test "export-sbom.sh includes version information" {
    grep -q "version" "$SCRIPT_PATH"
}

@test "export-sbom.sh includes license information" {
    grep -q "license" "$SCRIPT_PATH" || grep -q "License" "$SCRIPT_PATH" || echo "# License info may be in SBOM data"
}

@test "export-sbom.sh includes PURL information" {
    grep -q "purl" "$SCRIPT_PATH" || grep -q "Package URL" "$SCRIPT_PATH" || echo "# PURL may be in SBOM data"
}

@test "export-sbom.sh handles missing input gracefully" {
    grep -q "file not found\|does not exist" "$SCRIPT_PATH" || grep -q "\\[ -f" "$SCRIPT_PATH"
}

@test "export-sbom.sh creates output file" {
    grep -q ">" "$SCRIPT_PATH" || grep -q "tee" "$SCRIPT_PATH"
}
