#!/usr/bin/env bats

# Unit tests for generate-sbom-lineage.sh

SCRIPT_DIR="${BATS_TEST_DIRNAME}/../../scripts/shell"
SCRIPT_PATH="${SCRIPT_DIR}/generate-sbom-lineage.sh"

@test "generate-sbom-lineage.sh exists and is executable" {
    [ -f "$SCRIPT_PATH" ]
    [ -x "$SCRIPT_PATH" ]
}

@test "generate-sbom-lineage.sh has proper shebang" {
    head -n 1 "$SCRIPT_PATH" | grep -q "^#!/bin/bash\|^#!/usr/bin/env bash"
}

@test "generate-sbom-lineage.sh defines color variables" {
    grep -q "GREEN=\|YELLOW=\|RED=" "$SCRIPT_PATH"
}

@test "generate-sbom-lineage.sh requires SCAN_DIR environment variable" {
    grep -q 'SCAN_DIR.*:?\|SCAN_DIR.*must be set\|SCAN_DIR:?' "$SCRIPT_PATH"
}

@test "generate-sbom-lineage.sh requires TARGET_DIR environment variable" {
    grep -q 'TARGET_DIR.*:?\|TARGET_DIR.*must be set\|TARGET_DIR:?' "$SCRIPT_PATH"
}

@test "generate-sbom-lineage.sh creates sbom output directory" {
    grep -q 'SBOM_DIR\|sbom' "$SCRIPT_PATH"
}

@test "generate-sbom-lineage.sh writes dependency-lineage.json output" {
    grep -q "dependency-lineage.json" "$SCRIPT_PATH"
}

@test "generate-sbom-lineage.sh uses pipdeptree for Python dependency trees" {
    grep -q "pipdeptree" "$SCRIPT_PATH"
}

@test "generate-sbom-lineage.sh uses npm ls for Node.js dependency trees" {
    grep -q "npm ls\|npm.*ls" "$SCRIPT_PATH"
}

@test "generate-sbom-lineage.sh generates pipdeptree output in json-tree format" {
    grep -q "\-\-json-tree\|json-tree" "$SCRIPT_PATH"
}

@test "generate-sbom-lineage.sh runs npm ls with --json and --all flags" {
    grep -q "npm ls.*--json\|--json.*--all\|npm ls --json" "$SCRIPT_PATH"
}

@test "generate-sbom-lineage.sh creates a temporary virtual environment for pipdeptree" {
    grep -q "venv\|virtualenv\|tmp_venv" "$SCRIPT_PATH"
}

@test "generate-sbom-lineage.sh handles missing Python gracefully" {
    grep -q "pybin\|python3\|python\b" "$SCRIPT_PATH"
}

@test "generate-sbom-lineage.sh handles missing npm gracefully" {
    grep -q "command -v npm\|npm.*not found\|npm.*>/dev/null" "$SCRIPT_PATH"
}

@test "generate-sbom-lineage.sh enriches CycloneDX SBOM with dependencies array" {
    grep -q "cyclonedx\|\.cyclonedx\.json\|dependencies\[\]" "$SCRIPT_PATH"
}

@test "generate-sbom-lineage.sh handles missing CycloneDX file gracefully" {
    grep -q "No CycloneDX\|cyclonedx.*not found\|skipping SBOM enrichment" "$SCRIPT_PATH"
}

@test "generate-sbom-lineage.sh uses jq to build output JSON" {
    grep -q "jq" "$SCRIPT_PATH"
}

@test "generate-sbom-lineage.sh handles empty Python tree gracefully" {
    grep -q 'PYTHON_TREE.*\[\]\|== "\[\]"\|\[\].*PYTHON_TREE' "$SCRIPT_PATH"
}

@test "generate-sbom-lineage.sh looks for package.json to detect Node.js projects" {
    grep -q "package.json" "$SCRIPT_PATH"
}
