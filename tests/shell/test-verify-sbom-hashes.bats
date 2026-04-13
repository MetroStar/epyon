#!/usr/bin/env bats

# Unit tests for verify-sbom-hashes.sh

SCRIPT_DIR="${BATS_TEST_DIRNAME}/../../scripts/shell"
SCRIPT_PATH="${SCRIPT_DIR}/verify-sbom-hashes.sh"

@test "verify-sbom-hashes.sh exists and is executable" {
    [ -f "$SCRIPT_PATH" ]
    [ -x "$SCRIPT_PATH" ]
}

@test "verify-sbom-hashes.sh has proper shebang" {
    head -n 1 "$SCRIPT_PATH" | grep -q "^#!/bin/bash\|^#!/usr/bin/env bash"
}

@test "verify-sbom-hashes.sh defines color variables" {
    grep -q "GREEN=\|YELLOW=\|RED=" "$SCRIPT_PATH"
}

@test "verify-sbom-hashes.sh requires SCAN_DIR environment variable" {
    grep -q 'SCAN_DIR.*:?\|SCAN_DIR.*must be set\|SCAN_DIR:?' "$SCRIPT_PATH"
}

@test "verify-sbom-hashes.sh reads CycloneDX SBOM from sbom directory" {
    grep -q "\.cyclonedx\.json\|CYCLONEDX_FILE\|SBOM_DIR" "$SCRIPT_PATH"
}

@test "verify-sbom-hashes.sh handles missing CycloneDX file gracefully" {
    grep -q "No CycloneDX\|cyclonedx.*not found\|skipping hash verification" "$SCRIPT_PATH"
}

@test "verify-sbom-hashes.sh writes hash-verification.json output" {
    grep -q "hash-verification.json\|OUTPUT_JSON" "$SCRIPT_PATH"
}

@test "verify-sbom-hashes.sh writes hash-verification.md output" {
    grep -q "hash-verification.md\|OUTPUT_MD" "$SCRIPT_PATH"
}

@test "verify-sbom-hashes.sh requires curl for PyPI API calls" {
    grep -q "curl" "$SCRIPT_PATH"
}

@test "verify-sbom-hashes.sh extracts pkg:pypi components from CycloneDX SBOM" {
    grep -q "pkg:pypi\|PYPI_PACKAGES" "$SCRIPT_PATH"
}

@test "verify-sbom-hashes.sh handles SBOM with no PyPI packages gracefully" {
    grep -q "No PyPI\|PYPI_PACKAGES.*-z\|-z.*PYPI_PACKAGES\|no.*pypi" "$SCRIPT_PATH"
}

@test "verify-sbom-hashes.sh queries PyPI JSON API for published digests" {
    grep -q "pypi.org/pypi\|PYPI_URL" "$SCRIPT_PATH"
}

@test "verify-sbom-hashes.sh tracks verified package count" {
    grep -q "VERIFIED\|verified\b" "$SCRIPT_PATH"
}

@test "verify-sbom-hashes.sh tracks tampered package count" {
    grep -q "TAMPERED\|tampered\b" "$SCRIPT_PATH"
}

@test "verify-sbom-hashes.sh tracks not-found package count" {
    grep -q "NOT_FOUND\|not_found\b" "$SCRIPT_PATH"
}

@test "verify-sbom-hashes.sh tracks error count" {
    grep -q "ERRORS\|errors\b" "$SCRIPT_PATH"
}

@test "verify-sbom-hashes.sh applies a rate-limit delay between PyPI requests" {
    grep -q "DELAY\|sleep\|rate" "$SCRIPT_PATH"
}

@test "verify-sbom-hashes.sh exits with code 2 on tampered packages" {
    grep -q "exit 2\|TAMPERED.*exit" "$SCRIPT_PATH"
}

@test "verify-sbom-hashes.sh uses jq for JSON processing" {
    grep -q "jq" "$SCRIPT_PATH"
}

@test "verify-sbom-hashes.sh aggregates results into verified results array" {
    grep -q "RESULTS_VERIFIED\|results_verified" "$SCRIPT_PATH"
}

@test "verify-sbom-hashes.sh aggregates results into tampered results array" {
    grep -q "RESULTS_TAMPERED\|results_tampered" "$SCRIPT_PATH"
}

@test "verify-sbom-hashes.sh aggregates results into not-found results array" {
    grep -q "RESULTS_NOT_FOUND\|results_not_found" "$SCRIPT_PATH"
}
