#!/usr/bin/env bats

setup() {
    SCRIPT_DIR="${BATS_TEST_DIRNAME}/../../scripts/shell"
    TEST_SCAN_DIR="${BATS_TEST_TMPDIR}/scan"
    mkdir -p "$TEST_SCAN_DIR/consolidated-reports/dashboards" "$TEST_SCAN_DIR/sbom"
    printf '{"summary":{}}\n' > "$TEST_SCAN_DIR/security-findings-summary.json"
    printf '{"files":{}}\n' > "$TEST_SCAN_DIR/scan-manifest.json"
    printf '# Suppressed findings\n' > "$TEST_SCAN_DIR/suppressed-findings.md"
    printf '<html></html>\n' > "$TEST_SCAN_DIR/consolidated-reports/dashboards/security-dashboard.html"
}

@test "passes the core scan output contract" {
    run bash "$SCRIPT_DIR/validate-scan-output.sh" "$TEST_SCAN_DIR"
    [ "$status" -eq 0 ]
    [[ "$output" == *"validation passed"* ]]
}

@test "fails when a core artifact is missing" {
    rm "$TEST_SCAN_DIR/scan-manifest.json"

    run bash "$SCRIPT_DIR/validate-scan-output.sh" "$TEST_SCAN_DIR"
    [ "$status" -eq 1 ]
    [[ "$output" == *"MISSING: scan-manifest.json"* ]]
}

@test "requires build artifacts only when requested" {
    run bash "$SCRIPT_DIR/validate-scan-output.sh" "$TEST_SCAN_DIR" --require-build
    [ "$status" -eq 1 ]
    [[ "$output" == *"MISSING: build/"* ]]

    mkdir -p "$TEST_SCAN_DIR/build" "$TEST_SCAN_DIR/sbom"
    printf 'sha256:test\n' > "$TEST_SCAN_DIR/build/image-digest.txt"
    printf '{}\n' > "$TEST_SCAN_DIR/build/oci-manifest.json"
    printf 'build log\n' > "$TEST_SCAN_DIR/build/build.log"
    printf '{}\n' > "$TEST_SCAN_DIR/provenance.jsonl"
    printf '{}\n' > "$TEST_SCAN_DIR/image.sig"

    run bash "$SCRIPT_DIR/validate-scan-output.sh" "$TEST_SCAN_DIR" --require-build
    [ "$status" -eq 0 ]
}

@test "requires SSP evidence only when requested" {
    run bash "$SCRIPT_DIR/validate-scan-output.sh" "$TEST_SCAN_DIR" --require-ssp
    [ "$status" -eq 1 ]
    [[ "$output" == *"MISSING: ssp-ato-evidence-*"* ]]

    printf '# Evidence\n' > "$TEST_SCAN_DIR/ssp-ato-evidence-matrix.md"
    run bash "$SCRIPT_DIR/validate-scan-output.sh" "$TEST_SCAN_DIR" --require-ssp
    [ "$status" -eq 0 ]
}
