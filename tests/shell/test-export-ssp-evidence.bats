#!/usr/bin/env bats

# Unit tests for export-ssp-evidence.sh and SSP matrix generation

SCRIPT_DIR="${BATS_TEST_DIRNAME}/../../scripts/shell"
SCRIPT_PATH="${SCRIPT_DIR}/export-ssp-evidence.sh"

@test "export-ssp-evidence.sh exists and is executable" {
    [ -f "$SCRIPT_PATH" ]
    [ -x "$SCRIPT_PATH" ]
}

@test "export-ssp-evidence.sh displays help with --help" {
    run bash "$SCRIPT_PATH" --help
    [ "$status" -eq 0 ]
    [[ "$output" =~ "NIST SP 800-53" ]]
}

@test "export-ssp-evidence.sh generates ssp-ato-evidence-package.json and ssp-ato-evidence-matrix.md" {
    local scan_dir
    scan_dir=$(mktemp -d)

    mkdir -p "$scan_dir/build" "$scan_dir/sbom" "$scan_dir/grype"
    echo '{"scan_id": "test_scan"}' > "$scan_dir/scan-metadata.json"
    echo '{"file_hashes": {"scan-metadata.json": "sha256:123"}}' > "$scan_dir/scan-manifest.json"

    run bash "$SCRIPT_PATH" "$scan_dir"
    [ "$status" -eq 0 ]
    [ -f "$scan_dir/ssp-ato-evidence-package.json" ]
    [ -f "$scan_dir/ssp-ato-evidence-matrix.md" ]

    run jq -r '.controls | length > 0' "$scan_dir/ssp-ato-evidence-package.json"
    [ "$output" = "true" ]

    grep -q "NIST SP 800-53" "$scan_dir/ssp-ato-evidence-matrix.md"

    rm -rf "$scan_dir"
}
