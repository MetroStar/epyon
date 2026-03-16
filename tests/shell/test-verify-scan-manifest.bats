#!/usr/bin/env bats

# Unit tests for verify-scan-manifest.sh

SCRIPT_DIR="${BATS_TEST_DIRNAME}/../../scripts/shell"
SCRIPT_PATH="${SCRIPT_DIR}/verify-scan-manifest.sh"
MANIFEST_GEN="${SCRIPT_DIR}/generate-scan-manifest.sh"

@test "verify-scan-manifest.sh exists and is executable" {
    [ -f "$SCRIPT_PATH" ]
    [ -x "$SCRIPT_PATH" ]
}

@test "verify-scan-manifest.sh has proper shebang" {
    head -n 1 "$SCRIPT_PATH" | grep -q "^#!/bin/bash"
}

@test "verify-scan-manifest.sh defines color variables" {
    grep -q "RED=\|GREEN=\|CYAN=" "$SCRIPT_PATH"
}

@test "verify-scan-manifest.sh requires a scan directory argument" {
    run "$SCRIPT_PATH"
    [ "$status" -ne 0 ]
}

@test "verify-scan-manifest.sh exits with error for non-existent directory" {
    run "$SCRIPT_PATH" "/nonexistent/path/$(date +%s)"
    [ "$status" -ne 0 ]
}

@test "verify-scan-manifest.sh exits with error when manifest is absent" {
    local TMP_DIR
    TMP_DIR=$(mktemp -d)
    run "$SCRIPT_PATH" "$TMP_DIR"
    [ "$status" -ne 0 ]
    echo "$output" | grep -qi "manifest\|not found"
    rm -rf "$TMP_DIR"
}

@test "verify-scan-manifest.sh detects sha256sum or shasum" {
    grep -q "sha256sum\|shasum" "$SCRIPT_PATH"
}

@test "verify-scan-manifest.sh reads scan-manifest.json" {
    grep -q "scan-manifest.json" "$SCRIPT_PATH"
}

@test "verify-scan-manifest.sh compares file hashes" {
    grep -q "hash\|sha256\|verify\|compare\|mismatch" "$SCRIPT_PATH"
}

@test "verify-scan-manifest.sh reports tampering" {
    grep -q "tamper\|corrupt\|mismatch\|invalid\|fail" "$SCRIPT_PATH"
}

@test "verify-scan-manifest.sh succeeds on a freshly generated manifest" {
    # Skip if neither hash tool is available
    command -v sha256sum &>/dev/null || command -v shasum &>/dev/null \
        || skip "No SHA-256 tool available"
    [ -x "$MANIFEST_GEN" ] || skip "generate-scan-manifest.sh not executable"

    local TMP_SCAN
    TMP_SCAN=$(mktemp -d)
    local SCAN_DIR="$TMP_SCAN/testapp_user_2026-01-01_00-00-00"
    mkdir -p "$SCAN_DIR"

    cat > "$SCAN_DIR/scan-metadata.json" << 'EOF'
{
  "scan_id": "testapp_user_2026-01-01_00-00-00",
  "target_name": "testapp",
  "scan_user": "user",
  "scan_timestamp": "2026-01-01T00:00:00Z"
}
EOF

    # Generate the manifest first
    run "$MANIFEST_GEN" "$SCAN_DIR"
    [ "$status" -eq 0 ]
    [ -f "$SCAN_DIR/scan-manifest.json" ]

    # Verify should pass on the untampered directory
    run "$SCRIPT_PATH" "$SCAN_DIR"
    [ "$status" -eq 0 ]

    rm -rf "$TMP_SCAN"
}
