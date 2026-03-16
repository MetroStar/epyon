#!/usr/bin/env bats

# Unit tests for generate-scan-manifest.sh

SCRIPT_DIR="${BATS_TEST_DIRNAME}/../../scripts/shell"
SCRIPT_PATH="${SCRIPT_DIR}/generate-scan-manifest.sh"

@test "generate-scan-manifest.sh exists and is executable" {
    [ -f "$SCRIPT_PATH" ]
    [ -x "$SCRIPT_PATH" ]
}

@test "generate-scan-manifest.sh has proper shebang" {
    head -n 1 "$SCRIPT_PATH" | grep -q "^#!/bin/bash"
}

@test "generate-scan-manifest.sh defines color variables" {
    grep -q "RED=\|GREEN=\|CYAN=" "$SCRIPT_PATH"
}

@test "generate-scan-manifest.sh requires a scan directory argument" {
    run "$SCRIPT_PATH"
    [ "$status" -ne 0 ]
}

@test "generate-scan-manifest.sh exits with error for non-existent directory" {
    run "$SCRIPT_PATH" "/nonexistent/path/$(date +%s)"
    [ "$status" -ne 0 ]
}

@test "generate-scan-manifest.sh detects sha256sum or shasum" {
    grep -q "sha256sum\|shasum" "$SCRIPT_PATH"
}

@test "generate-scan-manifest.sh produces scan-manifest.json output" {
    grep -q "scan-manifest.json" "$SCRIPT_PATH"
}

@test "generate-scan-manifest.sh includes scan_id in manifest" {
    grep -q "scan_id" "$SCRIPT_PATH"
}

@test "generate-scan-manifest.sh hashes output files" {
    grep -q "sha256\|hash\|shasum" "$SCRIPT_PATH"
}

@test "generate-scan-manifest.sh records tool versions" {
    grep -q "version\|tool_version" "$SCRIPT_PATH"
}

@test "generate-scan-manifest.sh includes hostname in manifest" {
    grep -q "hostname\|HOSTNAME" "$SCRIPT_PATH"
}

@test "generate-scan-manifest.sh creates manifest for a real scan directory" {
    local TMP_SCAN
    TMP_SCAN=$(mktemp -d)
    local SCAN_NAME="testapp_user_2026-01-01_00-00-00"
    local SCAN_DIR="$TMP_SCAN/$SCAN_NAME"
    mkdir -p "$SCAN_DIR/trivy" "$SCAN_DIR/grype"

    # Create minimal scan metadata
    cat > "$SCAN_DIR/scan-metadata.json" << EOF
{
  "scan_id": "$SCAN_NAME",
  "target_name": "testapp",
  "scan_user": "user",
  "scan_timestamp": "2026-01-01T00:00:00Z"
}
EOF
    echo '{"matches":[]}' > "$SCAN_DIR/grype/grype-results.json"

    run "$SCRIPT_PATH" "$SCAN_DIR"
    [ "$status" -eq 0 ]
    [ -f "$SCAN_DIR/scan-manifest.json" ]

    run jq -e '.scan_metadata.scan_id' "$SCAN_DIR/scan-manifest.json"
    [ "$status" -eq 0 ]

    rm -rf "$TMP_SCAN"
}
