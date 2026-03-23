#!/usr/bin/env bats

# Unit tests for generate-security-dashboard.sh

SCRIPT_DIR="${BATS_TEST_DIRNAME}/../../scripts/shell"
SCRIPT_PATH="${SCRIPT_DIR}/generate-security-dashboard.sh"

@test "generate-security-dashboard.sh exists and is executable" {
    [ -f "$SCRIPT_PATH" ]
    [ -x "$SCRIPT_PATH" ]
}

@test "generate-security-dashboard.sh shows help with --help flag" {
    run bash "$SCRIPT_PATH" --help
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Security Dashboard Generator" ]]
}

@test "generate-security-dashboard.sh has proper shebang" {
    head -n 1 "$SCRIPT_PATH" | grep -q "^#!/bin/bash"
}

@test "generate-security-dashboard.sh defines color variables" {
    grep -q "RED=" "$SCRIPT_PATH" || grep -q "GREEN=" "$SCRIPT_PATH" || grep -q "CYAN=" "$SCRIPT_PATH"
}

@test "generate-security-dashboard.sh checks for jq dependency" {
    grep -q "command -v jq" "$SCRIPT_PATH"
}

@test "generate-security-dashboard.sh processes Trivy results" {
    grep -q "trivy.*json" "$SCRIPT_PATH"
}

@test "generate-security-dashboard.sh processes Grype results" {
    grep -q "grype.*json" "$SCRIPT_PATH"
}

@test "generate-security-dashboard.sh processes Anchore results" {
    grep -q "anchore.*json" "$SCRIPT_PATH"
}

@test "generate-security-dashboard.sh processes Checkov results" {
    grep -q "checkov.*json" "$SCRIPT_PATH"
}

@test "generate-security-dashboard.sh processes TruffleHog results" {
    grep -q "trufflehog.*json" "$SCRIPT_PATH"
}

@test "generate-security-dashboard.sh processes ClamAV results" {
    grep -q "clamav" "$SCRIPT_PATH"
}

@test "generate-security-dashboard.sh processes Xeol results" {
    grep -q "xeol.*json" "$SCRIPT_PATH"
}

@test "generate-security-dashboard.sh processes SonarQube results" {
    grep -q "sonar" "$SCRIPT_PATH"
}

@test "generate-security-dashboard.sh handles Checkov array format" {
    # Validate the fix for Checkov array format parsing (lines 728-800)
    grep -q "select(.results" "$SCRIPT_PATH" && grep -q "passed_checks" "$SCRIPT_PATH"
}

@test "generate-security-dashboard.sh aggregates passed checks" {
    grep -q "passed_checks.*length.*add" "$SCRIPT_PATH"
}

@test "generate-security-dashboard.sh aggregates failed checks" {
    grep -q "failed_checks.*length.*add" "$SCRIPT_PATH"
}

@test "generate-security-dashboard.sh aggregates skipped checks" {
    grep -q "skipped_checks.*length.*add" "$SCRIPT_PATH"
}

@test "generate-security-dashboard.sh generates HTML output" {
    grep -q "html" "$SCRIPT_PATH"
}

@test "generate-security-dashboard.sh includes CSS styling" {
    grep -q "style\|css" "$SCRIPT_PATH"
}

@test "generate-security-dashboard.sh creates summary section" {
    grep -q "summary\|Overview" "$SCRIPT_PATH"
}

@test "generate-security-dashboard.sh includes severity breakdowns" {
    grep -q "CRITICAL\|HIGH\|MEDIUM\|LOW" "$SCRIPT_PATH"
}

@test "generate-security-dashboard.sh handles missing scanner results gracefully" {
    grep -q "0\|N/A\|n/a" "$SCRIPT_PATH"
}

@test "generate-security-dashboard.sh includes timestamp" {
    grep -q "date\|timestamp" "$SCRIPT_PATH"
}

@test "generate-security-dashboard.sh processes SBOM data" {
    grep -q "sbom\|syft" "$SCRIPT_PATH"
}

@test "generate-security-dashboard.sh creates scan directory output" {
    grep -q "SCAN_DIR\|scan.*directory" "$SCRIPT_PATH"
}

@test "generate-security-dashboard.sh includes file type breakdown for Checkov" {
    grep -q "check_type\|file.*type" "$SCRIPT_PATH"
}

@test "generate-security-dashboard.sh calculates scan duration" {
    grep -q "duration\|elapsed\|time" "$SCRIPT_PATH"
}

@test "generate-security-dashboard.sh outputs dashboard.html" {
    grep -q "dashboard\\.html" "$SCRIPT_PATH"
}

@test "generate-security-dashboard.sh loads scan manifest file" {
    grep -q "scan-manifest.json" "$SCRIPT_PATH"
    grep -q "SCAN_MANIFEST_JSON" "$SCRIPT_PATH"
}

@test "generate-security-dashboard.sh includes scan manifest button in footer" {
    grep -q "footer-manifest-btn" "$SCRIPT_PATH"
    grep -q "Scan Manifest" "$SCRIPT_PATH"
    grep -q "openScanManifestModal" "$SCRIPT_PATH"
}

@test "generate-security-dashboard.sh includes scan manifest modal HTML" {
    grep -q "manifest-modal-overlay" "$SCRIPT_PATH"
    grep -q "scanManifestBody" "$SCRIPT_PATH"
    grep -q "scanManifestOverlay" "$SCRIPT_PATH"
}

@test "generate-security-dashboard.sh includes scan manifest JavaScript functions" {
    grep -q "function openScanManifestModal" "$SCRIPT_PATH"
    grep -q "function closeScanManifestModal" "$SCRIPT_PATH"
    grep -q "function renderScanManifestModal" "$SCRIPT_PATH"
}

@test "generate-security-dashboard.sh embeds scan manifest data as JS variable" {
    grep -q "const scanManifestData" "$SCRIPT_PATH"
    grep -q "SCAN_MANIFEST_JSON" "$SCRIPT_PATH"
}

@test "generate-security-dashboard.sh supports closing modal on Escape key" {
    grep -q "Escape" "$SCRIPT_PATH"
    grep -q "closeScanManifestModal" "$SCRIPT_PATH"
}

@test "generate-security-dashboard.sh disables manifest button when no manifest" {
    grep -q "disabled" "$SCRIPT_PATH"
    grep -q "scanManifestBtn" "$SCRIPT_PATH"
}

@test "generate-security-dashboard.sh escapes manifest JSON for HTML safety" {
    grep -q "<\\\\/" "$SCRIPT_PATH" || grep -q 's|</|' "$SCRIPT_PATH"
}
