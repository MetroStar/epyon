#!/usr/bin/env bats

# Unit tests for run-target-security-scan.sh

SCRIPT_DIR="${BATS_TEST_DIRNAME}/../../scripts/shell"
SCRIPT_PATH="${SCRIPT_DIR}/run-target-security-scan.sh"

@test "run-target-security-scan.sh exists and is executable" {
    [ -f "$SCRIPT_PATH" ]
    [ -x "$SCRIPT_PATH" ]
}

@test "run-target-security-scan.sh has proper shebang" {
    head -n 1 "$SCRIPT_PATH" | grep -q "^#!/bin/bash"
}

@test "run-target-security-scan.sh defines color variables" {
    grep -q "RED=" "$SCRIPT_PATH"
    grep -q "GREEN=" "$SCRIPT_PATH"
    grep -q "NC=" "$SCRIPT_PATH"
}

@test "run-target-security-scan.sh orchestrates multiple scans" {
    grep -q "run-trivy-scan\|run-grype-scan\|run-checkov-scan\|run-garak-scan" "$SCRIPT_PATH"
}

@test "run-target-security-scan.sh accepts target directory parameter" {
    grep -q "TARGET_DIR" "$SCRIPT_PATH"
}

@test "run-target-security-scan.sh creates scan directory" {
    grep -q "SCAN_DIR\|SCAN_ID" "$SCRIPT_PATH"
}

@test "run-target-security-scan.sh exports SCAN_DIR environment variable" {
    grep -q "export SCAN_DIR" "$SCRIPT_PATH"
}

@test "run-target-security-scan.sh generates scan ID" {
    grep -q "SCAN_ID" "$SCRIPT_PATH"
}

# ── CONFIG_DIR and validate_latest_image ──────────────────────────────────────

@test "run-target-security-scan.sh CONFIG_DIR uses REPORTS_ROOT not REPO_ROOT" {
    # REPO_ROOT points at scripts/ (wrong); REPORTS_ROOT points at the repo root (correct).
    grep -q 'CONFIG_DIR="\$REPORTS_ROOT/configuration"' "$SCRIPT_PATH"
}

@test "run-target-security-scan.sh defines validate_latest_image function" {
    grep -q "validate_latest_image()" "$SCRIPT_PATH"
}

# ── SKIP_* per-tool flags (parity with CI orchestrator) ───────────────────────

@test "run-target-security-scan.sh respects SKIP_SBOM" {
    grep -q 'SKIP_SBOM' "$SCRIPT_PATH"
}

@test "run-target-security-scan.sh respects SKIP_TRUFFLEHOG" {
    grep -q 'SKIP_TRUFFLEHOG' "$SCRIPT_PATH"
}

@test "run-target-security-scan.sh respects SKIP_SONAR" {
    grep -q 'SKIP_SONAR' "$SCRIPT_PATH"
}

@test "run-target-security-scan.sh respects SKIP_CLAMAV" {
    grep -q 'SKIP_CLAMAV' "$SCRIPT_PATH"
}

@test "run-target-security-scan.sh respects SKIP_HELM" {
    grep -q 'SKIP_HELM' "$SCRIPT_PATH"
}

@test "run-target-security-scan.sh respects SKIP_CHECKOV" {
    grep -q 'SKIP_CHECKOV' "$SCRIPT_PATH"
}

@test "run-target-security-scan.sh respects SKIP_TRIVY" {
    grep -q 'SKIP_TRIVY' "$SCRIPT_PATH"
}

@test "run-target-security-scan.sh respects SKIP_GRYPE" {
    grep -q 'SKIP_GRYPE' "$SCRIPT_PATH"
}

@test "run-target-security-scan.sh respects SKIP_XEOL" {
    grep -q 'SKIP_XEOL' "$SCRIPT_PATH"
}

@test "run-target-security-scan.sh respects SKIP_ANCHORE" {
    grep -q 'SKIP_ANCHORE' "$SCRIPT_PATH"
}

@test "run-target-security-scan.sh respects SKIP_API_DISCOVERY" {
    grep -q 'SKIP_API_DISCOVERY' "$SCRIPT_PATH"
}

# ── Quick mode layer set matches CI ───────────────────────────────────────────

# Extract the quick-mode block using sed (line numbers), portable on macOS
_quick_block() {
    local start end
    start=$(grep -n '"quick")' "$SCRIPT_PATH" | head -1 | cut -d: -f1)
    # Find the next bare ';;' after the start line
    end=$(awk -v s="$start" 'NR>s && /^[[:space:]]*;;[[:space:]]*$/{print NR; exit}' "$SCRIPT_PATH")
    sed -n "${start},${end}p" "$SCRIPT_PATH"
}

@test "run-target-security-scan.sh quick mode includes Trivy base scan" {
    # Trivy must scan both filesystem and base image in quick mode (CI parity)
    _quick_block | grep -q 'run-trivy-scan.sh.*base'
}

@test "run-target-security-scan.sh quick mode includes Grype images scan" {
    # Grype must scan both SBOM and images in quick mode (CI parity)
    _quick_block | grep -q 'run-grype-scan.sh.*images'
}

@test "run-target-security-scan.sh quick mode includes Xeol EOL detection" {
    _quick_block | grep -q 'run-xeol-scan.sh'
}

@test "run-target-security-scan.sh quick mode includes Helm build" {
    _quick_block | grep -q 'run-helm-build.sh'
}

@test "run-target-security-scan.sh quick mode includes API discovery" {
    _quick_block | grep -q 'run-api-discovery.sh'
}

@test "run-target-security-scan.sh quick mode skips Garak by default" {
    # Garak must require RUN_GARAK=true opt-in in quick mode (CI parity)
    _quick_block | grep -q 'RUN_GARAK'
}

@test "run-target-security-scan.sh quick mode skips ClamAV (CI parity)" {
    # ClamAV is not in CI quick mode; verify it is absent from quick block
    # The quick block should not unconditionally invoke ClamAV
    ! _quick_block | grep -qE 'run_security_tool.*clamav'
}

# ── Full mode: all 12 layers present ─────────────────────────────────────────

# Extract the full-mode block using sed (line numbers), portable on macOS
_full_block() {
    local start end
    start=$(grep -n '"full")' "$SCRIPT_PATH" | head -1 | cut -d: -f1)
    end=$(awk -v s="$start" 'NR>s && /^[[:space:]]*;;[[:space:]]*$/{print NR; exit}' "$SCRIPT_PATH")
    sed -n "${start},${end}p" "$SCRIPT_PATH"
}

@test "run-target-security-scan.sh full mode includes all 12 layers" {
    _full_block | grep -q 'run-complete-sbom-scan.sh'
    _full_block | grep -q 'run-trufflehog-scan.sh'
    _full_block | grep -q 'run-sonar-analysis.sh'
    _full_block | grep -q 'run-clamav-scan.sh'
    _full_block | grep -q 'run-helm-build.sh'
    _full_block | grep -q 'run-checkov-scan.sh'
    _full_block | grep -q 'run-trivy-scan.sh'
    _full_block | grep -q 'run-grype-scan.sh'
    _full_block | grep -q 'run-xeol-scan.sh'
    _full_block | grep -q 'run-anchore-scan.sh'
    _full_block | grep -q 'run-api-discovery.sh'
    _full_block | grep -q 'run-garak-scan.sh'
}

@test "run-target-security-scan.sh full mode Garak requires RUN_GARAK=true opt-in" {
    # Garak should only run when RUN_GARAK is explicitly true (CI parity)
    grep -q 'RUN_GARAK' "$SCRIPT_PATH"
    # Confirm the opt-in pattern is present
    grep -q 'RUN_GARAK.*true' "$SCRIPT_PATH"
}

# ── Suppression rules ─────────────────────────────────────────────────────────

@test "run-target-security-scan.sh applies .epyon-ignore.yml suppression rules" {
    grep -q 'parse-epyon-ignore\|filter-ignored-findings' "$SCRIPT_PATH"
}

@test "run-target-security-scan.sh writes filtered findings summary" {
    # After applying suppressions, a *-filtered.json file must be created (CI parity)
    grep -q 'filtered.json\|FILTERED_SUMMARY' "$SCRIPT_PATH"
}

# ── CLI option handling ───────────────────────────────────────────────────────

@test "run-target-security-scan.sh --no-garak sets SKIP_GARAK=true" {
    grep -q '\-\-no-garak' "$SCRIPT_PATH"
    grep -A2 '\-\-no-garak' "$SCRIPT_PATH" | grep -q 'SKIP_GARAK=true'
}

@test "run-target-security-scan.sh --help exits cleanly" {
    run bash "$SCRIPT_PATH" --help
    [ "$status" -eq 0 ]
}

@test "run-target-security-scan.sh exits non-zero when no target given" {
    run bash "$SCRIPT_PATH" 2>&1 <<< ""
    [ "$status" -ne 0 ]
}

@test "run-target-security-scan.sh exits non-zero for unknown option" {
    run bash "$SCRIPT_PATH" --unknown-flag /tmp 2>&1
    [ "$status" -ne 0 ]
}

@test "run-target-security-scan.sh rejects --subdir with local path" {
    run bash "$SCRIPT_PATH" --subdir apps/api /tmp 2>&1
    [ "$status" -ne 0 ]
    [[ "$output" == *"subdir"* ]] || [[ "$output" == *"Git"* ]]
}

@test "run-target-security-scan.sh exits non-zero for nonexistent target path" {
    run bash "$SCRIPT_PATH" /nonexistent/path/that/does/not/exist 2>&1
    [ "$status" -ne 0 ]
}
