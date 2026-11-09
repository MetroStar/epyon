#!/usr/bin/env bats

# Unit tests for run-trufflehog-scan.sh

SCRIPT_DIR="${BATS_TEST_DIRNAME}/../../scripts/shell"
SCRIPT_PATH="${SCRIPT_DIR}/run-trufflehog-scan.sh"

@test "run-trufflehog-scan.sh exists and is executable" {
    [ -f "$SCRIPT_PATH" ]
    [ -x "$SCRIPT_PATH" ]
}

@test "run-trufflehog-scan.sh has proper shebang" {
    head -n 1 "$SCRIPT_PATH" | grep -q "^#!/bin/bash"
}

@test "run-trufflehog-scan.sh sources scan-directory-template.sh" {
    grep -q "source.*scan-directory-template.sh" "$SCRIPT_PATH"
}

@test "run-trufflehog-scan.sh contains init_scan_environment function call" {
    grep -q "init_scan_environment" "$SCRIPT_PATH"
}

@test "run-trufflehog-scan.sh defines color variables" {
    grep -q "RED=" "$SCRIPT_PATH"
    grep -q "GREEN=" "$SCRIPT_PATH"
    grep -q "NC=" "$SCRIPT_PATH"
}

@test "run-trufflehog-scan.sh uses Docker or native trufflehog" {
    grep -q "docker" "$SCRIPT_PATH" || grep -q "trufflehog" "$SCRIPT_PATH"
}

@test "run-trufflehog-scan.sh uses trufflehog image" {
    grep -q "dhi.io/trufflehog" "$SCRIPT_PATH"
}

@test "trufflehog scan defines custom detectors for hardcoded passwords and secret keys" {
    grep -q "name: HardcodedPassword$" "$SCRIPT_PATH"
    grep -q "name: HardcodedSecretKey" "$SCRIPT_PATH"
    grep -q "name: HardcodedPasswordEnv" "$SCRIPT_PATH"
}

@test "trufflehog ignore patterns are anchored to path boundaries" {
    grep -q '^(^|/)build/$' "$SCRIPT_PATH"
    ! grep -qE '^(seed-data|examples|env|\.env)/$' "$SCRIPT_PATH"
}

@test "trufflehog ignore and custom detector files are written for local binary and container runs" {
    local write_line run_line
    write_line=$(grep -n 'cat > "\$OUTPUT_DIR/.trufflehogignore"' "$SCRIPT_PATH" | head -1 | cut -d: -f1)
    run_line=$(grep -n 'if \[ -n "\$LOCAL_TRUFFLEHOG" \]; then' "$SCRIPT_PATH" | tail -1 | cut -d: -f1)
    [ "$write_line" -lt "$run_line" ]
}
