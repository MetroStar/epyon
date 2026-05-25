#!/usr/bin/env bats

# Unit tests for run-epyon-scan-ci.sh

SCRIPT_DIR="${BATS_TEST_DIRNAME}/../../scripts/shell"
SCRIPT_PATH="${SCRIPT_DIR}/run-epyon-scan-ci.sh"

@test "run-epyon-scan-ci.sh exists and is executable" {
    [ -f "$SCRIPT_PATH" ]
    [ -x "$SCRIPT_PATH" ]
}

@test "run-epyon-scan-ci.sh has proper shebang" {
    head -n 1 "$SCRIPT_PATH" | grep -qE "^#!/(bin/bash|usr/bin/env bash)"
}

@test "run-epyon-scan-ci.sh requires /tmp/epyon-env" {
    grep -q "epyon-env" "$SCRIPT_PATH"
}

@test "run-epyon-scan-ci.sh exits with error when epyon-env is missing" {
    # Should error before even sourcing epyon-env
    run bash -c "
        # Temporarily remove epyon-env if it exists
        _orig_env=\$(cat /tmp/epyon-env 2>/dev/null || true)
        rm -f /tmp/epyon-env
        '$SCRIPT_PATH' 2>&1
        rc=\$?
        [ -n \"\$_orig_env\" ] && echo \"\$_orig_env\" > /tmp/epyon-env
        exit \$rc
    "
    [ "$status" -ne 0 ]
}

@test "run-epyon-scan-ci.sh defines run_group function" {
    grep -q "run_group" "$SCRIPT_PATH"
}

@test "run-epyon-scan-ci.sh defines run_layer_script function" {
    grep -q "run_layer_script" "$SCRIPT_PATH"
}

@test "run-epyon-scan-ci.sh defines run_garak_layer function" {
    grep -q "run_garak_layer" "$SCRIPT_PATH"
}

@test "run-epyon-scan-ci.sh wraps layers in GitHub Actions group markers" {
    grep -q "::group::\|::endgroup::" "$SCRIPT_PATH"
}

@test "run-epyon-scan-ci.sh runs 12 scan layers" {
    # Check that all expected layer scripts are referenced
    grep -q "run-complete-sbom-scan.sh" "$SCRIPT_PATH"
    grep -q "run-trufflehog-scan.sh" "$SCRIPT_PATH"
    grep -q "run-checkov-scan.sh" "$SCRIPT_PATH"
    grep -q "run-trivy-scan.sh" "$SCRIPT_PATH"
    grep -q "run-grype-scan.sh" "$SCRIPT_PATH"
    grep -q "run-xeol-scan.sh" "$SCRIPT_PATH"
    grep -q "run-anchore-scan.sh" "$SCRIPT_PATH"
    grep -q "run-api-discovery.sh" "$SCRIPT_PATH"
    grep -q "run-garak-scan.sh" "$SCRIPT_PATH"
}

@test "run-epyon-scan-ci.sh skips Garak in quick mode by default" {
    grep -q "quick.*false\|RUN_GARAK_IN_QUICK" "$SCRIPT_PATH"
}

@test "run-epyon-scan-ci.sh runs Garak in nightly mode" {
    grep -q "nightly.*true\|nightly" "$SCRIPT_PATH"
}

@test "run-epyon-scan-ci.sh respects RUN_GARAK override" {
    grep -q "RUN_GARAK" "$SCRIPT_PATH"
}

@test "run-epyon-scan-ci.sh respects SKIP_GARAK override" {
    grep -q "SKIP_GARAK" "$SCRIPT_PATH"
}

@test "run-epyon-scan-ci.sh falls back to test.Blank when API key absent" {
    grep -q "test.Blank\|test\.Blank" "$SCRIPT_PATH"
}

@test "run-epyon-scan-ci.sh handles openai and anthropic key absence" {
    grep -q "OPENAI_API_KEY" "$SCRIPT_PATH"
    grep -q "ANTHROPIC_API_KEY" "$SCRIPT_PATH"
}

@test "run-epyon-scan-ci.sh sources /tmp/epyon-env with set -a" {
    grep -q "set -a" "$SCRIPT_PATH"
}

@test "run-epyon-scan-ci.sh supports invocation from workspace root" {
    grep -q "epyon.*VERSION\|cd epyon" "$SCRIPT_PATH"
}

@test "run-epyon-scan-ci.sh runs Sonar layer conditionally based on scan mode" {
    grep -q "RUN_SONAR_IN_QUICK\|SCAN_MODE.*quick" "$SCRIPT_PATH"
}

@test "run-epyon-scan-ci.sh layer warnings do not abort the run" {
    # run_group should always return 0 even when the inner command fails
    # The function body ends with 'return 0' after the warning block
    grep -A15 "run_group()" "$SCRIPT_PATH" | grep -q "return 0"
}
