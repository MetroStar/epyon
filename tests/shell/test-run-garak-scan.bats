#!/usr/bin/env bats

# Unit tests for run-garak-scan.sh

SCRIPT_DIR="${BATS_TEST_DIRNAME}/../../scripts/shell"
SCRIPT_PATH="${SCRIPT_DIR}/run-garak-scan.sh"

@test "run-garak-scan.sh exists and is executable" {
    [ -f "$SCRIPT_PATH" ]
    [ -x "$SCRIPT_PATH" ]
}

@test "run-garak-scan.sh has proper shebang" {
    head -n 1 "$SCRIPT_PATH" | grep -q "^#!/bin/bash"
}

@test "run-garak-scan.sh sources scan-directory-template.sh" {
    grep -q "source.*scan-directory-template.sh" "$SCRIPT_PATH"
}

@test "run-garak-scan.sh calls init_scan_environment" {
    grep -q "init_scan_environment" "$SCRIPT_PATH"
}

@test "run-garak-scan.sh references garak command" {
    grep -q "garak" "$SCRIPT_PATH"
}

@test "run-garak-scan.sh supports target type environment variable" {
    grep -q "GARAK_TARGET_TYPE" "$SCRIPT_PATH"
}

@test "run-garak-scan.sh supports GARAK_AUTO_INSTALL flag" {
    grep -q "GARAK_AUTO_INSTALL" "$SCRIPT_PATH"
}

@test "run-garak-scan.sh supports GARAK_PIP_SPEC for custom package spec" {
    grep -q "GARAK_PIP_SPEC" "$SCRIPT_PATH"
}

@test "run-garak-scan.sh uses PIP_NO_CACHE_DIR=1 during install" {
    grep -q "PIP_NO_CACHE_DIR" "$SCRIPT_PATH"
}

@test "run-garak-scan.sh purges pip cache before install attempt" {
    grep -q "pip cache purge" "$SCRIPT_PATH"
}

@test "run-garak-scan.sh has three pip install fallback attempts" {
    # Standard → --break-system-packages → --user
    local count
    count=$(grep -c "pip install" "$SCRIPT_PATH")
    [ "$count" -ge 3 ]
}

@test "run-garak-scan.sh falls back to --break-system-packages install" {
    grep -q "\-\-break-system-packages" "$SCRIPT_PATH"
}

@test "run-garak-scan.sh falls back to --user install" {
    grep -q "pip install --user\|--user" "$SCRIPT_PATH"
}

@test "run-garak-scan.sh records failed install as status=failed in JSON" {
    grep -q '"status": "failed"\|status.*failed' "$SCRIPT_PATH"
}

@test "run-garak-scan.sh records skipped garak as status=skipped in JSON" {
    grep -q '"status": "skipped"\|status.*skipped' "$SCRIPT_PATH"
}

@test "run-garak-scan.sh handles missing python3 gracefully" {
    grep -q "python3\|python" "$SCRIPT_PATH"
    grep -q "python3 not found\|python.*required" "$SCRIPT_PATH"
}

@test "run-garak-scan.sh detects --target_type vs --model_type CLI differences" {
    grep -q "target_type\|model_type" "$SCRIPT_PATH"
}

@test "run-garak-scan.sh detects --report_prefix flag support" {
    grep -q "report_prefix" "$SCRIPT_PATH"
}

@test "run-garak-scan.sh writes garak-results.json output file" {
    grep -q "garak-results.json" "$SCRIPT_PATH"
}

@test "run-garak-scan.sh supports openai target type" {
    grep -q "openai" "$SCRIPT_PATH"
}

@test "run-garak-scan.sh supports anthropic target type" {
    grep -q "anthropic" "$SCRIPT_PATH"
}

@test "run-garak-scan.sh supports huggingface target type" {
    grep -q "huggingface" "$SCRIPT_PATH"
}

@test "run-garak-scan.sh supports ollama target type" {
    grep -q "ollama" "$SCRIPT_PATH"
}

@test "run-garak-scan.sh supports test target type" {
    grep -q '"test"\|test\.Blank' "$SCRIPT_PATH"
}

@test "run-garak-scan.sh stores runtime classification in results JSON" {
    grep -q "runtime_classification\|api-provider" "$SCRIPT_PATH"
}

