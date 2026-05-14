#!/usr/bin/env bats

# Unit tests for run-stig-scan.sh (Layer 13 — STIG Compliance Assessment)

SCRIPT_DIR="${BATS_TEST_DIRNAME}/../../scripts/shell"
SCRIPT_PATH="${SCRIPT_DIR}/run-stig-scan.sh"

@test "run-stig-scan.sh exists and is executable" {
    [ -f "$SCRIPT_PATH" ]
    [ -x "$SCRIPT_PATH" ]
}

@test "run-stig-scan.sh has proper shebang" {
    head -n 1 "$SCRIPT_PATH" | grep -q "^#!/bin/bash"
}

@test "run-stig-scan.sh supports --help flag" {
    grep -q "\-h|\-\-help\|show_help" "$SCRIPT_PATH"
}

@test "run-stig-scan.sh has a show_help function" {
    grep -q "^show_help()" "$SCRIPT_PATH"
}

@test "run-stig-scan.sh resolves SCRIPT_DIR" {
    grep -q "SCRIPT_DIR" "$SCRIPT_PATH"
}

@test "run-stig-scan.sh resolves PROJECT_ROOT" {
    grep -q "PROJECT_ROOT" "$SCRIPT_PATH"
}

@test "run-stig-scan.sh supports STIGS_DIR environment variable" {
    grep -q "STIGS_DIR" "$SCRIPT_PATH"
}

@test "run-stig-scan.sh supports STIGS_FILE environment variable for single-file mode" {
    grep -q "STIGS_FILE" "$SCRIPT_PATH"
}

@test "run-stig-scan.sh supports OPENAI_API_KEY environment variable" {
    grep -q "OPENAI_API_KEY" "$SCRIPT_PATH"
}

@test "run-stig-scan.sh supports OPENAI_MODEL environment variable" {
    grep -q "OPENAI_MODEL" "$SCRIPT_PATH"
}

@test "run-stig-scan.sh defaults OPENAI_MODEL to gpt-4.1-mini" {
    grep -q "gpt-4.1-mini" "$SCRIPT_PATH"
}

@test "run-stig-scan.sh supports BATCH_SIZE environment variable" {
    grep -q "BATCH_SIZE" "$SCRIPT_PATH"
}

@test "run-stig-scan.sh supports BATCH_DELAY environment variable" {
    grep -q "BATCH_DELAY" "$SCRIPT_PATH"
}

@test "run-stig-scan.sh supports APP_NAME environment variable" {
    grep -q "APP_NAME" "$SCRIPT_PATH"
}

@test "run-stig-scan.sh supports SCAN_DIR environment variable" {
    grep -q "SCAN_DIR" "$SCRIPT_PATH"
}

@test "run-stig-scan.sh supports SKIP_STIG flag to bypass Layer 13" {
    grep -q "SKIP_STIG" "$SCRIPT_PATH"
}

@test "run-stig-scan.sh exits early when SKIP_STIG=true" {
    grep -q 'SKIP_STIG.*true\|SKIP_STIG == "true"' "$SCRIPT_PATH"
}

@test "run-stig-scan.sh validates that STIGS_DIR exists" {
    grep -q "STIGS_DIR.*not found\|\[ERROR\].*STIGS_DIR\|! -d.*STIGS_DIR\|-d.*STIGS_DIR" "$SCRIPT_PATH"
}

@test "run-stig-scan.sh validates that STIGS_FILE exists when set" {
    grep -q "STIGS_FILE.*not found\|\[ERROR\].*STIGS_FILE\|! -f.*STIGS_FILE\|-f.*STIGS_FILE" "$SCRIPT_PATH"
}

@test "run-stig-scan.sh scans for .cklb STIG files" {
    grep -q "\.cklb" "$SCRIPT_PATH"
}

@test "run-stig-scan.sh scans for .xml STIG files" {
    grep -q "\.xml" "$SCRIPT_PATH"
}

@test "run-stig-scan.sh requires python3" {
    grep -q "python3" "$SCRIPT_PATH"
}

@test "run-stig-scan.sh checks for the openai Python package" {
    grep -q "import openai\|openai" "$SCRIPT_PATH"
}

@test "run-stig-scan.sh warns when OPENAI_API_KEY is not set" {
    grep -q "OPENAI_API_KEY.*not set\|OPENAI_API_KEY.*WARNING\|\[WARNING\].*OPENAI_API_KEY" "$SCRIPT_PATH"
}

@test "run-stig-scan.sh delegates to run-stig-assessment.py" {
    grep -q "run-stig-assessment.py" "$SCRIPT_PATH"
}

@test "run-stig-scan.sh passes --target to the assessment script" {
    grep -q "\-\-target" "$SCRIPT_PATH"
}

@test "run-stig-scan.sh passes --scan-dir to the assessment script" {
    grep -q "\-\-scan-dir" "$SCRIPT_PATH"
}

@test "run-stig-scan.sh passes --app-name to the assessment script" {
    grep -q "\-\-app-name" "$SCRIPT_PATH"
}

@test "run-stig-scan.sh passes --model to the assessment script" {
    grep -q "\-\-model" "$SCRIPT_PATH"
}

@test "run-stig-scan.sh passes --batch-size to the assessment script" {
    grep -q "\-\-batch-size" "$SCRIPT_PATH"
}

@test "run-stig-scan.sh passes --stigs-dir or --cklb to the assessment script" {
    grep -q "\-\-stigs-dir\|\-\-cklb" "$SCRIPT_PATH"
}

@test "run-stig-scan.sh produces stig-controls JSON output" {
    grep -q "stig-controls" "$SCRIPT_PATH"
}

@test "run-stig-scan.sh produces stig-results JSON output" {
    grep -q "stig-results" "$SCRIPT_PATH"
}

@test "run-stig-scan.sh produces findings markdown report" {
    grep -q "findings-" "$SCRIPT_PATH"
}

@test "run-stig-scan.sh identifies Layer 13 in comments or output" {
    grep -q "Layer 13\|layer 13\|layer-13" "$SCRIPT_PATH"
}

@test "run-stig-scan.sh validates ASSESSMENT_SCRIPT exists before running" {
    grep -q "ASSESSMENT_SCRIPT" "$SCRIPT_PATH"
    grep -q "! -f.*ASSESSMENT_SCRIPT\|\[ERROR\].*Assessment script" "$SCRIPT_PATH"
}
