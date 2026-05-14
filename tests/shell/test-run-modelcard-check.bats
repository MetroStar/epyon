#!/usr/bin/env bats

# Unit tests for run-modelcard-check.sh (Layer 15 — Model Card Compliance)

SCRIPT_DIR="${BATS_TEST_DIRNAME}/../../scripts/shell"
SCRIPT_PATH="${SCRIPT_DIR}/run-modelcard-check.sh"

@test "run-modelcard-check.sh exists and is executable" {
    [ -f "$SCRIPT_PATH" ]
    [ -x "$SCRIPT_PATH" ]
}

@test "run-modelcard-check.sh has proper shebang" {
    head -n 1 "$SCRIPT_PATH" | grep -q "^#!/bin/bash"
}

@test "run-modelcard-check.sh sources scan-directory-template.sh" {
    grep -q "source.*scan-directory-template.sh" "$SCRIPT_PATH"
}

@test "run-modelcard-check.sh calls init_scan_environment" {
    grep -q "init_scan_environment" "$SCRIPT_PATH"
}

@test "run-modelcard-check.sh calls init_scan_environment with modelcard tool name" {
    grep -q 'init_scan_environment.*modelcard\|init_scan_environment "modelcard"' "$SCRIPT_PATH"
}

@test "run-modelcard-check.sh supports --help flag" {
    grep -q "\-h|\-\-help\|show_help" "$SCRIPT_PATH"
}

@test "run-modelcard-check.sh has a show_help function" {
    grep -q "^show_help()" "$SCRIPT_PATH"
}

@test "run-modelcard-check.sh handles missing TARGET_DIR by writing skipped JSON" {
    grep -q "skipped" "$SCRIPT_PATH"
    grep -q "modelcard-results.json" "$SCRIPT_PATH"
}

@test "run-modelcard-check.sh writes modelcard-results.json output file" {
    grep -q "modelcard-results.json" "$SCRIPT_PATH"
}

@test "run-modelcard-check.sh writes a scan log file" {
    grep -q "modelcard.log" "$SCRIPT_PATH"
}

@test "run-modelcard-check.sh checks for Model Details section" {
    grep -qi "model.?details\|model-details" "$SCRIPT_PATH"
}

@test "run-modelcard-check.sh checks for Intended Use section" {
    grep -qi "intended.?use\|intended-use" "$SCRIPT_PATH"
}

@test "run-modelcard-check.sh checks for Limitations section" {
    grep -qi "limitations\|out.?of.?scope" "$SCRIPT_PATH"
}

@test "run-modelcard-check.sh checks for Training Data section" {
    grep -qi "training.?data\|training-data" "$SCRIPT_PATH"
}

@test "run-modelcard-check.sh checks for Bias or Risks section" {
    grep -qi "bias\|risks" "$SCRIPT_PATH"
}

@test "run-modelcard-check.sh checks for license in YAML frontmatter" {
    grep -qi "license\|frontmatter" "$SCRIPT_PATH"
}

@test "run-modelcard-check.sh checks README.md or MODEL_CARD.md" {
    grep -q "README.md\|MODEL_CARD.md" "$SCRIPT_PATH"
}

@test "run-modelcard-check.sh records passed count in output JSON" {
    grep -q '"passed"' "$SCRIPT_PATH"
}

@test "run-modelcard-check.sh records failed count in output JSON" {
    grep -q '"failed"' "$SCRIPT_PATH"
}

@test "run-modelcard-check.sh records warnings count in output JSON" {
    grep -q '"warnings"' "$SCRIPT_PATH"
}

@test "run-modelcard-check.sh records findings array in output JSON" {
    grep -q '"findings"' "$SCRIPT_PATH"
}

@test "run-modelcard-check.sh records status field in output JSON" {
    grep -q '"status"' "$SCRIPT_PATH"
}

@test "run-modelcard-check.sh records a skipped status when TARGET_DIR is missing" {
    grep -q '"status": "skipped"' "$SCRIPT_PATH"
}

@test "run-modelcard-check.sh records file_checked in output JSON" {
    grep -q '"file_checked"' "$SCRIPT_PATH"
}

@test "run-modelcard-check.sh identifies Layer 15 in comments or output" {
    grep -q "Layer 15\|layer 15\|layer-15" "$SCRIPT_PATH"
}
