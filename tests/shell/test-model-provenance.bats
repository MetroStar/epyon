#!/usr/bin/env bats
# Tests for Layer 18 — Model Provenance & Threat Intelligence
# Tests run-model-provenance-check.py and run-model-provenance-check.sh

SCRIPT_DIR="${BATS_TEST_DIRNAME}/../../scripts/shell"
PYTHON_SCANNER="$SCRIPT_DIR/run-model-provenance-check.py"
BASH_WRAPPER="$SCRIPT_DIR/run-model-provenance-check.sh"
BLOCKLIST_PATH="${BATS_TEST_DIRNAME}/../../configuration/ml-blocklist.json"

setup() {
    # Create temporary directory for test scans
    export TEST_SCAN_DIR="$(mktemp -d)"
    export TEST_OUTPUT_DIR="$(mktemp -d)"
    export TEST_APP_NAME="provenance-test"
    
    # Ensure fixtures exist
    if [[ ! -d "tests/fixtures/ml-models-provenance" ]]; then
        skip "Test fixtures not found"
    fi
    
    # Ensure blocklist exists
    if [[ ! -f "$BLOCKLIST_PATH" ]]; then
        skip "Blocklist not found: $BLOCKLIST_PATH"
    fi
}

teardown() {
    # Clean up temporary directories
    [[ -d "$TEST_SCAN_DIR" ]] && rm -rf "$TEST_SCAN_DIR"
    [[ -d "$TEST_OUTPUT_DIR" ]] && rm -rf "$TEST_OUTPUT_DIR"
}

# ── Python scanner tests ─────────────────────────────────────────────────────

@test "Provenance scanner: --help flag works" {
    run python3 "$PYTHON_SCANNER" --help
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Layer 18" ]]
    [[ "$output" =~ "Provenance" ]]
}

@test "Provenance scanner: requires --target argument" {
    run python3 "$PYTHON_SCANNER" --scan-dir "$TEST_OUTPUT_DIR" --app-name test
    [ "$status" -ne 0 ]
    [[ "$output" =~ "required: --target" ]]
}

@test "Provenance scanner: clean model passes" {
    run python3 "$PYTHON_SCANNER" \
        --target tests/fixtures/ml-models-provenance/clean \
        --scan-dir "$TEST_OUTPUT_DIR" \
        --app-name "$TEST_APP_NAME" \
        --blocklist-path "$BLOCKLIST_PATH"
    
    # Should exit 0 for clean model
    [ "$status" -eq 0 ]
    
    # Check results file exists
    [ -f "$TEST_OUTPUT_DIR/model-provenance-results.json" ]
    
    # Check no critical findings
    run python3 -c "import json; d=json.load(open('$TEST_OUTPUT_DIR/model-provenance-results.json')); print(d['summary']['critical_findings'])"
    [ "$status" -eq 0 ]
    [ "$output" -eq 0 ]
}

@test "Provenance scanner: detects blocked author" {
    run python3 "$PYTHON_SCANNER" \
        --target tests/fixtures/ml-models-provenance/blocked-author \
        --scan-dir "$TEST_OUTPUT_DIR" \
        --app-name "$TEST_APP_NAME" \
        --blocklist-path "$BLOCKLIST_PATH"
    
    # Should exit 1 due to critical finding
    [ "$status" -ne 0 ]
    
    # Check for blocked author finding
    run python3 -c "
import json
d = json.load(open('$TEST_OUTPUT_DIR/model-provenance-results.json'))
blocked_author_findings = [f for f in d['findings'] if f['type'] == 'blocked_author']
print(len(blocked_author_findings))
"
    [ "$status" -eq 0 ]
    [ "$output" -gt 0 ]
}

@test "Provenance scanner: detects typosquatting" {
    run python3 "$PYTHON_SCANNER" \
        --target tests/fixtures/ml-models-provenance/typosquat \
        --scan-dir "$TEST_OUTPUT_DIR" \
        --app-name "$TEST_APP_NAME" \
        --blocklist-path "$BLOCKLIST_PATH"
    
    # Should exit 1 due to high severity finding
    [ "$status" -ne 0 ]
    
    # Check for typosquat finding
    run python3 -c "
import json
d = json.load(open('$TEST_OUTPUT_DIR/model-provenance-results.json'))
typosquat_findings = [f for f in d['findings'] if f['type'] == 'typosquat_warning']
print(len(typosquat_findings))
"
    [ "$status" -eq 0 ]
    [ "$output" -gt 0 ]
}

@test "Provenance scanner: tracks unverified models" {
    run python3 "$PYTHON_SCANNER" \
        --target tests/fixtures/ml-models-provenance/unsigned \
        --scan-dir "$TEST_OUTPUT_DIR" \
        --app-name "$TEST_APP_NAME" \
        --blocklist-path "$BLOCKLIST_PATH"
    
    # Check statistics
    run python3 -c "
import json
d = json.load(open('$TEST_OUTPUT_DIR/model-provenance-results.json'))
print(d['statistics']['unverified_models'])
"
    [ "$status" -eq 0 ]
    [ "$output" -gt 0 ]
}

@test "Provenance scanner: produces valid JSON output" {
    run python3 "$PYTHON_SCANNER" \
        --target tests/fixtures/ml-models-provenance/clean \
        --scan-dir "$TEST_OUTPUT_DIR" \
        --app-name "$TEST_APP_NAME"
    
    # Check JSON is valid
    run python3 -c "import json; json.load(open('$TEST_OUTPUT_DIR/model-provenance-results.json'))"
    [ "$status" -eq 0 ]
}

@test "Provenance scanner: JSON contains required fields" {
    run python3 "$PYTHON_SCANNER" \
        --target tests/fixtures/ml-models-provenance/clean \
        --scan-dir "$TEST_OUTPUT_DIR" \
        --app-name "$TEST_APP_NAME"
    
    # Check required fields exist
    run python3 -c "
import json, sys
d = json.load(open('$TEST_OUTPUT_DIR/model-provenance-results.json'))
required = ['tool', 'version', 'status', 'target', 'generated_at', 'statistics', 'findings', 'summary']
missing = [f for f in required if f not in d]
if missing:
    print('Missing fields:', missing)
    sys.exit(1)
print('OK')
"
    [ "$status" -eq 0 ]
    [[ "$output" = "OK" ]]
}

@test "Provenance scanner: loads blocklist when provided" {
    run python3 "$PYTHON_SCANNER" \
        --target tests/fixtures/ml-models-provenance/clean \
        --scan-dir "$TEST_OUTPUT_DIR" \
        --app-name "$TEST_APP_NAME" \
        --blocklist-path "$BLOCKLIST_PATH"
    
    run python3 -c "
import json
d = json.load(open('$TEST_OUTPUT_DIR/model-provenance-results.json'))
assert d['blocklist_loaded'] == True, 'Blocklist should be loaded'
print('OK')
"
    [ "$status" -eq 0 ]
    [[ "$output" = "OK" ]]
}

@test "Provenance scanner: checks model cards" {
    run python3 "$PYTHON_SCANNER" \
        --target tests/fixtures/ml-models-provenance/clean \
        --scan-dir "$TEST_OUTPUT_DIR" \
        --app-name "$TEST_APP_NAME"
    
    # Clean fixture has complete model card, should have no incomplete_model_card findings
    run python3 -c "
import json
d = json.load(open('$TEST_OUTPUT_DIR/model-provenance-results.json'))
incomplete = [f for f in d['findings'] if f['type'] == 'incomplete_model_card']
print(len(incomplete))
"
    [ "$status" -eq 0 ]
    [ "$output" -eq 0 ]
}

# ── Bash wrapper tests ───────────────────────────────────────────────────────

@test "Bash wrapper: validates syntax" {
    run bash -n "$BASH_WRAPPER"
    [ "$status" -eq 0 ]
}

@test "Bash wrapper: displays help text" {
    run "$BASH_WRAPPER" --help
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Layer 18" ]]
    [[ "$output" =~ "Provenance" ]]
}

@test "Bash wrapper: executable flag set" {
    [ -x "$BASH_WRAPPER" ]
}

# ── Blocklist tests ──────────────────────────────────────────────────────────

@test "Blocklist: file exists and is valid JSON" {
    [ -f "$BLOCKLIST_PATH" ]
    run python3 -c "import json; json.load(open('$BLOCKLIST_PATH'))"
    [ "$status" -eq 0 ]
}

@test "Blocklist: contains required sections" {
    run python3 -c "
import json, sys
d = json.load(open('$BLOCKLIST_PATH'))
required = ['blocked_hashes', 'blocked_authors', 'blocked_repos', 'patterns']
missing = [f for f in required if f not in d]
if missing:
    print('Missing sections:', missing)
    sys.exit(1)
print('OK')
"
    [ "$status" -eq 0 ]
    [[ "$output" = "OK" ]]
}

@test "Blocklist: has malicious-user in blocked_authors" {
    run python3 -c "
import json
d = json.load(open('$BLOCKLIST_PATH'))
authors = [a['username'] for a in d['blocked_authors']]
assert 'malicious-user' in authors, 'malicious-user should be in blocklist'
print('OK')
"
    [ "$status" -eq 0 ]
    [[ "$output" = "OK" ]]
}

# ── Edge cases ───────────────────────────────────────────────────────────────

@test "Edge case: empty directory produces no findings" {
    mkdir -p "$TEST_SCAN_DIR/empty"
    
    run python3 "$PYTHON_SCANNER" \
        --target "$TEST_SCAN_DIR/empty" \
        --scan-dir "$TEST_OUTPUT_DIR" \
        --app-name "$TEST_APP_NAME"
    
    [ "$status" -eq 0 ]
    
    run python3 -c "
import json
d = json.load(open('$TEST_OUTPUT_DIR/model-provenance-results.json'))
assert d['statistics']['total_models'] == 0
assert len(d['findings']) == 0
print('OK')
"
    [ "$status" -eq 0 ]
    [[ "$output" = "OK" ]]
}

@test "Edge case: nonexistent target directory fails gracefully" {
    run python3 "$PYTHON_SCANNER" \
        --target /nonexistent/path/does/not/exist \
        --scan-dir "$TEST_OUTPUT_DIR" \
        --app-name "$TEST_APP_NAME"
    
    [ "$status" -ne 0 ]
    [[ "$output" =~ "does not exist" ]]
}

@test "Edge case: scan directory is created if missing" {
    NEW_OUTPUT="$TEST_OUTPUT_DIR/nested/deep/path"
    
    run python3 "$PYTHON_SCANNER" \
        --target tests/fixtures/ml-models-provenance/clean \
        --scan-dir "$NEW_OUTPUT" \
        --app-name "$TEST_APP_NAME"
    
    # Should create the directory and succeed
    [ -d "$NEW_OUTPUT" ]
    [ -f "$NEW_OUTPUT/model-provenance-results.json" ]
}
