#!/usr/bin/env bats
# Tests for Enhanced Layer 14 — Comprehensive Model File Analysis
# Tests run-picklescan.py and run-picklescan.sh

SCRIPT_DIR="${BATS_TEST_DIRNAME}/../../scripts/shell"
PYTHON_SCANNER="$SCRIPT_DIR/run-picklescan.py"
BASH_WRAPPER="$SCRIPT_DIR/run-picklescan.sh"

setup() {
    # Create temporary directory for test scans
    export TEST_SCAN_DIR="$(mktemp -d)"
    export TEST_OUTPUT_DIR="$(mktemp -d)"
    export TEST_APP_NAME="picklescan-test"
    
    # Ensure fixtures exist
    if [[ ! -d "tests/fixtures/ml-models" ]]; then
        skip "Test fixtures not found — run: mkdir -p tests/fixtures/ml-models/{benign,malicious}"
    fi
}

teardown() {
    # Clean up temporary directories
    [[ -d "$TEST_SCAN_DIR" ]] && rm -rf "$TEST_SCAN_DIR"
    [[ -d "$TEST_OUTPUT_DIR" ]] && rm -rf "$TEST_OUTPUT_DIR"
}

# ── Python scanner tests ─────────────────────────────────────────────────────

@test "Enhanced picklescan scanner: --help flag works" {
    run python3 "$PYTHON_SCANNER" --help
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Enhanced Layer 14" ]]
    [[ "$output" =~ "Comprehensive Model File Analysis" ]]
}

@test "Enhanced picklescan scanner: requires --target argument" {
    run python3 "$PYTHON_SCANNER" --scan-dir "$TEST_OUTPUT_DIR" --app-name test
    [ "$status" -ne 0 ]
    [[ "$output" =~ "required: --target" ]]
}

@test "Enhanced picklescan scanner: detects dangerous imports in pickle files" {
    run python3 "$PYTHON_SCANNER" \
        --target tests/fixtures/ml-models/malicious \
        --scan-dir "$TEST_OUTPUT_DIR" \
        --app-name "$TEST_APP_NAME"
    
    # Should exit 1 due to critical findings
    [ "$status" -ne 0 ]
    
    # Check results file exists
    [ -f "$TEST_OUTPUT_DIR/picklescan-results.json" ]
    
    # Check findings
    run python3 -c "import json; d=json.load(open('$TEST_OUTPUT_DIR/picklescan-results.json')); print(d['summary']['critical_findings'])"
    [ "$status" -eq 0 ]
    [ "$output" -gt 0 ]
}

@test "Enhanced picklescan scanner: detects ONNX operator injection" {
    run python3 "$PYTHON_SCANNER" \
        --target tests/fixtures/ml-models/malicious \
        --scan-dir "$TEST_OUTPUT_DIR" \
        --app-name "$TEST_APP_NAME"
    
    [ "$status" -ne 0 ]
    
    # Check for ONNX findings
    run python3 -c "
import json
d = json.load(open('$TEST_OUTPUT_DIR/picklescan-results.json'))
onnx_findings = [f for f in d['findings'] if f['format'] == 'onnx']
print(len(onnx_findings))
"
    [ "$status" -eq 0 ]
    [ "$output" -gt 0 ]
}

@test "Enhanced picklescan scanner: detects config file exploits" {
    run python3 "$PYTHON_SCANNER" \
        --target tests/fixtures/ml-models/malicious \
        --scan-dir "$TEST_OUTPUT_DIR" \
        --app-name "$TEST_APP_NAME" \
        --formats config
    
    [ "$status" -ne 0 ]
    
    # Check for config findings
    run python3 -c "
import json
d = json.load(open('$TEST_OUTPUT_DIR/picklescan-results.json'))
config_findings = [f for f in d['findings'] if f['format'] == 'config']
print(len(config_findings))
"
    [ "$status" -eq 0 ]
    [ "$output" -gt 0 ]
}

@test "Enhanced picklescan scanner: detects obfuscation patterns" {
    run python3 "$PYTHON_SCANNER" \
        --target tests/fixtures/ml-models/malicious \
        --scan-dir "$TEST_OUTPUT_DIR" \
        --app-name "$TEST_APP_NAME"
    
    # Check for obfuscation findings
    run python3 -c "
import json
d = json.load(open('$TEST_OUTPUT_DIR/picklescan-results.json'))
obfuscation = [f for f in d['findings'] if 'obfuscation' in f['type']]
print(len(obfuscation))
"
    [ "$status" -eq 0 ]
    [ "$output" -gt 0 ]
}

@test "Enhanced picklescan scanner: clean scan exits with 0" {
    run python3 "$PYTHON_SCANNER" \
        --target tests/fixtures/ml-models/benign \
        --scan-dir "$TEST_OUTPUT_DIR" \
        --app-name "$TEST_APP_NAME"
    
    # Benign files should pass (unless benign fixtures contain false positives)
    # Note: This might fail if benign files trigger any patterns
    # For now, we just check that it runs and produces output
    [ "$status" -eq 0 ]
    [ -f "$TEST_OUTPUT_DIR/picklescan-results.json" ]
}

@test "Enhanced picklescan scanner: produces valid JSON output" {
    run python3 "$PYTHON_SCANNER" \
        --target tests/fixtures/ml-models \
        --scan-dir "$TEST_OUTPUT_DIR" \
        --app-name "$TEST_APP_NAME"
    
    # Check JSON is valid
    run python3 -c "import json; json.load(open('$TEST_OUTPUT_DIR/picklescan-results.json'))"
    [ "$status" -eq 0 ]
}

@test "Enhanced picklescan scanner: JSON contains required fields" {
    run python3 "$PYTHON_SCANNER" \
        --target tests/fixtures/ml-models \
        --scan-dir "$TEST_OUTPUT_DIR" \
        --app-name "$TEST_APP_NAME"
    
    # Check required fields exist
    run python3 -c "
import json, sys
d = json.load(open('$TEST_OUTPUT_DIR/picklescan-results.json'))
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

@test "Enhanced picklescan scanner: statistics track file counts" {
    run python3 "$PYTHON_SCANNER" \
        --target tests/fixtures/ml-models \
        --scan-dir "$TEST_OUTPUT_DIR" \
        --app-name "$TEST_APP_NAME"
    
    run python3 -c "
import json
d = json.load(open('$TEST_OUTPUT_DIR/picklescan-results.json'))
stats = d['statistics']
assert stats['total_files'] > 0, 'No files scanned'
assert 'pickle_files' in stats
assert 'pytorch_files' in stats
assert 'onnx_files' in stats
assert 'tf_files' in stats
assert 'config_files' in stats
print('OK')
"
    [ "$status" -eq 0 ]
    [[ "$output" = "OK" ]]
}

# ── Bash wrapper tests ───────────────────────────────────────────────────────

@test "Bash wrapper: validates syntax" {
    run bash -n "$BASH_WRAPPER"
    [ "$status" -eq 0 ]
}

@test "Bash wrapper: displays help text" {
    run "$BASH_WRAPPER" --help
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Layer 14" ]]
    [[ "$output" =~ "Pickle" ]]
}

@test "Bash wrapper: requires --target argument" {
    run "$BASH_WRAPPER" --scan-dir "$TEST_OUTPUT_DIR"
    [ "$status" -ne 0 ]
}

@test "Bash wrapper: invokes Python scanner correctly" {
    skip "Integration test — requires full environment setup"
    
    run "$BASH_WRAPPER" \
        --target tests/fixtures/ml-models \
        --scan-dir "$TEST_OUTPUT_DIR" \
        --app-name "$TEST_APP_NAME"
    
    # Check that it created the expected output
    [ -f "$TEST_OUTPUT_DIR/picklescan-results.json" ]
    [ -f "$TEST_OUTPUT_DIR/picklescan.log" ]
}

# ── Format-specific tests ────────────────────────────────────────────────────

@test "Format filter: --formats pickle scans only pickle files" {
    run python3 "$PYTHON_SCANNER" \
        --target tests/fixtures/ml-models \
        --scan-dir "$TEST_OUTPUT_DIR" \
        --app-name "$TEST_APP_NAME" \
        --formats pickle
    
    run python3 -c "
import json
d = json.load(open('$TEST_OUTPUT_DIR/picklescan-results.json'))
formats = d['formats_scanned']
assert formats == ['pickle'], f'Expected [pickle], got {formats}'
print('OK')
"
    [ "$status" -eq 0 ]
    [[ "$output" = "OK" ]]
}

@test "Format filter: --formats onnx scans only ONNX files" {
    run python3 "$PYTHON_SCANNER" \
        --target tests/fixtures/ml-models \
        --scan-dir "$TEST_OUTPUT_DIR" \
        --app-name "$TEST_APP_NAME" \
        --formats onnx
    
    run python3 -c "
import json
d = json.load(open('$TEST_OUTPUT_DIR/picklescan-results.json'))
formats = d['formats_scanned']
assert formats == ['onnx'], f'Expected [onnx], got {formats}'
stats = d['statistics']
assert stats['pickle_files'] == 0, 'Should not scan pickle files when format is onnx'
print('OK')
"
    [ "$status" -eq 0 ]
    [[ "$output" = "OK" ]]
}

@test "Format filter: multiple formats work" {
    run python3 "$PYTHON_SCANNER" \
        --target tests/fixtures/ml-models \
        --scan-dir "$TEST_OUTPUT_DIR" \
        --app-name "$TEST_APP_NAME" \
        --formats "pickle,config"
    
    run python3 -c "
import json
d = json.load(open('$TEST_OUTPUT_DIR/picklescan-results.json'))
formats = set(d['formats_scanned'])
expected = {'pickle', 'config'}
assert formats == expected, f'Expected {expected}, got {formats}'
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
d = json.load(open('$TEST_OUTPUT_DIR/picklescan-results.json'))
assert d['statistics']['total_files'] == 0
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
        --target tests/fixtures/ml-models/benign \
        --scan-dir "$NEW_OUTPUT" \
        --app-name "$TEST_APP_NAME"
    
    # Should create the directory and succeed
    [ -d "$NEW_OUTPUT" ]
    [ -f "$NEW_OUTPUT/picklescan-results.json" ]
}
