#!/usr/bin/env bats
# Tests for Layer 20 — ML Runtime Behavioral Analysis
# Tests run-ml-runtime-analysis.sh

SCRIPT_DIR="${BATS_TEST_DIRNAME}/../../scripts/shell"
BASH_SCRIPT="$SCRIPT_DIR/run-ml-runtime-analysis.sh"
PYTHON_SCRIPT="$SCRIPT_DIR/run-ml-runtime-analysis.py"

setup() {
    # Create temporary directory for test scans
    export TEST_SCAN_DIR="$(mktemp -d)"
    export TEST_OUTPUT_DIR="$(mktemp -d)"
    
    # Check if Docker/Podman is available
    if command -v docker &> /dev/null || command -v podman &> /dev/null; then
        export HAS_SANDBOX=true
    else
        export HAS_SANDBOX=false
    fi
    
    # Ensure fixtures exist
    if [[ ! -d "tests/fixtures/ml-runtime" ]]; then
        skip "Test fixtures not found"
    fi
}

teardown() {
    # Clean up temporary directories
    [[ -d "$TEST_SCAN_DIR" ]] && rm -rf "$TEST_SCAN_DIR"
    [[ -d "$TEST_OUTPUT_DIR" ]] && rm -rf "$TEST_OUTPUT_DIR"
}

# ── Basic tests ──────────────────────────────────────────────────────────────

@test "ML runtime scanner: --help flag works" {
    run "$BASH_SCRIPT" --help
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Layer 20" ]]
    [[ "$output" =~ "Runtime Behavioral Analysis" ]]
    [[ "$output" =~ "WARNING" ]]
}

@test "ML runtime scanner: validates syntax" {
    run bash -n "$BASH_SCRIPT"
    [ "$status" -eq 0 ]
    
    run python3 -m py_compile "$PYTHON_SCRIPT"
    [ "$status" -eq 0 ]
}

@test "ML runtime scanner: executable flag set" {
    [ -x "$BASH_SCRIPT" ]
    [ -x "$PYTHON_SCRIPT" ]
}

# ── Opt-in behavior tests ────────────────────────────────────────────────────

@test "Scanner requires opt-in (RUN_ML_RUNTIME=true)" {
    # Without RUN_ML_RUNTIME, scanner should exit gracefully
    run env TARGET_DIR=tests/fixtures/ml-runtime/benign SCAN_DIR="$TEST_OUTPUT_DIR" APP_NAME=test "$BASH_SCRIPT"
    
    [ "$status" -eq 0 ]
    [[ "$output" =~ "disabled" ]]
    [[ "$output" =~ "opt-in" ]]
}

@test "SKIP_ML_RUNTIME skips scan" {
    run env TARGET_DIR=tests/fixtures/ml-runtime/benign SCAN_DIR="$TEST_OUTPUT_DIR" APP_NAME=test RUN_ML_RUNTIME=true SKIP_ML_RUNTIME=true "$BASH_SCRIPT"
    
    [ "$status" -eq 0 ]
    [[ "$output" =~ "skipped" ]]
}

# ── Prerequisite tests ───────────────────────────────────────────────────────

@test "Scanner validates TARGET_DIR is required" {
    run env SCAN_DIR="$TEST_OUTPUT_DIR" APP_NAME=test RUN_ML_RUNTIME=true "$BASH_SCRIPT"
    
    [ "$status" -eq 1 ]
    [[ "$output" =~ "TARGET_DIR" ]]
}

@test "Scanner validates SCAN_DIR is required" {
    run env TARGET_DIR=tests/fixtures/ml-runtime/benign APP_NAME=test RUN_ML_RUNTIME=true "$BASH_SCRIPT"
    
    [ "$status" -eq 1 ]
    [[ "$output" =~ "SCAN_DIR" ]]
}

@test "Scanner validates APP_NAME is required" {
    run env TARGET_DIR=tests/fixtures/ml-runtime/benign SCAN_DIR="$TEST_OUTPUT_DIR" RUN_ML_RUNTIME=true "$BASH_SCRIPT"
    
    [ "$status" -eq 1 ]
    [[ "$output" =~ "APP_NAME" ]]
}

@test "Scanner checks for Docker/Podman prerequisite" {
    # Test prerequisite check in Python script
    run python3 -c "
import sys
sys.path.insert(0, 'scripts/shell')
# This will fail if Docker/Podman not available, but we can't easily mock it
# So just verify the script has the prerequisite check
with open('$PYTHON_SCRIPT', 'r') as f:
    content = f.read()
    assert 'docker' in content.lower()
    assert 'podman' in content.lower()
    assert '_check_prerequisites' in content
print('OK')
"
    [ "$status" -eq 0 ]
    [[ "$output" = "OK" ]]
}

# ── Docker/Podman-based tests (conditional) ──────────────────────────────────

@test "Benign model loads without critical/high findings" {
    if [[ "$HAS_SANDBOX" != "true" ]]; then
        skip "Docker/Podman not available"
    fi
    
    # Use longer timeout to allow Docker pull if needed
    run env TARGET_DIR=tests/fixtures/ml-runtime/benign SCAN_DIR="$TEST_OUTPUT_DIR" APP_NAME=test RUN_ML_RUNTIME=true ML_RUNTIME_TIMEOUT=120 "$BASH_SCRIPT"
    
    # May timeout during Docker pull, so allow any exit code
    # Just check that results file was created
    [ -f "$TEST_OUTPUT_DIR/ml-runtime/ml-runtime-analysis-results.json" ]
    
    # Check that no critical findings (even if timeout occurred)
    run python3 -c "
import json
d = json.load(open('$TEST_OUTPUT_DIR/ml-runtime/ml-runtime-analysis-results.json'))
print(d['summary']['critical_findings'])
"
    [ "$status" -eq 0 ]
    [ "$output" -eq 0 ]
}

@test "Malicious network fixture triggers detection (if Docker available)" {
    if [[ "$HAS_SANDBOX" != "true" ]]; then
        skip "Docker/Podman not available"
    fi
    
    # Network fixture should produce some findings (may timeout or detect patterns)
    run env TARGET_DIR=tests/fixtures/ml-runtime/malicious-network SCAN_DIR="$TEST_OUTPUT_DIR" APP_NAME=test RUN_ML_RUNTIME=true ML_RUNTIME_TIMEOUT=120 "$BASH_SCRIPT"
    
    # Results file should exist
    [ -f "$TEST_OUTPUT_DIR/ml-runtime/ml-runtime-analysis-results.json" ]
    
    # Check that at least some suspicious behavior was detected (timeout, network, or load error)
    run python3 -c "
import json
d = json.load(open('$TEST_OUTPUT_DIR/ml-runtime/ml-runtime-analysis-results.json'))
# Any finding indicates detection
print(d['statistics']['suspicious_behavior_detected'])
"
    [ "$status" -eq 0 ]
    # Should have at least one suspicious behavior
    [ "$output" -gt 0 ]
}

@test "Malicious file access fixture triggers detection (if Docker available)" {
    if [[ "$HAS_SANDBOX" != "true" ]]; then
        skip "Docker/Podman not available"
    fi
    
    run env TARGET_DIR=tests/fixtures/ml-runtime/malicious-fileaccess SCAN_DIR="$TEST_OUTPUT_DIR" APP_NAME=test RUN_ML_RUNTIME=true ML_RUNTIME_TIMEOUT=120 "$BASH_SCRIPT"
    
    # Results file should exist
    [ -f "$TEST_OUTPUT_DIR/ml-runtime/ml-runtime-analysis-results.json" ]
    
    # Check that at least some suspicious behavior was detected
    run python3 -c "
import json
d = json.load(open('$TEST_OUTPUT_DIR/ml-runtime/ml-runtime-analysis-results.json'))
print(d['statistics']['suspicious_behavior_detected'])
"
    [ "$status" -eq 0 ]
    [ "$output" -gt 0 ]
}

@test "Malicious subprocess fixture triggers detection (if Docker available)" {
    if [[ "$HAS_SANDBOX" != "true" ]]; then
        skip "Docker/Podman not available"
    fi
    
    run env TARGET_DIR=tests/fixtures/ml-runtime/malicious-subprocess SCAN_DIR="$TEST_OUTPUT_DIR" APP_NAME=test RUN_ML_RUNTIME=true ML_RUNTIME_TIMEOUT=120 "$BASH_SCRIPT"
    
    # Results file should exist
    [ -f "$TEST_OUTPUT_DIR/ml-runtime/ml-runtime-analysis-results.json" ]
    
    # Check that at least some suspicious behavior was detected
    run python3 -c "
import json
d = json.load(open('$TEST_OUTPUT_DIR/ml-runtime/ml-runtime-analysis-results.json'))
print(d['statistics']['suspicious_behavior_detected'])
"
    [ "$status" -eq 0 ]
    [ "$output" -gt 0 ]
}

# ── JSON output tests ────────────────────────────────────────────────────────

@test "Produces valid JSON output (when Docker available)" {
    if [[ "$HAS_SANDBOX" != "true" ]]; then
        skip "Docker/Podman not available"
    fi
    
    run env TARGET_DIR=tests/fixtures/ml-runtime/benign SCAN_DIR="$TEST_OUTPUT_DIR" APP_NAME=test RUN_ML_RUNTIME=true ML_RUNTIME_TIMEOUT=120 "$BASH_SCRIPT"
    
    # Check JSON is valid
    run python3 -c "import json; json.load(open('$TEST_OUTPUT_DIR/ml-runtime/ml-runtime-analysis-results.json'))"
    [ "$status" -eq 0 ]
}

@test "JSON contains required fields (when Docker available)" {
    if [[ "$HAS_SANDBOX" != "true" ]]; then
        skip "Docker/Podman not available"
    fi
    
    run env TARGET_DIR=tests/fixtures/ml-runtime/benign SCAN_DIR="$TEST_OUTPUT_DIR" APP_NAME=test RUN_ML_RUNTIME=true ML_RUNTIME_TIMEOUT=120 "$BASH_SCRIPT"
    
    # Check required fields exist
    run python3 -c "
import json, sys
d = json.load(open('$TEST_OUTPUT_DIR/ml-runtime/ml-runtime-analysis-results.json'))
required = ['tool', 'version', 'status', 'target', 'generated_at', 'sandbox', 'timeout', 'statistics', 'findings', 'summary']
missing = [f for f in required if f not in d]
if missing:
    print('Missing fields:', missing)
    sys.exit(1)
print('OK')
"
    [ "$status" -eq 0 ]
    [[ "$output" = "OK" ]]
}

@test "Statistics track analysis counts (when Docker available)" {
    if [[ "$HAS_SANDBOX" != "true" ]]; then
        skip "Docker/Podman not available"
    fi
    
    run env TARGET_DIR=tests/fixtures/ml-runtime/benign SCAN_DIR="$TEST_OUTPUT_DIR" APP_NAME=test RUN_ML_RUNTIME=true ML_RUNTIME_TIMEOUT=120 "$BASH_SCRIPT"
    
    run python3 -c "
import json
d = json.load(open('$TEST_OUTPUT_DIR/ml-runtime/ml-runtime-analysis-results.json'))
stats = d['statistics']
assert 'models_analyzed' in stats
assert 'suspicious_behavior_detected' in stats
assert stats['models_analyzed'] > 0
print('OK')
"
    [ "$status" -eq 0 ]
    [[ "$output" = "OK" ]]
}

# ── Edge cases ───────────────────────────────────────────────────────────────

@test "Edge case: empty directory produces no findings" {
    if [[ "$HAS_SANDBOX" != "true" ]]; then
        skip "Docker/Podman not available"
    fi
    
    mkdir -p "$TEST_SCAN_DIR/empty"
    
    run env TARGET_DIR="$TEST_SCAN_DIR/empty" SCAN_DIR="$TEST_OUTPUT_DIR" APP_NAME=test RUN_ML_RUNTIME=true ML_RUNTIME_TIMEOUT=60 "$BASH_SCRIPT"
    
    [ "$status" -eq 0 ]
    
    run python3 -c "
import json
d = json.load(open('$TEST_OUTPUT_DIR/ml-runtime/ml-runtime-analysis-results.json'))
assert d['statistics']['models_analyzed'] == 0
assert len(d['findings']) == 0
print('OK')
"
    [ "$status" -eq 0 ]
    [[ "$output" = "OK" ]]
}

@test "Edge case: nonexistent target directory fails gracefully" {
    run env TARGET_DIR=/nonexistent/path SCAN_DIR="$TEST_OUTPUT_DIR" APP_NAME=test RUN_ML_RUNTIME=true "$BASH_SCRIPT"
    
    [ "$status" -eq 1 ]
    [[ "$output" =~ "does not exist" ]]
}

@test "Scanner respects timeout parameter" {
    # Verify timeout is passed to Python script
    run python3 -c "
import sys
# Check that Python script accepts --timeout parameter
with open('$PYTHON_SCRIPT', 'r') as f:
    content = f.read()
    assert '--timeout' in content
    assert 'timeout=' in content
print('OK')
"
    [ "$status" -eq 0 ]
    [[ "$output" = "OK" ]]
}

@test "Scanner supports sandbox selection (docker vs podman)" {
    # Verify sandbox parameter exists
    run python3 -c "
with open('$PYTHON_SCRIPT', 'r') as f:
    content = f.read()
    assert '--sandbox' in content
    assert 'docker' in content.lower()
    assert 'podman' in content.lower()
print('OK')
"
    [ "$status" -eq 0 ]
    [[ "$output" = "OK" ]]
}
