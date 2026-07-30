#!/usr/bin/env bats
# Tests for ML STIG control assessment
# Tests ML control logic in run-stig-assessment.py

SCRIPT_DIR="${BATS_TEST_DIRNAME}/../../scripts/shell"
PYTHON_SCRIPT="$SCRIPT_DIR/run-stig-assessment.py"
ML_CHECKLIST="configuration/stigs/ML-Security-Checklist.json"

setup() {
    # Create temporary directory for test outputs
    export TEST_OUTPUT_DIR="$(mktemp -d)"
    export TEST_TARGET_DIR="$(mktemp -d)"
    
    # Ensure fixtures exist
    if [[ ! -f "$ML_CHECKLIST" ]]; then
        skip "ML-Security-Checklist.json not found"
    fi
}

teardown() {
    # Clean up temporary directories
    [[ -d "$TEST_OUTPUT_DIR" ]] && rm -rf "$TEST_OUTPUT_DIR"
    [[ -d "$TEST_TARGET_DIR" ]] && rm -rf "$TEST_TARGET_DIR"
}

# ── Basic tests ──────────────────────────────────────────────────────────────

@test "ML checklist: validates JSON syntax" {
    run python3 -c "import json; json.load(open('$ML_CHECKLIST'))"
    [ "$status" -eq 0 ]
}

@test "ML checklist: contains required fields" {
    run python3 -c "
import json
checklist = json.load(open('$ML_CHECKLIST'))
assert 'title' in checklist
assert 'version' in checklist
assert 'controls' in checklist
assert len(checklist['controls']) > 0
print('OK')
"
    [ "$status" -eq 0 ]
    [[ "$output" = "OK" ]]
}

@test "ML checklist: has 15 controls" {
    run python3 -c "
import json
checklist = json.load(open('$ML_CHECKLIST'))
print(len(checklist['controls']))
"
    [ "$status" -eq 0 ]
    [ "$output" -eq 15 ]
}

@test "ML checklist: all controls have required fields" {
    run python3 -c "
import json
checklist = json.load(open('$ML_CHECKLIST'))
required = ['id', 'title', 'severity', 'category', 'description', 'check_text', 'fix_text', 'status_guidance']
for control in checklist['controls']:
    for field in required:
        assert field in control, f\"Control {control.get('id', 'unknown')} missing {field}\"
print('OK')
"
    [ "$status" -eq 0 ]
    [[ "$output" = "OK" ]]
}

@test "ML checklist: control IDs are ML-001 through ML-015" {
    run python3 -c "
import json
checklist = json.load(open('$ML_CHECKLIST'))
ids = [c['id'] for c in checklist['controls']]
expected = [f'ML-{i:03d}' for i in range(1, 16)]
assert ids == expected, f'Got {ids}, expected {expected}'
print('OK')
"
    [ "$status" -eq 0 ]
    [[ "$output" = "OK" ]]
}

# ── ML control assessment tests ──────────────────────────────────────────────

@test "ML checklist: categories are correct" {
    run python3 -c "
import json
checklist = json.load(open('$ML_CHECKLIST'))
categories = set(c['category'] for c in checklist['controls'])
expected = {'Model Security', 'Supply Chain Security', 'Infrastructure Security', 'Runtime Security'}
assert categories == expected, f'Got {categories}'
print('OK')
"
    [ "$status" -eq 0 ]
    [[ "$output" = "OK" ]]
}

@test "ML checklist: severities are valid" {
    run python3 -c "
import json
checklist = json.load(open('$ML_CHECKLIST'))
valid_severities = {'critical', 'high', 'medium', 'low'}
for control in checklist['controls']:
    severity = control['severity'].lower()
    assert severity in valid_severities, f\"Invalid severity: {severity}\"
print('OK')
"
    [ "$status" -eq 0 ]
    [[ "$output" = "OK" ]]
}

@test "ML checklist: Layer 14 controls (ML-001 to ML-004)" {
    run python3 -c "
import json
checklist = json.load(open('$ML_CHECKLIST'))
layer14_controls = [c for c in checklist['controls'] if c['id'] in ['ML-001', 'ML-002', 'ML-003', 'ML-004']]
assert len(layer14_controls) == 4
for c in layer14_controls:
    assert c['category'] == 'Model Security'
print('OK')
"
    [ "$status" -eq 0 ]
    [[ "$output" = "OK" ]]
}

@test "ML checklist: Layer 18 controls (ML-005 to ML-009)" {
    run python3 -c "
import json
checklist = json.load(open('$ML_CHECKLIST'))
layer18_controls = [c for c in checklist['controls'] if c['id'] in ['ML-005', 'ML-006', 'ML-007', 'ML-008', 'ML-009']]
assert len(layer18_controls) == 5
for c in layer18_controls:
    assert c['category'] == 'Supply Chain Security'
print('OK')
"
    [ "$status" -eq 0 ]
    [[ "$output" = "OK" ]]
}

@test "ML checklist: Layer 19 controls (ML-010 to ML-012)" {
    run python3 -c "
import json
checklist = json.load(open('$ML_CHECKLIST'))
layer19_controls = [c for c in checklist['controls'] if c['id'] in ['ML-010', 'ML-011', 'ML-012']]
assert len(layer19_controls) == 3
for c in layer19_controls:
    assert c['category'] == 'Infrastructure Security'
print('OK')
"
    [ "$status" -eq 0 ]
    [[ "$output" = "OK" ]]
}

@test "ML checklist: Layer 20 controls (ML-013 to ML-015)" {
    run python3 -c "
import json
checklist = json.load(open('$ML_CHECKLIST'))
layer20_controls = [c for c in checklist['controls'] if c['id'] in ['ML-013', 'ML-014', 'ML-015']]
assert len(layer20_controls) == 3
for c in layer20_controls:
    assert c['category'] == 'Runtime Security'
    assert 'not_reviewed' in c['status_guidance']
print('OK')
"
    [ "$status" -eq 0 ]
    [[ "$output" = "OK" ]]
}

# ── Integration tests ────────────────────────────────────────────────────────

@test "Test fixtures exist" {
    [ -f "tests/fixtures/ml-stig/layer14/picklescan-results.json" ]
    [ -f "tests/fixtures/ml-stig/layer18/model-provenance-results.json" ]
    [ -f "tests/fixtures/ml-stig/layer19/inference-security-results.json" ]
    [ -f "tests/fixtures/ml-stig/layer20-present/ml-runtime-analysis-results.json" ]
}

@test "Layer 14 fixture: has dangerous import findings" {
    run python3 -c "
import json
data = json.load(open('tests/fixtures/ml-stig/layer14/picklescan-results.json'))
findings = [f for f in data['findings'] if f['type'] == 'dangerous_imports']
assert len(findings) > 0
print('OK')
"
    [ "$status" -eq 0 ]
    [[ "$output" = "OK" ]]
}

@test "Layer 18 fixture: has provenance findings" {
    run python3 -c "
import json
data = json.load(open('tests/fixtures/ml-stig/layer18/model-provenance-results.json'))
finding_types = [f['type'] for f in data['findings']]
assert 'blocked_hash' in finding_types
assert 'blocked_author' in finding_types
assert 'typosquat' in finding_types
print('OK')
"
    [ "$status" -eq 0 ]
    [[ "$output" = "OK" ]]
}

@test "Layer 19 fixture: has infrastructure findings" {
    run python3 -c "
import json
data = json.load(open('tests/fixtures/ml-stig/layer19/inference-security-results.json'))
finding_types = [f['type'] for f in data['findings']]
assert 'dockerfile_root_user' in finding_types
assert 'compose_privileged_mode' in finding_types
print('OK')
"
    [ "$status" -eq 0 ]
    [[ "$output" = "OK" ]]
}

@test "Layer 20 fixture: has runtime findings" {
    run python3 -c "
import json
data = json.load(open('tests/fixtures/ml-stig/layer20-present/ml-runtime-analysis-results.json'))
finding_types = [f['type'] for f in data['findings']]
assert 'network_attempt' in finding_types
assert 'suspicious_file_access' in finding_types
assert 'subprocess_execution' in finding_types
print('OK')
"
    [ "$status" -eq 0 ]
    [[ "$output" = "OK" ]]
}

@test "STIG assessment script: syntax is valid" {
    run python3 -m py_compile "$PYTHON_SCRIPT"
    [ "$status" -eq 0 ]
}
