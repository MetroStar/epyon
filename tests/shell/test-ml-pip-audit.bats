#!/usr/bin/env bats
# Tests for ML-aware pip-audit enhancements
# Tests analyze-ml-dependencies.py

SCRIPT_DIR="${BATS_TEST_DIRNAME}/../../scripts/shell"
PYTHON_SCRIPT="$SCRIPT_DIR/analyze-ml-dependencies.py"

setup() {
    # Create temporary directory for test outputs
    export TEST_OUTPUT_DIR="$(mktemp -d)"
    
    # Ensure fixtures exist
    if [[ ! -d "tests/fixtures/pip-audit" ]]; then
        skip "Test fixtures not found"
    fi
}

teardown() {
    # Clean up temporary directories
    [[ -d "$TEST_OUTPUT_DIR" ]] && rm -rf "$TEST_OUTPUT_DIR"
}

# ── Basic tests ──────────────────────────────────────────────────────────────

@test "ML analyzer: validates syntax" {
    run python3 -m py_compile "$PYTHON_SCRIPT"
    [ "$status" -eq 0 ]
}

@test "ML analyzer: executable flag set" {
    [ -x "$PYTHON_SCRIPT" ]
}

@test "ML analyzer: requires two arguments" {
    run python3 "$PYTHON_SCRIPT"
    [ "$status" -eq 1 ]
    [[ "$output" =~ "Usage" ]]
}

@test "ML analyzer: validates input file exists" {
    run python3 "$PYTHON_SCRIPT" /nonexistent/file.json "$TEST_OUTPUT_DIR/output.json"
    [ "$status" -eq 1 ]
    [[ "$output" =~ "not found" ]]
}

# ── ML package detection tests ──────────────────────────────────────────────

@test "Detects ML packages (torch)" {
    OUTPUT_FILE="$TEST_OUTPUT_DIR/enhanced.json"
    
    run python3 "$PYTHON_SCRIPT" tests/fixtures/pip-audit/mock-pip-audit-results.json "$OUTPUT_FILE"
    
    # Check output mentions ML packages
    [[ "$output" =~ "torch" ]]
    
    # Check JSON contains ML findings
    run python3 -c "
import json
d = json.load(open('$OUTPUT_FILE'))
ml_pkgs = d['ml_specific_findings']['ml_packages_found']
assert len(ml_pkgs) > 0, 'Should detect ML packages'
assert ml_pkgs[0]['name'] == 'torch', 'Should detect torch'
print('OK')
"
    [ "$status" -eq 0 ]
    [[ "$output" = "OK" ]]
}

@test "Detects ML vulnerabilities" {
    OUTPUT_FILE="$TEST_OUTPUT_DIR/enhanced.json"
    
    run python3 "$PYTHON_SCRIPT" tests/fixtures/pip-audit/mock-pip-audit-results.json "$OUTPUT_FILE"
    
    # Check JSON contains ML vulnerabilities
    run python3 -c "
import json
d = json.load(open('$OUTPUT_FILE'))
ml_vulns = d['ml_specific_findings']['ml_vulnerabilities']
assert len(ml_vulns) > 0, 'Should detect ML vulnerabilities'
assert ml_vulns[0]['package'] == 'torch', 'Should have torch vuln'
print('OK')
"
    [ "$status" -eq 0 ]
    [[ "$output" = "OK" ]]
}

@test "Detects high-severity ML CVEs" {
    OUTPUT_FILE="$TEST_OUTPUT_DIR/enhanced.json"
    
    run python3 "$PYTHON_SCRIPT" tests/fixtures/pip-audit/mock-pip-audit-results.json "$OUTPUT_FILE"
    
    # Check JSON contains high-severity CVEs
    run python3 -c "
import json
d = json.load(open('$OUTPUT_FILE'))
high_cves = d['ml_specific_findings']['high_severity_ml_cves']
assert len(high_cves) > 0, 'Should detect high-severity CVEs'
print('OK')
"
    [ "$status" -eq 0 ]
    [[ "$output" = "OK" ]]
}

# ── Typosquatting detection tests ───────────────────────────────────────────

@test "Detects typosquatting (torh vs torch)" {
    OUTPUT_FILE="$TEST_OUTPUT_DIR/enhanced.json"
    
    run python3 "$PYTHON_SCRIPT" tests/fixtures/pip-audit/mock-pip-audit-results.json "$OUTPUT_FILE"
    
    # Should exit with code 2 for typosquat
    [ "$status" -eq 2 ]
    
    # Check output mentions typosquat
    [[ "$output" =~ "torh" ]]
    [[ "$output" =~ "torch" ]]
    
    # Check JSON contains typosquat warning
    run python3 -c "
import json
d = json.load(open('$OUTPUT_FILE'))
typosquats = d['ml_specific_findings']['typosquat_warnings']
assert len(typosquats) > 0, 'Should detect typosquats'
assert typosquats[0]['package'] == 'torh', 'Should detect torh'
assert typosquats[0]['suspected_target'] == 'torch', 'Should identify target as torch'
assert typosquats[0]['levenshtein_distance'] == 1, 'Distance should be 1'
print('OK')
"
    [ "$status" -eq 0 ]
    [[ "$output" = "OK" ]]
}

@test "Typosquat warnings have critical severity" {
    OUTPUT_FILE="$TEST_OUTPUT_DIR/enhanced.json"
    
    run python3 "$PYTHON_SCRIPT" tests/fixtures/pip-audit/mock-pip-audit-results.json "$OUTPUT_FILE"
    
    run python3 -c "
import json
d = json.load(open('$OUTPUT_FILE'))
typosquats = d['ml_specific_findings']['typosquat_warnings']
for ts in typosquats:
    assert ts['severity'] == 'critical', 'Typosquats should be critical'
print('OK')
"
    [ "$status" -eq 0 ]
    [[ "$output" = "OK" ]]
}

@test "Levenshtein distance calculation works" {
    # Test the Levenshtein distance function inline
    run python3 -c "
def levenshtein_distance(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]

# Test exact match
assert levenshtein_distance('torch', 'torch') == 0, 'Exact match should be 0'

# Test single substitution
assert levenshtein_distance('torch', 'torh') == 1, 'Single substitution should be 1'

# Test single deletion
assert levenshtein_distance('torch', 'toch') == 1, 'Single deletion should be 1'

# Test single insertion
assert levenshtein_distance('torch', 'toarch') == 1, 'Single insertion should be 1'

# Test multiple changes
assert levenshtein_distance('torch', 'tensor') == 5, 'Multiple changes should be 5'

print('OK')
"
    [ "$status" -eq 0 ]
    [[ "$output" = "OK" ]]
}

@test "Does not flag exact matches as typosquats" {
    # Create test data with exact match
    cat > "$TEST_OUTPUT_DIR/exact-match.json" <<EOF
{
  "scan_id": "test",
  "timestamp": "2026-07-30T12:00:00Z",
  "target": "/test",
  "total_vulnerabilities": 0,
  "dependency_files_scanned": 1,
  "scan_results": [
    {
      "file": "requirements.txt",
      "results": [
        {
          "name": "torch",
          "version": "2.0.0",
          "id": "N/A",
          "description": "No vulnerability",
          "fix_versions": [],
          "aliases": []
        }
      ]
    }
  ]
}
EOF
    
    OUTPUT_FILE="$TEST_OUTPUT_DIR/enhanced.json"
    
    run python3 "$PYTHON_SCRIPT" "$TEST_OUTPUT_DIR/exact-match.json" "$OUTPUT_FILE"
    
    # Should not exit with typosquat error (exit 0 or 1, but not 2)
    [[ "$status" -ne 2 ]]
    
    # Check no typosquat warnings
    run python3 -c "
import json
d = json.load(open('$OUTPUT_FILE'))
typosquats = d['ml_specific_findings']['typosquat_warnings']
assert len(typosquats) == 0, 'Exact match should not trigger typosquat warning'
print('OK')
"
    [ "$status" -eq 0 ]
    [[ "$output" = "OK" ]]
}

# ── Output format tests ──────────────────────────────────────────────────────

@test "Produces valid JSON output" {
    OUTPUT_FILE="$TEST_OUTPUT_DIR/enhanced.json"
    
    run python3 "$PYTHON_SCRIPT" tests/fixtures/pip-audit/mock-pip-audit-results.json "$OUTPUT_FILE"
    
    # Check JSON is valid
    run python3 -c "import json; json.load(open('$OUTPUT_FILE'))"
    [ "$status" -eq 0 ]
}

@test "Enhanced results contain required ML fields" {
    OUTPUT_FILE="$TEST_OUTPUT_DIR/enhanced.json"
    
    run python3 "$PYTHON_SCRIPT" tests/fixtures/pip-audit/mock-pip-audit-results.json "$OUTPUT_FILE"
    
    run python3 -c "
import json, sys
d = json.load(open('$OUTPUT_FILE'))

# Check top-level fields
required = ['ml_packages_detected', 'ml_vulnerabilities_count', 'typosquat_warnings_count']
missing = [f for f in required if f not in d]
if missing:
    print('Missing fields:', missing)
    sys.exit(1)

# Check ml_specific_findings structure
ml_findings = d['ml_specific_findings']
required_ml = ['ml_packages_found', 'ml_vulnerabilities', 'typosquat_warnings', 'high_severity_ml_cves']
missing_ml = [f for f in required_ml if f not in ml_findings]
if missing_ml:
    print('Missing ML findings fields:', missing_ml)
    sys.exit(1)

print('OK')
"
    [ "$status" -eq 0 ]
    [[ "$output" = "OK" ]]
}

@test "Summary counts match findings arrays" {
    OUTPUT_FILE="$TEST_OUTPUT_DIR/enhanced.json"
    
    run python3 "$PYTHON_SCRIPT" tests/fixtures/pip-audit/mock-pip-audit-results.json "$OUTPUT_FILE"
    
    run python3 -c "
import json
d = json.load(open('$OUTPUT_FILE'))
ml = d['ml_specific_findings']

assert d['ml_packages_detected'] == len(ml['ml_packages_found']), 'Package count mismatch'
assert d['ml_vulnerabilities_count'] == len(ml['ml_vulnerabilities']), 'Vuln count mismatch'
assert d['typosquat_warnings_count'] == len(ml['typosquat_warnings']), 'Typosquat count mismatch'

print('OK')
"
    [ "$status" -eq 0 ]
    [[ "$output" = "OK" ]]
}

# ── Edge cases ───────────────────────────────────────────────────────────────

@test "Edge case: empty scan results" {
    cat > "$TEST_OUTPUT_DIR/empty.json" <<EOF
{
  "scan_id": "test",
  "timestamp": "2026-07-30T12:00:00Z",
  "target": "/test",
  "total_vulnerabilities": 0,
  "dependency_files_scanned": 0,
  "scan_results": []
}
EOF
    
    OUTPUT_FILE="$TEST_OUTPUT_DIR/enhanced.json"
    
    run python3 "$PYTHON_SCRIPT" "$TEST_OUTPUT_DIR/empty.json" "$OUTPUT_FILE"
    
    [ "$status" -eq 0 ]
    
    # Check counts are zero
    run python3 -c "
import json
d = json.load(open('$OUTPUT_FILE'))
assert d['ml_packages_detected'] == 0
assert d['ml_vulnerabilities_count'] == 0
assert d['typosquat_warnings_count'] == 0
print('OK')
"
    [ "$status" -eq 0 ]
    [[ "$output" = "OK" ]]
}

@test "Edge case: non-ML packages only" {
    cat > "$TEST_OUTPUT_DIR/non-ml.json" <<EOF
{
  "scan_id": "test",
  "timestamp": "2026-07-30T12:00:00Z",
  "target": "/test",
  "total_vulnerabilities": 1,
  "dependency_files_scanned": 1,
  "scan_results": [
    {
      "file": "requirements.txt",
      "results": [
        {
          "name": "requests",
          "version": "2.25.0",
          "id": "GHSA-1234-5678-9abc",
          "description": "HTTP library vulnerability",
          "fix_versions": ["2.26.0"],
          "aliases": ["CVE-2021-12345"]
        }
      ]
    }
  ]
}
EOF
    
    OUTPUT_FILE="$TEST_OUTPUT_DIR/enhanced.json"
    
    run python3 "$PYTHON_SCRIPT" "$TEST_OUTPUT_DIR/non-ml.json" "$OUTPUT_FILE"
    
    [ "$status" -eq 0 ]
    
    # Check no ML packages detected
    run python3 -c "
import json
d = json.load(open('$OUTPUT_FILE'))
assert d['ml_packages_detected'] == 0, 'Should detect no ML packages'
assert d['ml_vulnerabilities_count'] == 0, 'Should have no ML vulns'
print('OK')
"
    [ "$status" -eq 0 ]
    [[ "$output" = "OK" ]]
}

@test "Identifies multiple ML packages" {
    cat > "$TEST_OUTPUT_DIR/multi-ml.json" <<EOF
{
  "scan_id": "test",
  "timestamp": "2026-07-30T12:00:00Z",
  "target": "/test",
  "total_vulnerabilities": 3,
  "dependency_files_scanned": 1,
  "scan_results": [
    {
      "file": "requirements.txt",
      "results": [
        {
          "name": "torch",
          "version": "1.9.0",
          "id": "GHSA-1111-2222-3333",
          "description": "PyTorch vuln",
          "fix_versions": ["2.0.0"],
          "aliases": []
        },
        {
          "name": "tensorflow",
          "version": "2.8.0",
          "id": "GHSA-4444-5555-6666",
          "description": "TensorFlow vuln",
          "fix_versions": ["2.12.0"],
          "aliases": []
        },
        {
          "name": "transformers",
          "version": "4.20.0",
          "id": "GHSA-7777-8888-9999",
          "description": "Transformers vuln",
          "fix_versions": ["4.30.0"],
          "aliases": []
        }
      ]
    }
  ]
}
EOF
    
    OUTPUT_FILE="$TEST_OUTPUT_DIR/enhanced.json"
    
    run python3 "$PYTHON_SCRIPT" "$TEST_OUTPUT_DIR/multi-ml.json" "$OUTPUT_FILE"
    
    # Check multiple ML packages detected
    run python3 -c "
import json
d = json.load(open('$OUTPUT_FILE'))
assert d['ml_packages_detected'] == 3, 'Should detect 3 ML packages'
assert d['ml_vulnerabilities_count'] == 3, 'Should have 3 ML vulns'

pkg_names = [p['name'] for p in d['ml_specific_findings']['ml_packages_found']]
assert 'torch' in pkg_names
assert 'tensorflow' in pkg_names
assert 'transformers' in pkg_names

print('OK')
"
    [ "$status" -eq 0 ]
    [[ "$output" = "OK" ]]
}
