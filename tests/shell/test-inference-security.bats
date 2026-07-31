#!/usr/bin/env bats
# Tests for Layer 19 — Inference Environment Security
# Tests run-inference-security-scan.sh

SCRIPT_DIR="${BATS_TEST_DIRNAME}/../../scripts/shell"
BASH_SCRIPT="$SCRIPT_DIR/run-inference-security-scan.sh"

setup() {
    # Create temporary directory for test scans
    export TEST_SCAN_DIR="$(mktemp -d)"
    export TEST_OUTPUT_DIR="$(mktemp -d)"
    
    # Ensure fixtures exist
    if [[ ! -d "tests/fixtures/inference-configs" ]]; then
        skip "Test fixtures not found"
    fi
}

teardown() {
    # Clean up temporary directories
    [[ -d "$TEST_SCAN_DIR" ]] && rm -rf "$TEST_SCAN_DIR"
    [[ -d "$TEST_OUTPUT_DIR" ]] && rm -rf "$TEST_OUTPUT_DIR"
}

# ── Basic tests ──────────────────────────────────────────────────────────────

@test "Inference security scanner: --help flag works" {
    run "$BASH_SCRIPT" --help
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Layer 19" ]]
    [[ "$output" =~ "Inference Environment" ]]
}

@test "Inference security scanner: validates syntax" {
    run bash -n "$BASH_SCRIPT"
    [ "$status" -eq 0 ]
}

@test "Inference security scanner: executable flag set" {
    [ -x "$BASH_SCRIPT" ]
}

# ── Secure configurations ────────────────────────────────────────────────────

@test "Secure Dockerfile passes" {
    run env TARGET_DIR=tests/fixtures/inference-configs/secure SCAN_DIR="$TEST_OUTPUT_DIR" "$BASH_SCRIPT"
    
    # Should exit 0 for secure config
    [ "$status" -eq 0 ]
    
    # Check results file exists
    [ -f "$TEST_OUTPUT_DIR/inference-security/inference-security-results.json" ]
    
    # Check no critical findings
    run python3 -c "import json; d=json.load(open('$TEST_OUTPUT_DIR/inference-security/inference-security-results.json')); print(d['summary']['critical_findings'])"
    [ "$status" -eq 0 ]
    [ "$output" -eq 0 ]
}

@test "Secure configurations produce no high severity findings" {
    run env TARGET_DIR=tests/fixtures/inference-configs/secure SCAN_DIR="$TEST_OUTPUT_DIR" "$BASH_SCRIPT"
    
    run python3 -c "import json; d=json.load(open('$TEST_OUTPUT_DIR/inference-security/inference-security-results.json')); print(d['summary']['high_findings'])"
    [ "$status" -eq 0 ]
    [ "$output" -eq 0 ]
}

# ── Insecure Dockerfile tests ────────────────────────────────────────────────

@test "Detects missing USER directive in Dockerfile" {
    run env TARGET_DIR=tests/fixtures/inference-configs/insecure-dockerfile SCAN_DIR="$TEST_OUTPUT_DIR" "$BASH_SCRIPT"
    
    # Should exit 1 due to findings
    [ "$status" -ne 0 ]
    
    # Check for specific finding
    run python3 -c "
import json
d = json.load(open('$TEST_OUTPUT_DIR/inference-security/inference-security-results.json'))
no_user_findings = [f for f in d['findings'] if f['type'] == 'dockerfile_no_user']
print(len(no_user_findings))
"
    [ "$status" -eq 0 ]
    [ "$output" -gt 0 ]
}

@test "Detects explicit USER root in Dockerfile" {
    run env TARGET_DIR=tests/fixtures/inference-configs/insecure-dockerfile SCAN_DIR="$TEST_OUTPUT_DIR" "$BASH_SCRIPT"
    
    # Check for root user finding
    run python3 -c "
import json
d = json.load(open('$TEST_OUTPUT_DIR/inference-security/inference-security-results.json'))
root_user_findings = [f for f in d['findings'] if f['type'] == 'dockerfile_root_user']
print(len(root_user_findings))
"
    [ "$status" -eq 0 ]
    [ "$output" -gt 0 ]
}

@test "Detects missing --chown in COPY directive" {
    run env TARGET_DIR=tests/fixtures/inference-configs/insecure-dockerfile SCAN_DIR="$TEST_OUTPUT_DIR" "$BASH_SCRIPT"
    
    # Check for copy_no_chown finding
    run python3 -c "
import json
d = json.load(open('$TEST_OUTPUT_DIR/inference-security/inference-security-results.json'))
copy_findings = [f for f in d['findings'] if f['type'] == 'dockerfile_copy_no_chown']
print(len(copy_findings))
"
    [ "$status" -eq 0 ]
    [ "$output" -gt 0 ]
}

@test "Detects privileged port exposure" {
    run env TARGET_DIR=tests/fixtures/inference-configs/insecure-dockerfile SCAN_DIR="$TEST_OUTPUT_DIR" "$BASH_SCRIPT"
    
    # Check for privileged port finding
    run python3 -c "
import json
d = json.load(open('$TEST_OUTPUT_DIR/inference-security/inference-security-results.json'))
port_findings = [f for f in d['findings'] if f['type'] == 'dockerfile_privileged_port']
print(len(port_findings))
"
    [ "$status" -eq 0 ]
    [ "$output" -gt 0 ]
}

# ── Insecure docker-compose tests ───────────────────────────────────────────

@test "Detects privileged mode in docker-compose" {
    run env TARGET_DIR=tests/fixtures/inference-configs/insecure-compose SCAN_DIR="$TEST_OUTPUT_DIR" "$BASH_SCRIPT"
    
    [ "$status" -ne 0 ]
    
    # Check for privileged mode finding
    run python3 -c "
import json
d = json.load(open('$TEST_OUTPUT_DIR/inference-security/inference-security-results.json'))
priv_findings = [f for f in d['findings'] if f['type'] == 'compose_privileged_mode']
print(len(priv_findings))
"
    [ "$status" -eq 0 ]
    [ "$output" -gt 0 ]
}

@test "Detects dangerous capabilities in docker-compose" {
    run env TARGET_DIR=tests/fixtures/inference-configs/insecure-compose SCAN_DIR="$TEST_OUTPUT_DIR" "$BASH_SCRIPT"
    
    # Check for dangerous capabilities finding
    run python3 -c "
import json
d = json.load(open('$TEST_OUTPUT_DIR/inference-security/inference-security-results.json'))
cap_findings = [f for f in d['findings'] if f['type'] == 'compose_dangerous_capabilities']
print(len(cap_findings))
"
    [ "$status" -eq 0 ]
    [ "$output" -gt 0 ]
}

@test "Detects disabled security options in docker-compose" {
    run env TARGET_DIR=tests/fixtures/inference-configs/insecure-compose SCAN_DIR="$TEST_OUTPUT_DIR" "$BASH_SCRIPT"
    
    # Check for disabled security finding
    run python3 -c "
import json
d = json.load(open('$TEST_OUTPUT_DIR/inference-security/inference-security-results.json'))
sec_findings = [f for f in d['findings'] if f['type'] == 'compose_disabled_security']
print(len(sec_findings))
"
    [ "$status" -eq 0 ]
    [ "$output" -gt 0 ]
}

# ── Insecure Kubernetes tests ────────────────────────────────────────────────

@test "Detects runAsNonRoot: false in k8s manifest" {
    run env TARGET_DIR=tests/fixtures/inference-configs/insecure-k8s SCAN_DIR="$TEST_OUTPUT_DIR" "$BASH_SCRIPT"
    
    [ "$status" -ne 0 ]
    
    # Check for run_as_root finding
    run python3 -c "
import json
d = json.load(open('$TEST_OUTPUT_DIR/inference-security/inference-security-results.json'))
root_findings = [f for f in d['findings'] if f['type'] == 'k8s_run_as_root']
print(len(root_findings))
"
    [ "$status" -eq 0 ]
    [ "$output" -gt 0 ]
}

@test "Detects missing runAsNonRoot in k8s manifest" {
    run env TARGET_DIR=tests/fixtures/inference-configs/insecure-k8s SCAN_DIR="$TEST_OUTPUT_DIR" "$BASH_SCRIPT"
    
    # Check for missing run_as_non_root finding
    run python3 -c "
import json
d = json.load(open('$TEST_OUTPUT_DIR/inference-security/inference-security-results.json'))
missing_findings = [f for f in d['findings'] if f['type'] == 'k8s_missing_run_as_non_root']
print(len(missing_findings))
"
    [ "$status" -eq 0 ]
    [ "$output" -gt 0 ]
}

@test "Detects privileged: true in k8s manifest" {
    run env TARGET_DIR=tests/fixtures/inference-configs/insecure-k8s SCAN_DIR="$TEST_OUTPUT_DIR" "$BASH_SCRIPT"
    
    # Check for privileged container finding
    run python3 -c "
import json
d = json.load(open('$TEST_OUTPUT_DIR/inference-security/inference-security-results.json'))
priv_findings = [f for f in d['findings'] if f['type'] == 'k8s_privileged_container']
print(len(priv_findings))
"
    [ "$status" -eq 0 ]
    [ "$output" -gt 0 ]
}

@test "Detects allowPrivilegeEscalation: true in k8s manifest" {
    run env TARGET_DIR=tests/fixtures/inference-configs/insecure-k8s SCAN_DIR="$TEST_OUTPUT_DIR" "$BASH_SCRIPT"
    
    # Check for allow_privilege_escalation finding
    run python3 -c "
import json
d = json.load(open('$TEST_OUTPUT_DIR/inference-security/inference-security-results.json'))
esc_findings = [f for f in d['findings'] if f['type'] == 'k8s_allow_privilege_escalation']
print(len(esc_findings))
"
    [ "$status" -eq 0 ]
    [ "$output" -gt 0 ]
}

# ── JSON output tests ────────────────────────────────────────────────────────

@test "Produces valid JSON output" {
    run env TARGET_DIR=tests/fixtures/inference-configs/secure SCAN_DIR="$TEST_OUTPUT_DIR" "$BASH_SCRIPT"
    
    # Check JSON is valid
    run python3 -c "import json; json.load(open('$TEST_OUTPUT_DIR/inference-security/inference-security-results.json'))"
    [ "$status" -eq 0 ]
}

@test "JSON contains required fields" {
    run env TARGET_DIR=tests/fixtures/inference-configs/secure SCAN_DIR="$TEST_OUTPUT_DIR" "$BASH_SCRIPT"
    
    # Check required fields exist
    run python3 -c "
import json, sys
d = json.load(open('$TEST_OUTPUT_DIR/inference-security/inference-security-results.json'))
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

@test "Statistics track file counts" {
    run env TARGET_DIR=tests/fixtures/inference-configs/secure SCAN_DIR="$TEST_OUTPUT_DIR" "$BASH_SCRIPT"
    
    run python3 -c "
import json
d = json.load(open('$TEST_OUTPUT_DIR/inference-security/inference-security-results.json'))
stats = d['statistics']
assert stats['dockerfiles_scanned'] > 0, 'Should scan Dockerfiles'
assert stats['k8s_manifests_scanned'] > 0, 'Should scan k8s manifests'
assert stats['total_files'] > 0, 'Should have total file count'
print('OK')
"
    [ "$status" -eq 0 ]
    [[ "$output" = "OK" ]]
}

# ── Edge cases ───────────────────────────────────────────────────────────────

@test "Edge case: empty directory produces no findings" {
    mkdir -p "$TEST_SCAN_DIR/empty"
    
    run env TARGET_DIR="$TEST_SCAN_DIR/empty" SCAN_DIR="$TEST_OUTPUT_DIR" "$BASH_SCRIPT"
    
    [ "$status" -eq 0 ]
    
    run python3 -c "
import json
d = json.load(open('$TEST_OUTPUT_DIR/inference-security/inference-security-results.json'))
assert d['statistics']['total_files'] == 0
assert len(d['findings']) == 0
print('OK')
"
    [ "$status" -eq 0 ]
    [[ "$output" = "OK" ]]
}

@test "Edge case: handles non-k8s YAML files gracefully" {
    # Create a non-k8s YAML file
    mkdir -p "$TEST_SCAN_DIR/non-k8s"
    cat > "$TEST_SCAN_DIR/non-k8s/config.yaml" <<EOF
# Not a k8s manifest
app:
  name: test
  port: 8080
EOF
    
    run env TARGET_DIR="$TEST_SCAN_DIR/non-k8s" SCAN_DIR="$TEST_OUTPUT_DIR" "$BASH_SCRIPT"
    
    # Should not crash
    [ "$status" -eq 0 ]
    
    # Should not count non-k8s files
    run python3 -c "
import json
d = json.load(open('$TEST_OUTPUT_DIR/inference-security/inference-security-results.json'))
assert d['statistics']['k8s_manifests_scanned'] == 0
print('OK')
"
    [ "$status" -eq 0 ]
    [[ "$output" = "OK" ]]
}
