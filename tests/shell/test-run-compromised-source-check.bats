#!/usr/bin/env bats
# Tests for Layer 21 — Compromised Source / Supply Chain Incident Detection
# Tests run-compromised-source-check.py and run-compromised-source-check.sh

SCRIPT_DIR="${BATS_TEST_DIRNAME}/../../scripts/shell"
PYTHON_SCANNER="$SCRIPT_DIR/run-compromised-source-check.py"
BASH_WRAPPER="$SCRIPT_DIR/run-compromised-source-check.sh"
TEST_REGISTRY="${BATS_TEST_DIRNAME}/../fixtures/compromised-source/test-registry.json"
PROD_REGISTRY="${BATS_TEST_DIRNAME}/../../configuration/compromised-sources.json"

setup() {
    export TEST_OUTPUT_DIR="$(mktemp -d)"
    export TEST_APP_NAME="compromised-source-test"

    if [[ ! -f "$TEST_REGISTRY" ]]; then
        skip "Test registry not found: $TEST_REGISTRY"
    fi
}

teardown() {
    [[ -d "$TEST_OUTPUT_DIR" ]] && rm -rf "$TEST_OUTPUT_DIR"
}

# ── Python scanner tests ─────────────────────────────────────────────────────

@test "Compromised-source scanner: --help flag works" {
    run python3 "$PYTHON_SCANNER" --help
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Layer 21" ]]
    [[ "$output" =~ "Compromised Source" ]]
}

@test "Compromised-source scanner: requires --target argument" {
    run python3 "$PYTHON_SCANNER" --scan-dir "$TEST_OUTPUT_DIR" --app-name test
    [ "$status" -ne 0 ]
    [[ "$output" =~ "required: --target" ]]
}

@test "Compromised-source scanner: clean target produces no findings" {
    run python3 "$PYTHON_SCANNER" \
        --target tests/fixtures/compromised-source/clean \
        --scan-dir "$TEST_OUTPUT_DIR" \
        --app-name "$TEST_APP_NAME" \
        --registry-path "$TEST_REGISTRY"

    [ "$status" -eq 0 ]
    [ -f "$TEST_OUTPUT_DIR/compromised-source-results.json" ]

    run python3 -c "import json; d=json.load(open('$TEST_OUTPUT_DIR/compromised-source-results.json')); print(d['statistics']['matches_found'])"
    [ "$status" -eq 0 ]
    [ "$output" -eq 0 ]
}

@test "Compromised-source scanner: detects .npmrc reference to compromised host" {
    run python3 "$PYTHON_SCANNER" \
        --target tests/fixtures/compromised-source/npmrc-match \
        --scan-dir "$TEST_OUTPUT_DIR" \
        --app-name "$TEST_APP_NAME" \
        --registry-path "$TEST_REGISTRY"

    # Should exit 1 due to critical finding
    [ "$status" -ne 0 ]

    run python3 -c "
import json
d = json.load(open('$TEST_OUTPUT_DIR/compromised-source-results.json'))
matches = [f for f in d['findings'] if f['type'] == 'compromised_source_reference' and f['host'] == 'artifactory.test-incident.example.org']
print(len(matches))
"
    [ "$status" -eq 0 ]
    [ "$output" -gt 0 ]
}

@test "Compromised-source scanner: detects Dockerfile FROM reference to compromised host" {
    run python3 "$PYTHON_SCANNER" \
        --target tests/fixtures/compromised-source/dockerfile-match \
        --scan-dir "$TEST_OUTPUT_DIR" \
        --app-name "$TEST_APP_NAME" \
        --registry-path "$TEST_REGISTRY"

    [ "$status" -ne 0 ]

    run python3 -c "
import json
d = json.load(open('$TEST_OUTPUT_DIR/compromised-source-results.json'))
matches = [f for f in d['findings'] if f['file'] == 'Dockerfile']
print(len(matches))
"
    [ "$status" -eq 0 ]
    [ "$output" -gt 0 ]
}

@test "Compromised-source scanner: finding includes remediation and control metadata" {
    run python3 "$PYTHON_SCANNER" \
        --target tests/fixtures/compromised-source/npmrc-match \
        --scan-dir "$TEST_OUTPUT_DIR" \
        --app-name "$TEST_APP_NAME" \
        --registry-path "$TEST_REGISTRY"

    run python3 -c "
import json
d = json.load(open('$TEST_OUTPUT_DIR/compromised-source-results.json'))
f = d['findings'][0]
assert f['cve'] == 'CVE-2026-00000'
assert 'CM-5' in f['controls']
assert len(f['remediation']) > 0
print('ok')
"
    [ "$status" -eq 0 ]
    [[ "$output" =~ "ok" ]]
}

@test "Compromised-source scanner: missing registry produces empty findings, exit 0" {
    run python3 "$PYTHON_SCANNER" \
        --target tests/fixtures/compromised-source/npmrc-match \
        --scan-dir "$TEST_OUTPUT_DIR" \
        --app-name "$TEST_APP_NAME" \
        --registry-path "/nonexistent/registry.json"

    [ "$status" -eq 0 ]
    run python3 -c "import json; d=json.load(open('$TEST_OUTPUT_DIR/compromised-source-results.json')); print(d['statistics']['matches_found'])"
    [ "$output" -eq 0 ]
}

@test "Compromised-source scanner: default production registry is valid JSON" {
    [ -f "$PROD_REGISTRY" ]
    run python3 -c "import json; json.load(open('$PROD_REGISTRY'))"
    [ "$status" -eq 0 ]
}

@test "Compromised-source scanner: respects .epyon-ignore.yml path exclusions" {
    local ignore_target="$TEST_OUTPUT_DIR/ignore-target"
    mkdir -p "$ignore_target"
    cp "${BATS_TEST_DIRNAME}/../fixtures/compromised-source/npmrc-match/.npmrc" "$ignore_target/.npmrc"
    cat > "$ignore_target/.epyon-ignore.yml" <<'EOF'
ignores:
  - type: path
    value: ".npmrc"
EOF

    run python3 "$PYTHON_SCANNER" \
        --target "$ignore_target" \
        --scan-dir "$TEST_OUTPUT_DIR/ignore-out" \
        --app-name "$TEST_APP_NAME" \
        --registry-path "$TEST_REGISTRY"

    [ "$status" -eq 0 ]
    run python3 -c "import json; d=json.load(open('$TEST_OUTPUT_DIR/ignore-out/compromised-source-results.json')); print(d['statistics']['matches_found'])"
    [ "$output" -eq 0 ]
}

# ── Bash wrapper tests ───────────────────────────────────────────────────────

@test "Compromised-source wrapper: --help flag works" {
    run bash "$BASH_WRAPPER" --help
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Layer 21" ]]
}

@test "Compromised-source wrapper: runs end-to-end via orchestrator environment" {
    export TARGET_DIR="tests/fixtures/compromised-source/npmrc-match"
    export SCAN_DIR="$TEST_OUTPUT_DIR/scan"
    export SCAN_ID="wrapper-test_$(whoami)_$(date +%Y-%m-%d_%H-%M-%S)"
    export COMPROMISED_SOURCES_PATH="$TEST_REGISTRY"

    run bash "$BASH_WRAPPER"

    # Exit 1 expected: critical finding present
    [ "$status" -eq 1 ]
    [ -f "$SCAN_DIR/compromised-source/compromised-source-results.json" ]
    [ -f "$SCAN_DIR/compromised-source/status.json" ]

    run python3 -c "import json; d=json.load(open('$SCAN_DIR/compromised-source/status.json')); print(d['status'])"
    [ "$status" -eq 0 ]
    [[ "$output" == "open" ]]
}
