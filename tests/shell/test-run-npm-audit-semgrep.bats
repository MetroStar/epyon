#!/usr/bin/env bats

# Tests for the npm audit and Semgrep SAST layers

SCRIPT_DIR="${BATS_TEST_DIRNAME}/../../scripts/shell"

setup() {
    TMP="$(mktemp -d)"
    export SCAN_DIR="$TMP/scan"
    mkdir -p "$SCAN_DIR"
}

teardown() {
    rm -rf "$TMP"
}

@test "npm audit and semgrep scripts are executable" {
    [ -x "$SCRIPT_DIR/run-npm-audit-scan.sh" ]
    [ -x "$SCRIPT_DIR/run-semgrep-scan.sh" ]
}

@test "npm audit scanner writes an empty result for a target without package.json" {
    command -v npm >/dev/null || skip "npm not installed"
    mkdir -p "$TMP/target"
    run "$SCRIPT_DIR/run-npm-audit-scan.sh" --target "$TMP/target"
    [ "$status" -eq 0 ]
    [ "$(jq '.scan_results | length' "$SCAN_DIR/npm-audit/npm-audit-consolidated-results.json")" -eq 0 ]
}

@test "npm audit scanner never writes a lockfile into the target" {
    command -v npm >/dev/null || skip "npm not installed"
    mkdir -p "$TMP/target"
    echo '{"name":"x","version":"1.0.0","dependencies":{}}' > "$TMP/target/package.json"
    run "$SCRIPT_DIR/run-npm-audit-scan.sh" --target "$TMP/target"
    [ ! -e "$TMP/target/package-lock.json" ]
}

@test "findings summary maps npm-audit and semgrep severities" {
    local scan="zz_bats_$$"
    local dir="${BATS_TEST_DIRNAME}/../../scans/$scan"
    mkdir -p "$dir/npm-audit" "$dir/semgrep"
    cat > "$dir/npm-audit/npm-audit-consolidated-results.json" <<'EOF'
{"scan_results":[{"file":"a/package.json","results":[
 {"id":"GHSA-aaaa-bbbb-cccc","name":"express","v":"4.18.2","severity":"critical","title":"t","advisory":"u","fix_available":true},
 {"id":"GHSA-dddd-eeee-ffff","name":"lodash","v":"4.0.0","severity":"moderate","title":"t","advisory":"u","fix_available":false}]}]}
EOF
    cat > "$dir/semgrep/semgrep-results.json" <<'EOF'
{"results":[{"check_id":"x.sql-injection","path":"app.js","start":{"line":3},"extra":{"severity":"ERROR","message":"m"}}]}
EOF
    run bash "$SCRIPT_DIR/generate-scan-findings-summary.sh" "$scan"
    local summary="$dir/security-findings-summary.json"
    local crit high med
    crit=$(jq '.summary.total_critical' "$summary"); high=$(jq '.summary.total_high' "$summary"); med=$(jq '.summary.total_medium' "$summary")
    rm -rf "$dir"
    [ "$crit" -eq 1 ]
    [ "$high" -eq 1 ]
    [ "$med" -eq 1 ]
}

@test "custom semgrep rules file is present with unique rule ids" {
    local f="${BATS_TEST_DIRNAME}/../../configuration/semgrep-rules/epyon-webapp.yml"
    [ -f "$f" ]
    local ids uniq_ids
    ids=$(grep -c '^  - id: epyon\.' "$f")
    uniq_ids=$(grep '^  - id: epyon\.' "$f" | sort -u | wc -l | tr -d ' ')
    [ "$ids" -gt 20 ]
    [ "$ids" -eq "$uniq_ids" ]
}

@test "semgrep scan runs bundled rules as a separate pass so registry failures can't empty the results" {
    local s="$SCRIPT_DIR/run-semgrep-scan.sh"
    grep -q 'run_pass "\$RESULTS.local" --config "\$rules_path"' "$s"
    grep -q 'run_pass "\$RESULTS.registry"' "$s"
}
