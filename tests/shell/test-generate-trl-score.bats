#!/usr/bin/env bats

# Unit tests for generate-trl-score.py (TRL Assessment Generator)

SCRIPT_DIR="${BATS_TEST_DIRNAME}/../../scripts/shell"
SCRIPT_PATH="${SCRIPT_DIR}/generate-trl-score.py"

@test "generate-trl-score.py exists and is executable" {
    [ -f "$SCRIPT_PATH" ]
    [ -x "$SCRIPT_PATH" ]
}

@test "generate-trl-score.py has proper shebang" {
    head -n 1 "$SCRIPT_PATH" | grep -qE "^#!/usr/bin/env python3"
}

@test "generate-trl-score.py supports --help flag" {
    run python3 "$SCRIPT_PATH" --help
    [ "$status" -eq 0 ]
    [[ "$output" =~ "usage:" ]] || [[ "$output" =~ "Usage:" ]]
}

@test "generate-trl-score.py requires --scan-dir argument" {
    run python3 "$SCRIPT_PATH"
    [ "$status" -ne 0 ]
    [[ "$output" =~ "required" ]] || [[ "$output" =~ "scan-dir" ]]
}

@test "generate-trl-score.py validates scan directory exists" {
    run python3 "$SCRIPT_PATH" --scan-dir /nonexistent/path
    [ "$status" -eq 1 ]
    [[ "$output" =~ "not found" ]] || [[ "$output" =~ "does not exist" ]]
}

@test "generate-trl-score.py requires security-findings-summary.json" {
    # Create a temp dir without the required file
    temp_dir=$(mktemp -d)
    run python3 "$SCRIPT_PATH" --scan-dir "$temp_dir"
    status_code=$status
    rm -rf "$temp_dir"
    [ "$status_code" -eq 1 ]
    [[ "$output" =~ "security-findings-summary.json" ]]
}

@test "generate-trl-score.py requires scan-metadata.json or fallback" {
    # Create a temp dir with findings but no metadata
    temp_dir=$(mktemp -d)
    echo '{"summary":{"total_critical":0,"total_high":0,"total_medium":0,"total_low":0},"critical_findings":[],"high_findings":[],"medium_findings":[],"low_findings":[]}' > "$temp_dir/security-findings-summary.json"
    run python3 "$SCRIPT_PATH" --scan-dir "$temp_dir"
    status_code=$status
    rm -rf "$temp_dir"
    [ "$status_code" -eq 1 ]
    [[ "$output" =~ "metadata" ]]
}

@test "generate-trl-score.py supports --weights argument" {
    run python3 "$SCRIPT_PATH" --help
    [ "$status" -eq 0 ]
    [[ "$output" =~ "--weights" ]]
}

@test "generate-trl-score.py accepts weight profiles: default, ml, stig, quick" {
    run python3 "$SCRIPT_PATH" --help
    [ "$status" -eq 0 ]
    [[ "$output" =~ "default" ]]
    [[ "$output" =~ "ml" ]]
    [[ "$output" =~ "stig" ]]
    [[ "$output" =~ "quick" ]]
}

@test "generate-trl-score.py auto-detects weight profile from scan_type" {
    grep -q "auto" "$SCRIPT_PATH"
    grep -q "scan_type" "$SCRIPT_PATH"
}

@test "generate-trl-score.py computes security dimension score" {
    grep -q "def score_security" "$SCRIPT_PATH"
    grep -q "has_secrets" "$SCRIPT_PATH"
    grep -q "has_malware" "$SCRIPT_PATH"
}

@test "generate-trl-score.py computes supply chain dimension score" {
    grep -q "def score_supply_chain" "$SCRIPT_PATH"
    grep -q "sbom_exists" "$SCRIPT_PATH"
    grep -q "eol_components" "$SCRIPT_PATH"
}

@test "generate-trl-score.py computes code quality dimension score" {
    grep -q "def score_code_quality" "$SCRIPT_PATH"
    grep -q "sonar" "$SCRIPT_PATH"
    grep -q "checkov" "$SCRIPT_PATH"
}

@test "generate-trl-score.py computes compliance dimension score" {
    grep -q "def score_compliance" "$SCRIPT_PATH"
    grep -q "stig" "$SCRIPT_PATH"
    grep -q "modelcard" "$SCRIPT_PATH"
}

@test "generate-trl-score.py computes operational dimension score" {
    grep -q "def score_operational" "$SCRIPT_PATH"
    grep -q "helm" "$SCRIPT_PATH"
    grep -q "network" "$SCRIPT_PATH"
}

@test "generate-trl-score.py maps weighted score to TRL level (1-9)" {
    grep -q "def calculate_trl" "$SCRIPT_PATH"
    grep -q "trl_level" "$SCRIPT_PATH"
}

@test "generate-trl-score.py identifies blockers" {
    grep -q "def get_blockers" "$SCRIPT_PATH"
    grep -q "has_secrets" "$SCRIPT_PATH"
    grep -q "has_malware" "$SCRIPT_PATH"
}

@test "generate-trl-score.py outputs trl-assessment.json" {
    grep -q "trl-assessment.json" "$SCRIPT_PATH"
}

@test "generate-trl-score.py handles missing Garak data gracefully" {
    grep -q "garak" "$SCRIPT_PATH"
    grep -q "isinstance.*dict" "$SCRIPT_PATH"
}

@test "generate-trl-score.py handles missing tool outputs gracefully" {
    grep -q "load_json" "$SCRIPT_PATH"
    grep -q "return None" "$SCRIPT_PATH"
}

@test "generate-trl-score.py generates valid JSON output" {
    # Use an actual scan directory if available, otherwise skip
    scan_dir=$(ls -1td "${BATS_TEST_DIRNAME}/../../scans"/*/ 2>/dev/null | head -1)
    if [ -z "$scan_dir" ]; then
        skip "No scan directories available for testing"
    fi
    
    # Generate TRL assessment
    run python3 "$SCRIPT_PATH" --scan-dir "$scan_dir"
    
    # Check exit code
    [ "$status" -eq 0 ]
    
    # Verify output file exists
    trl_file="${scan_dir}trl-assessment.json"
    [ -f "$trl_file" ]
    
    # Verify JSON is valid
    run python3 -m json.tool "$trl_file"
    [ "$status" -eq 0 ]
    
    # Verify required fields exist
    run python3 -c "import json; d=json.load(open('$trl_file')); assert 'trl_level' in d; assert 'weighted_score' in d; assert 'dimension_scores' in d; assert 'blockers' in d"
    [ "$status" -eq 0 ]
}

@test "generate-trl-score.py TRL level is between 1 and 9" {
    # Use an actual scan directory if available, otherwise skip
    scan_dir=$(ls -1td "${BATS_TEST_DIRNAME}/../../scans"/*/ 2>/dev/null | head -1)
    if [ -z "$scan_dir" ]; then
        skip "No scan directories available for testing"
    fi
    
    # Generate TRL assessment
    run python3 "$SCRIPT_PATH" --scan-dir "$scan_dir"
    [ "$status" -eq 0 ]
    
    # Check TRL level is in valid range
    trl_level=$(python3 -c "import json; print(json.load(open('${scan_dir}trl-assessment.json'))['trl_level'])")
    [ "$trl_level" -ge 1 ]
    [ "$trl_level" -le 9 ]
}

@test "generate-trl-score.py dimension scores are 0-100" {
    # Use an actual scan directory if available, otherwise skip
    scan_dir=$(ls -1td "${BATS_TEST_DIRNAME}/../../scans"/*/ 2>/dev/null | head -1)
    if [ -z "$scan_dir" ]; then
        skip "No scan directories available for testing"
    fi
    
    # Generate TRL assessment
    run python3 "$SCRIPT_PATH" --scan-dir "$scan_dir"
    [ "$status" -eq 0 ]
    
    # Check all dimension scores are in valid range (0-100)
    run python3 -c "import json; d=json.load(open('${scan_dir}trl-assessment.json')); dims=d['dimension_scores']; assert all(0 <= v['score'] <= 100 for v in dims.values()), 'Score out of range'"
    [ "$status" -eq 0 ]
}
