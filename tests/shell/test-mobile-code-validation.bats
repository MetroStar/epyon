#!/usr/bin/env bats
# Mobile code scanner validation corpus tests

@test "mobile-code-scanner: validation corpus test suite" {
    python3 tests/validate-mobile-code-scanner.py
}

@test "mobile-code-scanner: detects Category 1A (unsigned/inline) findings" {
    local scan_dir="tests/tmp/mobile-code-cat1a-test"
    mkdir -p "$scan_dir"
    
    python3 scripts/shell/run-mobile-code-scan.py \
        --target tests/fixtures/mobile-code/category-1a \
        --scan-dir "$scan_dir" \
        --app-name test-cat1a
    
    # Should detect: inline JS, Java applet, Flash, ActiveX, VBScript
    local results="$scan_dir/mobile-code-results.json"
    [ -f "$results" ]
    
    # Count critical findings (Category 1A)
    local critical_count=$(python3 -c "import json; d=json.load(open('$results')); print(len([f for f in d.get('findings', []) if f.get('risk_level') == 'critical']))")
    [ "$critical_count" -ge 4 ]  # At least 4 critical findings expected
}

@test "mobile-code-scanner: detects Category 1B (external/signed) findings" {
    local scan_dir="tests/tmp/mobile-code-cat1b-test"
    mkdir -p "$scan_dir"
    
    python3 scripts/shell/run-mobile-code-scan.py \
        --target tests/fixtures/mobile-code/category-1b \
        --scan-dir "$scan_dir" \
        --app-name test-cat1b
    
    local results="$scan_dir/mobile-code-results.json"
    [ -f "$results" ]
    
    # Count high findings (Category 1B)
    local high_count=$(python3 -c "import json; d=json.load(open('$results')); print(len([f for f in d.get('findings', []) if f.get('risk_level') == 'high']))")
    [ "$high_count" -ge 1 ]  # At least 1 high finding expected
}

@test "mobile-code-scanner: detects Category 2 (controlled) findings" {
    local scan_dir="tests/tmp/mobile-code-cat2-test"
    mkdir -p "$scan_dir"
    
    python3 scripts/shell/run-mobile-code-scan.py \
        --target tests/fixtures/mobile-code/category-2 \
        --scan-dir "$scan_dir" \
        --app-name test-cat2
    
    local results="$scan_dir/mobile-code-results.json"
    [ -f "$results" ]
    
    # Count medium findings (Category 2)
    local medium_count=$(python3 -c "import json; d=json.load(open('$results')); print(len([f for f in d.get('findings', []) if f.get('risk_level') == 'medium']))")
    [ "$medium_count" -ge 1 ]  # At least 1 medium finding expected
}

@test "mobile-code-scanner: does NOT flag legitimate static content" {
    local scan_dir="tests/tmp/mobile-code-legitimate-test"
    mkdir -p "$scan_dir"
    
    python3 scripts/shell/run-mobile-code-scan.py \
        --target tests/fixtures/mobile-code/legitimate \
        --scan-dir "$scan_dir" \
        --app-name test-legitimate
    
    local results="$scan_dir/mobile-code-results.json"
    [ -f "$results" ]
    
    # Should have ZERO findings for legitimate content
    local finding_count=$(python3 -c "import json; d=json.load(open('$results')); print(len(d.get('findings', [])))")
    [ "$finding_count" -eq 0 ]
}

@test "mobile-code-scanner: ignores node_modules directory" {
    local scan_dir="tests/tmp/mobile-code-ignored-test"
    mkdir -p "$scan_dir"
    
    python3 scripts/shell/run-mobile-code-scan.py \
        --target tests/fixtures/mobile-code/ignored \
        --scan-dir "$scan_dir" \
        --app-name test-ignored
    
    local results="$scan_dir/mobile-code-results.json"
    [ -f "$results" ]
    
    # Should have ZERO findings (node_modules should be skipped)
    local finding_count=$(python3 -c "import json; d=json.load(open('$results')); print(len(d.get('findings', [])))")
    [ "$finding_count" -eq 0 ]
}

@test "mobile-code-scanner: scan metadata includes diagnostic info" {
    local scan_dir="tests/tmp/mobile-code-metadata-test"
    mkdir -p "$scan_dir"
    
    python3 scripts/shell/run-mobile-code-scan.py \
        --target tests/fixtures/mobile-code \
        --scan-dir "$scan_dir" \
        --app-name test-metadata
    
    local results="$scan_dir/mobile-code-results.json"
    [ -f "$results" ]
    
    # Check that scan_metadata exists and has required fields
    python3 -c "import json, sys; d=json.load(open('$results')); m=d.get('scan_metadata', {}); sys.exit(0 if all(k in m for k in ['scan_date', 'target_directory', 'scanner_version']) else 1)"
}
