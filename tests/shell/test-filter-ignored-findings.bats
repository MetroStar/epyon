#!/usr/bin/env bats

# Unit tests for filter-ignored-findings.sh

SCRIPT_DIR="${BATS_TEST_DIRNAME}/../../scripts/shell"
SCRIPT_PATH="${SCRIPT_DIR}/filter-ignored-findings.sh"

@test "filter-ignored-findings.sh exists and is executable" {
    [ -f "$SCRIPT_PATH" ]
    [ -x "$SCRIPT_PATH" ]
}

@test "filter-ignored-findings.sh has proper shebang" {
    head -n 1 "$SCRIPT_PATH" | grep -q "^#!/bin/bash"
}

@test "filter-ignored-findings.sh defines IGNORE_CACHE variable" {
    grep -q "IGNORE_CACHE" "$SCRIPT_PATH"
}

@test "filter-ignored-findings.sh defines SUPPRESSED_LOG variable" {
    grep -q "SUPPRESSED_LOG" "$SCRIPT_PATH"
}

@test "filter-ignored-findings.sh defines is_tool_ignored function" {
    grep -q "is_tool_ignored" "$SCRIPT_PATH"
}

@test "filter-ignored-findings.sh defines is_cve_ignored function" {
    grep -q "is_cve_ignored" "$SCRIPT_PATH"
}

@test "filter-ignored-findings.sh defines is_path_ignored function" {
    grep -q "is_path_ignored" "$SCRIPT_PATH"
}

@test "filter-ignored-findings.sh defines log_suppressed function" {
    grep -q "log_suppressed" "$SCRIPT_PATH"
}

@test "filter-ignored-findings.sh defines init_suppressed_log function" {
    grep -q "init_suppressed_log" "$SCRIPT_PATH"
}

@test "filter-ignored-findings.sh uses jq to query ignore cache" {
    grep -q "jq" "$SCRIPT_PATH"
}

@test "filter-ignored-findings.sh handles missing ignore cache gracefully" {
    grep -q "\-f.*IGNORE_CACHE\|\! -f\|not found\|return 1" "$SCRIPT_PATH"
}

@test "filter-ignored-findings.sh records suppression reason" {
    grep -q "reason\|approved_by\|Approved" "$SCRIPT_PATH"
}

@test "filter-ignored-findings.sh is_tool_ignored returns 1 when cache absent" {
    # Source the script and call is_tool_ignored with no cache present
    IGNORE_CACHE="/tmp/epyon-no-such-cache-$$.json"
    SUPPRESSED_LOG="/tmp/epyon-test-suppressed-$$.log"
    run bash -c "source '$SCRIPT_PATH' && is_tool_ignored 'Trivy'"
    [ "$status" -ne 0 ]
    rm -f "$IGNORE_CACHE" "$SUPPRESSED_LOG"
}

@test "filter-ignored-findings.sh is_cve_ignored returns 1 when cache absent" {
    IGNORE_CACHE="/tmp/epyon-no-such-cache-$$.json"
    SUPPRESSED_LOG="/tmp/epyon-test-suppressed-$$.log"
    run bash -c "source '$SCRIPT_PATH' && is_cve_ignored 'CVE-2024-0001'"
    [ "$status" -ne 0 ]
    rm -f "$IGNORE_CACHE" "$SUPPRESSED_LOG"
}

@test "filter-ignored-findings.sh recognises CVE in cache" {
    local CACHE
    CACHE=$(mktemp)
    cat > "$CACHE" << 'EOF'
{
  "ignores": [
    {
      "type": "cve",
      "value": "CVE-2024-1234",
      "reason": "test suppression",
      "approved_by": "test",
      "expired": false
    }
  ]
}
EOF
    local LOG
    LOG=$(mktemp)

    run bash -c "
        IGNORE_CACHE='$CACHE'
        SUPPRESSED_LOG='$LOG'
        source '$SCRIPT_PATH'
        is_cve_ignored 'CVE-2024-1234'
    "
    [ "$status" -eq 0 ]
    rm -f "$CACHE" "$LOG"
}

@test "filter-ignored-findings.sh does not suppress non-matching CVE" {
    local CACHE
    CACHE=$(mktemp)
    cat > "$CACHE" << 'EOF'
{"ignores": [{"type": "cve", "value": "CVE-2024-9999", "reason": "test", "approved_by": "test"}]}
EOF
    local LOG
    LOG=$(mktemp)

    run bash -c "
        IGNORE_CACHE='$CACHE'
        SUPPRESSED_LOG='$LOG'
        source '$SCRIPT_PATH'
        is_cve_ignored 'CVE-2024-0001'
    "
    [ "$status" -ne 0 ]
    rm -f "$CACHE" "$LOG"
}
