#!/usr/bin/env bats

# Unit tests for get-scan-metrics.sh

SCRIPT_DIR="${BATS_TEST_DIRNAME}/../../scripts/shell"
SCRIPT_PATH="${SCRIPT_DIR}/get-scan-metrics.sh"

@test "get-scan-metrics.sh exists and is executable" {
    [ -f "$SCRIPT_PATH" ]
    [ -x "$SCRIPT_PATH" ]
}

@test "get-scan-metrics.sh has proper shebang" {
    head -n 1 "$SCRIPT_PATH" | grep -q "^#!/bin/bash"
}

@test "get-scan-metrics.sh defines color variables" {
    grep -q "RED=\|GREEN=\|YELLOW=" "$SCRIPT_PATH"
}

@test "get-scan-metrics.sh has --help flag" {
    grep -q "\-\-help\|-h" "$SCRIPT_PATH"
}

@test "get-scan-metrics.sh displays help and exits cleanly" {
    run "$SCRIPT_PATH" --help
    [ "$status" -eq 0 ]
    echo "$output" | grep -q "get-scan-metrics\|Cross-Scan\|Usage"
}

@test "get-scan-metrics.sh help mentions --from-github option" {
    run "$SCRIPT_PATH" --help
    [ "$status" -eq 0 ]
    echo "$output" | grep -q "\-\-from-github"
}

@test "get-scan-metrics.sh help mentions --target filter" {
    run "$SCRIPT_PATH" --help
    [ "$status" -eq 0 ]
    echo "$output" | grep -q "\-\-target"
}

@test "get-scan-metrics.sh help mentions --since filter" {
    run "$SCRIPT_PATH" --help
    [ "$status" -eq 0 ]
    echo "$output" | grep -q "\-\-since"
}

@test "get-scan-metrics.sh help mentions --output option" {
    run "$SCRIPT_PATH" --help
    [ "$status" -eq 0 ]
    echo "$output" | grep -q "\-\-output"
}

@test "get-scan-metrics.sh help mentions --repos option" {
    run "$SCRIPT_PATH" --help
    [ "$status" -eq 0 ]
    echo "$output" | grep -q "\-\-repos"
}

@test "get-scan-metrics.sh help mentions --no-cache option" {
    run "$SCRIPT_PATH" --help
    [ "$status" -eq 0 ]
    echo "$output" | grep -q "\-\-no-cache"
}

@test "get-scan-metrics.sh help mentions --fetch-legacy option" {
    run "$SCRIPT_PATH" --help
    [ "$status" -eq 0 ]
    echo "$output" | grep -q "\-\-fetch-legacy"
}

@test "get-scan-metrics.sh rejects unknown flags" {
    run "$SCRIPT_PATH" --this-flag-does-not-exist
    [ "$status" -ne 0 ]
}

@test "get-scan-metrics.sh requires jq" {
    grep -q "jq" "$SCRIPT_PATH"
}

@test "get-scan-metrics.sh searches scans and baseline/scans directories" {
    grep -q "baseline/scans\|baseline.*scans" "$SCRIPT_PATH"
}

@test "get-scan-metrics.sh reads scan-metadata.json" {
    grep -q "scan-metadata.json" "$SCRIPT_PATH"
}

@test "get-scan-metrics.sh reads security-findings-summary.json" {
    grep -q "security-findings-summary.json" "$SCRIPT_PATH"
}

@test "get-scan-metrics.sh sanitizes N/A values before jq parsing" {
    grep -q "N/A\|N\\\\/A" "$SCRIPT_PATH"
}

@test "get-scan-metrics.sh extracts critical high medium low counts" {
    grep -q "total_critical\|total_high\|total_medium\|total_low" "$SCRIPT_PATH"
}

@test "get-scan-metrics.sh deduplicates tools_analyzed list" {
    grep -q "unique\|sort" "$SCRIPT_PATH"
}

@test "get-scan-metrics.sh produces JSON output with trend array" {
    grep -q 'trend' "$SCRIPT_PATH"
}

@test "get-scan-metrics.sh includes generated_at timestamp in output" {
    grep -q "generated_at\|todate" "$SCRIPT_PATH"
}

@test "get-scan-metrics.sh supports --quiet mode" {
    grep -q "quiet\|QUIET" "$SCRIPT_PATH"
}

@test "get-scan-metrics.sh produces scan-history.json by default" {
    grep -q "scan-history.json" "$SCRIPT_PATH"
}

@test "get-scan-metrics.sh uses a temp file for dedup (bash-3 compat)" {
    grep -q "_SEEN_IDS_FILE\|mktemp" "$SCRIPT_PATH"
}

@test "get-scan-metrics.sh auto-detects repo from git remote when --from-github used" {
    grep -q "remote get-url\|remote.*origin" "$SCRIPT_PATH"
}

@test "get-scan-metrics.sh caches GitHub artifact rows locally" {
    grep -q "github-cache\|GH_CACHE_DIR" "$SCRIPT_PATH"
}

@test "get-scan-metrics.sh extracts scan-metrics.json from artifact zip" {
    grep -q "scan-metrics.json" "$SCRIPT_PATH"
}

@test "get-scan-metrics.sh supports --fetch-legacy for older full-scan zips" {
    grep -q "fetch.legacy\|FETCH_LEGACY" "$SCRIPT_PATH"
}

@test "get-scan-metrics.sh runs successfully against local scan directories" {
    # Create a minimal scan directory with required JSON files
    local TMP_SCANS
    TMP_SCANS=$(mktemp -d)
    local SCAN_DIR="$TMP_SCANS/myapp_testuser_2026-01-01_00-00-00"
    mkdir -p "$SCAN_DIR"

    cat > "$SCAN_DIR/scan-metadata.json" << 'EOF'
{
  "scan_id": "myapp_testuser_2026-01-01_00-00-00",
  "target_name": "myapp",
  "scan_type": "full",
  "scan_user": "testuser",
  "scan_timestamp": "2026-01-01T00:00:00Z",
  "scan_timestamp_local": "2026-01-01 00:00:00 UTC"
}
EOF

    cat > "$SCAN_DIR/security-findings-summary.json" << 'EOF'
{
  "summary": {
    "scan_id": "myapp_testuser_2026-01-01_00-00-00",
    "total_critical": 2,
    "total_high": 5,
    "total_medium": 10,
    "total_low": 3,
    "tools_analyzed": ["Trivy", "Grype"]
  }
}
EOF

    local OUT="$TMP_SCANS/out.json"
    run "$SCRIPT_PATH" --scans-dir "$TMP_SCANS" --quiet --output "$OUT"
    [ "$status" -eq 0 ]
    [ -f "$OUT" ]

    # Verify JSON structure
    run jq -e '.total_scans == 1' "$OUT"
    [ "$status" -eq 0 ]

    run jq -e '.totals.critical == 2' "$OUT"
    [ "$status" -eq 0 ]

    run jq -e '.totals.high == 5' "$OUT"
    [ "$status" -eq 0 ]

    run jq -e '.trend[0].scan_id == "myapp_testuser_2026-01-01_00-00-00"' "$OUT"
    [ "$status" -eq 0 ]

    rm -rf "$TMP_SCANS"
}

@test "get-scan-metrics.sh handles scan-metadata.json with N/A values" {
    local TMP_SCANS
    TMP_SCANS=$(mktemp -d)
    local SCAN_DIR="$TMP_SCANS/iris_ci_2026-03-14_11-00-00"
    mkdir -p "$SCAN_DIR"

    # Simulate the invalid JSON produced by CI (total_files: N/A)
    cat > "$SCAN_DIR/scan-metadata.json" << 'EOF'
{
  "scan_id": "iris_ci_2026-03-14_11-00-00",
  "target_name": "iris",
  "scan_type": "full",
  "scan_user": "ci",
  "scan_timestamp": "2026-03-14T11:00:00Z",
  "scan_timestamp_local": "2026-03-14 11:00:00 UTC",
  "file_statistics": {
    "total_files": N/A,
    "javascript_typescript": 0
  }
}
EOF

    local OUT="$TMP_SCANS/out.json"
    run "$SCRIPT_PATH" --scans-dir "$TMP_SCANS" --quiet --output "$OUT"
    [ "$status" -eq 0 ]
    [ -f "$OUT" ]

    run jq -e '.total_scans == 1' "$OUT"
    [ "$status" -eq 0 ]

    rm -rf "$TMP_SCANS"
}

@test "get-scan-metrics.sh --target filter excludes non-matching scans" {
    local TMP_SCANS
    TMP_SCANS=$(mktemp -d)

    for app in alpha beta; do
        local SCAN_DIR="$TMP_SCANS/${app}_user_2026-01-01_00-00-00"
        mkdir -p "$SCAN_DIR"
        cat > "$SCAN_DIR/scan-metadata.json" << EOF
{
  "scan_id": "${app}_user_2026-01-01_00-00-00",
  "target_name": "${app}",
  "scan_type": "full",
  "scan_user": "user",
  "scan_timestamp": "2026-01-01T00:00:00Z",
  "scan_timestamp_local": ""
}
EOF
    done

    local OUT="$TMP_SCANS/out.json"
    run "$SCRIPT_PATH" --scans-dir "$TMP_SCANS" --target alpha --quiet --output "$OUT"
    [ "$status" -eq 0 ]

    run jq -e '.total_scans == 1 and .trend[0].target_name == "alpha"' "$OUT"
    [ "$status" -eq 0 ]

    rm -rf "$TMP_SCANS"
}

@test "get-scan-metrics.sh --since filter excludes older scans" {
    local TMP_SCANS
    TMP_SCANS=$(mktemp -d)

    # Old scan (should be excluded)
    local OLD_DIR="$TMP_SCANS/app_user_2025-06-01_00-00-00"
    mkdir -p "$OLD_DIR"
    cat > "$OLD_DIR/scan-metadata.json" << 'EOF'
{
  "scan_id": "app_user_2025-06-01_00-00-00",
  "target_name": "app",
  "scan_type": "full",
  "scan_user": "user",
  "scan_timestamp": "2025-06-01T00:00:00Z",
  "scan_timestamp_local": ""
}
EOF

    # New scan (should be included)
    local NEW_DIR="$TMP_SCANS/app_user_2026-01-15_00-00-00"
    mkdir -p "$NEW_DIR"
    cat > "$NEW_DIR/scan-metadata.json" << 'EOF'
{
  "scan_id": "app_user_2026-01-15_00-00-00",
  "target_name": "app",
  "scan_type": "full",
  "scan_user": "user",
  "scan_timestamp": "2026-01-15T00:00:00Z",
  "scan_timestamp_local": ""
}
EOF

    local OUT="$TMP_SCANS/out.json"
    run "$SCRIPT_PATH" --scans-dir "$TMP_SCANS" --since 2026-01-01 --quiet --output "$OUT"
    [ "$status" -eq 0 ]

    run jq -e '.total_scans == 1 and .trend[0].scan_id == "app_user_2026-01-15_00-00-00"' "$OUT"
    [ "$status" -eq 0 ]

    rm -rf "$TMP_SCANS"
}

@test "get-scan-metrics.sh cumulative totals sum all scans" {
    local TMP_SCANS
    TMP_SCANS=$(mktemp -d)

    for i in 01 02; do
        local SCAN_DIR="$TMP_SCANS/app_user_2026-01-${i}_00-00-00"
        mkdir -p "$SCAN_DIR"
        cat > "$SCAN_DIR/scan-metadata.json" << EOF
{
  "scan_id": "app_user_2026-01-${i}_00-00-00",
  "target_name": "app",
  "scan_type": "full",
  "scan_user": "user",
  "scan_timestamp": "2026-01-${i}T00:00:00Z",
  "scan_timestamp_local": ""
}
EOF
        cat > "$SCAN_DIR/security-findings-summary.json" << 'EOF'
{
  "summary": {
    "total_critical": 1,
    "total_high": 2,
    "total_medium": 3,
    "total_low": 4,
    "tools_analyzed": ["Trivy"]
  }
}
EOF
    done

    local OUT="$TMP_SCANS/out.json"
    run "$SCRIPT_PATH" --scans-dir "$TMP_SCANS" --quiet --output "$OUT"
    [ "$status" -eq 0 ]

    run jq -e '.totals.critical == 2 and .totals.high == 4' "$OUT"
    [ "$status" -eq 0 ]

    rm -rf "$TMP_SCANS"
}

@test "get-scan-metrics.sh trend array is sorted oldest-first" {
    local TMP_SCANS
    TMP_SCANS=$(mktemp -d)

    for ts in "2026-03-01T00:00:00Z" "2026-01-01T00:00:00Z" "2026-02-01T00:00:00Z"; do
        local date_part
        date_part=$(echo "$ts" | cut -c1-10 | tr '-' '-')
        local SCAN_DIR="$TMP_SCANS/app_u_${date_part//-/_}_00-00-00"
        # Use a sanitized directory name
        local sane_date="${date_part//-/}"
        mkdir -p "$TMP_SCANS/app_u_${sane_date}_000000"
        cat > "$TMP_SCANS/app_u_${sane_date}_000000/scan-metadata.json" << EOF
{
  "scan_id": "app_u_${sane_date}_000000",
  "target_name": "app",
  "scan_type": "full",
  "scan_user": "u",
  "scan_timestamp": "${ts}",
  "scan_timestamp_local": ""
}
EOF
    done

    local OUT="$TMP_SCANS/out.json"
    run "$SCRIPT_PATH" --scans-dir "$TMP_SCANS" --quiet --output "$OUT"
    [ "$status" -eq 0 ]

    # First element should have the earliest timestamp
    run jq -e '.trend[0].scan_timestamp <= .trend[1].scan_timestamp' "$OUT"
    [ "$status" -eq 0 ]

    rm -rf "$TMP_SCANS"
}
