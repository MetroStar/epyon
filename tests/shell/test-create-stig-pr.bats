#!/usr/bin/env bats

# Tests for create-stig-pr.sh (publishes STIG review records to docs/stig-reviews/)

SCRIPT_DIR="${BATS_TEST_DIRNAME}/../../scripts/shell"
SCRIPT_PATH="${SCRIPT_DIR}/create-stig-pr.sh"

setup() {
    TMP="$(mktemp -d)"
    mkdir -p "$TMP/target" "$TMP/scan/stig-reviews-asd"
    git -C "$TMP/target" init -q
    unset GITHUB_TOKEN GH_PAT SKIP_STIG_PR
    export EPYON_STIG_FORMAT=etk
}

teardown() {
    rm -rf "$TMP"
}

@test "create-stig-pr.sh passes bash -n" {
    run bash -n "$SCRIPT_PATH"
    [ "$status" -eq 0 ]
}

@test "create-stig-pr.sh publishes docs/stig-reviews and never writes stig-findings.md" {
    grep -q "docs/stig-reviews" "$SCRIPT_PATH"
    grep -q "stig_records.py" "$SCRIPT_PATH"
    ! grep -q 'TARGET_FILE="\$TARGET_DIR/stig-findings.md"' "$SCRIPT_PATH"
    ! grep -q "git add stig-findings.md" "$SCRIPT_PATH"
}

@test "create-stig-pr.sh keeps the branch naming and skip switch" {
    grep -q 'BRANCH_NAME="stig-update-\${BRANCH_DATE}"' "$SCRIPT_PATH"
    grep -q "SKIP_STIG_PR" "$SCRIPT_PATH"
}

@test "create-stig-pr.sh exits 0 when SKIP_STIG_PR=true" {
    SKIP_STIG_PR=true run "$SCRIPT_PATH" --target "$TMP/target" --scan-dir "$TMP/scan" --app-name demo
    [ "$status" -eq 0 ]
    [[ "$output" == *"SKIP_STIG_PR=true"* ]]
}

@test "create-stig-pr.sh soft-fails without a token" {
    run "$SCRIPT_PATH" --target "$TMP/target" --scan-dir "$TMP/scan" --app-name demo
    [ "$status" -eq 0 ]
    [[ "$output" == *"GITHUB_TOKEN or GH_PAT not set"* ]]
    [ ! -d "$TMP/target/docs/stig-reviews" ]
}

@test "create-stig-pr.sh soft-fails when the scan has no records" {
    rmdir "$TMP/scan/stig-reviews-asd"
    GITHUB_TOKEN=x run "$SCRIPT_PATH" --target "$TMP/target" --scan-dir "$TMP/scan" --app-name demo
    [ "$status" -eq 0 ]
    [[ "$output" == *"No stig-reviews-*/ records found"* ]]
}

@test "stig_records.py publish writes docs/stig-reviews and leaves docs/stig-findings.md alone" {
    mkdir -p "$TMP/target/docs"
    echo manual > "$TMP/target/docs/stig-findings.md"
    printf '# V-1\n\n- **Reviewed:** 2026-10-21 by Epyon (no AI key configured)\n' > "$TMP/scan/stig-reviews-asd/v-1.md"
    run python3 "${SCRIPT_DIR}/stig_records.py" publish --scan-dir "$TMP/scan" --target "$TMP/target"
    [ "$status" -eq 0 ]
    [ -f "$TMP/target/docs/stig-reviews/v-1.md" ]
    [ ! -f "$TMP/target/stig-findings.md" ]
    [ "$(cat "$TMP/target/docs/stig-findings.md")" = "manual" ]
}
