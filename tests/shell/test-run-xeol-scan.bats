#!/usr/bin/env bats

# Unit tests for run-xeol-scan.sh

SCRIPT_DIR="${BATS_TEST_DIRNAME}/../../scripts/shell"
SCRIPT_PATH="${SCRIPT_DIR}/run-xeol-scan.sh"

@test "run-xeol-scan.sh exists and is executable" {
    [ -f "$SCRIPT_PATH" ]
    [ -x "$SCRIPT_PATH" ]
}

@test "run-xeol-scan.sh has proper shebang" {
    head -n 1 "$SCRIPT_PATH" | grep -q "^#!/bin/bash"
}

@test "run-xeol-scan.sh sources scan-directory-template.sh" {
    grep -q "source.*scan-directory-template.sh" "$SCRIPT_PATH"
}

@test "run-xeol-scan.sh contains init_scan_environment function call" {
    grep -q "init_scan_environment" "$SCRIPT_PATH"
}

@test "run-xeol-scan.sh defines color variables" {
    grep -q "RED=" "$SCRIPT_PATH"
    grep -q "GREEN=" "$SCRIPT_PATH"
    grep -q "NC=" "$SCRIPT_PATH"
}

@test "run-xeol-scan.sh uses Docker or native xeol" {
    grep -q "docker" "$SCRIPT_PATH" || grep -q "xeol" "$SCRIPT_PATH"
}

@test "run-xeol-scan.sh uses xeol image" {
    grep -q "noqcks/xeol" "$SCRIPT_PATH"
}

@test "run-xeol-scan.sh captures the real DB update exit code via PIPESTATUS, not tee's" {
    # Regression test: 'cmd | tee -a log; RESULT=\$?' silently masks 'cmd's failure
    # because \$? reflects tee's exit status (almost always 0), not the DB
    # update's. This made 'xeol db update' failures on ephemeral CI runners
    # silently report "updated successfully" while actually scanning with a
    # stale/incomplete EOL database, producing under-reported findings with no
    # visible warning.
    run grep -c 'DB_UPDATE_RESULT=\$?' "$SCRIPT_PATH"
    [ "$status" -ne 0 ] || [ "$output" -eq 0 ]
    run grep -c 'DB_UPDATE_RESULT="\${PIPESTATUS\[0\]}"' "$SCRIPT_PATH"
    [ "$status" -eq 0 ]
    [ "$output" -ge 1 ]
}
