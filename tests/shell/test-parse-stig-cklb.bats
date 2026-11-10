#!/usr/bin/env bats

SCRIPT="${BATS_TEST_DIRNAME}/../../scripts/shell/parse-stig-cklb.py"

@test "parse-stig-cklb rejects XML with DOCTYPE/ENTITY declarations" {
    local f; f="$(mktemp).xml"
    printf '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "b">]><Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1"/>' > "$f"
    run python3 "$SCRIPT" "$f"
    rm -f "$f"
    [ "$status" -ne 0 ]
    [[ "$output" == *"EntitiesForbidden"* ]]
}

@test "parse-stig-cklb still parses the bundled XCCDF STIG" {
    run python3 "$SCRIPT" "${BATS_TEST_DIRNAME}/../../configuration/stigs/U_ASD_STIG_V6R4_Manual-xccdf.xml"
    [ "$status" -eq 0 ]
    [[ "$output" == *"Application Security and Development"* ]]
}
