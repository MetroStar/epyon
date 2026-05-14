#!/usr/bin/env bats

# Unit tests for run-picklescan.sh (Layer 14 — Pickle/Serialization Safety)

SCRIPT_DIR="${BATS_TEST_DIRNAME}/../../scripts/shell"
SCRIPT_PATH="${SCRIPT_DIR}/run-picklescan.sh"

@test "run-picklescan.sh exists and is executable" {
    [ -f "$SCRIPT_PATH" ]
    [ -x "$SCRIPT_PATH" ]
}

@test "run-picklescan.sh has proper shebang" {
    head -n 1 "$SCRIPT_PATH" | grep -q "^#!/bin/bash"
}

@test "run-picklescan.sh sources scan-directory-template.sh" {
    grep -q "source.*scan-directory-template.sh" "$SCRIPT_PATH"
}

@test "run-picklescan.sh calls init_scan_environment" {
    grep -q "init_scan_environment" "$SCRIPT_PATH"
}

@test "run-picklescan.sh calls init_scan_environment with picklescan tool name" {
    grep -q 'init_scan_environment.*picklescan\|init_scan_environment "picklescan"' "$SCRIPT_PATH"
}

@test "run-picklescan.sh supports --help flag" {
    grep -q "\-h|\-\-help\|show_help" "$SCRIPT_PATH"
}

@test "run-picklescan.sh has a show_help function" {
    grep -q "^show_help()" "$SCRIPT_PATH"
}

@test "run-picklescan.sh supports PICKLESCAN_AUTO_INSTALL environment variable" {
    grep -q "PICKLESCAN_AUTO_INSTALL" "$SCRIPT_PATH"
}

@test "run-picklescan.sh supports PICKLESCAN_PIP_SPEC environment variable" {
    grep -q "PICKLESCAN_PIP_SPEC" "$SCRIPT_PATH"
}

@test "run-picklescan.sh handles missing TARGET_DIR by writing skipped JSON" {
    grep -q "skipped" "$SCRIPT_PATH"
    grep -q "picklescan-results.json" "$SCRIPT_PATH"
}

@test "run-picklescan.sh writes picklescan-results.json output file" {
    grep -q "picklescan-results.json" "$SCRIPT_PATH"
}

@test "run-picklescan.sh writes picklescan-raw.json output file" {
    grep -q "picklescan-raw.json" "$SCRIPT_PATH"
}

@test "run-picklescan.sh writes a scan log file" {
    grep -q "picklescan.log" "$SCRIPT_PATH"
}

@test "run-picklescan.sh targets .pkl files" {
    grep -q "\.pkl" "$SCRIPT_PATH"
}

@test "run-picklescan.sh targets .pt and .pth files" {
    grep -q "\.pt\b\|\.pth" "$SCRIPT_PATH"
}

@test "run-picklescan.sh targets .bin files" {
    grep -q "\.bin" "$SCRIPT_PATH"
}

@test "run-picklescan.sh targets .ckpt files" {
    grep -q "\.ckpt" "$SCRIPT_PATH"
}

@test "run-picklescan.sh targets .h5 and .hdf5 files" {
    grep -q "\.h5\b\|\.hdf5" "$SCRIPT_PATH"
}

@test "run-picklescan.sh targets .npy and .npz files" {
    grep -q "\.npy\|\.npz" "$SCRIPT_PATH"
}

@test "run-picklescan.sh targets .joblib files" {
    grep -q "\.joblib" "$SCRIPT_PATH"
}

@test "run-picklescan.sh falls back to python3 -m picklescan" {
    grep -q "python3 -m picklescan" "$SCRIPT_PATH"
}

@test "run-picklescan.sh auto-installs picklescan via pip when missing" {
    grep -q "pip install\|pip3 install" "$SCRIPT_PATH"
}

@test "run-picklescan.sh records infected_files in output JSON" {
    grep -q "infected_files" "$SCRIPT_PATH"
}

@test "run-picklescan.sh records flagged_count in output JSON" {
    grep -q "flagged_count" "$SCRIPT_PATH"
}

@test "run-picklescan.sh records file_count in output JSON" {
    grep -q "file_count" "$SCRIPT_PATH"
}

@test "run-picklescan.sh records status field in output JSON" {
    grep -q '"status"' "$SCRIPT_PATH"
}

@test "run-picklescan.sh records a skipped status when TARGET_DIR is missing" {
    grep -q '"status": "skipped"' "$SCRIPT_PATH"
}

@test "run-picklescan.sh identifies Layer 14 in comments or output" {
    grep -q "Layer 14\|layer 14\|layer-14" "$SCRIPT_PATH"
}
