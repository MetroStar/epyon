#!/usr/bin/env bats

# Unit tests for enrich-findings.sh

SCRIPT_DIR="${BATS_TEST_DIRNAME}/../../scripts/shell"
SCRIPT_PATH="${SCRIPT_DIR}/enrich-findings.sh"

@test "enrich-findings.sh exists and is executable" {
    [ -f "$SCRIPT_PATH" ]
    [ -x "$SCRIPT_PATH" ]
}

@test "enrich-findings.sh has proper shebang" {
    head -n 1 "$SCRIPT_PATH" | grep -q "^#!/bin/bash\|^#!/usr/bin/env bash"
}

@test "enrich-findings.sh defines color variables" {
    grep -q "RED=\|GREEN=\|CYAN=" "$SCRIPT_PATH"
}

@test "enrich-findings.sh accepts SCAN_DIR argument" {
    grep -q "SCAN_DIR" "$SCRIPT_PATH"
}

@test "enrich-findings.sh exits with error when security-findings-summary.json is missing" {
    grep -q "security-findings-summary.json" "$SCRIPT_PATH"
}

@test "enrich-findings.sh requires python3" {
    grep -q "python3" "$SCRIPT_PATH"
}

@test "enrich-findings.sh requires curl" {
    grep -q "curl" "$SCRIPT_PATH"
}

@test "enrich-findings.sh fetches CISA KEV catalog" {
    grep -q "cisa.gov\|known_exploited_vulnerabilities\|KEV_URL\|KEV_CACHE" "$SCRIPT_PATH"
}

@test "enrich-findings.sh supports NVD_API_KEY environment variable" {
    grep -q "NVD_API_KEY" "$SCRIPT_PATH"
}

@test "enrich-findings.sh supports dry-run mode" {
    grep -q "DRY_RUN\|dry.run\|--dry-run" "$SCRIPT_PATH"
}

@test "enrich-findings.sh supports QUIET mode" {
    grep -q "QUIET" "$SCRIPT_PATH"
}

@test "enrich-findings.sh auto-detects latest scan directory when no SCAN_DIR given" {
    grep -q "ls -td.*scans\|LATEST.*scans\|head -1" "$SCRIPT_PATH"
}

@test "enrich-findings.sh exits with error when no scan directory can be found" {
    grep -q "No scan directory\|no scan\|SCAN_DIR.*not found\|LATEST.*-z" "$SCRIPT_PATH"
}

@test "enrich-findings.sh validates findings contain CVE-format identifiers" {
    grep -q "CVE_RE\|CVE-\|cve_id\|CVE_ID" "$SCRIPT_PATH"
}

@test "enrich-findings.sh queries NVD for CVE enrichment data" {
    grep -q "nvd\|nvd_api\|NVD\|services.nvd.nist.gov" "$SCRIPT_PATH"
}

@test "enrich-findings.sh caches NVD lookups to avoid duplicate API calls" {
    grep -q "nvd_cache\|cache\[" "$SCRIPT_PATH"
}

@test "enrich-findings.sh flags KEV entries that indicate ransomware usage" {
    grep -q "ransomware" "$SCRIPT_PATH"
}

@test "enrich-findings.sh records required_action from KEV catalog" {
    grep -q "required_action" "$SCRIPT_PATH"
}

@test "enrich-findings.sh enriches findings with CWE identifiers" {
    grep -q "CWE-\|cwe" "$SCRIPT_PATH"
}

@test "enrich-findings.sh writes enriched output back to the findings file" {
    grep -q "security-findings-summary.json" "$SCRIPT_PATH"
    grep -q "write\|output\|>\|json.dump\|json\.dump" "$SCRIPT_PATH"
}

@test "enrich-findings.sh uses a rate-limit delay between NVD API calls" {
    grep -q "sleep\|DELAY\|rate" "$SCRIPT_PATH"
}
