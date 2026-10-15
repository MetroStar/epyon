#!/usr/bin/env bats

# Unit tests for create-jira-tickets.sh

SCRIPT_DIR="${BATS_TEST_DIRNAME}/../../scripts/shell"
SCRIPT_PATH="${SCRIPT_DIR}/create-jira-tickets.sh"
WORKFLOW_PATH="${BATS_TEST_DIRNAME}/../../.github/workflows/epyon-scan.yml"

@test "create-jira-tickets.sh exists and is executable" {
    [ -f "$SCRIPT_PATH" ]
    [ -x "$SCRIPT_PATH" ]
}

@test "create-jira-tickets.sh has proper shebang" {
    head -n 1 "$SCRIPT_PATH" | grep -q "^#!/usr/bin/env bash\|^#!/bin/bash"
}

@test "create-jira-tickets.sh uses set -euo pipefail" {
    grep -q "set -euo pipefail" "$SCRIPT_PATH"
}

@test "create-jira-tickets.sh documents JIRA_URL environment variable" {
    grep -q "JIRA_URL" "$SCRIPT_PATH"
}

@test "create-jira-tickets.sh documents FINDINGS_FILE environment variable" {
    grep -q "FINDINGS_FILE" "$SCRIPT_PATH"
}

@test "create-jira-tickets.sh documents PROJECT_KEY environment variable" {
    grep -q "PROJECT_KEY" "$SCRIPT_PATH"
}

@test "create-jira-tickets.sh documents AUTH environment variable" {
    grep -q "AUTH" "$SCRIPT_PATH"
}

@test "create-jira-tickets.sh documents REPO_NAME environment variable" {
    grep -q "REPO_NAME" "$SCRIPT_PATH"
}

@test "create-jira-tickets.sh handles critical severity tier" {
    grep -q "epyon-critical\|critical_findings\|CRITICAL_COUNT" "$SCRIPT_PATH"
}

@test "create-jira-tickets.sh handles high severity tier" {
    grep -q "epyon-high\|high_findings\|HIGH_COUNT" "$SCRIPT_PATH"
}

@test "create-jira-tickets.sh handles medium severity tier" {
    grep -q "epyon-medium\|medium_findings\|MEDIUM_COUNT" "$SCRIPT_PATH"
}

@test "create-jira-tickets.sh handles low severity tier" {
    grep -q "epyon-low\|low_findings\|LOW_COUNT" "$SCRIPT_PATH"
}

@test "create-jira-tickets.sh uses curl for Jira REST API calls" {
    grep -q "curl" "$SCRIPT_PATH"
}

@test "create-jira-tickets.sh uses jq to build ticket payload" {
    grep -q "jq" "$SCRIPT_PATH"
}

@test "create-jira-tickets.sh writes payload to temp file for safe delivery" {
    grep -q "/tmp/jira_payload.json" "$SCRIPT_PATH"
}

@test "create-jira-tickets.sh deduplicates tickets by checking for existing open tickets" {
    grep -q "find_existing_jira_ticket\|existing_key" "$SCRIPT_PATH"
}

@test "create-jira-tickets.sh validates Jira project accessibility before creating tickets" {
    grep -q "project/${PROJECT_KEY}\|rest/api/3/project" "$SCRIPT_PATH" || \
    grep -q 'rest/api/3/project' "$SCRIPT_PATH"
}

@test "create-jira-tickets.sh embeds ticket key into GitHub issue body for dedup tracking" {
    grep -q "epyon-jira-\|store_jira_key_in_github" "$SCRIPT_PATH"
}

@test "create-jira-tickets.sh uses python3 for ADF body construction" {
    grep -q "python3" "$SCRIPT_PATH"
}

@test "create-jira-tickets.sh writes output to GITHUB_STEP_SUMMARY" {
    grep -q "GITHUB_STEP_SUMMARY" "$SCRIPT_PATH"
}

@test "create-jira-tickets.sh defaults ISSUE_TYPE to Bug" {
    grep -q 'ISSUE_TYPE.*:-.*Bug\|ISSUE_TYPE:-Bug' "$SCRIPT_PATH"
}

@test "create-jira-tickets.sh applies epyon and security labels to all tickets" {
    grep -q '"epyon".*"security"\|epyon.*security' "$SCRIPT_PATH"
}

@test "create-jira-tickets.sh includes RUN_URL in ticket description" {
    grep -q "RUN_URL" "$SCRIPT_PATH"
}

@test "create-jira-tickets.sh includes GITHUB_TOKEN for issue body read and dedup" {
    grep -q "GITHUB_TOKEN" "$SCRIPT_PATH"
}

@test "create-jira-tickets.sh CVE ticket body includes a CVE Details section" {
    grep -q '"CVE Details"' "$SCRIPT_PATH"
}

@test "create-jira-tickets.sh CVE ticket body includes CVSS score and vector" {
    grep -q "CVSS score/vector" "$SCRIPT_PATH"
}

@test "create-jira-tickets.sh CVE ticket body includes a Definition of Done section" {
    grep -q '"Definition of Done"' "$SCRIPT_PATH"
}

@test "build_cve_adf_body emits CVE Details, Acceptance Criteria, and Definition of Done headings with CVSS data" {
    cat > "${BATS_TEST_TMPDIR}/findings.json" <<'EOF'
[
  {"vulnerability_id": "CVE-2026-42198", "package_name": "pgjdbc", "package_version": "42.5.5",
   "fixed_version": "42.7.11", "tool": "Grype", "description": "pgjdbc: Unbounded PBKDF2 iterations",
   "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2026-42198", "cvss_score": 7.5,
   "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", "cisa_kev": false}
]
EOF
    run bash -c '
      set -euo pipefail
      RUN_URL="https://example.com/run/1"
      REPO_NAME="acme/widgets"
      JIRA_URL="https://acme.atlassian.net"
      '"$(sed -n '/^build_cve_adf_body() {/,/^}/p' "$SCRIPT_PATH")"'
      build_cve_adf_body "'"${BATS_TEST_TMPDIR}"'/findings.json" "CVE-2026-42198" "critical" ""
    '
    [ "$status" -eq 0 ]
    echo "$output" > "${BATS_TEST_TMPDIR}/adf.json"
    run python3 -c "
import json
d = json.load(open('${BATS_TEST_TMPDIR}/adf.json'))
headings = [b['content'][0]['text'] for b in d['content'] if b.get('type') == 'heading']
assert headings == ['CVE Details', 'Acceptance Criteria', 'Definition of Done'], headings
text = json.dumps(d)
assert '7.5' in text
assert 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H' in text
assert '42.7.11' in text
print('OK')
"
    [ "$status" -eq 0 ]
    [[ "$output" == *"OK"* ]]
}

@test "reusable workflow marks Jira ticket creation input deprecated and ignored" {
    grep -q "Deprecated and ignored; Jira tickets require manual review" "$WORKFLOW_PATH"
}

@test "reusable workflow never invokes the Jira ticket creation script" {
    ! grep -q "create-jira-tickets.sh" "$WORKFLOW_PATH"
}

@test "reusable workflow does not forward an automatic Jira creation flag" {
    ! grep -q "CREATE_JIRA_TICKETS" "$WORKFLOW_PATH"
}
