#!/usr/bin/env bats

# Contract tests for user-facing shell CLIs.

SCRIPT_DIR="${BATS_TEST_DIRNAME}/../../scripts/shell"

CLI_SCRIPTS=(
  "run-epyon-scan-ci.sh"
  "run-target-security-scan.sh"
  "run-trivy-scan.sh"
  "run-grype-scan.sh"
  "run-checkov-scan.sh"
  "check-docker-runtime.sh"
  "check-severity-gate.sh"
  "check-sonar-config.sh"
  "create-jira-tickets.sh"
  "generate-interactive-dashboard.sh"
  "generate-sbom-lineage.sh"
  "generate-scan-manifest.sh"
  "run-athena-sbom.sh"
  "run-sonar-analysis.sh"
  "update-base-images.sh"
  "verify-sbom-hashes.sh"
  "verify-scan-manifest.sh"
)

PRIMARY_SCAN_CLI_SCRIPTS=(
  "run-epyon-scan-ci.sh"
  "run-target-security-scan.sh"
  "run-trivy-scan.sh"
  "run-grype-scan.sh"
  "run-checkov-scan.sh"
)

@test "all user-facing CLI scripts support --help" {
  for script_name in "${CLI_SCRIPTS[@]}"; do
    script_path="${SCRIPT_DIR}/${script_name}"
    [ -f "$script_path" ]

    run bash "$script_path" --help
    [ "$status" -eq 0 ]
    [[ "$output" =~ [Uu]sage: ]]
  done
}

@test "all user-facing CLI scripts support -h" {
  for script_name in "${CLI_SCRIPTS[@]}"; do
    script_path="${SCRIPT_DIR}/${script_name}"
    [ -f "$script_path" ]

    run bash "$script_path" -h
    [ "$status" -eq 0 ]
    [[ "$output" =~ [Uu]sage: ]]
  done
}

@test "primary scan CLIs include examples in help output" {
  for script_name in "${PRIMARY_SCAN_CLI_SCRIPTS[@]}"; do
    script_path="${SCRIPT_DIR}/${script_name}"
    [ -f "$script_path" ]

    run bash "$script_path" --help
    [ "$status" -eq 0 ]
    [[ "$output" =~ [Ee]xamples?: ]]
  done
}

@test "primary scan CLIs return actionable hints on unknown options" {
  for script_name in "${PRIMARY_SCAN_CLI_SCRIPTS[@]}"; do
    script_path="${SCRIPT_DIR}/${script_name}"
    [ -f "$script_path" ]

    run bash "$script_path" --definitely-unknown-flag
    [ "$status" -ne 0 ]
    [[ "$output" =~ [Hh]elp ]] || [[ "$output" =~ [Uu]sage ]]
  done
}
