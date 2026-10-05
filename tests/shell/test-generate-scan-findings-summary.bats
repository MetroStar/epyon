#!/usr/bin/env bats

# Unit tests for generate-scan-findings-summary.sh

SCRIPT_DIR="${BATS_TEST_DIRNAME}/../../scripts/shell"
SCRIPT_PATH="${SCRIPT_DIR}/generate-scan-findings-summary.sh"

@test "generate-scan-findings-summary.sh exists and is executable" {
    [ -f "$SCRIPT_PATH" ]
    [ -x "$SCRIPT_PATH" ]
}

@test "generate-scan-findings-summary.sh has proper shebang" {
    head -n 1 "$SCRIPT_PATH" | grep -q "^#!/bin/bash"
}

@test "generate-scan-findings-summary.sh defines color variables" {
    grep -q "RED=\|GREEN=\|YELLOW=" "$SCRIPT_PATH"
}

@test "generate-scan-findings-summary.sh processes scan results" {
    grep -q "scan.*results\|findings" "$SCRIPT_PATH"
}

@test "generate-scan-findings-summary.sh aggregates findings" {
    grep -q "summary\|aggregate\|total" "$SCRIPT_PATH"
}

@test "generate-scan-findings-summary.sh includes severity counts" {
    grep -q "CRITICAL\|HIGH\|MEDIUM\|LOW\|severity" "$SCRIPT_PATH"
}

@test "generate-scan-findings-summary.sh creates summary report" {
    grep -q "summary\|report\|output" "$SCRIPT_PATH"
}

@test "generate-scan-findings-summary.sh processes JSON results" {
    grep -q "json\|jq" "$SCRIPT_PATH"
}

# ── Container vs. app-code classification ────────────────────────────────────
# Trivy/Grype base-image scans (filenames like "trivy-base-<slug>-results.json")
# must be tagged type: "container_vulnerability" with a container_image field
# so findings are never mistaken for application-code CVEs. Filesystem/SBOM
# scans of the same tools must remain untagged (type: "vulnerability").

setup_findings_fixture() {
    local project_root="$1"
    local scan_id="test-scan"
    mkdir -p "${project_root}/scans/${scan_id}/trivy" "${project_root}/scans/${scan_id}/grype"

    cat > "${project_root}/scans/${scan_id}/trivy/trivy-base-python-3.12-slim-bookworm-results.json" <<'JSON'
{
  "Results": [
    {
      "Target": "python:3.12-slim-bookworm (debian 12.15)",
      "Vulnerabilities": [
        {"VulnerabilityID": "CVE-2023-45853", "PkgName": "zlib1g", "InstalledVersion": "1:1.2.13.dfsg-1", "Severity": "CRITICAL", "Description": "base image cve"}
      ]
    }
  ]
}
JSON

    cat > "${project_root}/scans/${scan_id}/trivy/trivy-filesystem-results.json" <<'JSON'
{
  "Results": [
    {
      "Target": "requirements.txt",
      "Vulnerabilities": [
        {"VulnerabilityID": "CVE-2024-11111", "PkgName": "flask", "InstalledVersion": "2.0.0", "Severity": "CRITICAL", "Description": "app code cve"}
      ]
    }
  ]
}
JSON

    cat > "${project_root}/scans/${scan_id}/grype/grype-base-ubuntu-22.04-results.json" <<'JSON'
{
  "matches": [
    {
      "vulnerability": {"id": "CVE-2025-99999", "severity": "Critical", "description": "test", "fix": {"versions": []}},
      "artifact": {"name": "libc6", "version": "2.35", "type": "deb", "locations": [{"path": "/usr/lib/libc6"}]}
    }
  ],
  "source": {"type": "image", "target": {"userInput": "ubuntu:22.04", "tags": ["ubuntu:22.04"]}}
}
JSON

    # Directory-sourced (SBOM/filesystem) Grype scan: source.target is a
    # plain string here, not an object — must not crash the container_image
    # lookup or drop these findings from the summary.
    cat > "${project_root}/scans/${scan_id}/grype/grype-sbom-results.json" <<'JSON'
{
  "matches": [
    {
      "vulnerability": {"id": "CVE-2025-88888", "severity": "Critical", "description": "test", "fix": {"versions": []}},
      "artifact": {"name": "mypkg", "version": "1.0", "type": "python", "locations": [{"path": "/app/mypkg"}]}
    }
  ],
  "source": {"type": "directory", "target": "/app"}
}
JSON
    echo "$scan_id"
}

@test "generate-scan-findings-summary.sh tags Trivy base-image findings as container_vulnerability with the image name" {
    local project_root tmp_target scan_id
    project_root="$(mktemp -d)"
    tmp_target="$(mktemp -d)"
    scan_id="$(setup_findings_fixture "$project_root")"

    run bash -c "'$SCRIPT_PATH' '$scan_id' '$tmp_target' '$project_root'"
    [ "$status" -eq 0 ]

    local summary="${project_root}/scans/${scan_id}/security-findings-summary.json"
    [ -f "$summary" ]

    local base_type base_image
    base_type=$(jq -r '.critical_findings[] | select(.tool == "Trivy-base-python-3.12-slim-bookworm") | .type' "$summary")
    base_image=$(jq -r '.critical_findings[] | select(.tool == "Trivy-base-python-3.12-slim-bookworm") | .container_image' "$summary")
    [ "$base_type" = "container_vulnerability" ]
    [ "$base_image" = "python:3.12-slim-bookworm (debian 12.15)" ]

    rm -rf "$project_root" "$tmp_target"
}

@test "generate-scan-findings-summary.sh leaves Trivy filesystem findings as plain vulnerability (app code)" {
    local project_root tmp_target scan_id
    project_root="$(mktemp -d)"
    tmp_target="$(mktemp -d)"
    scan_id="$(setup_findings_fixture "$project_root")"

    run bash -c "'$SCRIPT_PATH' '$scan_id' '$tmp_target' '$project_root'"
    [ "$status" -eq 0 ]

    local summary="${project_root}/scans/${scan_id}/security-findings-summary.json"
    local fs_type
    fs_type=$(jq -r '.critical_findings[] | select(.tool == "Trivy-filesystem") | .type' "$summary")
    [ "$fs_type" = "vulnerability" ]

    rm -rf "$project_root" "$tmp_target"
}

@test "generate-scan-findings-summary.sh tags Grype base-image findings as container_vulnerability with the image name" {
    local project_root tmp_target scan_id
    project_root="$(mktemp -d)"
    tmp_target="$(mktemp -d)"
    scan_id="$(setup_findings_fixture "$project_root")"

    run bash -c "'$SCRIPT_PATH' '$scan_id' '$tmp_target' '$project_root'"
    [ "$status" -eq 0 ]

    local summary="${project_root}/scans/${scan_id}/security-findings-summary.json"
    local base_type base_image
    base_type=$(jq -r '.critical_findings[] | select(.tool == "Grype-base-ubuntu-22.04") | .type' "$summary")
    base_image=$(jq -r '.critical_findings[] | select(.tool == "Grype-base-ubuntu-22.04") | .container_image' "$summary")
    [ "$base_type" = "container_vulnerability" ]
    [ "$base_image" = "ubuntu:22.04" ]

    rm -rf "$project_root" "$tmp_target"
}

@test "generate-scan-findings-summary.sh does not drop Grype directory-sourced (SBOM) findings when source.target is a string" {
    local project_root tmp_target scan_id
    project_root="$(mktemp -d)"
    tmp_target="$(mktemp -d)"
    scan_id="$(setup_findings_fixture "$project_root")"

    run bash -c "'$SCRIPT_PATH' '$scan_id' '$tmp_target' '$project_root'"
    [ "$status" -eq 0 ]

    local summary="${project_root}/scans/${scan_id}/security-findings-summary.json"
    local sbom_type sbom_present
    sbom_present=$(jq -r '[.critical_findings[] | select(.tool == "Grype-sbom")] | length' "$summary")
    sbom_type=$(jq -r '.critical_findings[] | select(.tool == "Grype-sbom") | .type' "$summary")
    [ "$sbom_present" = "1" ]
    [ "$sbom_type" = "vulnerability" ]

    rm -rf "$project_root" "$tmp_target"
}
