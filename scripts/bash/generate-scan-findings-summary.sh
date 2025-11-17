#!/bin/bash

# Scan Directory Security Findings Summary Script
# Analyzes security scan results for CRITICAL, HIGH, MEDIUM, and LOW severity findings
# Works with the new scan directory architecture: scans/{SCAN_ID}/{tool}/

# Function to generate scan-specific findings summary from scan directory
generate_scan_findings_summary() {
    local scan_id="$1"
    local target_dir="$2"
    local project_root="$3"
    
    # Colors for output
    local RED='\033[0;31m'
    local YELLOW='\033[1;33m'
    local BLUE='\033[0;34m'
    local GREEN='\033[0;32m'
    local WHITE='\033[1;37m'
    local NC='\033[0m' # No Color
    
    # Determine paths
    local SCAN_DIR="$project_root/scans/$scan_id"
    local OUTPUT_FILE="$SCAN_DIR/security-findings-summary.json"
    local OUTPUT_HTML="$SCAN_DIR/security-findings-summary.html"
    
    # Validate scan directory exists
    if [[ ! -d "$SCAN_DIR" ]]; then
        echo -e "${RED}❌ Scan directory not found: $SCAN_DIR${NC}"
        return 1
    fi
    
    # Create output directory
    mkdir -p "$(dirname "$OUTPUT_FILE")"
    
    echo -e "${BLUE}🚨 Generating Security Findings Summary for Scan: ${scan_id}${NC}"
    
    # Initialize summary object
    cat > "$OUTPUT_FILE" << EOF
{
  "summary": {
    "scan_id": "$scan_id",
    "target_directory": "$target_dir",
    "scan_timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
    "total_critical": 0,
    "total_high": 0,
    "total_medium": 0,
    "total_low": 0,
    "tools_analyzed": [],
    "summary_by_tool": {}
  },
  "critical_findings": [],
  "high_findings": [],
  "medium_findings": [],
  "low_findings": []
}
EOF

    local total_critical=0
    local total_high=0
    local total_medium=0
    local total_low=0
    local tools_analyzed=()
    
    # Process TruffleHog results (scan directory structure)
    local trufflehog_dir="$SCAN_DIR/trufflehog"
    if [[ -d "$trufflehog_dir" ]]; then
        for trufflehog_file in "$trufflehog_dir"/*-results.json; do
            if [[ -f "$trufflehog_file" ]]; then
                tools_analyzed+=("TruffleHog")
                
                # Count secrets by type and verification status (TruffleHog uses NDJSON format)
                local verified_secrets=$(grep -v '"level":' "$trufflehog_file" | jq -s '[.[] | select(.Verified == true)]' 2>/dev/null || echo "[]")
                local postgres_secrets=$(grep -v '"level":' "$trufflehog_file" | jq -s '[.[] | select(.DetectorName == "Postgres")]' 2>/dev/null || echo "[]")
                local private_keys=$(grep -v '"level":' "$trufflehog_file" | jq -s '[.[] | select(.DetectorName == "PrivateKey")]' 2>/dev/null || echo "[]")
                local github_secrets=$(grep -v '"level":' "$trufflehog_file" | jq -s '[.[] | select(.DetectorName == "GitHubOauth2")]' 2>/dev/null || echo "[]")
                
                # Create findings based on secret types and verification
                local verified_count=$(echo "$verified_secrets" | jq 'length' 2>/dev/null || echo "0")
                local postgres_count=$(echo "$postgres_secrets" | jq 'length' 2>/dev/null || echo "0")
                local private_key_count=$(echo "$private_keys" | jq 'length' 2>/dev/null || echo "0")
                local github_count=$(echo "$github_secrets" | jq 'length' 2>/dev/null || echo "0")
                
                # Critical: Verified secrets
                if [[ $verified_count -gt 0 ]]; then
                    local critical_findings=$(echo "$verified_secrets" | jq --arg tool "TruffleHog" --arg scan_id "$scan_id" '
                        [.[] | {
                            tool: $tool,
                            type: "verified_secret",
                            severity: "Critical",
                            detector: .DetectorName,
                            file_path: .SourceMetadata.Data.Filesystem.file,
                            line_number: .SourceMetadata.Data.Filesystem.line,
                            description: ("CRITICAL: VERIFIED " + .DetectorName + " credentials - IMMEDIATE ACTION REQUIRED"),
                            credential_type: .DetectorName,
                            raw_secret: .Raw,
                            redacted_secret: .Redacted,
                            verified: .Verified,
                            verification_error: .VerificationError,
                            scan_location: ("scans/" + $scan_id + "/trufflehog/"),
                            validation_steps: [
                                "1. Check if credentials are still active",
                                "2. Rotate credentials immediately",
                                "3. Review access logs for unauthorized usage",
                                "4. Remove from code and Git history"
                            ],
                            priority: "P0 - Critical",
                            impact: "Full database access with verified working credentials"
                        }]' 2>/dev/null || echo "[]")
                    
                    jq --argjson critical "$critical_findings" '
                        .critical_findings += $critical' "$OUTPUT_FILE" > "${OUTPUT_FILE}.tmp" && mv "${OUTPUT_FILE}.tmp" "$OUTPUT_FILE"
                    
                    total_critical=$((total_critical + verified_count))
                fi
                
                # High: Private keys and database credentials
                if [[ $private_key_count -gt 0 ]]; then
                    local high_findings=$(echo "$private_keys" | jq --arg tool "TruffleHog" --arg scan_id "$scan_id" '
                        [.[] | {
                            tool: $tool,
                            type: "private_key",
                            severity: "High",
                            detector: .DetectorName,
                            file_path: .SourceMetadata.Data.Filesystem.file,
                            line_number: .SourceMetadata.Data.Filesystem.line,
                            description: ("HIGH: Private key detected - " + (.DetectorName // "Unknown type")),
                            key_type: (.DetectorName // "Unknown"),
                            verified: .Verified,
                            verification_error: .VerificationError,
                            scan_location: ("scans/" + $scan_id + "/trufflehog/"),
                            validation_steps: [
                                "1. Identify key purpose and system access",
                                "2. Generate new key pair if still in use",
                                "3. Update systems with new public key",
                                "4. Remove private key from repository",
                                "5. Audit systems for unauthorized access"
                            ],
                            priority: "P1 - High",
                            impact: "Potential unauthorized system access",
                            remediation: "Remove immediately and rotate if active"
                        }]' 2>/dev/null || echo "[]")
                    
                    jq --argjson high "$high_findings" '
                        .high_findings += $high' "$OUTPUT_FILE" > "${OUTPUT_FILE}.tmp" && mv "${OUTPUT_FILE}.tmp" "$OUTPUT_FILE"
                    
                    total_high=$((total_high + private_key_count))
                fi
                
                # Medium: Unverified database credentials
                local unverified_postgres=$(echo "$postgres_secrets" | jq '[.[] | select(.Verified == false)]' 2>/dev/null || echo "[]")
                local unverified_postgres_count=$(echo "$unverified_postgres" | jq 'length' 2>/dev/null || echo "0")
                
                if [[ $unverified_postgres_count -gt 0 ]]; then
                    local medium_findings=$(echo "$unverified_postgres" | jq --arg tool "TruffleHog" --arg scan_id "$scan_id" '
                        [.[] | {
                            tool: $tool,
                            type: "database_credential",
                            severity: "Medium",
                            detector: .DetectorName,
                            file_path: .SourceMetadata.Data.Filesystem.file,
                            line_number: .SourceMetadata.Data.Filesystem.line,
                            description: ("MEDIUM: " + .DetectorName + " credentials found (unverified)"),
                            credential_type: .DetectorName,
                            raw_secret: .Raw,
                            verified: .Verified,
                            verification_error: .VerificationError,
                            scan_location: ("scans/" + $scan_id + "/trufflehog/"),
                            validation_steps: [
                                "1. Test if credentials are valid",
                                "2. Check if database/service exists",
                                "3. Remove if test credentials",
                                "4. Rotate if production credentials"
                            ],
                            priority: "P2 - Medium",
                            impact: "Potential database access if credentials are valid"
                        }]' 2>/dev/null || echo "[]")
                    
                    jq --argjson medium "$medium_findings" '
                        .medium_findings += $medium' "$OUTPUT_FILE" > "${OUTPUT_FILE}.tmp" && mv "${OUTPUT_FILE}.tmp" "$OUTPUT_FILE"
                    
                    total_medium=$((total_medium + unverified_postgres_count))
                fi
                
                # Medium: GitHub OAuth tokens
                if [[ $github_count -gt 0 ]]; then
                    local github_findings=$(echo "$github_secrets" | jq --arg tool "TruffleHog" '
                        [.[] | {
                            tool: $tool,
                            type: "api_token",
                            severity: "Medium",
                            detector: .DetectorName,
                            file: .SourceMetadata.Data.Filesystem.file,
                            line: .SourceMetadata.Data.Filesystem.line,
                            description: "GitHub OAuth2 credentials found",
                            verified: .Verified
                        }]' 2>/dev/null || echo "[]")
                    
                    jq --argjson medium "$github_findings" '
                        .medium_findings += $medium' "$OUTPUT_FILE" > "${OUTPUT_FILE}.tmp" && mv "${OUTPUT_FILE}.tmp" "$OUTPUT_FILE"
                    
                    total_medium=$((total_medium + github_count))
                fi
            fi
        done
    fi
    
    # Process Grype results (scan directory structure)
    local grype_dir="$SCAN_DIR/grype"
    if [[ -d "$grype_dir" ]]; then
        for grype_file in "$grype_dir"/*-results.json; do
            if [[ -f "$grype_file" ]] && [[ $(basename "$grype_file") != *"sbom"* ]]; then
                local scan_type=$(basename "$grype_file" | sed 's/.*grype-//; s/-results.json//')
                tools_analyzed+=("Grype-$scan_type")
                
                # Extract findings by severity
                local critical_vulns=$(jq -r --arg tool "Grype-$scan_type" --arg scan_id "$scan_id" --arg grype_file "$grype_file" '
                    [.matches[]? | select(.vulnerability.severity == "Critical") | {
                        tool: $tool,
                        type: "vulnerability",
                        severity: .vulnerability.severity,
                        vulnerability_id: .vulnerability.id,
                        package_name: .artifact.name,
                        package_version: .artifact.version,
                        package_type: .artifact.type,
                        description: .vulnerability.description,
                        cvss_score: (.vulnerability.cvss[0].metrics.baseScore // "N/A"),
                        fix_available: (if .vulnerability.fix.versions then "Yes" else "No" end),
                        fixed_versions: (.vulnerability.fix.versions // []),
                        scan_location: ("scans/" + $scan_id + "/grype/"),
                        result_file: $grype_file,
                        validation_steps: [
                            "1. Verify package is actually in use",
                            "2. Check if vulnerability affects your usage",
                            "3. Update to fixed version if available",
                            "4. Apply workarounds if no fix available"
                        ],
                        priority: "P0 - Critical",
                        impact: "Critical vulnerability in dependency"
                    }]' "$grype_file" 2>/dev/null || echo "[]")
                
                local high_vulns=$(jq -r --arg tool "Grype-$scan_type" --arg scan_id "$scan_id" --arg grype_file "$grype_file" '
                    [.matches[]? | select(.vulnerability.severity == "High") | {
                        tool: $tool,
                        type: "vulnerability",
                        severity: .vulnerability.severity,
                        vulnerability_id: .vulnerability.id,
                        package_name: .artifact.name,
                        package_version: .artifact.version,
                        package_type: .artifact.type,
                        description: .vulnerability.description,
                        cvss_score: (.vulnerability.cvss[0].metrics.baseScore // "N/A"),
                        fix_available: (if .vulnerability.fix.versions then "Yes" else "No" end),
                        fixed_versions: (.vulnerability.fix.versions // []),
                        scan_location: ("scans/" + $scan_id + "/grype/"),
                        result_file: $grype_file,
                        validation_steps: [
                            "1. Verify package is actually in use",
                            "2. Check if vulnerability affects your usage",
                            "3. Update to fixed version if available",
                            "4. Consider alternative packages if no fix"
                        ],
                        priority: "P1 - High",
                        impact: "High severity vulnerability in dependency"
                    }]' "$grype_file" 2>/dev/null || echo "[]")
                
                local medium_vulns=$(jq -r --arg tool "Grype-$scan_type" '
                    [.matches[]? | select(.vulnerability.severity == "Medium") | {
                        tool: $tool,
                        type: "vulnerability",
                        severity: .vulnerability.severity,
                        id: .vulnerability.id,
                        package: .artifact.name,
                        version: .artifact.version,
                        description: .vulnerability.description,
                        cvss_score: (.vulnerability.cvss[0].metrics.baseScore // "N/A"),
                        fix_available: (if .vulnerability.fix.versions then "Yes" else "No" end)
                    }]' "$grype_file" 2>/dev/null || echo "[]")
                
                local low_vulns=$(jq -r --arg tool "Grype-$scan_type" '
                    [.matches[]? | select(.vulnerability.severity == "Low") | {
                        tool: $tool,
                        type: "vulnerability",
                        severity: .vulnerability.severity,
                        id: .vulnerability.id,
                        package: .artifact.name,
                        version: .artifact.version,
                        description: .vulnerability.description,
                        cvss_score: (.vulnerability.cvss[0].metrics.baseScore // "N/A"),
                        fix_available: (if .vulnerability.fix.versions then "Yes" else "No" end)
                    }]' "$grype_file" 2>/dev/null || echo "[]")
                
                # Add to summary
                jq --argjson critical "$critical_vulns" --argjson high "$high_vulns" --argjson medium "$medium_vulns" --argjson low "$low_vulns" '
                    .critical_findings += $critical |
                    .high_findings += $high |
                    .medium_findings += $medium |
                    .low_findings += $low' "$OUTPUT_FILE" > "${OUTPUT_FILE}.tmp" && mv "${OUTPUT_FILE}.tmp" "$OUTPUT_FILE"
                
                local crit_count=$(echo "$critical_vulns" | jq 'length' 2>/dev/null || echo "0")
                local high_count=$(echo "$high_vulns" | jq 'length' 2>/dev/null || echo "0")
                local med_count=$(echo "$medium_vulns" | jq 'length' 2>/dev/null || echo "0")
                local low_count=$(echo "$low_vulns" | jq 'length' 2>/dev/null || echo "0")
                
                total_critical=$((total_critical + crit_count))
                total_high=$((total_high + high_count))
                total_medium=$((total_medium + med_count))
                total_low=$((total_low + low_count))
            fi
        done
    fi
    
    # Process Trivy results (scan directory structure)
    local trivy_dir="$SCAN_DIR/trivy"
    if [[ -d "$trivy_dir" ]]; then
        for trivy_file in "$trivy_dir"/*-results.json; do
            if [[ -f "$trivy_file" ]]; then
                local scan_type=$(basename "$trivy_file" | sed 's/.*trivy-//; s/-results.json//')
                tools_analyzed+=("Trivy-$scan_type")
                
                # Extract Trivy findings
                local critical_vulns=$(jq -r --arg tool "Trivy-$scan_type" '
                    [.Results[]?.Vulnerabilities[]? | select(.Severity == "CRITICAL") | {
                        tool: $tool,
                        type: "vulnerability",
                        severity: .Severity,
                        id: .VulnerabilityID,
                        package: .PkgName,
                        version: .InstalledVersion,
                        description: .Description,
                        cvss_score: (.CVSS.nvd.V3Score // "N/A"),
                        fix_available: (if .FixedVersion then "Yes" else "No" end)
                    }]' "$trivy_file" 2>/dev/null || echo "[]")
                
                local high_vulns=$(jq -r --arg tool "Trivy-$scan_type" '
                    [.Results[]?.Vulnerabilities[]? | select(.Severity == "HIGH") | {
                        tool: $tool,
                        type: "vulnerability",
                        severity: .Severity,
                        id: .VulnerabilityID,
                        package: .PkgName,
                        version: .InstalledVersion,
                        description: .Description,
                        cvss_score: (.CVSS.nvd.V3Score // "N/A"),
                        fix_available: (if .FixedVersion then "Yes" else "No" end)
                    }]' "$trivy_file" 2>/dev/null || echo "[]")
                
                local medium_vulns=$(jq -r --arg tool "Trivy-$scan_type" '
                    [.Results[]?.Vulnerabilities[]? | select(.Severity == "MEDIUM") | {
                        tool: $tool,
                        type: "vulnerability",
                        severity: .Severity,
                        id: .VulnerabilityID,
                        package: .PkgName,
                        version: .InstalledVersion,
                        description: .Description,
                        cvss_score: (.CVSS.nvd.V3Score // "N/A"),
                        fix_available: (if .FixedVersion then "Yes" else "No" end)
                    }]' "$trivy_file" 2>/dev/null || echo "[]")
                
                local low_vulns=$(jq -r --arg tool "Trivy-$scan_type" '
                    [.Results[]?.Vulnerabilities[]? | select(.Severity == "LOW") | {
                        tool: $tool,
                        type: "vulnerability",
                        severity: .Severity,
                        id: .VulnerabilityID,
                        package: .PkgName,
                        version: .InstalledVersion,
                        description: .Description,
                        cvss_score: (.CVSS.nvd.V3Score // "N/A"),
                        fix_available: (if .FixedVersion then "Yes" else "No" end)
                    }]' "$trivy_file" 2>/dev/null || echo "[]")
                
                # Add to summary
                jq --argjson critical "$critical_vulns" --argjson high "$high_vulns" --argjson medium "$medium_vulns" --argjson low "$low_vulns" '
                    .critical_findings += $critical |
                    .high_findings += $high |
                    .medium_findings += $medium |
                    .low_findings += $low' "$OUTPUT_FILE" > "${OUTPUT_FILE}.tmp" && mv "${OUTPUT_FILE}.tmp" "$OUTPUT_FILE"
                
                local crit_count=$(echo "$critical_vulns" | jq 'length' 2>/dev/null || echo "0")
                local high_count=$(echo "$high_vulns" | jq 'length' 2>/dev/null || echo "0")
                local med_count=$(echo "$medium_vulns" | jq 'length' 2>/dev/null || echo "0")
                local low_count=$(echo "$low_vulns" | jq 'length' 2>/dev/null || echo "0")
                
                total_critical=$((total_critical + crit_count))
                total_high=$((total_high + high_count))
                total_medium=$((total_medium + med_count))
                total_low=$((total_low + low_count))
            fi
        done
    fi
    
    # Process Checkov results (scan directory structure)
    local checkov_dir="$SCAN_DIR/checkov"
    if [[ -d "$checkov_dir" ]]; then
        for checkov_file in "$checkov_dir"/*-results.json; do
            if [[ -f "$checkov_file" ]]; then
                tools_analyzed+=("Checkov")
                
                # Extract Checkov findings - they use different severity classification
                local checkov_failures=$(jq -r --arg tool "Checkov" '
                    [.results.failed_checks[]? | {
                        tool: $tool,
                        type: "iac_misconfiguration",
                        severity: (if .severity == "HIGH" then "High" elif .severity == "MEDIUM" then "Medium" elif .severity == "CRITICAL" then "Critical" else "Low" end),
                        id: .check_id,
                        description: .check_name,
                        file: .file_path,
                        line: .file_line_range,
                        guideline: .guideline
                    }]' "$checkov_file" 2>/dev/null || echo "[]")
                
                # Categorize by severity
                local checkov_critical=$(echo "$checkov_failures" | jq '[.[] | select(.severity == "Critical")]' 2>/dev/null || echo "[]")
                local checkov_high=$(echo "$checkov_failures" | jq '[.[] | select(.severity == "High")]' 2>/dev/null || echo "[]")
                local checkov_medium=$(echo "$checkov_failures" | jq '[.[] | select(.severity == "Medium")]' 2>/dev/null || echo "[]")
                local checkov_low=$(echo "$checkov_failures" | jq '[.[] | select(.severity == "Low")]' 2>/dev/null || echo "[]")
                
                # Add to summary
                jq --argjson critical "$checkov_critical" --argjson high "$checkov_high" --argjson medium "$checkov_medium" --argjson low "$checkov_low" '
                    .critical_findings += $critical |
                    .high_findings += $high |
                    .medium_findings += $medium |
                    .low_findings += $low' "$OUTPUT_FILE" > "${OUTPUT_FILE}.tmp" && mv "${OUTPUT_FILE}.tmp" "$OUTPUT_FILE"
                
                local crit_count=$(echo "$checkov_critical" | jq 'length' 2>/dev/null || echo "0")
                local high_count=$(echo "$checkov_high" | jq 'length' 2>/dev/null || echo "0")
                local med_count=$(echo "$checkov_medium" | jq 'length' 2>/dev/null || echo "0")
                local low_count=$(echo "$checkov_low" | jq 'length' 2>/dev/null || echo "0")
                
                total_critical=$((total_critical + crit_count))
                total_high=$((total_high + high_count))
                total_medium=$((total_medium + med_count))
                total_low=$((total_low + low_count))
            fi
        done
    fi
    
    # Update final summary
    local tools_json=$(printf '%s\n' "${tools_analyzed[@]}" | jq -R . | jq -s .)
    jq --argjson tools "$tools_json" \
       --arg total_critical "$total_critical" \
       --arg total_high "$total_high" \
       --arg total_medium "$total_medium" \
       --arg total_low "$total_low" '
        .summary.tools_analyzed = $tools |
        .summary.total_critical = ($total_critical | tonumber) |
        .summary.total_high = ($total_high | tonumber) |
        .summary.total_medium = ($total_medium | tonumber) |
        .summary.total_low = ($total_low | tonumber)' "$OUTPUT_FILE" > "${OUTPUT_FILE}.tmp" && mv "${OUTPUT_FILE}.tmp" "$OUTPUT_FILE"
    
    echo -e "${GREEN}✅ Security findings summary generated: $(basename "$OUTPUT_FILE")${NC}"
    echo -e "${RED}🔴 Critical: $total_critical${NC}"
    echo -e "${YELLOW}🟡 High: $total_high${NC}"
    echo -e "${BLUE}🔵 Medium: $total_medium${NC}"
    echo -e "${WHITE}⚪ Low: $total_low${NC}"
    echo -e "${BLUE}📊 Tools analyzed: ${#tools_analyzed[@]}${NC}"
    
    return 0
}

# If script is run directly (not sourced)
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    # Extract parameters from environment or arguments
    SCAN_ID="${1:-$SCAN_ID}"
    TARGET_DIR="${2:-$TARGET_DIR}"
    PROJECT_ROOT="${3:-$(dirname "$(dirname "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)")")}"
    
    if [[ -z "$SCAN_ID" ]]; then
        echo "Error: SCAN_ID not provided"
        echo "Usage: $0 <scan_id> [target_dir] [project_root]"
        echo "Example: $0 advana-marketplace-monolith-node_rnelson_2025-11-17_09-00-19"
        exit 1
    fi
    
    generate_scan_findings_summary "$SCAN_ID" "$TARGET_DIR" "$PROJECT_ROOT"
fi