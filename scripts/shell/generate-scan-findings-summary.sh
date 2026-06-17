#!/bin/bash

# Scan Directory Security Findings Summary Script
# Analyzes security scan results for CRITICAL, HIGH, MEDIUM, and LOW severity findings
# Works with the new scan directory architecture: scans/{SCAN_ID}/{tool}/

# Colors for help output
WHITE='\033[1;37m'
NC='\033[0m'

# Help function
show_help() {
    echo -e "${WHITE}Security Findings Summary Generator${NC}"
    echo ""
    echo "Usage: $0 [OPTIONS] <SCAN_ID> <TARGET_DIR> <PROJECT_ROOT>"
    echo ""
    echo "Analyzes security scan results and generates a severity-based findings summary."
    echo "Categorizes findings by CRITICAL, HIGH, MEDIUM, and LOW severity."
    echo ""
    echo "Arguments:"
    echo "  SCAN_ID         The scan identifier (e.g., project_user_2025-01-01_12-00-00)"
    echo "  TARGET_DIR      Original target directory that was scanned"
    echo "  PROJECT_ROOT    Root directory of the security architecture project"
    echo ""
    echo "Options:"
    echo "  -h, --help      Show this help message and exit"
    echo ""
    echo "Output:"
    echo "  Results saved to: scans/{SCAN_ID}/"
    echo "  - security-findings-summary.json    JSON summary"
    echo "  - security-findings-summary.html    HTML summary"
    echo ""
    echo "Summary Contents:"
    echo "  - Total findings by severity"
    echo "  - Findings breakdown by tool"
    echo "  - Critical findings list with details"
    echo "  - High priority findings list"
    echo "  - Medium and low findings counts"
    echo ""
    echo "Examples:"
    echo "  $0 myapp_user_2025-01-01 /path/to/app /path/to/security-arch"
    echo ""
    echo "Notes:"
    echo "  - Usually called automatically by run-target-security-scan.sh"
    echo "  - Can be run manually to regenerate summaries"
    exit 0
}

# Parse arguments
for arg in "$@"; do
    case $arg in
        -h|--help)
            show_help
            ;;
    esac
done

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
    
    # Resolve classification label for JSON/HTML output
    local CLASS_LEVEL
    CLASS_LEVEL="$(echo "${CLASSIFICATION_LEVEL:-INTERNAL}" | tr '[:lower:]' '[:upper:]')"
    local CLASS_LABEL_LOCAL
    case "${CLASS_LEVEL}" in
        NONE|"")         CLASS_LABEL_LOCAL="" ;;
        UNCLASSIFIED)    CLASS_LABEL_LOCAL="UNCLASSIFIED" ;;
        INTERNAL)        CLASS_LABEL_LOCAL="INTERNAL USE ONLY" ;;
        SBU|SENSITIVE)   CLASS_LABEL_LOCAL="SENSITIVE BUT UNCLASSIFIED // SBU" ;;
        CUI)             CLASS_LABEL_LOCAL="CONTROLLED UNCLASSIFIED INFORMATION // CUI" ;;
        FOUO)            CLASS_LABEL_LOCAL="FOR OFFICIAL USE ONLY // FOUO" ;;
        CONFIDENTIAL)    CLASS_LABEL_LOCAL="CONFIDENTIAL" ;;
        SECRET)          CLASS_LABEL_LOCAL="SECRET" ;;
        TOP_SECRET|TS)   CLASS_LABEL_LOCAL="TOP SECRET" ;;
        *)               CLASS_LABEL_LOCAL="${CLASS_LEVEL}" ;;
    esac

    # Initialize summary object
    cat > "$OUTPUT_FILE" << EOF
{
  "classification": "${CLASS_LABEL_LOCAL}",
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
            if [[ -f "$trufflehog_file" ]] && [[ ! -L "$trufflehog_file" ]]; then
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
            if [[ -f "$grype_file" ]] && [[ ! -L "$grype_file" ]]; then
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
                        package_path: ([.artifact.locations[]?.path] | join(", ")),
                        purl: .artifact.purl,
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
                        package_path: ([.artifact.locations[]?.path] | join(", ")),
                        purl: .artifact.purl,
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
                        vulnerability_id: .vulnerability.id,
                        id: .vulnerability.id,
                        package: .artifact.name,
                        package_name: .artifact.name,
                        version: .artifact.version,
                        package_version: .artifact.version,
                        package_type: .artifact.type,
                        package_path: ([.artifact.locations[]?.path] | join(", ")),
                        purl: .artifact.purl,
                        description: .vulnerability.description,
                        cvss_score: (.vulnerability.cvss[0].metrics.baseScore // "N/A"),
                        fix_available: (if .vulnerability.fix.versions then "Yes" else "No" end),
                        fixed_versions: (.vulnerability.fix.versions // [])
                    }]' "$grype_file" 2>/dev/null || echo "[]")
                
                local low_vulns=$(jq -r --arg tool "Grype-$scan_type" '
                    [.matches[]? | select(.vulnerability.severity == "Low") | {
                        tool: $tool,
                        type: "vulnerability",
                        severity: .vulnerability.severity,
                        vulnerability_id: .vulnerability.id,
                        id: .vulnerability.id,
                        package: .artifact.name,
                        package_name: .artifact.name,
                        version: .artifact.version,
                        package_version: .artifact.version,
                        package_type: .artifact.type,
                        package_path: ([.artifact.locations[]?.path] | join(", ")),
                        purl: .artifact.purl,
                        description: .vulnerability.description,
                        cvss_score: (.vulnerability.cvss[0].metrics.baseScore // "N/A"),
                        fix_available: (if .vulnerability.fix.versions then "Yes" else "No" end),
                        fixed_versions: (.vulnerability.fix.versions // [])
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
    
    # Process pip-audit results (scan directory structure)
    # Direct dependency vulnerability scanner complements Grype SBOM-based approach
    local pip_audit_dir="$SCAN_DIR/pip-audit"
    if [[ -d "$pip_audit_dir" ]]; then
        tools_analyzed+=("pip-audit")
        
        # Process consolidated pip-audit results
        local pip_audit_consolidated="$pip_audit_dir/pip-audit-consolidated-results.json"
        if [[ -f "$pip_audit_consolidated" ]]; then
            # Extract findings by severity (pip-audit uses different severity naming)
            # Note: pip-audit doesn't directly provide severity; we infer from fix_versions availability
            
            local pip_audit_vulns=$(jq -r --arg tool "pip-audit" '
                .scan_results[]? | .results[]? | select(. != null) | {
                    tool: $tool,
                    type: "vulnerability",
                    severity: (if .fix_versions and (.fix_versions | length > 0) then "Medium" else "High" end),
                    vulnerability_id: .id,
                    id: .id,
                    package: .name,
                    package_name: .name,
                    version: .v,
                    package_version: .v,
                    package_type: "python",
                    purl: ("pkg:pypi/" + .name + "@" + .v),
                    description: .description,
                    fix_available: (if .fix_versions and (.fix_versions | length > 0) then "Yes" else "No" end),
                    fixed_versions: (.fix_versions // []),
                    published: .published,
                    advisory: .advisory
                }' "$pip_audit_consolidated" 2>/dev/null || echo "[]")
            
            # Categorize by severity
            local pip_critical=$(echo "$pip_audit_vulns" | jq '[.[] | select(.severity == "Critical")]' 2>/dev/null || echo "[]")
            local pip_high=$(echo "$pip_audit_vulns" | jq '[.[] | select(.severity == "High")]' 2>/dev/null || echo "[]")
            local pip_medium=$(echo "$pip_audit_vulns" | jq '[.[] | select(.severity == "Medium")]' 2>/dev/null || echo "[]")
            local pip_low=$(echo "$pip_audit_vulns" | jq '[.[] | select(.severity == "Low")]' 2>/dev/null || echo "[]")
            
            # Add to findings summary
            jq --argjson critical "$pip_critical" --argjson high "$pip_high" --argjson medium "$pip_medium" --argjson low "$pip_low" '
                .critical_findings += $critical |
                .high_findings += $high |
                .medium_findings += $medium |
                .low_findings += $low' "$OUTPUT_FILE" > "${OUTPUT_FILE}.tmp" && mv "${OUTPUT_FILE}.tmp" "$OUTPUT_FILE"
            
            local crit_count=$(echo "$pip_critical" | jq 'length' 2>/dev/null || echo "0")
            local high_count=$(echo "$pip_high" | jq 'length' 2>/dev/null || echo "0")
            local med_count=$(echo "$pip_medium" | jq 'length' 2>/dev/null || echo "0")
            local low_count=$(echo "$pip_low" | jq 'length' 2>/dev/null || echo "0")
            
            total_critical=$((total_critical + crit_count))
            total_high=$((total_high + high_count))
            total_medium=$((total_medium + med_count))
            total_low=$((total_low + low_count))
        fi
    fi
    
    # Process Trivy results (scan directory structure)
    local trivy_dir="$SCAN_DIR/trivy"
    if [[ -d "$trivy_dir" ]]; then
        for trivy_file in "$trivy_dir"/*-results.json; do
            if [[ -f "$trivy_file" ]] && [[ ! -L "$trivy_file" ]]; then
                local scan_type=$(basename "$trivy_file" | sed 's/.*trivy-//; s/-results.json//')
                tools_analyzed+=("Trivy-$scan_type")
                
                # Extract Trivy findings
                local critical_vulns=$(jq -r --arg tool "Trivy-$scan_type" '
                    [.Results[] as $r | $r.Vulnerabilities[]? | select(.Severity == "CRITICAL") | {
                        tool: $tool,
                        type: "vulnerability",
                        severity: .Severity,
                        vulnerability_id: .VulnerabilityID,
                        id: .VulnerabilityID,
                        package: .PkgName,
                        package_name: .PkgName,
                        version: .InstalledVersion,
                        package_version: .InstalledVersion,
                        package_path: ($r.Target // ""),
                        description: .Description,
                        cvss_score: (.CVSS.nvd.V3Score // "N/A"),
                        fix_available: (if .FixedVersion and .FixedVersion != "" then "Yes" else "No" end),
                        fixed_versions: (if .FixedVersion and .FixedVersion != "" then [.FixedVersion] else [] end)
                    }]' "$trivy_file" 2>/dev/null || echo "[]")
                
                local high_vulns=$(jq -r --arg tool "Trivy-$scan_type" '
                    [.Results[] as $r | $r.Vulnerabilities[]? | select(.Severity == "HIGH") | {
                        tool: $tool,
                        type: "vulnerability",
                        severity: .Severity,
                        vulnerability_id: .VulnerabilityID,
                        id: .VulnerabilityID,
                        package: .PkgName,
                        package_name: .PkgName,
                        version: .InstalledVersion,
                        package_version: .InstalledVersion,
                        package_path: ($r.Target // ""),
                        description: .Description,
                        cvss_score: (.CVSS.nvd.V3Score // "N/A"),
                        fix_available: (if .FixedVersion and .FixedVersion != "" then "Yes" else "No" end),
                        fixed_versions: (if .FixedVersion and .FixedVersion != "" then [.FixedVersion] else [] end)
                    }]' "$trivy_file" 2>/dev/null || echo "[]")
                
                local medium_vulns=$(jq -r --arg tool "Trivy-$scan_type" '
                    [.Results[] as $r | $r.Vulnerabilities[]? | select(.Severity == "MEDIUM") | {
                        tool: $tool,
                        type: "vulnerability",
                        severity: .Severity,
                        vulnerability_id: .VulnerabilityID,
                        id: .VulnerabilityID,
                        package: .PkgName,
                        package_name: .PkgName,
                        version: .InstalledVersion,
                        package_version: .InstalledVersion,
                        package_path: ($r.Target // ""),
                        description: .Description,
                        cvss_score: (.CVSS.nvd.V3Score // "N/A"),
                        fix_available: (if .FixedVersion and .FixedVersion != "" then "Yes" else "No" end),
                        fixed_versions: (if .FixedVersion and .FixedVersion != "" then [.FixedVersion] else [] end)
                    }]' "$trivy_file" 2>/dev/null || echo "[]")
                
                local low_vulns=$(jq -r --arg tool "Trivy-$scan_type" '
                    [.Results[] as $r | $r.Vulnerabilities[]? | select(.Severity == "LOW") | {
                        tool: $tool,
                        type: "vulnerability",
                        severity: .Severity,
                        vulnerability_id: .VulnerabilityID,
                        id: .VulnerabilityID,
                        package: .PkgName,
                        package_name: .PkgName,
                        version: .InstalledVersion,
                        package_version: .InstalledVersion,
                        package_path: ($r.Target // ""),
                        description: .Description,
                        cvss_score: (.CVSS.nvd.V3Score // "N/A"),
                        fix_available: (if .FixedVersion and .FixedVersion != "" then "Yes" else "No" end),
                        fixed_versions: (if .FixedVersion and .FixedVersion != "" then [.FixedVersion] else [] end)
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
            if [[ -f "$checkov_file" ]] && [[ ! -L "$checkov_file" ]]; then
                tools_analyzed+=("Checkov")
                
                # Extract Checkov findings. Checkov 3.x outputs an array of per-check-type objects
                # [{check_type, results:{failed_checks:[...]}}, ...]; older versions and the Docker-
                # unavailable placeholder use a single object {results:{failed_checks:[...]}}.
                # We map all failed checks as HIGH severity (IaC misconfigurations are not CVEs).
                local checkov_failures=$(jq -r --arg tool "Checkov" '
                    [(if type == "array" then .[].results.failed_checks[] else .results.failed_checks[]? end) | {
                        tool: $tool,
                        type: "iac_misconfiguration",
                        severity: (if .severity and .severity != null and .severity != "" then (.severity | ascii_upcase | if . == "CRITICAL" then "Critical" elif . == "HIGH" then "High" elif . == "MEDIUM" then "Medium" elif . == "LOW" then "Low" else "High" end) else "High" end),
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
    
    # Process Xeol results — End-of-Life packages → High severity
    local xeol_dir="$SCAN_DIR/xeol"
    if [[ -d "$xeol_dir" ]]; then
        for xeol_file in "$xeol_dir"/*xeol-*.json; do
            if [[ -f "$xeol_file" ]] && [[ ! -L "$xeol_file" ]] && [[ -s "$xeol_file" ]]; then
                local xeol_count
                xeol_count=$(jq '.matches | length' "$xeol_file" 2>/dev/null || echo "0")
                if [[ "$xeol_count" -gt 0 ]]; then
                    tools_analyzed+=("Xeol")
                    local xeol_findings
                    xeol_findings=$(jq -r --arg tool "Xeol" '[
                        .matches[]? |
                        {
                            tool: $tool,
                            type: "eol_package",
                            severity: "High",
                            vulnerability_id: ("EOL-" + (.artifact.name // "unknown") + "-" + (.artifact.version // "unknown")),
                            package_name: (.artifact.name // "N/A"),
                            package_version: (.artifact.version // "N/A"),
                            description: ("End-of-Life package: " + (.artifact.name // "unknown") + " " + (.artifact.version // "") + " — no further security patches"),
                            eol_date: (.cycle.eol // "unknown"),
                            latest_version: (.cycle.latest // "N/A"),
                            file_path: (.artifact.locations[0].path // "N/A")
                        }
                    ]' "$xeol_file" 2>/dev/null || echo "[]")
                    jq --argjson high "$xeol_findings" '
                        .high_findings += $high' "$OUTPUT_FILE" > "${OUTPUT_FILE}.tmp" && mv "${OUTPUT_FILE}.tmp" "$OUTPUT_FILE"
                    total_high=$((total_high + xeol_count))
                fi
            fi
        done
    fi

    # Process ClamAV results — malware/virus detections → Critical severity
    local clamav_dir="$SCAN_DIR/clamav"
    if [[ -d "$clamav_dir" ]]; then
        local clamav_json="$clamav_dir/clamav-results.json"
        if [[ -f "$clamav_json" ]]; then
            local infected_count
            infected_count=$(jq '.infected_files // 0' "$clamav_json" 2>/dev/null || echo "0")
            if [[ "$infected_count" -gt 0 ]]; then
                tools_analyzed+=("ClamAV")
                local clamav_findings
                clamav_findings=$(jq -r --arg tool "ClamAV" '[
                    .detections[]? |
                    {
                        tool: $tool,
                        type: "malware_detection",
                        severity: "Critical",
                        vulnerability_id: ("MALWARE-" + (.signature // "UNKNOWN")),
                        description: ("Malware detected: " + (.signature // "Unknown signature")),
                        file_path: (.file // "N/A"),
                        package_name: (.file // "N/A"),
                        package_version: "N/A"
                    }
                ]' "$clamav_json" 2>/dev/null || echo "[]")
                jq --argjson critical "$clamav_findings" '
                    .critical_findings += $critical' "$OUTPUT_FILE" > "${OUTPUT_FILE}.tmp" && mv "${OUTPUT_FILE}.tmp" "$OUTPUT_FILE"
                total_critical=$((total_critical + infected_count))
            fi
        fi
    fi

    # Process Anchore results — container image CVEs (same format as Grype)
    local anchore_dir="$SCAN_DIR/anchore"
    if [[ -d "$anchore_dir" ]]; then
        local anchore_files=()
        [[ -f "$anchore_dir/anchore-filesystem-results.json" ]] && anchore_files+=("$anchore_dir/anchore-filesystem-results.json")
        for f in "$anchore_dir"/images/*.json; do
            [[ -f "$f" ]] && [[ ! -L "$f" ]] && anchore_files+=("$f")
        done
        for anchore_file in "${anchore_files[@]:-}"; do
            [[ -z "$anchore_file" ]] || [[ ! -f "$anchore_file" ]] && continue
            local anchore_match_count
            anchore_match_count=$(jq '[.matches[]? | select(.vulnerability.severity and .vulnerability.severity != "Negligible")] | length' "$anchore_file" 2>/dev/null || echo "0")
            if [[ "$anchore_match_count" -gt 0 ]]; then
                local scan_type
                scan_type=$(basename "$anchore_file" .json)
                tools_analyzed+=("Anchore-${scan_type}")
                local anchore_findings
                anchore_findings=$(jq -r --arg tool "Anchore" '[
                    .matches[]? |
                    select(.vulnerability.severity and .vulnerability.severity != "Negligible") |
                    {
                        tool: $tool,
                        type: "container_vulnerability",
                        severity: (.vulnerability.severity |
                            if . == "Critical" then "Critical"
                            elif . == "High" then "High"
                            elif . == "Medium" then "Medium"
                            else "Low" end),
                        vulnerability_id: (.vulnerability.id // "N/A"),
                        package_name: (.artifact.name // "N/A"),
                        package_version: (.artifact.version // "N/A"),
                        description: (.vulnerability.description // ("Container image vulnerability: " + (.vulnerability.id // "unknown"))),
                        nvd_url: ((.vulnerability.urls // []) | first // null),
                        fix_versions: (.vulnerability.fix.versions // [])
                    }
                ]' "$anchore_file" 2>/dev/null || echo "[]")
                local a_crit a_high a_med a_low
                a_crit=$(echo "$anchore_findings" | jq '[.[] | select(.severity == "Critical")]' 2>/dev/null || echo "[]")
                a_high=$(echo "$anchore_findings" | jq '[.[] | select(.severity == "High")]' 2>/dev/null || echo "[]")
                a_med=$(echo "$anchore_findings"  | jq '[.[] | select(.severity == "Medium")]' 2>/dev/null || echo "[]")
                a_low=$(echo "$anchore_findings"  | jq '[.[] | select(.severity == "Low")]' 2>/dev/null || echo "[]")
                jq --argjson critical "$a_crit" --argjson high "$a_high" --argjson medium "$a_med" --argjson low "$a_low" '
                    .critical_findings += $critical |
                    .high_findings     += $high |
                    .medium_findings   += $medium |
                    .low_findings      += $low' "$OUTPUT_FILE" > "${OUTPUT_FILE}.tmp" && mv "${OUTPUT_FILE}.tmp" "$OUTPUT_FILE"
                total_critical=$((total_critical + $(echo "$a_crit" | jq 'length' 2>/dev/null || echo 0)))
                total_high=$((total_high         + $(echo "$a_high" | jq 'length' 2>/dev/null || echo 0)))
                total_medium=$((total_medium     + $(echo "$a_med"  | jq 'length' 2>/dev/null || echo 0)))
                total_low=$((total_low           + $(echo "$a_low"  | jq 'length' 2>/dev/null || echo 0)))
            fi
        done
    fi

    # Process Helm results — lint errors → Medium, lint warnings → Low
    local helm_dir="$SCAN_DIR/helm"
    if [[ -d "$helm_dir" ]]; then
        for helm_file in "$helm_dir"/helm-results.json "$helm_dir"/helm-build-results.json; do
            if [[ -f "$helm_file" ]]; then
                local lint_errors lint_warnings
                lint_errors=$(jq '.summary.lint_errors // 0' "$helm_file" 2>/dev/null || echo "0")
                lint_warnings=$(jq '.summary.lint_warnings // 0' "$helm_file" 2>/dev/null || echo "0")
                if [[ "$lint_errors" -gt 0 ]] || [[ "$lint_warnings" -gt 0 ]]; then
                    tools_analyzed+=("Helm")
                    # Build medium findings from per-chart lint errors
                    local helm_medium helm_low
                    helm_medium=$(jq -r --arg tool "Helm" '[
                        .charts[]? | .name as $chart |
                        (.lint_results.errors // [])[] |
                        {
                            tool: $tool,
                            type: "helm_lint_error",
                            severity: "Medium",
                            check_id: ("HELM-ERROR-" + ($chart // "unknown") | ascii_upcase | gsub("[^A-Z0-9-]"; "-")),
                            description: .,
                            file_path: ($chart // "N/A"),
                            package_name: $chart
                        }
                    ]' "$helm_file" 2>/dev/null || echo "[]")
                    helm_low=$(jq -r --arg tool "Helm" '[
                        .charts[]? | .name as $chart |
                        (.lint_results.warnings // [])[] |
                        {
                            tool: $tool,
                            type: "helm_lint_warning",
                            severity: "Low",
                            check_id: ("HELM-WARN-" + ($chart // "unknown") | ascii_upcase | gsub("[^A-Z0-9-]"; "-")),
                            description: .,
                            file_path: ($chart // "N/A"),
                            package_name: $chart
                        }
                    ]' "$helm_file" 2>/dev/null || echo "[]")
                    jq --argjson medium "$helm_medium" --argjson low "$helm_low" '
                        .medium_findings += $medium |
                        .low_findings    += $low' "$OUTPUT_FILE" > "${OUTPUT_FILE}.tmp" && mv "${OUTPUT_FILE}.tmp" "$OUTPUT_FILE"
                    total_medium=$((total_medium + lint_errors))
                    total_low=$((total_low + lint_warnings))
                fi
                break  # only process first matching helm file
            fi
        done
    fi

    # Deduplicate findings to avoid counting the same vulnerability multiple times    echo -e "${CYAN}🔄 Deduplicating findings across tools...${NC}"
    
    # Deduplicate each severity level by creating unique keys and keeping first occurrence
    # Add metadata about which tools detected each finding
    
    jq '
    # Helper function to create unique key for vulnerabilities
    def vuln_key:
        if .vulnerability_id or .id then 
            ((.vulnerability_id // .id) + "|" + (.package_name // .package // "") + "|" + (.package_version // .version // ""))
        elif .detector then
            ((.detector // "") + "|" + (.file_path // .file // "") + "|" + ((.line_number // .line // "unknown") | tostring))
        elif .check_id then
            ((.check_id // "") + "|" + (.file_path // .file // "") + "|" + ((.line_number // "unknown") | tostring))
        else
            ((.type // "unknown") + "|" + (.file_path // .file // "") + "|" + ((.description // "")[0:50] // ""))
        end;
    
    # Deduplicate critical findings
    .critical_findings = (
        .critical_findings | 
        group_by(vuln_key) | 
        map(
            {
                item: .[0],
                detected_by: (map(.tool // "unknown") | unique),
                occurrences: length
            } | 
            .item.detected_by = .detected_by |
            .item.occurrences = .occurrences |
            .item
        )
    ) |
    
    # Deduplicate high findings
    .high_findings = (
        .high_findings | 
        group_by(vuln_key) | 
        map(
            {
                item: .[0],
                detected_by: (map(.tool // "unknown") | unique),
                occurrences: length
            } | 
            .item.detected_by = .detected_by |
            .item.occurrences = .occurrences |
            .item
        )
    ) |
    
    # Deduplicate medium findings
    .medium_findings = (
        .medium_findings | 
        group_by(vuln_key) | 
        map(
            {
                item: .[0],
                detected_by: (map(.tool // "unknown") | unique),
                occurrences: length
            } | 
            .item.detected_by = .detected_by |
            .item.occurrences = .occurrences |
            .item
        )
    ) |
    
    # Deduplicate low findings
    .low_findings = (
        .low_findings | 
        group_by(vuln_key) | 
        map(
            {
                item: .[0],
                detected_by: (map(.tool // "unknown") | unique),
                occurrences: length
            } | 
            .item.detected_by = .detected_by |
            .item.occurrences = .occurrences |
            .item
        )
    )
    ' "$OUTPUT_FILE" > "${OUTPUT_FILE}.tmp" && mv "${OUTPUT_FILE}.tmp" "$OUTPUT_FILE"
    
    # Recalculate totals after deduplication
    total_critical=$(jq '.critical_findings | length' "$OUTPUT_FILE")
    total_high=$(jq '.high_findings | length' "$OUTPUT_FILE")
    total_medium=$(jq '.medium_findings | length' "$OUTPUT_FILE")
    total_low=$(jq '.low_findings | length' "$OUTPUT_FILE")
    
    echo -e "${GREEN}✅ Deduplication complete${NC}"
    echo -e "   ${CYAN}Removed duplicate findings across tools${NC}"
    
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
    echo -e "${RED}🔴 Critical: $total_critical (unique)${NC}"
    echo -e "${YELLOW}🟡 High: $total_high (unique)${NC}"
    echo -e "${BLUE}🔵 Medium: $total_medium (unique)${NC}"
    echo -e "${WHITE}⚪ Low: $total_low (unique)${NC}"
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