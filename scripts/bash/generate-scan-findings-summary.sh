#!/bin/bash

# Scan-Specific Security Findings Summary Script
# Analyzes security scan results for CRITICAL, HIGH, MEDIUM, and LOW severity findings
# Only processes results from the current scan using SCAN_ID

# Function to generate scan-specific findings summary
generate_scan_findings_summary() {
    local scan_id="$1"
    local target_dir="$2"
    local reports_root="$3"
    
    # Colors for output
    local RED='\033[0;31m'
    local YELLOW='\033[1;33m'
    local BLUE='\033[0;34m'
    local GREEN='\033[0;32m'
    local WHITE='\033[1;37m'
    local NC='\033[0m' # No Color
    
    local OUTPUT_FILE="$reports_root/security-reports/${scan_id}_security-findings-summary.json"
    local OUTPUT_HTML="$reports_root/security-reports/${scan_id}_security-findings-summary.html"
    
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
    
    # Process Grype results
    local grype_files=(
        "$reports_root/grype-reports/${scan_id}_grype-filesystem-results.json"
        "$reports_root/grype-reports/${scan_id}_grype-images-results.json"
        "$reports_root/grype-reports/${scan_id}_grype-base-results.json"
    )
    
    for grype_file in "${grype_files[@]}"; do
        if [[ -f "$grype_file" ]]; then
            local scan_type=$(basename "$grype_file" | sed "s/${scan_id}_grype-//; s/-results.json//")
            tools_analyzed+=("Grype-$scan_type")
            
            # Extract findings by severity
            local critical_vulns=$(jq -r --arg tool "Grype-$scan_type" '
                [.matches[] | select(.vulnerability.severity == "Critical") | {
                    tool: $tool,
                    type: "vulnerability",
                    severity: .vulnerability.severity,
                    id: .vulnerability.id,
                    package: .artifact.name,
                    version: .artifact.version,
                    description: .vulnerability.description,
                    cvss_score: .vulnerability.cvss[0].metrics.baseScore // "N/A",
                    fix_available: (if .vulnerability.fix.versions then "Yes" else "No" end)
                }]' "$grype_file" 2>/dev/null || echo "[]")
            
            local high_vulns=$(jq -r --arg tool "Grype-$scan_type" '
                [.matches[] | select(.vulnerability.severity == "High") | {
                    tool: $tool,
                    type: "vulnerability",
                    severity: .vulnerability.severity,
                    id: .vulnerability.id,
                    package: .artifact.name,
                    version: .artifact.version,
                    description: .vulnerability.description,
                    cvss_score: .vulnerability.cvss[0].metrics.baseScore // "N/A",
                    fix_available: (if .vulnerability.fix.versions then "Yes" else "No" end)
                }]' "$grype_file" 2>/dev/null || echo "[]")
            
            local medium_vulns=$(jq -r --arg tool "Grype-$scan_type" '
                [.matches[] | select(.vulnerability.severity == "Medium") | {
                    tool: $tool,
                    type: "vulnerability",
                    severity: .vulnerability.severity,
                    id: .vulnerability.id,
                    package: .artifact.name,
                    version: .artifact.version,
                    description: .vulnerability.description,
                    cvss_score: .vulnerability.cvss[0].metrics.baseScore // "N/A",
                    fix_available: (if .vulnerability.fix.versions then "Yes" else "No" end)
                }]' "$grype_file" 2>/dev/null || echo "[]")
            
            local low_vulns=$(jq -r --arg tool "Grype-$scan_type" '
                [.matches[] | select(.vulnerability.severity == "Low") | {
                    tool: $tool,
                    type: "vulnerability",
                    severity: .vulnerability.severity,
                    id: .vulnerability.id,
                    package: .artifact.name,
                    version: .artifact.version,
                    description: .vulnerability.description,
                    cvss_score: .vulnerability.cvss[0].metrics.baseScore // "N/A",
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
    
    # Process Trivy results
    local trivy_files=(
        "$reports_root/trivy-reports/${scan_id}_trivy-filesystem-results.json"
        "$reports_root/trivy-reports/${scan_id}_trivy-images-results.json"
        "$reports_root/trivy-reports/${scan_id}_trivy-base-results.json"
    )
    
    for trivy_file in "${trivy_files[@]}"; do
        if [[ -f "$trivy_file" ]]; then
            local scan_type=$(basename "$trivy_file" | sed "s/${scan_id}_trivy-//; s/-results.json//")
            tools_analyzed+=("Trivy-$scan_type")
            
            # Extract findings by severity
            local critical_vulns=$(jq -r --arg tool "Trivy-$scan_type" '
                [.Results[]?.Vulnerabilities[]? | select(.Severity == "CRITICAL") | {
                    tool: $tool,
                    type: "vulnerability",
                    severity: .Severity,
                    id: .VulnerabilityID,
                    package: .PkgName,
                    version: .InstalledVersion,
                    description: .Description,
                    cvss_score: (.CVSS.nvd.V3Score // .CVSS.redhat.V3Score // "N/A"),
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
                    cvss_score: (.CVSS.nvd.V3Score // .CVSS.redhat.V3Score // "N/A"),
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
                    cvss_score: (.CVSS.nvd.V3Score // .CVSS.redhat.V3Score // "N/A"),
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
                    cvss_score: (.CVSS.nvd.V3Score // .CVSS.redhat.V3Score // "N/A"),
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
    
    # Process TruffleHog results (all are treated as High severity)
    local trufflehog_files=(
        "$reports_root/trufflehog-reports/${scan_id}_trufflehog-filesystem-results.json"
        "$reports_root/trufflehog-reports/${scan_id}_trufflehog-images-results.json"
    )
    
    for trufflehog_file in "${trufflehog_files[@]}"; do
        if [[ -f "$trufflehog_file" ]]; then
            local scan_type=$(basename "$trufflehog_file" | sed "s/${scan_id}_trufflehog-//; s/-results.json//")
            tools_analyzed+=("TruffleHog-$scan_type")
            
            local secrets=$(jq -r --arg tool "TruffleHog-$scan_type" '
                [.[] | {
                    tool: $tool,
                    type: "secret",
                    severity: "HIGH",
                    id: .DetectorName,
                    package: (.SourceMetadata.Data.Filesystem.file // "Unknown"),
                    version: "N/A",
                    description: ("Secret detected: " + .DetectorName),
                    cvss_score: "N/A",
                    fix_available: "Manual"
                }]' "$trufflehog_file" 2>/dev/null || echo "[]")
            
            jq --argjson secrets "$secrets" '.high_findings += $secrets' "$OUTPUT_FILE" > "${OUTPUT_FILE}.tmp" && mv "${OUTPUT_FILE}.tmp" "$OUTPUT_FILE"
            
            local secret_count=$(echo "$secrets" | jq 'length' 2>/dev/null || echo "0")
            total_high=$((total_high + secret_count))
        fi
    done
    
    # Process Checkov results
    local checkov_file="$reports_root/checkov-reports/${scan_id}_checkov-results.json"
    if [[ -f "$checkov_file" ]]; then
        tools_analyzed+=("Checkov")
        
        # Checkov severity mapping: CRITICAL->Critical, HIGH->High, MEDIUM->Medium, LOW->Low
        local checkov_findings=$(jq -r --arg tool "Checkov" '
            [(.results.failed_checks // []) | .[] | {
                tool: $tool,
                type: "infrastructure",
                severity: (if .severity == "CRITICAL" then "CRITICAL" 
                          elif .severity == "HIGH" then "HIGH"
                          elif .severity == "MEDIUM" then "MEDIUM"
                          elif .severity == "LOW" then "LOW"
                          else "MEDIUM" end),
                id: .check_id,
                package: .file_path,
                version: "N/A",
                description: .check_name,
                cvss_score: "N/A",
                fix_available: "Manual"
            }]' "$checkov_file" 2>/dev/null || echo "[]")
        
        # Split by severity
        local checkov_critical=$(echo "$checkov_findings" | jq '[.[] | select(.severity == "CRITICAL")]')
        local checkov_high=$(echo "$checkov_findings" | jq '[.[] | select(.severity == "HIGH")]')
        local checkov_medium=$(echo "$checkov_findings" | jq '[.[] | select(.severity == "MEDIUM")]')
        local checkov_low=$(echo "$checkov_findings" | jq '[.[] | select(.severity == "LOW")]')
        
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
    
    # Update summary totals
    jq --argjson critical "$total_critical" --argjson high "$total_high" --argjson medium "$total_medium" --argjson low "$total_low" --argjson tools "$(printf '%s\n' "${tools_analyzed[@]}" | jq -R . | jq -s .)" '
        .summary.total_critical = $critical |
        .summary.total_high = $high |
        .summary.total_medium = $medium |
        .summary.total_low = $low |
        .summary.tools_analyzed = $tools' "$OUTPUT_FILE" > "${OUTPUT_FILE}.tmp" && mv "${OUTPUT_FILE}.tmp" "$OUTPUT_FILE"
    
    # Create symlinks for latest results
    cd "$(dirname "$OUTPUT_FILE")"
    ln -sf "$(basename "$OUTPUT_FILE")" "security-findings-summary.json"
    
    # Display summary
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
    REPORTS_ROOT="${3:-$(dirname "$(dirname "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)")")/reports}"
    
    if [[ -z "$SCAN_ID" ]]; then
        echo "Error: SCAN_ID not provided"
        echo "Usage: $0 <scan_id> [target_dir] [reports_root]"
        exit 1
    fi
    
    generate_scan_findings_summary "$SCAN_ID" "$TARGET_DIR" "$REPORTS_ROOT"
fi