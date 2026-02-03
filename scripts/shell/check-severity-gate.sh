#!/bin/bash

# Severity Gate Check Script
# Checks scan results for critical/high severity findings and fails build if threshold exceeded

# Colors for output
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

# Configuration from environment variables
FAIL_ON_CRITICAL="${FAIL_ON_CRITICAL:-true}"
FAIL_ON_HIGH="${FAIL_ON_HIGH:-false}"
WARNING_ONLY="${WARNING_ONLY:-false}"
SCAN_DIR="${SCAN_DIR:-}"

if [[ -z "$SCAN_DIR" || ! -d "$SCAN_DIR" ]]; then
    echo -e "${RED}❌ Error: SCAN_DIR not set or directory doesn't exist${NC}"
    echo "SCAN_DIR value: '$SCAN_DIR'"
    echo "Listing workspace contents:"
    ls -la . || true
    exit 1
fi

echo ""
echo -e "${CYAN}============================================${NC}"
echo -e "${CYAN}🚦 Security Severity Gate Check${NC}"
echo -e "${CYAN}============================================${NC}"
echo -e "${CYAN}Scan Directory: $SCAN_DIR${NC}"
echo -e "${CYAN}Fail on Critical: $FAIL_ON_CRITICAL${NC}"
echo -e "${CYAN}Fail on High: $FAIL_ON_HIGH${NC}"
echo -e "${CYAN}Warning Only Mode: $WARNING_ONLY${NC}"
echo ""

TOTAL_CRITICAL=0
TOTAL_HIGH=0
TOTAL_MEDIUM=0
TOTAL_LOW=0
ISSUES_FOUND=false

# Check Grype results
GRYPE_FILE=$(find "$SCAN_DIR/grype" -name "*grype*results.json" -o -name "*grype*sbom*.json" 2>/dev/null | head -1)
if [[ -f "$GRYPE_FILE" ]]; then
    echo -e "${CYAN}📊 Checking Grype results...${NC}"
    GRYPE_CRITICAL=$(jq -r '[.matches[]? | select(.vulnerability.severity=="Critical")] | length' "$GRYPE_FILE" 2>/dev/null || echo "0")
    GRYPE_HIGH=$(jq -r '[.matches[]? | select(.vulnerability.severity=="High")] | length' "$GRYPE_FILE" 2>/dev/null || echo "0")
    GRYPE_MEDIUM=$(jq -r '[.matches[]? | select(.vulnerability.severity=="Medium")] | length' "$GRYPE_FILE" 2>/dev/null || echo "0")
    GRYPE_LOW=$(jq -r '[.matches[]? | select(.vulnerability.severity=="Low")] | length' "$GRYPE_FILE" 2>/dev/null || echo "0")
    
    echo "  Critical: $GRYPE_CRITICAL | High: $GRYPE_HIGH | Medium: $GRYPE_MEDIUM | Low: $GRYPE_LOW"
    TOTAL_CRITICAL=$((TOTAL_CRITICAL + GRYPE_CRITICAL))
    TOTAL_HIGH=$((TOTAL_HIGH + GRYPE_HIGH))
    TOTAL_MEDIUM=$((TOTAL_MEDIUM + GRYPE_MEDIUM))
    TOTAL_LOW=$((TOTAL_LOW + GRYPE_LOW))
else
    echo -e "${YELLOW}⚠️  Grype results not found in: $SCAN_DIR/grype/${NC}"
fi

# Check Trivy results
TRIVY_FILE=$(find "$SCAN_DIR/trivy" -name "*trivy*results.json" 2>/dev/null | head -1)
if [[ -f "$TRIVY_FILE" ]]; then
    echo -e "${CYAN}📊 Checking Trivy results...${NC}"
    TRIVY_CRITICAL=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "CRITICAL")] | length' "$TRIVY_FILE" 2>/dev/null || echo 0)
    TRIVY_HIGH=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "HIGH")] | length' "$TRIVY_FILE" 2>/dev/null || echo 0)
    TRIVY_MEDIUM=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "MEDIUM")] | length' "$TRIVY_FILE" 2>/dev/null || echo 0)
    TRIVY_LOW=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "LOW")] | length' "$TRIVY_FILE" 2>/dev/null || echo 0)
    
    echo "  Critical: $TRIVY_CRITICAL | High: $TRIVY_HIGH | Medium: $TRIVY_MEDIUM | Low: $TRIVY_LOW"
    TOTAL_CRITICAL=$((TOTAL_CRITICAL + TRIVY_CRITICAL))
    TOTAL_HIGH=$((TOTAL_HIGH + TRIVY_HIGH))
    TOTAL_MEDIUM=$((TOTAL_MEDIUM + TRIVY_MEDIUM))
    TOTAL_LOW=$((TOTAL_LOW + TRIVY_LOW))
else
    echo -e "${YELLOW}⚠️  Trivy results not found in: $SCAN_DIR/trivy/${NC}"
fi

# Check TruffleHog secrets
TRUFFLEHOG_FILE=$(find "$SCAN_DIR/trufflehog" -name "*trufflehog*results.json" 2>/dev/null | head -1)
if [[ -f "$TRUFFLEHOG_FILE" ]]; then
    echo -e "${CYAN}📊 Checking TruffleHog results...${NC}"
    # Count array elements if it's an array, otherwise return 0
    TRUFFLEHOG_SECRETS=$(jq 'if type=="array" then length else 0 end' "$TRUFFLEHOG_FILE" 2>/dev/null || echo "0")
    echo "  Secrets found: $TRUFFLEHOG_SECRETS"
    if [[ "$TRUFFLEHOG_SECRETS" =~ ^[0-9]+$ ]] && [[ $TRUFFLEHOG_SECRETS -gt 0 ]]; then
        # Treat all secrets as Critical
        TOTAL_CRITICAL=$((TOTAL_CRITICAL + TRUFFLEHOG_SECRETS))
    fi
else
    echo -e "${YELLOW}⚠️  TruffleHog results not found in: $SCAN_DIR/trufflehog/${NC}"
fi

# Check Checkov IaC issues
CHECKOV_FILE=$(find "$SCAN_DIR/checkov" -name "results_json.json" -o -name "*checkov*results.json" 2>/dev/null | head -1)
if [[ -f "$CHECKOV_FILE" ]]; then
    echo -e "${CYAN}📊 Checking Checkov results...${NC}"
    CHECKOV_FAILED=$(jq -r '.summary.failed // 0' "$CHECKOV_FILE" 2>/dev/null || echo "0")
    echo "  Failed checks: $CHECKOV_FAILED"
    if [[ $CHECKOV_FAILED -gt 0 ]]; then
        # Treat failed IaC checks as High severity
        TOTAL_HIGH=$((TOTAL_HIGH + CHECKOV_FAILED))
    fi
else
    echo -e "${YELLOW}⚠️  Checkov results not found in: $SCAN_DIR/checkov/${NC}"
fi

echo ""
echo -e "${CYAN}============================================${NC}"
echo -e "${CYAN}📊 Total Security Findings${NC}"
echo -e "${CYAN}============================================${NC}"
echo -e "🔴 Critical: ${RED}$TOTAL_CRITICAL${NC}"
echo -e "🟠 High: ${YELLOW}$TOTAL_HIGH${NC}"
echo -e "🟡 Medium: $TOTAL_MEDIUM"
echo -e "🟢 Low: $TOTAL_LOW"
echo ""

# Determine if build should fail
EXIT_CODE=0
FAILURE_REASONS=()

# Check if warning-only mode is enabled
if [[ "$WARNING_ONLY" == "true" ]]; then
    echo -e "${YELLOW}⚠️  Warning Only Mode: Build will not fail regardless of findings${NC}"
    if [[ $TOTAL_CRITICAL -gt 0 || $TOTAL_HIGH -gt 0 ]]; then
        FAILURE_REASONS+=("## ⚠️ Warning Only Mode - Vulnerabilities Detected")
        FAILURE_REASONS+=("")
        FAILURE_REASONS+=("**Note:** Build configured to report but not fail on security findings.")
        FAILURE_REASONS+=("")
    fi
elif [[ "$FAIL_ON_CRITICAL" == "true" && $TOTAL_CRITICAL -gt 0 ]]; then
    echo -e "${RED}❌ Build Gate Failed: $TOTAL_CRITICAL critical severity findings detected${NC}"
    echo -e "${RED}   Policy: FAIL_ON_CRITICAL=true${NC}"
    ISSUES_FOUND=true
    EXIT_CODE=1
    
    # Collect details about critical findings
    FAILURE_REASONS+=("## 🔴 Critical Severity Findings ($TOTAL_CRITICAL)")
    FAILURE_REASONS+=("")
    
    if [[ -f "$GRYPE_FILE" && $GRYPE_CRITICAL -gt 0 ]]; then
        FAILURE_REASONS+=("### Grype Vulnerabilities ($GRYPE_CRITICAL critical)")
        FAILURE_REASONS+=("\`\`\`")
        jq -r '.matches[]? | select(.vulnerability.severity=="Critical") | "CVE: \(.vulnerability.id) | Package: \(.artifact.name)@\(.artifact.version) | Severity: \(.vulnerability.severity)"' "$GRYPE_FILE" 2>/dev/null | head -20 >> /tmp/severity-gate-summary.txt || true
        FAILURE_REASONS+=("$(cat /tmp/severity-gate-summary.txt)")
        FAILURE_REASONS+=("\`\`\`")
        FAILURE_REASONS+=("")
        rm -f /tmp/severity-gate-summary.txt
    fi
    
    if [[ -f "$TRIVY_FILE" && $TRIVY_CRITICAL -gt 0 ]]; then
        FAILURE_REASONS+=("### Trivy Vulnerabilities ($TRIVY_CRITICAL critical)")
        FAILURE_REASONS+=("\`\`\`")
        jq -r '.Results[]?.Vulnerabilities[]? | select(.Severity == "CRITICAL") | "CVE: \(.VulnerabilityID) | Package: \(.PkgName)@\(.InstalledVersion) | Title: \(.Title)"' "$TRIVY_FILE" 2>/dev/null | head -20 >> /tmp/severity-gate-summary.txt || true
        FAILURE_REASONS+=("$(cat /tmp/severity-gate-summary.txt)")
        FAILURE_REASONS+=("\`\`\`")
        FAILURE_REASONS+=("")
        rm -f /tmp/severity-gate-summary.txt
    fi
    
    if [[ -f "$TRUFFLEHOG_FILE" && "$TRUFFLEHOG_SECRETS" -gt 0 ]]; then
        FAILURE_REASONS+=("### TruffleHog Secrets ($TRUFFLEHOG_SECRETS found)")
        FAILURE_REASONS+=("\`\`\`")
        jq -r '.[] | "Type: \(.DetectorName) | File: \(.SourceMetadata.Data.Filesystem.file // "N/A") | Line: \(.SourceMetadata.Data.Filesystem.line // "N/A")"' "$TRUFFLEHOG_FILE" 2>/dev/null | head -20 >> /tmp/severity-gate-summary.txt || true
        FAILURE_REASONS+=("$(cat /tmp/severity-gate-summary.txt)")
        FAILURE_REASONS+=("\`\`\`")
        FAILURE_REASONS+=("")
        rm -f /tmp/severity-gate-summary.txt
    fi
fi

if [[ "$FAIL_ON_HIGH" == "true" && $TOTAL_HIGH -gt 0 ]]; then
    echo -e "${RED}❌ Build Gate Failed: $TOTAL_HIGH high severity findings detected${NC}"
    echo -e "${RED}   Policy: FAIL_ON_HIGH=true${NC}"
    ISSUES_FOUND=true
    EXIT_CODE=1
    
    # Collect details about high findings
    FAILURE_REASONS+=("## 🟠 High Severity Findings ($TOTAL_HIGH)")
    FAILURE_REASONS+=("")
    
    if [[ -f "$GRYPE_FILE" && $GRYPE_HIGH -gt 0 ]]; then
        FAILURE_REASONS+=("### Grype Vulnerabilities ($GRYPE_HIGH high)")
        FAILURE_REASONS+=("\`\`\`")
        jq -r '.matches[]? | select(.vulnerability.severity=="High") | "CVE: \(.vulnerability.id) | Package: \(.artifact.name)@\(.artifact.version) | Severity: \(.vulnerability.severity)"' "$GRYPE_FILE" 2>/dev/null | head -20 >> /tmp/severity-gate-summary.txt || true
        FAILURE_REASONS+=("$(cat /tmp/severity-gate-summary.txt)")
        FAILURE_REASONS+=("\`\`\`")
        FAILURE_REASONS+=("")
        rm -f /tmp/severity-gate-summary.txt
    fi
    
    if [[ -f "$TRIVY_FILE" && $TRIVY_HIGH -gt 0 ]]; then
        FAILURE_REASONS+=("### Trivy Vulnerabilities ($TRIVY_HIGH high)")
        FAILURE_REASONS+=("\`\`\`")
        jq -r '.Results[]?.Vulnerabilities[]? | select(.Severity == "HIGH") | "CVE: \(.VulnerabilityID) | Package: \(.PkgName)@\(.InstalledVersion) | Title: \(.Title)"' "$TRIVY_FILE" 2>/dev/null | head -20 >> /tmp/severity-gate-summary.txt || true
        FAILURE_REASONS+=("$(cat /tmp/severity-gate-summary.txt)")
        FAILURE_REASONS+=("\`\`\`")
        FAILURE_REASONS+=("")
        rm -f /tmp/severity-gate-summary.txt
    fi
    
    if [[ -f "$CHECKOV_FILE" && $CHECKOV_FAILED -gt 0 ]]; then
        FAILURE_REASONS+=("### Checkov IaC Issues ($CHECKOV_FAILED failed checks)")
        FAILURE_REASONS+=("\`\`\`")
        jq -r '.results.failed_checks[]? | "Check: \(.check_id) | File: \(.file_path):\(.file_line_range[0]) | \(.check_name)"' "$CHECKOV_FILE" 2>/dev/null | head -20 >> /tmp/severity-gate-summary.txt || true
        FAILURE_REASONS+=("$(cat /tmp/severity-gate-summary.txt)")
        FAILURE_REASONS+=("\`\`\`")
        FAILURE_REASONS+=("")
        rm -f /tmp/severity-gate-summary.txt
    fi
fi

if [[ "$WARNING_ONLY" == "true" && ($TOTAL_CRITICAL -gt 0 || $TOTAL_HIGH -gt 0) ]]; then
    echo -e "${YELLOW}⚠️  Vulnerabilities detected but build will pass (warning-only mode)${NC}"
elif [[ "$ISSUES_FOUND" == "false" ]]; then
    echo -e "${GREEN}✅ Build Gate Passed: No critical or high severity findings above threshold${NC}"
fi

echo ""
echo -e "${CYAN}============================================${NC}"
echo ""

# Export to GitHub Actions output and step summary
if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    echo "critical_count=$TOTAL_CRITICAL" >> "$GITHUB_OUTPUT"
    echo "high_count=$TOTAL_HIGH" >> "$GITHUB_OUTPUT"
    echo "medium_count=$TOTAL_MEDIUM" >> "$GITHUB_OUTPUT"
    echo "low_count=$TOTAL_LOW" >> "$GITHUB_OUTPUT"
    echo "gate_passed=$([[ $EXIT_CODE -eq 0 ]] && echo "true" || echo "false")" >> "$GITHUB_OUTPUT"
fi

# Write detailed failure reasons to GitHub Step Summary
if [[ -n "${GITHUB_STEP_SUMMARY:-}" && ${#FAILURE_REASONS[@]} -gt 0 ]]; then
    echo "# ❌ Security Gate Failure Report" >> "$GITHUB_STEP_SUMMARY"
    echo "" >> "$GITHUB_STEP_SUMMARY"
    echo "**Total Findings:**" >> "$GITHUB_STEP_SUMMARY"
    echo "- 🔴 Critical: $TOTAL_CRITICAL" >> "$GITHUB_STEP_SUMMARY"
    echo "- 🟠 High: $TOTAL_HIGH" >> "$GITHUB_STEP_SUMMARY"
    echo "- 🟡 Medium: $TOTAL_MEDIUM" >> "$GITHUB_STEP_SUMMARY"
    echo "- 🟢 Low: $TOTAL_LOW" >> "$GITHUB_STEP_SUMMARY"
    echo "" >> "$GITHUB_STEP_SUMMARY"
    
    for line in "${FAILURE_REASONS[@]}"; do
        echo "$line" >> "$GITHUB_STEP_SUMMARY"
    done
    
    echo "" >> "$GITHUB_STEP_SUMMARY"
    echo "---" >> "$GITHUB_STEP_SUMMARY"
    echo "*Review the full scan results in the workflow artifacts for complete details.*" >> "$GITHUB_STEP_SUMMARY"
fi

exit $EXIT_CODE
