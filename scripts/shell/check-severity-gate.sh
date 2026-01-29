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
    TRUFFLEHOG_SECRETS=$(jq -r '. | length' "$TRUFFLEHOG_FILE" 2>/dev/null || echo "0")
    echo "  Secrets found: $TRUFFLEHOG_SECRETS"
    if [[ $TRUFFLEHOG_SECRETS -gt 0 ]]; then
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

if [[ "$FAIL_ON_CRITICAL" == "true" && $TOTAL_CRITICAL -gt 0 ]]; then
    echo -e "${RED}❌ Build Gate Failed: $TOTAL_CRITICAL critical severity findings detected${NC}"
    echo -e "${RED}   Policy: FAIL_ON_CRITICAL=true${NC}"
    ISSUES_FOUND=true
    EXIT_CODE=1
fi

if [[ "$FAIL_ON_HIGH" == "true" && $TOTAL_HIGH -gt 0 ]]; then
    echo -e "${RED}❌ Build Gate Failed: $TOTAL_HIGH high severity findings detected${NC}"
    echo -e "${RED}   Policy: FAIL_ON_HIGH=true${NC}"
    ISSUES_FOUND=true
    EXIT_CODE=1
fi

if [[ "$ISSUES_FOUND" == "false" ]]; then
    echo -e "${GREEN}✅ Build Gate Passed: No critical or high severity findings above threshold${NC}"
fi

echo ""
echo -e "${CYAN}============================================${NC}"
echo ""

# Export to GitHub Actions output if available
if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    echo "critical_count=$TOTAL_CRITICAL" >> "$GITHUB_OUTPUT"
    echo "high_count=$TOTAL_HIGH" >> "$GITHUB_OUTPUT"
    echo "medium_count=$TOTAL_MEDIUM" >> "$GITHUB_OUTPUT"
    echo "low_count=$TOTAL_LOW" >> "$GITHUB_OUTPUT"
    echo "gate_passed=$([[ $EXIT_CODE -eq 0 ]] && echo "true" || echo "false")" >> "$GITHUB_OUTPUT"
fi

exit $EXIT_CODE
