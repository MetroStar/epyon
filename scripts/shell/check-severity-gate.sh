#!/bin/bash

# Severity Gate Check Script
# Checks scan results for critical/high severity findings and fails build if threshold exceeded

show_help() {
        cat <<'EOF'
Usage: check-severity-gate.sh [--help]

Evaluates scan findings in SCAN_DIR and enforces severity gates.

Environment:
    SCAN_DIR           Required. Scan directory to evaluate.
    TARGET_DIR         Optional. Target directory used for ignore rules.
    FAIL_ON_CRITICAL   true|false (default: true)
    FAIL_ON_HIGH       true|false (default: true)
    HIGH_THRESHOLD     Integer high-severity threshold (default: 4)
    WARNING_ONLY       true|false (default: false)

Options:
    -h, --help         Show this help text and exit.
EOF
}

if [[ "${1:-}" == "--help" ]] || [[ "${1:-}" == "-h" ]]; then
        show_help
        exit 0
fi

# Colors for output
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

# Configuration from environment variables
FAIL_ON_CRITICAL="${FAIL_ON_CRITICAL:-true}"
FAIL_ON_HIGH="${FAIL_ON_HIGH:-true}"
HIGH_THRESHOLD="${HIGH_THRESHOLD:-4}"
WARNING_ONLY="${WARNING_ONLY:-false}"
SCAN_DIR="${SCAN_DIR:-}"
TARGET_DIR="${TARGET_DIR:-}"

# Get script directory for sourcing filter functions
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ -z "$SCAN_DIR" || ! -d "$SCAN_DIR" ]]; then
    echo -e "${RED}❌ Error: SCAN_DIR not set or directory doesn't exist${NC}"
    echo "SCAN_DIR value: '$SCAN_DIR'"
    echo "Listing workspace contents:"
    ls -la . || true
    exit 1
fi

# Parse ignore rules if they exist
export IGNORE_CACHE="/tmp/epyon-ignore-cache.json"
export SUPPRESSED_LOG="$SCAN_DIR/suppressed-findings.md"

if [[ -f "$SCRIPT_DIR/parse-epyon-ignore.sh" ]]; then
    source "$SCRIPT_DIR/parse-epyon-ignore.sh" 2>/dev/null || {
        echo -e "${YELLOW}⚠️  Failed to load parse script, continuing without filtering${NC}"
    }
    if declare -f parse_ignore_rules >/dev/null 2>&1; then
        # Try multiple candidate locations for .epyon-ignore.yml to handle
        # different workspace layouts (e.g., repo at TARGET_DIR, at GITHUB_WORKSPACE
        # root, or alongside the scan directory).
        _IGNORE_FILE=""
        for _candidate in \
            "${TARGET_DIR:-}/.epyon-ignore.yml" \
            "${GITHUB_WORKSPACE:-}/.epyon-ignore.yml" \
            "$(cd "$SCRIPT_DIR/../.." && pwd)/.epyon-ignore.yml"; do
            if [[ -n "$_candidate" && -f "$_candidate" ]]; then
                _IGNORE_FILE="$_candidate"
                break
            fi
        done

        if [[ -n "$_IGNORE_FILE" ]]; then
            echo -e "${CYAN}📋 Parsing ignore rules from: $_IGNORE_FILE${NC}"
            parse_ignore_rules "$_IGNORE_FILE" 2>/dev/null || {
                echo -e "${YELLOW}⚠️  Failed to parse ignore rules, continuing without filtering${NC}"
                echo '{"ignores": []}' > "$IGNORE_CACHE" 2>/dev/null || true
            }
        else
            echo -e "${YELLOW}⚠️  No .epyon-ignore.yml found (TARGET_DIR=${TARGET_DIR:-<unset>}, GITHUB_WORKSPACE=${GITHUB_WORKSPACE:-<unset>}) — skipping suppression${NC}"
            echo '{"ignores": []}' > "$IGNORE_CACHE" 2>/dev/null || true
        fi

        # Debug: Show what was parsed
        if [[ -f "$IGNORE_CACHE" ]]; then
            IGNORE_COUNT=$(jq '.ignores | length' "$IGNORE_CACHE" 2>/dev/null || echo "0")
            echo -e "${CYAN}📊 Loaded $IGNORE_COUNT ignore rule(s) from cache${NC}"
            if [[ $IGNORE_COUNT -gt 0 ]]; then
                echo -e "${CYAN}📋 Ignore rules:${NC}"
                jq -r '.ignores[] | "  - \(.type): \(.value)"' "$IGNORE_CACHE" 2>/dev/null || true
            else
                echo -e "${YELLOW}⚠️  No ignore rules loaded - check YAML syntax in .epyon-ignore.yml${NC}"
            fi
        fi
    fi
fi

# Source filter functions
if [[ -f "$SCRIPT_DIR/filter-ignored-findings.sh" ]]; then
    source "$SCRIPT_DIR/filter-ignored-findings.sh" 2>/dev/null || {
        echo -e "${YELLOW}⚠️  Failed to load filter functions, continuing without filtering${NC}"
    }
    if init_suppressed_log; then
        echo -e "${CYAN}📝 Suppressed findings log: $SUPPRESSED_LOG${NC}"
    else
        echo -e "${YELLOW}⚠️  Could not initialize suppressed findings log${NC}"
    fi
fi

echo ""
echo -e "${CYAN}============================================${NC}"
echo -e "${CYAN}🚦 Security Severity Gate Check${NC}"
echo -e "${CYAN}============================================${NC}"
echo -e "${CYAN}Scan Directory: $SCAN_DIR${NC}"
echo -e "${CYAN}Fail on Critical: $FAIL_ON_CRITICAL${NC}"
echo -e "${CYAN}Fail on High: $FAIL_ON_HIGH (threshold: $HIGH_THRESHOLD)${NC}"
echo -e "${CYAN}Warning Only Mode: $WARNING_ONLY${NC}"
echo ""

TOTAL_CRITICAL=0
TOTAL_HIGH=0
TOTAL_MEDIUM=0
TOTAL_LOW=0
ISSUES_FOUND=false

# Try to use deduplicated summary first
FINDINGS_SUMMARY="$SCAN_DIR/security-findings-summary.json"
# Create filtered version with name expected by workflow
FILTERED_SUMMARY="$SCAN_DIR/security-findings-filtered.json"

# After we create the filtered file below, we'll use it for display
# For now, start with the raw summary
if [[ -f "$FINDINGS_SUMMARY" ]]; then
    echo -e "${CYAN}📊 Using deduplicated security findings summary${NC}"

    # Build a jq select filter that excludes findings from any tool suppressed via .epyon-ignore.yml.
    SUPPRESSED_TOOLS_JQ=""
    for tool_name in grype trivy trufflehog checkov clamav anchore xeol pip-audit safety; do
        if declare -f is_tool_ignored >/dev/null 2>&1 && is_tool_ignored "$tool_name" 2>/dev/null; then
            echo -e "${YELLOW}⚠️  Excluding $tool_name findings from severity totals (suppressed by .epyon-ignore.yml)${NC}"
            SUPPRESSED_TOOLS_JQ="${SUPPRESSED_TOOLS_JQ} and ((.tool // \"\" | ascii_downcase) | startswith(\"${tool_name}\") | not)"
        fi
    done

    # Filter findings by suppression rules (tool-level AND finding-level)
    echo -e "${CYAN}🔍 Applying suppression rules to findings...${NC}"
    
    # Build a list of suppressed finding fingerprints using existing bash functions
    # This ensures we use the same suppression logic that's already tested
    SUPPRESSED_FINGERPRINTS=$(mktemp)
    
    # Process each finding and check if it should be suppressed
    for severity_key in critical_findings high_findings medium_findings low_findings; do
        jq -c ".${severity_key}[]?" "$FINDINGS_SUMMARY" 2>/dev/null | while IFS= read -r finding; do
            if [[ -z "$finding" ]]; then
                continue
            fi
            
            # Extract finding details
            tool=$(echo "$finding" | jq -r '.tool // ""')
            detector=$(echo "$finding" | jq -r '.detector // ""')
            file_path=$(echo "$finding" | jq -r '.file_path // ""')
            cve=$(echo "$finding" | jq -r '.vulnerability_id // .id // ""')
            package=$(echo "$finding" | jq -r '.package_name // .package // ""')
            version=$(echo "$finding" | jq -r '.package_version // .version // ""')
            line_num=$(echo "$finding" | jq -r '.line_number // ""')
            
            # Strip /workspace/ prefix
            file_path="${file_path#/workspace/}"
            
            # Create a unique fingerprint for this finding
            fingerprint="${tool}|${detector}|${cve}|${package}|${version}|${file_path}|${line_num}"
            
            # Check if suppressed using existing bash functions
            suppressed=false
            
            if [[ -n "$detector" && -n "$file_path" ]] && declare -f is_secret_ignored >/dev/null 2>&1; then
                if is_secret_ignored "$detector" "$file_path" "$tool" 2>/dev/null; then
                    suppressed=true
                fi
            elif [[ -n "$cve" ]] && declare -f is_cve_ignored >/dev/null 2>&1; then
                if is_cve_ignored "$cve" "$tool" 2>/dev/null; then
                    suppressed=true
                fi
            elif [[ -n "$package" ]] && declare -f is_package_ignored >/dev/null 2>&1; then
                if is_package_ignored "$package" "$version" "$tool" 2>/dev/null; then
                    suppressed=true
                fi
            elif [[ -n "$file_path" ]] && declare -f is_path_ignored >/dev/null 2>&1; then
                if is_path_ignored "$file_path" "$tool" 2>/dev/null; then
                    suppressed=true
                fi
            fi
            
            if [[ "$suppressed" == "true" ]]; then
                echo "$fingerprint" >> "$SUPPRESSED_FINGERPRINTS"
            fi
        done
    done
    
    # Now use jq to filter out the suppressed findings
    FILTERED_SUMMARY="$SCAN_DIR/security-findings-filtered.json"
    
    # Read suppressed fingerprints into a bash array for jq
    mapfile -t SUPPRESSED_ARRAY < "$SUPPRESSED_FINGERPRINTS"
    SUPPRESSED_JSON=$(printf '%s\n' "${SUPPRESSED_ARRAY[@]}" | jq -R . | jq -s .)
    
    jq --argjson suppressed "$SUPPRESSED_JSON" '
    # Helper to create fingerprint from finding
    def fingerprint:
        [
            (.tool // ""),
            (.detector // ""),
            (.vulnerability_id // .id // ""),
            (.package_name // .package // ""),
            (.package_version // .version // ""),
            ((.file_path // "") | sub("^/workspace/"; "")),
            (.line_number // "")
        ] | join("|");
    
    # Filter findings
    {
        critical_findings: [.critical_findings[]? | select(fingerprint as $fp | $suppressed | index($fp) | not)],
        high_findings: [.high_findings[]? | select(fingerprint as $fp | $suppressed | index($fp) | not)],
        medium_findings: [.medium_findings[]? | select(fingerprint as $fp | $suppressed | index($fp) | not)],
        low_findings: [.low_findings[]? | select(fingerprint as $fp | $suppressed | index($fp) | not)],
        summary: {
            total_critical: ([.critical_findings[]? | select(fingerprint as $fp | $suppressed | index($fp) | not)] | length),
            total_high: ([.high_findings[]? | select(fingerprint as $fp | $suppressed | index($fp) | not)] | length),
            total_medium: ([.medium_findings[]? | select(fingerprint as $fp | $suppressed | index($fp) | not)] | length),
            total_low: ([.low_findings[]? | select(fingerprint as $fp | $suppressed | index($fp) | not)] | length)
        },
        scan_metadata: .scan_metadata
    }
    ' "$FINDINGS_SUMMARY" > "$FILTERED_SUMMARY" 2>/dev/null
    
    # Check if filtering succeeded
    if [[ $? -eq 0 && -f "$FILTERED_SUMMARY" && -s "$FILTERED_SUMMARY" ]]; then
        # Read filtered counts
        TOTAL_CRITICAL=$(jq -r '.summary.total_critical // 0' "$FILTERED_SUMMARY" 2>/dev/null || echo "0")
        TOTAL_HIGH=$(jq -r '.summary.total_high // 0' "$FILTERED_SUMMARY" 2>/dev/null || echo "0")
        TOTAL_MEDIUM=$(jq -r '.summary.total_medium // 0' "$FILTERED_SUMMARY" 2>/dev/null || echo "0")
        TOTAL_LOW=$(jq -r '.summary.total_low // 0' "$FILTERED_SUMMARY" 2>/dev/null || echo "0")
        
        echo -e "${GREEN}✅ Wrote filtered findings: $FILTERED_SUMMARY${NC}"
        echo -e "${YELLOW}  After all suppressions — Critical: $TOTAL_CRITICAL | High: $TOTAL_HIGH | Medium: $TOTAL_MEDIUM | Low: $TOTAL_LOW${NC}"
        
        # Use the filtered file for all subsequent operations
        FINDINGS_SUMMARY="$FILTERED_SUMMARY"
    else
        echo -e "${YELLOW}⚠️  Could not create filtered findings, using original counts${NC}"
        TOTAL_CRITICAL=$(jq -r '.summary.total_critical // 0' "$FINDINGS_SUMMARY" 2>/dev/null || echo "0")
        TOTAL_HIGH=$(jq -r '.summary.total_high // 0' "$FINDINGS_SUMMARY" 2>/dev/null || echo "0")
        TOTAL_MEDIUM=$(jq -r '.summary.total_medium // 0' "$FINDINGS_SUMMARY" 2>/dev/null || echo "0")
        TOTAL_LOW=$(jq -r '.summary.total_low // 0' "$FINDINGS_SUMMARY" 2>/dev/null || echo "0")
    fi
    
    rm -f "$SUPPRESSED_FINGERPRINTS"
    

    echo -e "${GREEN}✅ Using unique vulnerability counts (deduplicated)${NC}"

    # NOTE: Deduplicated summary includes all tool findings (Trivy, Grype, Anchore, pip-audit,
    # safety, TruffleHog, Checkov, ClamAV, Xeol, SonarQube) from security-findings-summary.json.
    # Individual tool blocks below run for suppression logging but only add to totals
    # when the dedup summary is absent (to avoid double-counting).
else
    echo -e "${YELLOW}⚠️  Deduplicated summary not found, counting from individual tools (may include duplicates)${NC}"
fi

# Check Grype results (always runs for suppression logging; counts only when no dedup summary)
GRYPE_FILE=$(find "$SCAN_DIR/grype" -name "*grype*sbom*.json" 2>/dev/null | head -1)
if [[ -f "$GRYPE_FILE" ]]; then
    # Check if Grype tool is ignored
    if declare -f is_tool_ignored >/dev/null 2>&1 && is_tool_ignored "grype"; then
        echo -e "${YELLOW}⚠️  Grype scans ignored by .epyon-ignore.yml${NC}"
    else
        echo -e "${CYAN}📊 Checking Grype SBOM scan results (suppression logging)...${NC}"
        
        # Filter out ignored CVEs and packages
        GRYPE_CRITICAL=0
        GRYPE_HIGH=0
        GRYPE_MEDIUM=0
        GRYPE_LOW=0
        
        # Use process substitution to avoid subshell variable scope issue
        while IFS= read -r match; do
            if [[ -z "$match" ]]; then
                continue
            fi
            
            # Extract finding details
            cve=$(echo "$match" | jq -r '.vulnerability.id // ""' 2>/dev/null)
            severity=$(echo "$match" | jq -r '.vulnerability.severity // ""' 2>/dev/null)
            package=$(echo "$match" | jq -r '.artifact.name // ""' 2>/dev/null)
            version=$(echo "$match" | jq -r '.artifact.version // ""' 2>/dev/null)
            
            # Check if ignored
            ignored=false
            
            if declare -f is_cve_ignored >/dev/null 2>&1 && is_cve_ignored "$cve" "Grype"; then
                ignored=true
            elif declare -f is_package_ignored >/dev/null 2>&1 && is_package_ignored "$package" "$version" "Grype"; then
                ignored=true
            fi
            
            # Only update counts when not using dedup summary (avoid double-counting)
            if [[ "$ignored" == "false" ]] && [[ ! -f "$FINDINGS_SUMMARY" ]]; then
                case "$severity" in
                    Critical) ((GRYPE_CRITICAL++)) ;;
                    High) ((GRYPE_HIGH++)) ;;
                    Medium) ((GRYPE_MEDIUM++)) ;;
                    Low) ((GRYPE_LOW++)) ;;
                esac
            fi
        done < <(jq -c '.matches[]?' "$GRYPE_FILE" 2>/dev/null)
        
        if [[ ! -f "$FINDINGS_SUMMARY" ]]; then
            echo "  Critical: $GRYPE_CRITICAL | High: $GRYPE_HIGH | Medium: $GRYPE_MEDIUM | Low: $GRYPE_LOW"
            TOTAL_CRITICAL=$((TOTAL_CRITICAL + GRYPE_CRITICAL))
            TOTAL_HIGH=$((TOTAL_HIGH + GRYPE_HIGH))
            TOTAL_MEDIUM=$((TOTAL_MEDIUM + GRYPE_MEDIUM))
            TOTAL_LOW=$((TOTAL_LOW + GRYPE_LOW))
        else
            echo -e "  ${CYAN}ℹ️  Grype counts from dedup summary; processed for suppression logging only${NC}"
        fi
    fi
else
    echo -e "${YELLOW}⚠️  Grype SBOM results not found in: $SCAN_DIR/grype/${NC}"
fi

# Always check Trivy for suppression logging; use counts only if no dedup summary
TRIVY_FILE=$(find "$SCAN_DIR/trivy" -name "*trivy*results.json" 2>/dev/null | head -1)
if [[ -f "$TRIVY_FILE" ]]; then
    # Check if Trivy tool is ignored
    if declare -f is_tool_ignored >/dev/null 2>&1 && is_tool_ignored "trivy"; then
        echo -e "${YELLOW}⚠️  Trivy scans ignored by .epyon-ignore.yml${NC}"
    else
        echo -e "${CYAN}📊 Checking Trivy results (suppression logging)...${NC}"
        
        # Filter out ignored CVEs and packages
        TRIVY_CRITICAL=0
        TRIVY_HIGH=0
        TRIVY_MEDIUM=0
        TRIVY_LOW=0
        
        # Create temp file for counting
        TEMP_COUNTS=$(mktemp)
        echo "0 0 0 0" > "$TEMP_COUNTS"
        
        # Process each vulnerability
        while IFS='|' read -r cve severity package version target_path; do
            if [[ -z "$cve" ]]; then
                continue
            fi
            
            # Check if ignored (always runs for suppression logging regardless of dedup summary)
            ignored=false
            
            if declare -f is_cve_ignored >/dev/null 2>&1 && is_cve_ignored "$cve" "Trivy"; then
                ignored=true
            elif declare -f is_package_ignored >/dev/null 2>&1 && is_package_ignored "$package" "$version" "Trivy"; then
                ignored=true
            elif [[ -n "$target_path" ]] && declare -f is_path_ignored >/dev/null 2>&1 && is_path_ignored "$target_path" "Trivy"; then
                ignored=true
            fi
            
            # Only update counts when not using dedup summary (avoid double-counting)
            if [[ "$ignored" == "false" ]] && [[ ! -f "$FINDINGS_SUMMARY" ]]; then
                case "$severity" in
                    CRITICAL) ((TRIVY_CRITICAL++)) ;;
                    HIGH) ((TRIVY_HIGH++)) ;;
                    MEDIUM) ((TRIVY_MEDIUM++)) ;;
                    LOW) ((TRIVY_LOW++)) ;;
                esac
            fi
        done < <(jq -r '.Results[]? | .Target as $target | .Vulnerabilities[]? | [.VulnerabilityID // "", .Severity // "", .PkgName // "", .InstalledVersion // "", $target] | @tsv' "$TRIVY_FILE" 2>/dev/null | tr '\t' '|')
        
        rm -f "$TEMP_COUNTS"
        
        if [[ ! -f "$FINDINGS_SUMMARY" ]]; then
            echo "  Critical: $TRIVY_CRITICAL | High: $TRIVY_HIGH | Medium: $TRIVY_MEDIUM | Low: $TRIVY_LOW"
            TOTAL_CRITICAL=$((TOTAL_CRITICAL + TRIVY_CRITICAL))
            TOTAL_HIGH=$((TOTAL_HIGH + TRIVY_HIGH))
            TOTAL_MEDIUM=$((TOTAL_MEDIUM + TRIVY_MEDIUM))
            TOTAL_LOW=$((TOTAL_LOW + TRIVY_LOW))
        else
            echo -e "  ${CYAN}ℹ️  Trivy counts from dedup summary; processed for suppression logging only${NC}"
        fi
    fi
else
    echo -e "${YELLOW}⚠️  Trivy results not found in: $SCAN_DIR/trivy/${NC}"
fi

# Always check TruffleHog for suppression logging; use counts only if no dedup summary
TRUFFLEHOG_FILE=$(find "$SCAN_DIR/trufflehog" -name "*trufflehog*results.json" 2>/dev/null | head -1)
if [[ -f "$TRUFFLEHOG_FILE" ]]; then
    # Check if TruffleHog tool is ignored
    if declare -f is_tool_ignored >/dev/null 2>&1 && is_tool_ignored "trufflehog"; then
        echo -e "${YELLOW}⚠️  TruffleHog scans ignored by .epyon-ignore.yml${NC}"
    else
        echo -e "${CYAN}📊 Checking TruffleHog results (suppression logging)...${NC}"
        
        # Filter secrets by detector type and path
        TRUFFLEHOG_SECRETS=0
        
        # Read NDJSON format (one JSON object per line) - use process substitution
        while IFS= read -r line; do
            if [[ -z "$line" ]]; then
                continue
            fi
            
            detector=$(echo "$line" | jq -r '.DetectorName // ""' 2>/dev/null)
            file_path=$(echo "$line" | jq -r '.SourceMetadata.Data.Filesystem.file // ""' 2>/dev/null)
            
            # Strip /workspace/ prefix added by Docker volume mount so path patterns match
            clean_file_path="${file_path#/workspace/}"
            
            # Check if ignored (always runs for suppression logging)
            ignored=false
            
            if declare -f is_secret_ignored >/dev/null 2>&1 && is_secret_ignored "$detector" "$clean_file_path" "TruffleHog"; then
                ignored=true
            elif [[ -n "$clean_file_path" ]] && declare -f is_path_ignored >/dev/null 2>&1 && is_path_ignored "$clean_file_path" "TruffleHog"; then
                ignored=true
            fi
            
            # Only update counts when not using dedup summary (avoid double-counting)
            if [[ "$ignored" == "false" ]] && [[ ! -f "$FINDINGS_SUMMARY" ]]; then
                ((TRUFFLEHOG_SECRETS++))
            fi
        done < <(grep -v '"level":' "$TRUFFLEHOG_FILE" 2>/dev/null)
        
        if [[ ! -f "$FINDINGS_SUMMARY" ]]; then
            echo "  Secrets found: $TRUFFLEHOG_SECRETS"
            if [[ $TRUFFLEHOG_SECRETS -gt 0 ]]; then
                # Treat all secrets as Critical
                TOTAL_CRITICAL=$((TOTAL_CRITICAL + TRUFFLEHOG_SECRETS))
            fi
        else
            echo -e "  ${CYAN}ℹ️  TruffleHog counts from dedup summary; processed for suppression logging only${NC}"
        fi
    fi
else
    echo -e "${YELLOW}⚠️  TruffleHog results not found in: $SCAN_DIR/trufflehog/${NC}"
fi

# Check Checkov IaC issues
# Use -type f with parentheses to avoid matching the checkov-results.json *directory*
# that Checkov creates when --output-file is used (directory name matches *checkov*results.json)
CHECKOV_FILE=$(find "$SCAN_DIR/checkov" -type f \( -name "results_json.json" -o -name "*checkov*results.json" \) 2>/dev/null | head -1)
if [[ -f "$CHECKOV_FILE" ]]; then
    # Check if Checkov tool is ignored
    if declare -f is_tool_ignored >/dev/null 2>&1 && is_tool_ignored "checkov"; then
        echo -e "${YELLOW}⚠️  Checkov scans ignored by .epyon-ignore.yml${NC}"
    else
        echo -e "${CYAN}📊 Checking Checkov results...${NC}"
        
        # Filter failed checks by path and dedupe repeated line-range variants
        # using check_id + normalized file path as the stable key.
        CHECKOV_FAILED=0
        CHECKOV_TOTAL=0
        CHECKOV_UNIQUE_FAILED=0
        CHECKOV_DEDUP_LINES=""
        
        # Use process substitution to avoid subshell
        # Iterate through all check types and their failed checks
        while IFS= read -r check; do
            if [[ -z "$check" ]]; then
                continue
            fi
            
            ((CHECKOV_TOTAL++))
            
            file_path=$(echo "$check" | jq -r '.file_path // ""' 2>/dev/null)
            check_id=$(echo "$check" | jq -r '.check_id // ""' 2>/dev/null)
            check_name=$(echo "$check" | jq -r '.check_name // ""' 2>/dev/null)
            
            # Strip /workspace/ prefix added by Docker volume mount so path patterns match
            clean_file_path="${file_path#/workspace/}"
            
            # Check if check_id (e.g. CKV_AWS_260) is suppressed via type: cve
            ignored=false
            
            if [[ -n "$check_id" ]] && declare -f is_cve_ignored >/dev/null 2>&1 && is_cve_ignored "$check_id" "Checkov"; then
                ignored=true
                echo -e "${CYAN}  ✓ Suppressed: $check_id ($check_name)${NC}"
            elif [[ -n "$clean_file_path" ]] && declare -f is_path_ignored >/dev/null 2>&1 && is_path_ignored "$clean_file_path" "Checkov"; then
                ignored=true
                echo -e "${CYAN}  ✓ Suppressed: $check_id in $clean_file_path${NC}"
                # Note: is_path_ignored already calls log_suppressed internally
            else
                echo -e "${YELLOW}  ⚠️  $check_id: $check_name in $file_path${NC}"
            fi
            
            # Count if not ignored
            if [[ "$ignored" == "false" ]]; then
                ((CHECKOV_FAILED++))
                dedup_key="${check_id}|${clean_file_path}"
                case "\n${CHECKOV_DEDUP_LINES}\n" in
                    *"\n${dedup_key}\n"*)
                        ;;
                    *)
                        CHECKOV_DEDUP_LINES+="${dedup_key}"$'\n'
                        ((CHECKOV_UNIQUE_FAILED++))
                        ;;
                esac
            fi
        done < <(jq -c '.[]? | .results.failed_checks[]?' "$CHECKOV_FILE" 2>/dev/null)
        
        echo "  Total checks found: $CHECKOV_TOTAL"
        echo "  Failed checks: $CHECKOV_FAILED"
        echo "  Unique failed checks (rule+file): $CHECKOV_UNIQUE_FAILED"
        if [[ $CHECKOV_FAILED -gt 0 ]]; then
            # Treat failed IaC checks as High severity
            # Only add to totals when not using dedup summary (Checkov is now included there)
            if [[ ! -f "$FINDINGS_SUMMARY" ]]; then
                TOTAL_HIGH=$((TOTAL_HIGH + CHECKOV_UNIQUE_FAILED))
            else
                echo -e "  ${CYAN}ℹ️  Checkov counts from dedup summary; processed for suppression logging only${NC}"
            fi
        fi
    fi
else
    echo -e "${YELLOW}⚠️  Checkov results not found in: $SCAN_DIR/checkov/${NC}"
fi

# Check ClamAV malware detection
CLAMAV_LOG=$(find "$SCAN_DIR/clamav" -name "scan.log" 2>/dev/null | head -1)
if [[ -f "$CLAMAV_LOG" ]]; then
    # Check if ClamAV tool is ignored
    if declare -f is_tool_ignored >/dev/null 2>&1 && is_tool_ignored "clamav"; then
        echo -e "${YELLOW}⚠️  ClamAV scans ignored by .epyon-ignore.yml${NC}"
    else
        echo -e "${CYAN}📊 Checking ClamAV results...${NC}"
        
        # Filter infected files by path
        CLAMAV_INFECTED=0
        
        # Use process substitution to avoid subshell
        while IFS= read -r line; do
            # Extract file path from ClamAV log line
            # Format: /path/to/file: Malware.Name FOUND
            file_path=$(echo "$line" | sed 's/:.*$//' | xargs)
            
            # Check if path is ignored
            ignored=false
            
            if [[ -n "$file_path" ]] && declare -f is_path_ignored >/dev/null 2>&1 && is_path_ignored "$file_path" "ClamAV"; then
                ignored=true
            fi
            
            # Count if not ignored
            if [[ "$ignored" == "false" ]]; then
                ((CLAMAV_INFECTED++))
            fi
        done < <(grep "FOUND$" "$CLAMAV_LOG" 2>/dev/null)
        
        echo "  Infected files: $CLAMAV_INFECTED"
        if [[ $CLAMAV_INFECTED -gt 0 ]]; then
            # Treat ALL malware detections as Critical severity
            TOTAL_CRITICAL=$((TOTAL_CRITICAL + CLAMAV_INFECTED))
            echo -e "  ${RED}⚠️  Malware detected - automatically marked as CRITICAL${NC}"
        fi
    fi
else
    echo -e "${YELLOW}⚠️  ClamAV results not found in: $SCAN_DIR/clamav/${NC}"
fi

# End of all checks
echo ""
echo -e "${CYAN}============================================${NC}"
echo -e "${CYAN}📊 Total Security Findings${NC}"
echo -e "${CYAN}============================================${NC}"
echo -e "🔴 Critical: ${RED}$TOTAL_CRITICAL${NC}"
echo -e "🟠 High: ${YELLOW}$TOTAL_HIGH${NC}"
echo -e "🟡 Medium: $TOTAL_MEDIUM"
echo -e "🟢 Low: $TOTAL_LOW"
echo ""

# Show suppressed findings summary if any
if [[ -f "$SUPPRESSED_LOG" ]]; then
    # Count suppressed findings  
    if [[ -f "$SUPPRESSED_LOG" ]]; then
        SUPPRESSED_COUNT=$(grep -c "^## Suppressed:" "$SUPPRESSED_LOG" 2>/dev/null)
    else
        SUPPRESSED_COUNT=0
    fi
    if [[ -z "$SUPPRESSED_COUNT" ]]; then
        SUPPRESSED_COUNT=0
    fi
    if [[ $SUPPRESSED_COUNT -gt 0 ]]; then
        echo -e "${CYAN}============================================${NC}"
        echo -e "${CYAN}🔕 Suppressed Findings (via .epyon-ignore.yml)${NC}"
        echo -e "${CYAN}============================================${NC}"
        echo -e "${YELLOW}$SUPPRESSED_COUNT finding(s) were suppressed${NC}"
        echo -e "${CYAN}Full report: suppressed-findings.md${NC}"
        echo ""
    fi
fi

# Determine if build should fail
EXIT_CODE=0
FAILURE_REASONS=()

# License gate — fail on denied copyleft licenses (runs before WARNING_ONLY so it's always surfaced)
if [[ "${LICENSE_DENIED:-0}" -gt 0 && "$WARNING_ONLY" != "true" ]]; then
    echo -e "${RED}❌ License Gate Failed: $LICENSE_DENIED package(s) have denied licenses${NC}"
    ISSUES_FOUND=true
    EXIT_CODE=1
    FAILURE_REASONS+=("## 🚨 License Policy Violations ($LICENSE_DENIED)")
    FAILURE_REASONS+=("")
    FAILURE_REASONS+=("The following packages use licenses that conflict with this project's policy:")
    FAILURE_REASONS+=("\`\`\`")
    while IFS= read -r line; do
        [[ -n "$line" ]] && FAILURE_REASONS+=("$line")
    done <<< "${DENIED_LICENSES_LIST:-}"
    FAILURE_REASONS+=("\`\`\`")
    FAILURE_REASONS+=("")
fi

# Supply chain integrity gate — fail on hash mismatches
if [[ "${HASH_TAMPERED:-0}" -gt 0 && "$WARNING_ONLY" != "true" ]]; then
    echo -e "${RED}❌ Supply Chain Gate Failed: $HASH_TAMPERED package hash mismatch(es) detected${NC}"
    ISSUES_FOUND=true
    EXIT_CODE=1
    FAILURE_REASONS+=("## 🚨 Supply Chain Integrity Violations ($HASH_TAMPERED)")
    FAILURE_REASONS+=("")
    FAILURE_REASONS+=("The following packages have SHA-256 hashes that do NOT match PyPI's published hashes:")
    FAILURE_REASONS+=("\`\`\`")
    if [[ -f "${HASH_VERIFY_FILE:-}" ]]; then
        jq -r '.tampered[] | "\(.name)==\(.version): found \(.sha256_found)"' "$HASH_VERIFY_FILE" 2>/dev/null | while read -r line; do
            FAILURE_REASONS+=("$line")
        done
    fi
    FAILURE_REASONS+=("\`\`\`")
    FAILURE_REASONS+=("")
fi

# Critical findings always fail the build — WARNING_ONLY does not suppress them.
if [[ "$FAIL_ON_CRITICAL" == "true" && $TOTAL_CRITICAL -gt 0 ]]; then
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
    
    if [[ -f "$CLAMAV_LOG" && "$CLAMAV_INFECTED" -gt 0 ]]; then
        FAILURE_REASONS+=("### ClamAV Malware Detection ($CLAMAV_INFECTED infected files)")
        FAILURE_REASONS+=("")
        FAILURE_REASONS+=("🚨 **CRITICAL:** Malware or infected files detected in the codebase!")
        FAILURE_REASONS+=("")
        FAILURE_REASONS+=("\`\`\`")
        grep "FOUND$" "$CLAMAV_LOG" 2>/dev/null | head -20 >> /tmp/severity-gate-summary.txt || true
        FAILURE_REASONS+=("$(cat /tmp/severity-gate-summary.txt)")
        FAILURE_REASONS+=("\`\`\`")
        FAILURE_REASONS+=("")
        rm -f /tmp/severity-gate-summary.txt
    fi
fi

# WARNING_ONLY suppresses high/medium gate failures but NOT critical findings above.
if [[ "$WARNING_ONLY" == "true" && $EXIT_CODE -eq 0 ]]; then
    echo -e "${YELLOW}⚠️  Warning Only Mode: non-critical findings will not fail the build${NC}"
    if [[ $TOTAL_HIGH -gt 0 || $TOTAL_MEDIUM -gt 0 ]]; then
        FAILURE_REASONS+=("## ⚠️ Warning Only Mode - Vulnerabilities Detected")
        FAILURE_REASONS+=("")
        FAILURE_REASONS+=("**Note:** Build configured to report but not fail on non-critical security findings.")
        FAILURE_REASONS+=("")
    fi
fi

if [[ "$FAIL_ON_HIGH" == "true" && "$WARNING_ONLY" != "true" && $TOTAL_HIGH -ge $HIGH_THRESHOLD ]]; then
    echo -e "${RED}❌ Build Gate Failed: $TOTAL_HIGH high severity findings detected (threshold: $HIGH_THRESHOLD)${NC}"
    echo -e "${RED}   Policy: FAIL_ON_HIGH=true, HIGH_THRESHOLD=$HIGH_THRESHOLD${NC}"
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
    
    if [[ -f "$CHECKOV_FILE" && ${CHECKOV_UNIQUE_FAILED:-0} -gt 0 ]]; then
        FAILURE_REASONS+=("### Checkov IaC Issues (${CHECKOV_UNIQUE_FAILED} unique failed checks)")
        FAILURE_REASONS+=("\`\`\`")
        jq -r '[.[]? | .results.failed_checks[]? | {check_id, check_name, file_path}] | unique_by(.check_id, .file_path) | .[] | "Check: \(.check_id) | File: \(.file_path) | \(.check_name)"' "$CHECKOV_FILE" 2>/dev/null | head -20 >> /tmp/severity-gate-summary.txt || true
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

# Write summary to GitHub Step Summary (always)
if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
    if [[ ${#FAILURE_REASONS[@]} -gt 0 ]]; then
        echo "# ❌ Security Gate Failure Report" >> "$GITHUB_STEP_SUMMARY"
    else
        echo "# ✅ Security Scan Summary" >> "$GITHUB_STEP_SUMMARY"
    fi
    echo "" >> "$GITHUB_STEP_SUMMARY"
    
    # Show scan metadata
    SCAN_USER="${GITHUB_ACTOR:-$(whoami)}"
    SCAN_ID=$(basename "$SCAN_DIR")
    SCAN_TIMESTAMP=$(date -u +"%Y-%m-%d %H:%M:%S UTC")
    echo "**Scan Details:**" >> "$GITHUB_STEP_SUMMARY"
    echo "- 👤 **Triggered by:** @$SCAN_USER" >> "$GITHUB_STEP_SUMMARY"
    echo "- 🆔 **Scan ID:** \`$SCAN_ID\`" >> "$GITHUB_STEP_SUMMARY"
    echo "- 🕐 **Timestamp:** $SCAN_TIMESTAMP" >> "$GITHUB_STEP_SUMMARY"
    echo "" >> "$GITHUB_STEP_SUMMARY"

    # Show skipped tools
    SKIPPED_TOOLS=()
    [[ "${SKIP_GARAK:-false}"         == "true" ]] && SKIPPED_TOOLS+=("Garak LLM")
    [[ "${SKIP_SBOM:-false}"          == "true" ]] && SKIPPED_TOOLS+=("SBOM")
    [[ "${SKIP_TRUFFLEHOG:-false}"    == "true" ]] && SKIPPED_TOOLS+=("TruffleHog")
    [[ "${SKIP_SONAR:-false}"         == "true" ]] && SKIPPED_TOOLS+=("SonarQube")
    [[ "${SKIP_CLAMAV:-false}"        == "true" ]] && SKIPPED_TOOLS+=("ClamAV")
    [[ "${SKIP_HELM:-false}"          == "true" ]] && SKIPPED_TOOLS+=("Helm")
    [[ "${SKIP_CHECKOV:-false}"       == "true" ]] && SKIPPED_TOOLS+=("Checkov")
    [[ "${SKIP_TRIVY:-false}"         == "true" ]] && SKIPPED_TOOLS+=("Trivy")
    [[ "${SKIP_GRYPE:-false}"         == "true" ]] && SKIPPED_TOOLS+=("Grype")
    [[ "${SKIP_XEOL:-false}"          == "true" ]] && SKIPPED_TOOLS+=("Xeol")
    [[ "${SKIP_ANCHORE:-false}"       == "true" ]] && SKIPPED_TOOLS+=("Anchore")
    [[ "${SKIP_API_DISCOVERY:-false}" == "true" ]] && SKIPPED_TOOLS+=("API Discovery")
    if [[ ${#SKIPPED_TOOLS[@]} -gt 0 ]]; then
        echo "" >> "$GITHUB_STEP_SUMMARY"
        echo "> ⏭️ **Skipped scans:** $(IFS=', '; echo "${SKIPPED_TOOLS[*]}")" >> "$GITHUB_STEP_SUMMARY"
    fi

    echo "" >> "$GITHUB_STEP_SUMMARY"
    echo "## 📊 Severity Summary" >> "$GITHUB_STEP_SUMMARY"
    echo "" >> "$GITHUB_STEP_SUMMARY"
    echo "**Total Findings:**" >> "$GITHUB_STEP_SUMMARY"
    echo "- 🔴 Critical: $TOTAL_CRITICAL" >> "$GITHUB_STEP_SUMMARY"
    echo "- 🟠 High: $TOTAL_HIGH" >> "$GITHUB_STEP_SUMMARY"
    echo "- 🟡 Medium: $TOTAL_MEDIUM" >> "$GITHUB_STEP_SUMMARY"
    echo "- 🟢 Low: $TOTAL_LOW" >> "$GITHUB_STEP_SUMMARY"
    echo "" >> "$GITHUB_STEP_SUMMARY"
    
    # Show high severity findings details (Checkov IaC and vulnerabilities)
    if [[ $TOTAL_HIGH -gt 0 ]] || [[ $TOTAL_CRITICAL -gt 0 ]]; then
        echo "## 🔴 High Severity Findings" >> "$GITHUB_STEP_SUMMARY"
        echo "" >> "$GITHUB_STEP_SUMMARY"
        
        # Show Checkov IaC issues if any
        if [[ ${CHECKOV_UNIQUE_FAILED:-0} -gt 0 ]]; then
            echo "### Checkov IaC Issues (${CHECKOV_UNIQUE_FAILED})" >> "$GITHUB_STEP_SUMMARY"
            CHECKOV_DISPLAY_FILE=$(find "$SCAN_DIR/checkov" -type f \( -name "results_json.json" -o -name "*checkov*results.json" \) 2>/dev/null | head -1)
            if [[ -f "$CHECKOV_DISPLAY_FILE" ]]; then
                jq -r '[.[]? | .results.failed_checks[]? | {check_id, check_name, file_path}] | unique_by(.check_id, .file_path) | .[] | "- `\(.check_id)`: \(.check_name) in `\(.file_path)`"' "$CHECKOV_DISPLAY_FILE" 2>/dev/null | head -20 >> "$GITHUB_STEP_SUMMARY"
            fi
            echo "" >> "$GITHUB_STEP_SUMMARY"
        fi
        
        # Calculate vulnerability counts (excluding Checkov IaC and TruffleHog secrets)
        if [[ -f "$FINDINGS_SUMMARY" ]]; then
            NON_CHECKOV_HIGH=$(jq '[.high_findings[] | select(.tool != "checkov" and .tool != "Checkov" and .tool != "TruffleHog")] | length' "$FINDINGS_SUMMARY" 2>/dev/null || echo "0")
            NON_CHECKOV_CRIT=$(jq '[.critical_findings[] | select(.tool != "checkov" and .tool != "Checkov" and .tool != "TruffleHog")] | length' "$FINDINGS_SUMMARY" 2>/dev/null || echo "0")
            VULN_COUNT=$((NON_CHECKOV_CRIT + NON_CHECKOV_HIGH))
        else
            VULN_COUNT=$((TOTAL_CRITICAL + TOTAL_HIGH - CHECKOV_UNIQUE_FAILED))
        fi
        
        # Only show CVE section if there are actual vulnerability findings (not just Checkov)
        if [[ $VULN_COUNT -gt 0 ]]; then
            if [[ -f "$FINDINGS_SUMMARY" ]]; then
                echo "### Vulnerabilities (CVEs)" >> "$GITHUB_STEP_SUMMARY"
                
                # Display critical findings (exclude Checkov IaC and TruffleHog secrets)
                CRIT_COUNT=$(jq '[.critical_findings[] | select(.tool != "checkov" and .tool != "Checkov" and .tool != "TruffleHog")] | length' "$FINDINGS_SUMMARY" 2>/dev/null || echo "0")
                if [[ $CRIT_COUNT -gt 0 ]]; then
                    jq -r '[.critical_findings[] | select(.tool != "checkov" and .tool != "Checkov" and .tool != "TruffleHog")] | .[] |
                        "- **CRITICAL**: `\(.vulnerability_id // .id // "unknown")` in \(.package_name // .package // "unknown")@\(.package_version // .version // "unknown")" +
                        (if (.package_path // "") != "" then " @ `\(.package_path)`" else "" end) +
                        " (\(.tool))"' "$FINDINGS_SUMMARY" 2>/dev/null >> "$GITHUB_STEP_SUMMARY"
                fi
                
                # Display high findings (exclude Checkov IaC and TruffleHog secrets)
                HIGH_COUNT=$(jq '[.high_findings[] | select(.tool != "checkov" and .tool != "Checkov" and .tool != "TruffleHog")] | length' "$FINDINGS_SUMMARY" 2>/dev/null || echo "0")
                if [[ $HIGH_COUNT -gt 0 ]]; then
                    jq -r '[.high_findings[] | select(.tool != "checkov" and .tool != "Checkov" and .tool != "TruffleHog")] |
                        .[] |
                        "- **HIGH**: `\(.vulnerability_id // .id // "unknown")` in \(.package_name // .package // "unknown")@\(.package_version // .version // "unknown")" +
                        (if (.package_path // "") != "" then " @ `\(.package_path)`" else "" end) +
                        " (\(.tool))"' "$FINDINGS_SUMMARY" 2>/dev/null >> "$GITHUB_STEP_SUMMARY"
                fi
                
                echo "" >> "$GITHUB_STEP_SUMMARY"
                echo "*Note: Suppressed vulnerabilities are not displayed (see .epyon-ignore.yml)*" >> "$GITHUB_STEP_SUMMARY"
                echo "" >> "$GITHUB_STEP_SUMMARY"
            fi
        fi
        
        # Show TruffleHog secrets in separate Misconfigurations section
        if [[ -f "$FINDINGS_SUMMARY" ]]; then
            TRUFFLEHOG_CRIT=$(jq '[.critical_findings[] | select(.tool == "TruffleHog")] | length' "$FINDINGS_SUMMARY" 2>/dev/null || echo "0")
            TRUFFLEHOG_HIGH=$(jq '[.high_findings[] | select(.tool == "TruffleHog")] | length' "$FINDINGS_SUMMARY" 2>/dev/null || echo "0")
            TRUFFLEHOG_TOTAL=$((TRUFFLEHOG_CRIT + TRUFFLEHOG_HIGH))
            
            if [[ $TRUFFLEHOG_TOTAL -gt 0 ]]; then
                echo "### Misconfigurations (Secrets)" >> "$GITHUB_STEP_SUMMARY"
                
                if [[ $TRUFFLEHOG_CRIT -gt 0 ]]; then
                    jq -r '[.critical_findings[] | select(.tool == "TruffleHog")] | .[] |
                        "- **CRITICAL**: `\(.detector)` secret in `\(.file_path // "unknown"):\(.line_number // "?")` (\(.tool))"' \
                        "$FINDINGS_SUMMARY" 2>/dev/null >> "$GITHUB_STEP_SUMMARY"
                fi
                
                if [[ $TRUFFLEHOG_HIGH -gt 0 ]]; then
                    jq -r '[.high_findings[] | select(.tool == "TruffleHog")] | .[] |
                        "- **HIGH**: `\(.detector)` secret in `\(.file_path // "unknown"):\(.line_number // "?")` (\(.tool))"' \
                        "$FINDINGS_SUMMARY" 2>/dev/null >> "$GITHUB_STEP_SUMMARY"
                fi
                
                echo "" >> "$GITHUB_STEP_SUMMARY"
                echo "*Note: Suppressed secrets are not displayed (see .epyon-ignore.yml)*" >> "$GITHUB_STEP_SUMMARY"
                echo "" >> "$GITHUB_STEP_SUMMARY"
            fi
        fi
    fi
    
    # Only show failure details if there are failures
    if [[ ${#FAILURE_REASONS[@]} -gt 0 ]]; then
        echo "## ⚠️ Gate Failures" >> "$GITHUB_STEP_SUMMARY"
        for line in "${FAILURE_REASONS[@]}"; do
            echo "$line" >> "$GITHUB_STEP_SUMMARY"
        done
        echo "" >> "$GITHUB_STEP_SUMMARY"
    fi
    
    echo "---" >> "$GITHUB_STEP_SUMMARY"
    echo "*Review the full scan results in the workflow artifacts for complete details.*" >> "$GITHUB_STEP_SUMMARY"
fi

exit $EXIT_CODE
