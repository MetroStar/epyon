 #!/bin/bash

# Critical and High Severity Findings Summary Script
# Analyzes all security scan results and extracts CRITICAL and HIGH severity findings
# Updated for comprehensive security architecture

# Colors for output
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# Set up paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPORTS_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")/reports"
OUTPUT_FILE="$REPORTS_ROOT/security-reports/critical-high-findings-summary.json"
OUTPUT_HTML="$REPORTS_ROOT/security-reports/critical-high-findings-summary.html"

# Create output directory
mkdir -p "$(dirname "$OUTPUT_FILE")"

echo
echo -e "${WHITE}============================================${NC}"
echo -e "${WHITE}🚨 Critical & High Severity Findings Summary${NC}"
echo -e "${WHITE}============================================${NC}"
echo

# Initialize summary object
cat > "$OUTPUT_FILE" << 'EOF'
{
  "summary": {
    "scan_timestamp": "",
    "total_critical": 0,
    "total_high": 0,
    "tools_analyzed": [],
    "summary_by_tool": {}
  },
  "critical_findings": [],
  "high_findings": []
}
EOF

# Add scan metadata
TARGET_NAME=$(basename "${TARGET_DIR:-$(pwd)}")
USERNAME=$(whoami)
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
SCAN_ID="${TARGET_NAME}_${USERNAME}_$(date '+%Y-%m-%d_%H-%M-%S')"
jq --arg ts "$TIMESTAMP" --arg id "$SCAN_ID" '.summary.scan_timestamp = $ts | .summary.scan_id = $id' "$OUTPUT_FILE" > "${OUTPUT_FILE}.tmp" && mv "${OUTPUT_FILE}.tmp" "$OUTPUT_FILE"

TOTAL_CRITICAL=0
TOTAL_HIGH=0
TOOLS_FOUND=()

echo -e "${BLUE}📊 Analyzing security scan results...${NC}"
echo

# Function to analyze Trivy results
analyze_trivy() {
    echo -e "${BLUE}🔍 Analyzing Trivy (Container Security) results...${NC}"
    local trivy_critical=0
    local trivy_high=0
    local findings=()
    
    for file in "$REPORTS_ROOT"/trivy-reports/trivy-*-results.json; do
        if [ -f "$file" ]; then
            local basename_file=$(basename "$file")
            echo "  📄 Processing: $basename_file"
            
            # Extract CRITICAL vulnerabilities
            if command -v jq &> /dev/null; then
                local critical_vulns=$(jq -r '.Results[]?.Vulnerabilities[]? | select(.Severity == "CRITICAL") | .VulnerabilityID + ": " + .Title + " (Package: " + .PkgName + ")"' "$file" 2>/dev/null || echo "")
                if [ ! -z "$critical_vulns" ]; then
                    while IFS= read -r vuln; do
                        if [ ! -z "$vuln" ]; then
                            findings+=("{\"severity\": \"CRITICAL\", \"tool\": \"Trivy\", \"source\": \"$basename_file\", \"finding\": \"$vuln\"}")
                            ((trivy_critical++))
                        fi
                    done <<< "$critical_vulns"
                fi
                
                # Extract HIGH vulnerabilities
                local high_vulns=$(jq -r '.Results[]?.Vulnerabilities[]? | select(.Severity == "HIGH") | .VulnerabilityID + ": " + .Title + " (Package: " + .PkgName + ")"' "$file" 2>/dev/null || echo "")
                if [ ! -z "$high_vulns" ]; then
                    while IFS= read -r vuln; do
                        if [ ! -z "$vuln" ]; then
                            findings+=("{\"severity\": \"HIGH\", \"tool\": \"Trivy\", \"source\": \"$basename_file\", \"finding\": \"$vuln\"}")
                            ((trivy_high++))
                        fi
                    done <<< "$high_vulns"
                fi
            fi
        fi
    done
    
    if [ ${#findings[@]} -gt 0 ]; then
        # Add findings to JSON
        for finding in "${findings[@]}"; do
            if [[ "$finding" == *"CRITICAL"* ]]; then
                jq --argjson finding "$finding" '.critical_findings += [$finding]' "$OUTPUT_FILE" > "${OUTPUT_FILE}.tmp" && mv "${OUTPUT_FILE}.tmp" "$OUTPUT_FILE"
            else
                jq --argjson finding "$finding" '.high_findings += [$finding]' "$OUTPUT_FILE" > "${OUTPUT_FILE}.tmp" && mv "${OUTPUT_FILE}.tmp" "$OUTPUT_FILE"
            fi
        done
    fi
    
    TOTAL_CRITICAL=$((TOTAL_CRITICAL + trivy_critical))
    TOTAL_HIGH=$((TOTAL_HIGH + trivy_high))
    TOOLS_FOUND+=("Trivy")
    
    # Update summary
    jq --arg tool "Trivy" --argjson crit "$trivy_critical" --argjson high "$trivy_high" \
       '.summary.summary_by_tool[$tool] = {"critical": $crit, "high": $high}' \
       "$OUTPUT_FILE" > "${OUTPUT_FILE}.tmp" && mv "${OUTPUT_FILE}.tmp" "$OUTPUT_FILE"
    
    echo "    🚨 Critical: $trivy_critical, ⚠️  High: $trivy_high"
}

# Function to analyze Grype results
analyze_grype() {
    echo -e "${BLUE}🔍 Analyzing Grype (Vulnerability Detection) results...${NC}"
    local grype_critical=0
    local grype_high=0
    local findings=()
    
    for file in "$REPORTS_ROOT"/grype-reports/grype-*-results.json; do
        if [ -f "$file" ]; then
            local basename_file=$(basename "$file")
            echo "  📄 Processing: $basename_file"
            
            if command -v jq &> /dev/null; then
                # Extract CRITICAL vulnerabilities
                local critical_vulns=$(jq -r '.matches[]? | select(.vulnerability.severity == "Critical") | .vulnerability.id + ": " + .vulnerability.description + " (Package: " + .artifact.name + ")"' "$file" 2>/dev/null || echo "")
                if [ ! -z "$critical_vulns" ]; then
                    while IFS= read -r vuln; do
                        if [ ! -z "$vuln" ]; then
                            findings+=("{\"severity\": \"CRITICAL\", \"tool\": \"Grype\", \"source\": \"$basename_file\", \"finding\": \"$vuln\"}")
                            ((grype_critical++))
                        fi
                    done <<< "$critical_vulns"
                fi
                
                # Extract HIGH vulnerabilities
                local high_vulns=$(jq -r '.matches[]? | select(.vulnerability.severity == "High") | .vulnerability.id + ": " + .vulnerability.description + " (Package: " + .artifact.name + ")"' "$file" 2>/dev/null || echo "")
                if [ ! -z "$high_vulns" ]; then
                    while IFS= read -r vuln; do
                        if [ ! -z "$vuln" ]; then
                            findings+=("{\"severity\": \"HIGH\", \"tool\": \"Grype\", \"source\": \"$basename_file\", \"finding\": \"$vuln\"}")
                            ((grype_high++))
                        fi
                    done <<< "$high_vulns"
                fi
            fi
        fi
    done
    
    if [ ${#findings[@]} -gt 0 ]; then
        # Add findings to JSON
        for finding in "${findings[@]}"; do
            if [[ "$finding" == *"CRITICAL"* ]]; then
                jq --argjson finding "$finding" '.critical_findings += [$finding]' "$OUTPUT_FILE" > "${OUTPUT_FILE}.tmp" && mv "${OUTPUT_FILE}.tmp" "$OUTPUT_FILE"
            else
                jq --argjson finding "$finding" '.high_findings += [$finding]' "$OUTPUT_FILE" > "${OUTPUT_FILE}.tmp" && mv "${OUTPUT_FILE}.tmp" "$OUTPUT_FILE"
            fi
        done
    fi
    
    TOTAL_CRITICAL=$((TOTAL_CRITICAL + grype_critical))
    TOTAL_HIGH=$((TOTAL_HIGH + grype_high))
    TOOLS_FOUND+=("Grype")
    
    # Update summary
    jq --arg tool "Grype" --argjson crit "$grype_critical" --argjson high "$grype_high" \
       '.summary.summary_by_tool[$tool] = {"critical": $crit, "high": $high}' \
       "$OUTPUT_FILE" > "${OUTPUT_FILE}.tmp" && mv "${OUTPUT_FILE}.tmp" "$OUTPUT_FILE"
    
    echo "    🚨 Critical: $grype_critical, ⚠️  High: $grype_high"
}

# Function to analyze TruffleHog results (secrets are always HIGH)
analyze_trufflehog() {
    echo -e "${BLUE}🔍 Analyzing TruffleHog (Secret Detection) results...${NC}"
    local trufflehog_high=0
    local findings=()
    
    for file in "$REPORTS_ROOT"/trufflehog-reports/trufflehog-*-results.json; do
        if [ -f "$file" ]; then
            local basename_file=$(basename "$file")
            echo "  📄 Processing: $basename_file"
            
            if command -v jq &> /dev/null; then
                # All secrets are treated as HIGH severity
                local secrets=$(jq -r '.[] | select(.Verified == true) | .DetectorName + ": Verified secret found in " + .SourceMetadata.Data.Filesystem.file' "$file" 2>/dev/null || echo "")
                if [ ! -z "$secrets" ]; then
                    while IFS= read -r secret; do
                        if [ ! -z "$secret" ]; then
                            findings+=("{\"severity\": \"HIGH\", \"tool\": \"TruffleHog\", \"source\": \"$basename_file\", \"finding\": \"$secret\"}")
                            ((trufflehog_high++))
                        fi
                    done <<< "$secrets"
                fi
                
                # Also check unverified secrets (lower priority but still HIGH)
                local unverified_secrets=$(jq -r '.[] | select(.Verified == false) | .DetectorName + ": Potential secret found in " + .SourceMetadata.Data.Filesystem.file' "$file" 2>/dev/null || echo "")
                if [ ! -z "$unverified_secrets" ]; then
                    while IFS= read -r secret; do
                        if [ ! -z "$secret" ]; then
                            findings+=("{\"severity\": \"HIGH\", \"tool\": \"TruffleHog\", \"source\": \"$basename_file\", \"finding\": \"$secret\"}")
                            ((trufflehog_high++))
                        fi
                    done <<< "$unverified_secrets"
                fi
            fi
        fi
    done
    
    if [ ${#findings[@]} -gt 0 ]; then
        # Add findings to JSON
        for finding in "${findings[@]}"; do
            jq --argjson finding "$finding" '.high_findings += [$finding]' "$OUTPUT_FILE" > "${OUTPUT_FILE}.tmp" && mv "${OUTPUT_FILE}.tmp" "$OUTPUT_FILE"
        done
    fi
    
    TOTAL_HIGH=$((TOTAL_HIGH + trufflehog_high))
    TOOLS_FOUND+=("TruffleHog")
    
    # Update summary
    jq --arg tool "TruffleHog" --argjson crit "0" --argjson high "$trufflehog_high" \
       '.summary.summary_by_tool[$tool] = {"critical": $crit, "high": $high}' \
       "$OUTPUT_FILE" > "${OUTPUT_FILE}.tmp" && mv "${OUTPUT_FILE}.tmp" "$OUTPUT_FILE"
    
    echo "    🚨 Critical: 0, ⚠️  High: $trufflehog_high"
}

# Function to analyze Checkov results (look for HIGH/CRITICAL findings)
analyze_checkov() {
    echo -e "${BLUE}🔍 Analyzing Checkov (Infrastructure Security) results...${NC}"
    local checkov_critical=0
    local checkov_high=0
    local findings=()
    
    for file in "$REPORTS_ROOT"/checkov-reports/*results*.json; do
        if [ -f "$file" ]; then
            local basename_file=$(basename "$file")
            echo "  📄 Processing: $basename_file"
            
            if command -v jq &> /dev/null; then
                # Look for failed checks (security issues)
                local failed_checks=$(jq -r '.results.failed_checks[]? | select(.severity == "HIGH" or .severity == "CRITICAL") | .severity + ": " + .check_name + " (" + .file_path + ")"' "$file" 2>/dev/null || echo "")
                if [ ! -z "$failed_checks" ]; then
                    while IFS= read -r check; do
                        if [ ! -z "$check" ]; then
                            if [[ "$check" == CRITICAL* ]]; then
                                findings+=("{\"severity\": \"CRITICAL\", \"tool\": \"Checkov\", \"source\": \"$basename_file\", \"finding\": \"$check\"}")
                                ((checkov_critical++))
                            elif [[ "$check" == HIGH* ]]; then
                                findings+=("{\"severity\": \"HIGH\", \"tool\": \"Checkov\", \"source\": \"$basename_file\", \"finding\": \"$check\"}")
                                ((checkov_high++))
                            fi
                        fi
                    done <<< "$failed_checks"
                fi
            fi
        fi
    done
    
    if [ ${#findings[@]} -gt 0 ]; then
        # Add findings to JSON
        for finding in "${findings[@]}"; do
            if [[ "$finding" == *"CRITICAL"* ]]; then
                jq --argjson finding "$finding" '.critical_findings += [$finding]' "$OUTPUT_FILE" > "${OUTPUT_FILE}.tmp" && mv "${OUTPUT_FILE}.tmp" "$OUTPUT_FILE"
            else
                jq --argjson finding "$finding" '.high_findings += [$finding]' "$OUTPUT_FILE" > "${OUTPUT_FILE}.tmp" && mv "${OUTPUT_FILE}.tmp" "$OUTPUT_FILE"
            fi
        done
    fi
    
    TOTAL_CRITICAL=$((TOTAL_CRITICAL + checkov_critical))
    TOTAL_HIGH=$((TOTAL_HIGH + checkov_high))
    TOOLS_FOUND+=("Checkov")
    
    # Update summary
    jq --arg tool "Checkov" --argjson crit "$checkov_critical" --argjson high "$checkov_high" \
       '.summary.summary_by_tool[$tool] = {"critical": $crit, "high": $high}' \
       "$OUTPUT_FILE" > "${OUTPUT_FILE}.tmp" && mv "${OUTPUT_FILE}.tmp" "$OUTPUT_FILE"
    
    echo "    🚨 Critical: $checkov_critical, ⚠️  High: $checkov_high"
}

# Run analysis for each tool
if [ -d "$REPORTS_ROOT/trivy-reports" ]; then
    analyze_trivy
fi

if [ -d "$REPORTS_ROOT/grype-reports" ]; then
    analyze_grype
fi

if [ -d "$REPORTS_ROOT/trufflehog-reports" ]; then
    analyze_trufflehog
fi

if [ -d "$REPORTS_ROOT/checkov-reports" ]; then
    analyze_checkov
fi

# Update final totals
jq --argjson total_crit "$TOTAL_CRITICAL" --argjson total_high "$TOTAL_HIGH" \
   '.summary.total_critical = $total_crit | .summary.total_high = $total_high' \
   "$OUTPUT_FILE" > "${OUTPUT_FILE}.tmp" && mv "${OUTPUT_FILE}.tmp" "$OUTPUT_FILE"

# Update tools analyzed
TOOLS_JSON=$(printf '%s\n' "${TOOLS_FOUND[@]}" | jq -R . | jq -s .)
jq --argjson tools "$TOOLS_JSON" '.summary.tools_analyzed = $tools' "$OUTPUT_FILE" > "${OUTPUT_FILE}.tmp" && mv "${OUTPUT_FILE}.tmp" "$OUTPUT_FILE"

# Generate HTML report
cat > "$OUTPUT_HTML" << EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Critical & High Severity Findings Summary</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { text-align: center; margin-bottom: 30px; }
        .summary-cards { display: flex; gap: 20px; margin-bottom: 30px; flex-wrap: wrap; }
        .card { flex: 1; min-width: 200px; padding: 20px; border-radius: 8px; text-align: center; }
        .critical-card { background: linear-gradient(135deg, #ff6b6b, #ee5a52); color: white; }
        .high-card { background: linear-gradient(135deg, #ffa726, #ff9800); color: white; }
        .info-card { background: linear-gradient(135deg, #42a5f5, #2196f3); color: white; }
        .card h3 { margin: 0 0 10px 0; font-size: 18px; }
        .card .number { font-size: 36px; font-weight: bold; margin: 10px 0; }
        .findings-section { margin: 30px 0; }
        .findings-section h2 { color: #333; border-bottom: 2px solid #ddd; padding-bottom: 10px; }
        .finding-item { background: #f9f9f9; margin: 10px 0; padding: 15px; border-radius: 5px; border-left: 4px solid #ddd; }
        .finding-item.critical { border-left-color: #ff6b6b; }
        .finding-item.high { border-left-color: #ffa726; }
        .tool-badge { display: inline-block; background: #e3f2fd; color: #1976d2; padding: 4px 8px; border-radius: 4px; font-size: 12px; margin-right: 10px; }
        .severity-badge { display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; margin-right: 10px; }
        .severity-badge.critical { background: #ff6b6b; color: white; }
        .severity-badge.high { background: #ffa726; color: white; }
        .timestamp { text-align: center; color: #666; margin-top: 30px; font-size: 14px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🚨 Critical & High Severity Findings Summary</h1>
            <p>Comprehensive Security Architecture Analysis</p>
        </div>
        
        <div class="summary-cards">
            <div class="card critical-card">
                <h3>Critical Findings</h3>
                <div class="number">$TOTAL_CRITICAL</div>
                <p>Immediate attention required</p>
            </div>
            <div class="card high-card">
                <h3>High Findings</h3>
                <div class="number">$TOTAL_HIGH</div>
                <p>Should be addressed soon</p>
            </div>
            <div class="card info-card">
                <h3>Tools Analyzed</h3>
                <div class="number">${#TOOLS_FOUND[@]}</div>
                <p>Security scanners</p>
            </div>
        </div>
        
        <div class="findings-section">
            <h2>🔥 Critical Findings (Immediate Action Required)</h2>
            <div id="critical-findings"></div>
        </div>
        
        <div class="findings-section">
            <h2>⚠️ High Severity Findings (High Priority)</h2>
            <div id="high-findings"></div>
        </div>
        
        <div class="timestamp">
            Report generated: $TIMESTAMP
        </div>
    </div>
    
    <script>
        // Load findings from JSON and populate HTML
        fetch('critical-high-findings-summary.json')
            .then(response => response.json())
            .then(data => {
                const criticalDiv = document.getElementById('critical-findings');
                const highDiv = document.getElementById('high-findings');
                
                if (data.critical_findings.length === 0) {
                    criticalDiv.innerHTML = '<p style="color: #4caf50; font-style: italic;">✅ No critical findings detected!</p>';
                } else {
                    data.critical_findings.forEach(finding => {
                        const div = document.createElement('div');
                        div.className = 'finding-item critical';
                        div.innerHTML = \`
                            <span class="severity-badge critical">CRITICAL</span>
                            <span class="tool-badge">\${finding.tool}</span>
                            <strong>\${finding.finding}</strong>
                            <br><small>Source: \${finding.source}</small>
                        \`;
                        criticalDiv.appendChild(div);
                    });
                }
                
                if (data.high_findings.length === 0) {
                    highDiv.innerHTML = '<p style="color: #4caf50; font-style: italic;">✅ No high severity findings detected!</p>';
                } else {
                    data.high_findings.forEach(finding => {
                        const div = document.createElement('div');
                        div.className = 'finding-item high';
                        div.innerHTML = \`
                            <span class="severity-badge high">HIGH</span>
                            <span class="tool-badge">\${finding.tool}</span>
                            <strong>\${finding.finding}</strong>
                            <br><small>Source: \${finding.source}</small>
                        \`;
                        highDiv.appendChild(div);
                    });
                }
            })
            .catch(error => {
                console.error('Error loading findings:', error);
                document.getElementById('critical-findings').innerHTML = '<p style="color: red;">Error loading critical findings data</p>';
                document.getElementById('high-findings').innerHTML = '<p style="color: red;">Error loading high findings data</p>';
            });
    </script>
</body>
</html>
EOF

echo
echo -e "${WHITE}============================================${NC}"
echo -e "${WHITE}📊 CRITICAL & HIGH SEVERITY SUMMARY${NC}"
echo -e "${WHITE}============================================${NC}"
echo
echo -e "${RED}🚨 CRITICAL FINDINGS: $TOTAL_CRITICAL${NC}"
echo -e "${YELLOW}⚠️  HIGH SEVERITY FINDINGS: $TOTAL_HIGH${NC}"
echo
echo -e "${BLUE}🔧 Tools Analyzed: ${TOOLS_FOUND[*]}${NC}"
echo
echo -e "${BLUE}📁 Reports Generated:${NC}"
echo "📄 JSON Report: $OUTPUT_FILE"
echo "🌐 HTML Report: $OUTPUT_HTML"
echo
echo -e "${WHITE}============================================${NC}"

if [ $TOTAL_CRITICAL -gt 0 ]; then
    echo -e "${RED}⚠️  CRITICAL ISSUES FOUND - IMMEDIATE ACTION REQUIRED!${NC}"
elif [ $TOTAL_HIGH -gt 0 ]; then
    echo -e "${YELLOW}⚠️  HIGH SEVERITY ISSUES FOUND - SHOULD BE ADDRESSED${NC}"
else
    echo -e "${NC}✅ No critical or high severity issues found!${NC}"
fi

echo -e "${WHITE}============================================${NC}"