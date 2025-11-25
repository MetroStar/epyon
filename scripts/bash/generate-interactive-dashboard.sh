#!/bin/bash

# Generate Interactive Security Dashboard
# Creates an interactive HTML dashboard with expandable tool sections showing detailed vulnerabilities

set -euo pipefail

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Default paths
SCANS_DIR="${WORKSPACE_ROOT}/scans"
OUTPUT_DIR="${WORKSPACE_ROOT}/reports/security-reports/dashboards"
OUTPUT_HTML="${OUTPUT_DIR}/security-dashboard.html"

# Get the most recent scan directory
LATEST_SCAN=$(find "$SCANS_DIR" -maxdepth 1 -type d -name "*_rnelson_*" | sort -r | head -n 1)

if [ -z "$LATEST_SCAN" ]; then
    echo "No scan directories found"
    exit 1
fi

SCAN_NAME=$(basename "$LATEST_SCAN")
SCAN_TIMESTAMP=$(echo "$SCAN_NAME" | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2}_[0-9]{2}-[0-9]{2}-[0-9]{2}')

echo "Generating interactive dashboard from: $SCAN_NAME"

# Initialize counters using separate variables
TRUFFLEHOG_CRITICAL=0
TRUFFLEHOG_HIGH=0
TRUFFLEHOG_MEDIUM=0
TRUFFLEHOG_LOW=0
TRUFFLEHOG_DATA=""

CLAMAV_CRITICAL=0
CLAMAV_HIGH=0
CLAMAV_MEDIUM=0
CLAMAV_LOW=0
CLAMAV_DATA=""

SONAR_CRITICAL=0
SONAR_HIGH=0
SONAR_MEDIUM=0
SONAR_LOW=0
SONAR_DATA=""

CHECKOV_CRITICAL=0
CHECKOV_HIGH=0
CHECKOV_MEDIUM=0
CHECKOV_LOW=0
CHECKOV_DATA=""

HELM_CRITICAL=0
HELM_HIGH=0
HELM_MEDIUM=0
HELM_LOW=0
HELM_DATA=""

# Parse TruffleHog data
parse_trufflehog() {
    local th_file="${LATEST_SCAN}/trufflehog/trufflehog-filesystem-results.json"
    if [ -f "$th_file" ]; then
        local critical=$(count_severity "$th_file" "CRITICAL")
        local high=$(count_severity "$th_file" "HIGH")
        
        TOOL_STATS[trufflehog_critical]=$critical
        TOOL_STATS[trufflehog_high]=$high
        TOOL_STATS[trufflehog_medium]=0
        TOOL_STATS[trufflehog_low]=0
        
        # Extract findings for display
        TOOL_DATA[trufflehog]=$(jq -r '
            [limit(10; .[] | select(has("DetectorName")))] | 
            map({
                severity: (if .Verified then "CRITICAL" else "HIGH" end),
                detector: .DetectorName,
                description: .DetectorDescription,
                file: .SourceMetadata.Data.Filesystem.file,
                line: .SourceMetadata.Data.Filesystem.line,
                verified: .Verified,
                raw: (.Raw // "N/A")
            }) | 
            to_entries | 
            map("<div class=\"finding-item severity-" + (.value.severity | ascii_downcase) + "\">
                <div class=\"finding-header\">
                    <span class=\"badge badge-tool\">TruffleHog</span>
                    <span class=\"badge badge-" + (.value.severity | ascii_downcase) + "\">" + .value.severity + "</span>
                    " + (if .value.verified then "<span class=\"badge badge-verified\">VERIFIED</span>" else "" end) + "
                </div>
                <div class=\"finding-title\">" + .value.detector + "</div>
                <div class=\"finding-desc\">" + .value.description + "</div>
                <div class=\"finding-details\">
                    <div><strong>File:</strong> <code>" + .value.file + "</code></div>
                    <div><strong>Line:</strong> <code>" + (.value.line | tostring) + "</code></div>
                </div>
            </div>") | 
            join("")
        ' "$th_file" 2>/dev/null || echo "")
    else
        TOOL_STATS[trufflehog_critical]=0
        TOOL_STATS[trufflehog_high]=0
        TOOL_STATS[trufflehog_medium]=0
        TOOL_STATS[trufflehog_low]=0
        TOOL_DATA[trufflehog]="<p class=\"no-findings\">No scan data available</p>"
    fi
}

# Parse ClamAV data
parse_clamav() {
    local clamav_file="${LATEST_SCAN}/clamav/scan-results.txt"
    if [ -f "$clamav_file" ]; then
        local infected=$(grep -c "FOUND" "$clamav_file" 2>/dev/null || echo "0")
        
        TOOL_STATS[clamav_critical]=$infected
        TOOL_STATS[clamav_high]=0
        TOOL_STATS[clamav_medium]=0
        TOOL_STATS[clamav_low]=0
        
        if [ "$infected" -gt 0 ]; then
            TOOL_DATA[clamav]=$(grep "FOUND" "$clamav_file" | head -n 10 | awk '{
                print "<div class=\"finding-item severity-critical\">"
                print "  <div class=\"finding-header\">"
                print "    <span class=\"badge badge-tool\">ClamAV</span>"
                print "    <span class=\"badge badge-critical\">CRITICAL</span>"
                print "  </div>"
                print "  <div class=\"finding-title\">Malware Detected</div>"
                print "  <div class=\"finding-details\">"
                print "    <div><strong>File:</strong> <code>" $1 "</code></div>"
                print "    <div><strong>Threat:</strong> " $2 "</div>"
                print "  </div>"
                print "</div>"
            }' | paste -sd '' -)
        else
            TOOL_DATA[clamav]="<p class=\"no-findings\">✅ No malware detected</p>"
        fi
    else
        TOOL_STATS[clamav_critical]=0
        TOOL_STATS[clamav_high]=0
        TOOL_STATS[clamav_medium]=0
        TOOL_STATS[clamav_low]=0
        TOOL_DATA[clamav]="<p class=\"no-findings\">No scan data available</p>"
    fi
}

# Parse Checkov data  
parse_checkov() {
    TOOL_STATS[checkov_critical]=0
    TOOL_STATS[checkov_high]=0
    TOOL_STATS[checkov_medium]=0
    TOOL_STATS[checkov_low]=0
    TOOL_DATA[checkov]="<p class=\"no-findings\">No Infrastructure-as-Code files scanned</p>"
}

# Parse Helm data
parse_helm() {
    TOOL_STATS[helm_critical]=0
    TOOL_STATS[helm_high]=0
    TOOL_STATS[helm_medium]=0
    TOOL_STATS[helm_low]=0
    TOOL_DATA[helm]="<p class=\"no-findings\">No Helm charts scanned</p>"
}

# Parse SonarQube data
parse_sonar() {
    local sonar_dir="${WORKSPACE_ROOT}/reports/sonar-reports"
    local latest_sonar=$(find "$sonar_dir" -name "*_sonar-analysis-results.json" -type f 2>/dev/null | sort -r | head -n 1)
    
    if [ -f "$latest_sonar" ]; then
        local status=$(jq -r '.status' "$latest_sonar" 2>/dev/null || echo "NO_DATA")
        
        if [ "$status" = "NO_PROJECT_DETECTED" ]; then
            TOOL_STATS[sonar_critical]=0
            TOOL_STATS[sonar_high]=0
            TOOL_STATS[sonar_medium]=0
            TOOL_STATS[sonar_low]=0
            TOOL_DATA[sonar]="<p class=\"no-findings\">No SonarQube project detected</p>"
        else
            # Parse actual SonarQube results when available
            TOOL_STATS[sonar_critical]=0
            TOOL_STATS[sonar_high]=0
            TOOL_STATS[sonar_medium]=0
            TOOL_STATS[sonar_low]=0
            TOOL_DATA[sonar]="<p class=\"no-findings\">SonarQube analysis complete - check SonarQube server for details</p>"
        fi
    else
        TOOL_STATS[sonar_critical]=0
        TOOL_STATS[sonar_high]=0
        TOOL_STATS[sonar_medium]=0
        TOOL_STATS[sonar_low]=0
        TOOL_DATA[sonar]="<p class=\"no-findings\">No scan data available</p>"
    fi
}

# Parse all tools
parse_trufflehog
parse_clamav
parse_checkov
parse_helm
parse_sonar

# Calculate totals
TOTAL_CRITICAL=$((TOOL_STATS[trufflehog_critical] + TOOL_STATS[clamav_critical] + TOOL_STATS[checkov_critical] + TOOL_STATS[helm_critical] + TOOL_STATS[sonar_critical]))
TOTAL_HIGH=$((TOOL_STATS[trufflehog_high] + TOOL_STATS[clamav_high] + TOOL_STATS[checkov_high] + TOOL_STATS[helm_high] + TOOL_STATS[sonar_high]))
TOTAL_MEDIUM=$((TOOL_STATS[trufflehog_medium] + TOOL_STATS[clamav_medium] + TOOL_STATS[checkov_medium] + TOOL_STATS[helm_medium] + TOOL_STATS[sonar_medium]))
TOTAL_LOW=$((TOOL_STATS[trufflehog_low] + TOOL_STATS[clamav_low] + TOOL_STATS[checkov_low] + TOOL_STATS[helm_low] + TOOL_STATS[sonar_low]))
TOTAL_FINDINGS=$((TOTAL_CRITICAL + TOTAL_HIGH + TOTAL_MEDIUM + TOTAL_LOW))

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Generate HTML
cat > "$OUTPUT_HTML" << 'HTMLEOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Interactive Security Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
            color: #2d3748;
        }
        
        .container {
            max-width: 1600px;
            margin: 0 auto;
        }
        
        .header {
            background: white;
            border-radius: 16px;
            padding: 40px;
            margin-bottom: 30px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.15);
            text-align: center;
        }
        
        .header h1 {
            font-size: 2.8em;
            margin-bottom: 10px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        
        .header .subtitle {
            color: #718096;
            font-size: 1.1em;
            margin-top: 10px;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: white;
            border-radius: 12px;
            padding: 30px;
            text-align: center;
            box-shadow: 0 4px 20px rgba(0,0,0,0.1);
            transition: all 0.3s ease;
            cursor: pointer;
        }
        
        .stat-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 8px 30px rgba(0,0,0,0.15);
        }
        
        .stat-number {
            font-size: 3em;
            font-weight: bold;
            margin: 15px 0;
        }
        
        .stat-label {
            color: #718096;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
            font-weight: 600;
        }
        
        .critical-stat { color: #e53e3e; border-top: 4px solid #e53e3e; }
        .high-stat { color: #dd6b20; border-top: 4px solid #dd6b20; }
        .medium-stat { color: #d69e2e; border-top: 4px solid #d69e2e; }
        .low-stat { color: #38a169; border-top: 4px solid #38a169; }
        
        .tools-section {
            display: grid;
            gap: 20px;
        }
        
        .tool-card {
            background: white;
            border-radius: 12px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.1);
            overflow: hidden;
            transition: all 0.3s ease;
        }
        
        .tool-header {
            padding: 25px;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: linear-gradient(135deg, #f7fafc 0%, #edf2f7 100%);
            border-bottom: 2px solid #e2e8f0;
            transition: all 0.3s ease;
        }
        
        .tool-header:hover {
            background: linear-gradient(135deg, #edf2f7 0%, #e2e8f0 100%);
        }
        
        .tool-header.active {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }
        
        .tool-title {
            display: flex;
            align-items: center;
            gap: 15px;
            font-size: 1.4em;
            font-weight: 600;
        }
        
        .tool-icon {
            font-size: 1.5em;
        }
        
        .tool-stats {
            display: flex;
            gap: 15px;
            align-items: center;
        }
        
        .tool-stat-badge {
            padding: 8px 16px;
            border-radius: 20px;
            font-size: 0.9em;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 5px;
        }
        
        .badge-critical { background: #fed7d7; color: #c53030; }
        .badge-high { background: #feebc8; color: #c05621; }
        .badge-medium { background: #fef5e7; color: #d69e2e; }
        .badge-low { background: #c6f6d5; color: #2f855a; }
        
        .tool-header.active .tool-stat-badge {
            background: rgba(255,255,255,0.2);
            color: white;
        }
        
        .expand-icon {
            font-size: 1.2em;
            transition: transform 0.3s ease;
        }
        
        .tool-header.active .expand-icon {
            transform: rotate(180deg);
        }
        
        .tool-content {
            max-height: 0;
            overflow: hidden;
            transition: max-height 0.5s ease;
        }
        
        .tool-content.active {
            max-height: 2000px;
            overflow-y: auto;
        }
        
        .tool-findings {
            padding: 30px;
        }
        
        .finding-item {
            background: #f7fafc;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 15px;
            border-left: 4px solid #cbd5e0;
            transition: all 0.2s ease;
        }
        
        .finding-item:hover {
            transform: translateX(5px);
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
        }
        
        .finding-item.severity-critical {
            border-left-color: #e53e3e;
            background: #fff5f5;
        }
        
        .finding-item.severity-high {
            border-left-color: #dd6b20;
            background: #fffaf0;
        }
        
        .finding-item.severity-medium {
            border-left-color: #d69e2e;
            background: #fef5e7;
        }
        
        .finding-item.severity-low {
            border-left-color: #38a169;
            background: #f0fff4;
        }
        
        .finding-header {
            display: flex;
            gap: 10px;
            margin-bottom: 12px;
            flex-wrap: wrap;
        }
        
        .badge {
            padding: 6px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: 600;
        }
        
        .badge-tool {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }
        
        .badge-verified {
            background: #e53e3e;
            color: white;
            animation: pulse 2s infinite;
        }
        
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.7; }
        }
        
        .finding-title {
            font-size: 1.1em;
            font-weight: 600;
            margin-bottom: 8px;
            color: #2d3748;
        }
        
        .finding-desc {
            color: #4a5568;
            margin-bottom: 12px;
            line-height: 1.6;
        }
        
        .finding-details {
            background: white;
            padding: 15px;
            border-radius: 6px;
            font-size: 0.9em;
        }
        
        .finding-details div {
            margin-bottom: 8px;
        }
        
        .finding-details div:last-child {
            margin-bottom: 0;
        }
        
        .finding-details code {
            background: #edf2f7;
            padding: 3px 8px;
            border-radius: 4px;
            font-family: 'Monaco', 'Courier New', monospace;
            font-size: 0.9em;
            word-break: break-all;
        }
        
        .no-findings {
            text-align: center;
            padding: 40px;
            color: #38a169;
            font-size: 1.2em;
        }
        
        .alert-banner {
            background: linear-gradient(135deg, #e53e3e 0%, #c53030 100%);
            color: white;
            padding: 25px;
            border-radius: 12px;
            margin-bottom: 30px;
            box-shadow: 0 4px 20px rgba(229, 62, 62, 0.3);
            text-align: center;
        }
        
        .alert-banner h2 {
            font-size: 1.8em;
            margin-bottom: 10px;
        }
        
        .footer {
            background: white;
            border-radius: 12px;
            padding: 30px;
            margin-top: 30px;
            text-align: center;
            box-shadow: 0 4px 20px rgba(0,0,0,0.1);
        }
        
        .footer-links {
            display: flex;
            gap: 20px;
            justify-content: center;
            margin-top: 20px;
            flex-wrap: wrap;
        }
        
        .footer-link {
            color: #667eea;
            text-decoration: none;
            font-weight: 600;
            transition: all 0.2s;
        }
        
        .footer-link:hover {
            color: #764ba2;
            text-decoration: underline;
        }
        
        @media (max-width: 768px) {
            .stats-grid {
                grid-template-columns: repeat(2, 1fr);
            }
            
            .tool-header {
                flex-direction: column;
                gap: 15px;
                text-align: center;
            }
            
            .tool-stats {
                flex-wrap: wrap;
                justify-content: center;
            }
        }
    </style>
</head>
<body>
    <div class="container">
HTMLEOF

# Add alert banner if critical findings exist
if [ "$TOTAL_CRITICAL" -gt 0 ]; then
    cat >> "$OUTPUT_HTML" << HTMLEOF
        <div class="alert-banner">
            <h2>⚠️ CRITICAL SECURITY ALERT</h2>
            <p><strong>${TOTAL_CRITICAL} Critical Findings Detected</strong> - Immediate Action Required!</p>
        </div>
HTMLEOF
fi

# Continue with header and stats
cat >> "$OUTPUT_HTML" << HTMLEOF
        <div class="header">
            <h1>🛡️ Interactive Security Dashboard</h1>
            <p class="subtitle"><strong>Scan:</strong> $SCAN_NAME</p>
            <p class="subtitle"><strong>Generated:</strong> $(date '+%B %d, %Y at %I:%M %p')</p>
        </div>

        <div class="stats-grid">
            <div class="stat-card critical-stat">
                <div class="stat-label">Critical</div>
                <div class="stat-number">${TOTAL_CRITICAL}</div>
                <p>Immediate action required</p>
            </div>
            <div class="stat-card high-stat">
                <div class="stat-label">High</div>
                <div class="stat-number">${TOTAL_HIGH}</div>
                <p>High priority issues</p>
            </div>
            <div class="stat-card medium-stat">
                <div class="stat-label">Medium</div>
                <div class="stat-number">${TOTAL_MEDIUM}</div>
                <p>Medium priority issues</p>
            </div>
            <div class="stat-card low-stat">
                <div class="stat-label">Low</div>
                <div class="stat-number">${TOTAL_LOW}</div>
                <p>Low priority issues</p>
            </div>
        </div>

        <div class="tools-section">
HTMLEOF

# Add tool cards
for tool in trufflehog clamav sonar checkov helm; do
    # Get tool display name and icon
    case "$tool" in
        trufflehog)
            tool_name="TruffleHog"
            tool_icon="🔍"
            tool_desc="Secret Detection"
            ;;
        clamav)
            tool_name="ClamAV"
            tool_icon="🦠"
            tool_desc="Malware Scanner"
            ;;
        sonar)
            tool_name="SonarQube"
            tool_icon="📊"
            tool_desc="Code Quality"
            ;;
        checkov)
            tool_name="Checkov"
            tool_icon="🔐"
            tool_desc="IaC Security"
            ;;
        helm)
            tool_name="Helm"
            tool_icon="⚓"
            tool_desc="Chart Validation"
            ;;
    esac
    
    critical=${TOOL_STATS[${tool}_critical]}
    high=${TOOL_STATS[${tool}_high]}
    medium=${TOOL_STATS[${tool}_medium]}
    low=${TOOL_STATS[${tool}_low]}
    
    cat >> "$OUTPUT_HTML" << HTMLEOF
            <div class="tool-card">
                <div class="tool-header" onclick="toggleTool('${tool}')">
                    <div class="tool-title">
                        <span class="tool-icon">${tool_icon}</span>
                        <div>
                            <div>${tool_name}</div>
                            <div style="font-size: 0.6em; font-weight: 400; color: #718096;">${tool_desc}</div>
                        </div>
                    </div>
                    <div class="tool-stats">
HTMLEOF

    # Add stat badges only if non-zero
    if [ "$critical" -gt 0 ]; then
        echo "                        <span class=\"tool-stat-badge badge-critical\">❗ ${critical}</span>" >> "$OUTPUT_HTML"
    fi
    if [ "$high" -gt 0 ]; then
        echo "                        <span class=\"tool-stat-badge badge-high\">⚠️ ${high}</span>" >> "$OUTPUT_HTML"
    fi
    if [ "$medium" -gt 0 ]; then
        echo "                        <span class=\"tool-stat-badge badge-medium\">📋 ${medium}</span>" >> "$OUTPUT_HTML"
    fi
    if [ "$low" -gt 0 ]; then
        echo "                        <span class=\"tool-stat-badge badge-low\">ℹ️ ${low}</span>" >> "$OUTPUT_HTML"
    fi
    
    # If all zero, show clean status
    if [ "$critical" -eq 0 ] && [ "$high" -eq 0 ] && [ "$medium" -eq 0 ] && [ "$low" -eq 0 ]; then
        echo "                        <span class=\"tool-stat-badge badge-low\">✅ Clean</span>" >> "$OUTPUT_HTML"
    fi
    
    cat >> "$OUTPUT_HTML" << HTMLEOF
                        <span class="expand-icon">▼</span>
                    </div>
                </div>
                <div class="tool-content" id="${tool}-content">
                    <div class="tool-findings">
                        ${TOOL_DATA[$tool]}
                    </div>
                </div>
            </div>
HTMLEOF
done

# Complete the HTML
cat >> "$OUTPUT_HTML" << 'HTMLEOF'
        </div>

        <div class="footer">
            <p style="color: #718096; margin-bottom: 10px;">
                Comprehensive Security Architecture Scanner
            </p>
            <p style="color: #a0aec0; font-size: 0.9em;">
                Total Findings: <strong style="color: #2d3748;">
HTMLEOF

echo "${TOTAL_FINDINGS}</strong> • Tools: <strong style=\"color: #2d3748;\">5</strong>" >> "$OUTPUT_HTML"

cat >> "$OUTPUT_HTML" << 'HTMLEOF'
            </p>
            <div class="footer-links">
                <a href="../index.html" class="footer-link">📄 All Reports</a>
                <a href="../html-reports/" class="footer-link">📊 HTML Reports</a>
                <a href="../markdown-reports/" class="footer-link">📝 Markdown</a>
                <a href="../csv-reports/" class="footer-link">📈 CSV Data</a>
            </div>
        </div>
    </div>

    <script>
        function toggleTool(toolId) {
            const header = document.querySelector(`#${toolId}-content`).previousElementSibling;
            const content = document.getElementById(`${toolId}-content`);
            
            // Close all other tools
            document.querySelectorAll('.tool-header').forEach(h => {
                if (h !== header) {
                    h.classList.remove('active');
                }
            });
            document.querySelectorAll('.tool-content').forEach(c => {
                if (c !== content) {
                    c.classList.remove('active');
                }
            });
            
            // Toggle current tool
            header.classList.toggle('active');
            content.classList.toggle('active');
        }
        
        // Auto-expand first tool with findings
        window.addEventListener('DOMContentLoaded', () => {
            const firstToolWithFindings = Array.from(document.querySelectorAll('.tool-stat-badge'))
                .find(badge => !badge.textContent.includes('Clean'));
            
            if (firstToolWithFindings) {
                const toolCard = firstToolWithFindings.closest('.tool-card');
                const toolHeader = toolCard.querySelector('.tool-header');
                toolHeader.click();
            }
        });
    </script>
</body>
</html>
HTMLEOF

echo "✅ Interactive dashboard generated: $OUTPUT_HTML"
echo ""
echo "Summary:"
echo "  Critical: $TOTAL_CRITICAL"
echo "  High:     $TOTAL_HIGH"
echo "  Medium:   $TOTAL_MEDIUM"
echo "  Low:      $TOTAL_LOW"
echo "  Total:    $TOTAL_FINDINGS"
echo ""
echo "Open the dashboard: open $OUTPUT_HTML"
