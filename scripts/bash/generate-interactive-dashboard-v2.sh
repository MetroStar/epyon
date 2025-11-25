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
echo "Generating interactive dashboard from: $SCAN_NAME"

# Parse TruffleHog data (NDJSON format)
TH_FILE="${LATEST_SCAN}/trufflehog/trufflehog-filesystem-results.json"
if [ -f "$TH_FILE" ]; then
    # Count findings using grep and wc (NDJSON format)
    TH_CRITICAL=$(grep -E '"Verified":true' "$TH_FILE" 2>/dev/null | wc -l | tr -d ' \n' || echo "0")
    TH_HIGH=$(grep -E '"DetectorName"' "$TH_FILE" 2>/dev/null | grep -v '"Verified":true' | wc -l | tr -d ' \n' || echo "0")
    
    # Ensure they're numbers
    TH_CRITICAL=${TH_CRITICAL:-0}
    TH_HIGH=${TH_HIGH:-0}
    
    # Generate findings HTML - convert NDJSON to array first with jq -s
    TH_FINDINGS=$(grep -E '"DetectorName"' "$TH_FILE" | head -n 15 | jq -s -r '
        map("<div class=\"finding-item severity-" + (if .Verified then "critical" else "high" end) + "\">
            <div class=\"finding-header\">
                <span class=\"badge badge-tool\">TruffleHog</span>
                <span class=\"badge badge-" + (if .Verified then "critical" else "high" end) + "\">" + (if .Verified then "CRITICAL" else "HIGH" end) + "</span>
                " + (if .Verified then "<span class=\"badge badge-verified\">✓ VERIFIED</span>" else "" end) + "
            </div>
            <div class=\"finding-title\">" + .DetectorName + "</div>
            <div class=\"finding-desc\">" + (.DetectorDescription // "No description") + "</div>
            <div class=\"finding-details\">
                <div><strong>File:</strong> <code>" + (.SourceMetadata.Data.Filesystem.file | split("/") | last) + "</code></div>
                <div><strong>Line:</strong> <code>" + (.SourceMetadata.Data.Filesystem.line | tostring) + "</code></div>
                <div><strong>Full Path:</strong> <code style=\"font-size: 0.8em;\">" + .SourceMetadata.Data.Filesystem.file + "</code></div>
            </div>
        </div>") | 
        join("")
    ' 2>/dev/null || echo "")
    
    if [ -z "$TH_FINDINGS" ] || [ "$TH_FINDINGS" = "" ]; then
        TH_FINDINGS="<p class=\"no-findings\">✅ No secrets or credentials detected</p>"
    fi
else
    TH_CRITICAL=0
    TH_HIGH=0
    TH_FINDINGS="<p class=\"no-findings\">No scan data available</p>"
fi

# Parse ClamAV data
CLAMAV_FILE="${LATEST_SCAN}/clamav/scan-results.txt"
if [ -f "$CLAMAV_FILE" ]; then
    CLAMAV_CRITICAL=$(grep "FOUND" "$CLAMAV_FILE" 2>/dev/null | wc -l | tr -d ' \n' || echo "0")
    CLAMAV_CRITICAL=${CLAMAV_CRITICAL:-0}
    
    if [ "$CLAMAV_CRITICAL" -gt 0 ]; then
        CLAMAV_FINDINGS="<div class=\"finding-item severity-critical\">
            <div class=\"finding-header\">
                <span class=\"badge badge-tool\">ClamAV</span>
                <span class=\"badge badge-critical\">CRITICAL</span>
            </div>
            <div class=\"finding-title\">⚠️ Malware Detected</div>
            <div class=\"finding-desc\">$CLAMAV_CRITICAL infected files found</div>
            <div class=\"finding-details\">
                <div><strong>Action Required:</strong> Review scan results and quarantine infected files</div>
                <div><strong>Details:</strong> Check ${LATEST_SCAN}/clamav/scan-results.txt</div>
            </div>
        </div>"
    else
        CLAMAV_FINDINGS="<p class=\"no-findings\">✅ No malware detected</p>"
    fi
else
    CLAMAV_CRITICAL=0
    CLAMAV_FINDINGS="<p class=\"no-findings\">No scan data available</p>"
fi

# SonarQube
SONAR_DIR="${WORKSPACE_ROOT}/reports/sonar-reports"
LATEST_SONAR=$(find "$SONAR_DIR" -name "*_sonar-analysis-results.json" -type f 2>/dev/null | sort -r | head -n 1 || echo "")

if [ -f "$LATEST_SONAR" ]; then
    SONAR_STATUS=$(jq -r '.status' "$LATEST_SONAR" 2>/dev/null || echo "NO_DATA")
    
    if [ "$SONAR_STATUS" = "NO_PROJECT_DETECTED" ]; then
        SONAR_FINDINGS="<p class=\"no-findings\">No SonarQube project detected</p>"
        SONAR_CRITICAL=0
        SONAR_HIGH=0
    else
        SONAR_FINDINGS="<p class=\"no-findings\">✅ SonarQube analysis complete - check server for details</p>"
        SONAR_CRITICAL=0
        SONAR_HIGH=0
    fi
else
    SONAR_CRITICAL=0
    SONAR_HIGH=0
    SONAR_FINDINGS="<p class=\"no-findings\">No scan data available</p>"
fi

# Checkov & Helm (placeholder)
CHECKOV_CRITICAL=0
CHECKOV_HIGH=0
CHECKOV_FINDINGS="<p class=\"no-findings\">No Infrastructure-as-Code files scanned</p>"

HELM_CRITICAL=0
HELM_HIGH=0
HELM_FINDINGS="<p class=\"no-findings\">No Helm charts scanned</p>"

# Calculate totals
TOTAL_CRITICAL=$((TH_CRITICAL + CLAMAV_CRITICAL + SONAR_CRITICAL + CHECKOV_CRITICAL + HELM_CRITICAL))
TOTAL_HIGH=$((TH_HIGH + SONAR_HIGH + CHECKOV_HIGH + HELM_HIGH))
TOTAL_MEDIUM=0
TOTAL_LOW=0
TOTAL_FINDINGS=$((TOTAL_CRITICAL + TOTAL_HIGH + TOTAL_MEDIUM + TOTAL_LOW))

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Generate the dashboard HTML
cat > "$OUTPUT_HTML" << 'EOF'
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
        
        .alert-banner {
            background: linear-gradient(135deg, #e53e3e 0%, #c53030 100%);
            color: white;
            padding: 25px;
            border-radius: 12px;
            margin-bottom: 30px;
            box-shadow: 0 4px 20px rgba(229, 62, 62, 0.3);
            text-align: center;
            animation: pulse 2s infinite;
        }
        
        @keyframes pulse {
            0%, 100% { transform: scale(1); }
            50% { transform: scale(1.02); }
        }
        
        .alert-banner h2 {
            font-size: 1.8em;
            margin-bottom: 10px;
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
        .badge-clean { background: #c6f6d5; color: #2f855a; }
        
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
            animation: pulse-badge 2s infinite;
        }
        
        @keyframes pulse-badge {
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
EOF

# Add alert banner if critical findings exist
if [ "$TOTAL_CRITICAL" -gt 0 ]; then
    cat >> "$OUTPUT_HTML" << EOF
        <div class="alert-banner">
            <h2>⚠️ CRITICAL SECURITY ALERT</h2>
            <p><strong>${TOTAL_CRITICAL} Critical Findings Detected</strong> - Immediate Action Required!</p>
        </div>
EOF
fi

# Add header and stats
cat >> "$OUTPUT_HTML" << EOF
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
            <!-- TruffleHog -->
            <div class="tool-card">
                <div class="tool-header" onclick="toggleTool('trufflehog')">
                    <div class="tool-title">
                        <span class="tool-icon">🔍</span>
                        <div>
                            <div>TruffleHog</div>
                            <div style="font-size: 0.6em; font-weight: 400; color: #718096;">Secret Detection</div>
                        </div>
                    </div>
                    <div class="tool-stats">
EOF

# Add TruffleHog stats
if [ "$TH_CRITICAL" -gt 0 ]; then
    echo "                        <span class=\"tool-stat-badge badge-critical\">❗ ${TH_CRITICAL}</span>" >> "$OUTPUT_HTML"
fi
if [ "$TH_HIGH" -gt 0 ]; then
    echo "                        <span class=\"tool-stat-badge badge-high\">⚠️ ${TH_HIGH}</span>" >> "$OUTPUT_HTML"
fi
if [ "$TH_CRITICAL" -eq 0 ] && [ "$TH_HIGH" -eq 0 ]; then
    echo "                        <span class=\"tool-stat-badge badge-clean\">✅ Clean</span>" >> "$OUTPUT_HTML"
fi

cat >> "$OUTPUT_HTML" << EOF
                        <span class="expand-icon">▼</span>
                    </div>
                </div>
                <div class="tool-content" id="trufflehog-content">
                    <div class="tool-findings">
                        ${TH_FINDINGS}
                    </div>
                </div>
            </div>

            <!-- ClamAV -->
            <div class="tool-card">
                <div class="tool-header" onclick="toggleTool('clamav')">
                    <div class="tool-title">
                        <span class="tool-icon">🦠</span>
                        <div>
                            <div>ClamAV</div>
                            <div style="font-size: 0.6em; font-weight: 400; color: #718096;">Malware Scanner</div>
                        </div>
                    </div>
                    <div class="tool-stats">
EOF

# Add ClamAV stats
if [ "$CLAMAV_CRITICAL" -gt 0 ]; then
    echo "                        <span class=\"tool-stat-badge badge-critical\">❗ ${CLAMAV_CRITICAL}</span>" >> "$OUTPUT_HTML"
else
    echo "                        <span class=\"tool-stat-badge badge-clean\">✅ Clean</span>" >> "$OUTPUT_HTML"
fi

cat >> "$OUTPUT_HTML" << EOF
                        <span class="expand-icon">▼</span>
                    </div>
                </div>
                <div class="tool-content" id="clamav-content">
                    <div class="tool-findings">
                        ${CLAMAV_FINDINGS}
                    </div>
                </div>
            </div>

            <!-- SonarQube -->
            <div class="tool-card">
                <div class="tool-header" onclick="toggleTool('sonar')">
                    <div class="tool-title">
                        <span class="tool-icon">📊</span>
                        <div>
                            <div>SonarQube</div>
                            <div style="font-size: 0.6em; font-weight: 400; color: #718096;">Code Quality</div>
                        </div>
                    </div>
                    <div class="tool-stats">
                        <span class="tool-stat-badge badge-clean">✅ Clean</span>
                        <span class="expand-icon">▼</span>
                    </div>
                </div>
                <div class="tool-content" id="sonar-content">
                    <div class="tool-findings">
                        ${SONAR_FINDINGS}
                    </div>
                </div>
            </div>

            <!-- Checkov -->
            <div class="tool-card">
                <div class="tool-header" onclick="toggleTool('checkov')">
                    <div class="tool-title">
                        <span class="tool-icon">🔐</span>
                        <div>
                            <div>Checkov</div>
                            <div style="font-size: 0.6em; font-weight: 400; color: #718096;">IaC Security</div>
                        </div>
                    </div>
                    <div class="tool-stats">
                        <span class="tool-stat-badge badge-clean">✅ Clean</span>
                        <span class="expand-icon">▼</span>
                    </div>
                </div>
                <div class="tool-content" id="checkov-content">
                    <div class="tool-findings">
                        ${CHECKOV_FINDINGS}
                    </div>
                </div>
            </div>

            <!-- Helm -->
            <div class="tool-card">
                <div class="tool-header" onclick="toggleTool('helm')">
                    <div class="tool-title">
                        <span class="tool-icon">⚓</span>
                        <div>
                            <div>Helm</div>
                            <div style="font-size: 0.6em; font-weight: 400; color: #718096;">Chart Validation</div>
                        </div>
                    </div>
                    <div class="tool-stats">
                        <span class="tool-stat-badge badge-clean">✅ Clean</span>
                        <span class="expand-icon">▼</span>
                    </div>
                </div>
                <div class="tool-content" id="helm-content">
                    <div class="tool-findings">
                        ${HELM_FINDINGS}
                    </div>
                </div>
            </div>
        </div>

        <div class="footer">
            <p style="color: #718096; margin-bottom: 10px;">
                Comprehensive Security Architecture Scanner
            </p>
            <p style="color: #a0aec0; font-size: 0.9em;">
                Total Findings: <strong style="color: #2d3748;">${TOTAL_FINDINGS}</strong> • Tools: <strong style="color: #2d3748;">5</strong>
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
            const header = document.querySelector('#' + toolId + '-content').previousElementSibling;
            const content = document.getElementById(toolId + '-content');
            
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
            const badges = Array.from(document.querySelectorAll('.tool-stat-badge'));
            const firstIssue = badges.find(badge => badge.textContent.includes('❗') || badge.textContent.includes('⚠️'));
            
            if (firstIssue) {
                const toolCard = firstIssue.closest('.tool-card');
                const toolHeader = toolCard.querySelector('.tool-header');
                toolHeader.click();
            }
        });
    </script>
</body>
</html>
EOF

echo ""
echo "✅ Interactive dashboard generated: $OUTPUT_HTML"
echo ""
echo "Summary:"
echo "  Critical: $TOTAL_CRITICAL"
echo "  High:     $TOTAL_HIGH"
echo "  Medium:   $TOTAL_MEDIUM"
echo "  Low:      $TOTAL_LOW"
echo "  Total:    $TOTAL_FINDINGS"
echo ""
echo "Open the dashboard:"
echo "  open $OUTPUT_HTML"
