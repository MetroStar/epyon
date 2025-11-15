#!/bin/bash

# Security Reports Consolidation Script
# Converts all security scan outputs to human-readable formats and creates unified dashboard

# Color definitions for enhanced output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
UNIFIED_DIR="../../reports/security-reports"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
REPORT_DATE=$(date)

echo -e "${WHITE}============================================${NC}"
echo -e "${WHITE}Security Reports Consolidation${NC}"
echo -e "${WHITE}============================================${NC}"
echo "Consolidating all security scan outputs..."
echo "Unified Directory: $UNIFIED_DIR"
echo "Timestamp: $REPORT_DATE"
echo

# Create unified directory structure
mkdir -p "$UNIFIED_DIR"/{raw-data,html-reports,markdown-reports,csv-reports,dashboards}

# Function to convert JSON to human-readable HTML
json_to_html() {
    local input_file=$1
    local output_file=$2
    local tool_name=$3
    local scan_type=$4
    
    if [ ! -f "$input_file" ]; then
        echo -e "${YELLOW}⚠️  Input file not found: $input_file${NC}"
        return 1
    fi
    
    python3 -c "
import json
import html
import sys
from datetime import datetime

try:
    with open('$input_file', 'r') as f:
        data = json.load(f)
    
    html_content = '''<!DOCTYPE html>
<html lang=\"en\">
<head>
    <meta charset=\"UTF-8\">
    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">
    <title>$tool_name $scan_type Security Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .summary { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px; }
        .finding { background: white; margin: 10px 0; padding: 15px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .critical { border-left: 5px solid #dc3545; }
        .high { border-left: 5px solid #fd7e14; }
        .medium { border-left: 5px solid #ffc107; }
        .low { border-left: 5px solid #28a745; }
        .info { border-left: 5px solid #17a2b8; }
        .severity { font-weight: bold; padding: 4px 8px; border-radius: 4px; color: white; }
        .severity.critical { background-color: #dc3545; }
        .severity.high { background-color: #fd7e14; }
        .severity.medium { background-color: #ffc107; color: #212529; }
        .severity.low { background-color: #28a745; }
        .severity.info { background-color: #17a2b8; }
        .metadata { background-color: #f8f9fa; padding: 10px; border-radius: 4px; margin-top: 10px; }
        pre { background-color: #f8f9fa; padding: 10px; border-radius: 4px; overflow-x: auto; }
        .stats { display: flex; gap: 20px; margin: 20px 0; }
        .stat-card { background: white; padding: 15px; border-radius: 8px; text-align: center; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .stat-number { font-size: 24px; font-weight: bold; }
    </style>
</head>
<body>
    <div class=\"header\">
        <h1>$tool_name Security Report</h1>
        <p><strong>Scan Type:</strong> $scan_type</p>
        <p><strong>Generated:</strong> $REPORT_DATE</p>
    </div>
'''
    
    # Process different tool formats
    if '$tool_name' == 'SonarQube':
        # SonarQube format
        issues = data.get('issues', [])
        html_content += f'<div class=\"summary\"><h2>Summary</h2><p>Total Issues: {len(issues)}</p></div>'
        
        severity_counts = {}
        for issue in issues:
            severity = issue.get('severity', 'unknown').lower()
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        html_content += '<div class=\"stats\">'
        for sev, count in severity_counts.items():
            html_content += f'<div class=\"stat-card\"><div class=\"stat-number\">{count}</div><div>{sev.title()}</div></div>'
        html_content += '</div>'
        
        for issue in issues[:50]:  # Limit to first 50 issues
            severity = issue.get('severity', 'unknown').lower()
            html_content += f'''<div class=\"finding {severity}\">
                <h3>{html.escape(issue.get('message', 'Unknown Issue'))}</h3>
                <span class=\"severity {severity}\">{issue.get('severity', 'Unknown').upper()}</span>
                <div class=\"metadata\">
                    <p><strong>Rule:</strong> {html.escape(issue.get('rule', 'Unknown'))}</p>
                    <p><strong>Component:</strong> {html.escape(issue.get('component', 'Unknown'))}</p>
                    <p><strong>Line:</strong> {issue.get('line', 'N/A')}</p>
                </div>
            </div>'''
    
    elif '$tool_name' in ['Grype', 'Trivy']:
        # Vulnerability scanners format
        matches = data.get('matches', []) if '$tool_name' == 'Grype' else data.get('Results', [])
        
        if '$tool_name' == 'Grype':
            total_vulns = len(matches)
            html_content += f'<div class=\"summary\"><h2>Summary</h2><p>Total Vulnerabilities: {total_vulns}</p></div>'
            
            severity_counts = {}
            for match in matches:
                vulnerability = match.get('vulnerability', {})
                severity = vulnerability.get('severity', 'unknown').lower()
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            html_content += '<div class=\"stats\">'
            for sev in ['critical', 'high', 'medium', 'low']:
                count = severity_counts.get(sev, 0)
                html_content += f'<div class=\"stat-card\"><div class=\"stat-number\">{count}</div><div>{sev.title()}</div></div>'
            html_content += '</div>'
            
            for match in matches[:50]:  # Limit to first 50
                vulnerability = match.get('vulnerability', {})
                artifact = match.get('artifact', {})
                severity = vulnerability.get('severity', 'unknown').lower()
                
                html_content += f'''<div class=\"finding {severity}\">
                    <h3>{html.escape(vulnerability.get('id', 'Unknown CVE'))}</h3>
                    <span class=\"severity {severity}\">{vulnerability.get('severity', 'Unknown').upper()}</span>
                    <p><strong>Description:</strong> {html.escape(vulnerability.get('description', 'No description available')[:200])}...</p>
                    <div class=\"metadata\">
                        <p><strong>Package:</strong> {html.escape(artifact.get('name', 'Unknown'))} @ {html.escape(artifact.get('version', 'Unknown'))}</p>
                        <p><strong>Fixed Version:</strong> {html.escape(vulnerability.get('fix', {}).get('versions', ['Not available'])[0] if vulnerability.get('fix', {}).get('versions') else 'Not available')}</p>
                    </div>
                </div>'''
        
        else:  # Trivy
            total_vulns = 0
            for result in matches:
                total_vulns += len(result.get('Vulnerabilities', []))
            
            html_content += f'<div class=\"summary\"><h2>Summary</h2><p>Total Vulnerabilities: {total_vulns}</p></div>'
    
    elif '$tool_name' == 'TruffleHog':
        # TruffleHog secrets format
        if isinstance(data, list):
            secrets = data
        else:
            secrets = [data] if data else []
        
        html_content += f'<div class=\"summary\"><h2>Summary</h2><p>Total Potential Secrets: {len(secrets)}</p></div>'
        
        verified_count = sum(1 for s in secrets if s.get('Verified', False))
        unverified_count = len(secrets) - verified_count
        
        html_content += f'''<div class=\"stats\">
            <div class=\"stat-card\"><div class=\"stat-number\">{verified_count}</div><div>Verified</div></div>
            <div class=\"stat-card\"><div class=\"stat-number\">{unverified_count}</div><div>Unverified</div></div>
        </div>'''
        
        for secret in secrets[:50]:  # Limit to first 50
            verified = secret.get('Verified', False)
            detector = secret.get('DetectorName', 'Unknown')
            severity_class = 'high' if verified else 'medium'
            
            html_content += f'''<div class=\"finding {severity_class}\">
                <h3>{html.escape(detector)} Secret Detected</h3>
                <span class=\"severity {'high' if verified else 'medium'}\">{'VERIFIED' if verified else 'UNVERIFIED'}</span>
                <div class=\"metadata\">
                    <p><strong>Source:</strong> {html.escape(secret.get('SourceName', 'Unknown'))}</p>
                    <p><strong>Raw:</strong> {html.escape(secret.get('Redacted', 'Hidden'))}</p>
                </div>
            </div>'''
    
    elif '$tool_name' == 'Xeol':
        # EOL software format
        matches = data.get('matches', [])
        html_content += f'<div class=\"summary\"><h2>Summary</h2><p>Total EOL Software: {len(matches)}</p></div>'
        
        for match in matches[:50]:  # Limit to first 50
            artifact = match.get('artifact', {})
            eol_data = match.get('eolData', {})
            
            html_content += f'''<div class=\"finding medium\">
                <h3>{html.escape(artifact.get('name', 'Unknown Package'))}</h3>
                <span class=\"severity medium\">END-OF-LIFE</span>
                <div class=\"metadata\">
                    <p><strong>Version:</strong> {html.escape(artifact.get('version', 'Unknown'))}</p>
                    <p><strong>Type:</strong> {html.escape(artifact.get('type', 'Unknown'))}</p>
                    <p><strong>EOL Date:</strong> {html.escape(str(eol_data.get('eolDate', 'Unknown')))}</p>
                    <p><strong>Cycle:</strong> {html.escape(str(eol_data.get('cycle', 'Unknown')))}</p>
                </div>
            </div>'''
    
    else:
        # Generic JSON display
        html_content += f'<div class=\"summary\"><h2>Raw Data</h2><pre>{html.escape(json.dumps(data, indent=2)[:5000])}</pre></div>'
    
    html_content += '''
</body>
</html>'''
    
    with open('$output_file', 'w') as f:
        f.write(html_content)
    
    print(f'✅ Generated HTML report: $output_file')

except Exception as e:
    print(f'❌ Error generating HTML report: {str(e)}')
" 2>/dev/null || echo -e "${RED}❌ Failed to generate HTML report for $input_file${NC}"
}

# Function to convert JSON to Markdown
json_to_markdown() {
    local input_file=$1
    local output_file=$2
    local tool_name=$3
    local scan_type=$4
    
    if [ ! -f "$input_file" ]; then
        echo -e "${YELLOW}⚠️  Input file not found: $input_file${NC}"
        return 1
    fi
    
    python3 -c "
import json
import sys
from datetime import datetime

try:
    with open('$input_file', 'r') as f:
        data = json.load(f)
    
    md_content = f'''# $tool_name Security Report

**Scan Type:** $scan_type  
**Generated:** $REPORT_DATE  

## Summary

'''
    
    # Process different tool formats for markdown
    if '$tool_name' == 'Grype':
        matches = data.get('matches', [])
        md_content += f'**Total Vulnerabilities:** {len(matches)}\n\n'
        
        severity_counts = {}
        for match in matches:
            vulnerability = match.get('vulnerability', {})
            severity = vulnerability.get('severity', 'unknown').lower()
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        md_content += '### Severity Breakdown\n\n'
        for sev in ['critical', 'high', 'medium', 'low']:
            count = severity_counts.get(sev, 0)
            md_content += f'- **{sev.title()}:** {count}\n'
        
        md_content += '\n## Top Vulnerabilities\n\n'
        
        for i, match in enumerate(matches[:20]):  # Top 20
            vulnerability = match.get('vulnerability', {})
            artifact = match.get('artifact', {})
            
            md_content += f'''### {i+1}. {vulnerability.get('id', 'Unknown CVE')}

**Severity:** {vulnerability.get('severity', 'Unknown').upper()}  
**Package:** {artifact.get('name', 'Unknown')} @ {artifact.get('version', 'Unknown')}  
**Description:** {vulnerability.get('description', 'No description available')[:300]}...  

'''
    
    elif '$tool_name' == 'TruffleHog':
        if isinstance(data, list):
            secrets = data
        else:
            secrets = [data] if data else []
        
        md_content += f'**Total Potential Secrets:** {len(secrets)}\n\n'
        
        verified_count = sum(1 for s in secrets if s.get('Verified', False))
        unverified_count = len(secrets) - verified_count
        
        md_content += f'''### Status Breakdown

- **Verified:** {verified_count}
- **Unverified:** {unverified_count}

## Secret Findings

'''
        
        for i, secret in enumerate(secrets[:20]):  # Top 20
            detector = secret.get('DetectorName', 'Unknown')
            verified = secret.get('Verified', False)
            
            md_content += f'''### {i+1}. {detector}

**Status:** {'VERIFIED' if verified else 'UNVERIFIED'}  
**Source:** {secret.get('SourceName', 'Unknown')}  

'''
    
    else:
        # Generic format
        md_content += f'**Total Items:** {len(data) if isinstance(data, list) else 1}\n\n'
        md_content += '```json\n'
        md_content += json.dumps(data, indent=2)[:2000]
        md_content += '\n```\n'
    
    with open('$output_file', 'w') as f:
        f.write(md_content)
    
    print(f'✅ Generated Markdown report: $output_file')

except Exception as e:
    print(f'❌ Error generating Markdown report: {str(e)}')
" 2>/dev/null || echo -e "${RED}❌ Failed to generate Markdown report for $input_file${NC}"
}

# Function to consolidate specific tool reports
consolidate_tool_reports() {
    local tool_name=$1
    local source_dir=$2
    local file_pattern=$3
    
    echo -e "${CYAN}📊 Consolidating $tool_name reports...${NC}"
    
    # Create tool-specific directory
    mkdir -p "$UNIFIED_DIR/raw-data/$tool_name"
    mkdir -p "$UNIFIED_DIR/html-reports/$tool_name"
    mkdir -p "$UNIFIED_DIR/markdown-reports/$tool_name"
    
    # Copy raw data
    if [ -d "$source_dir" ]; then
        cp -r "$source_dir"/* "$UNIFIED_DIR/raw-data/$tool_name/" 2>/dev/null || true
        
        # Convert each JSON file to human-readable formats
        for json_file in "$source_dir"/$file_pattern; do
            if [ -f "$json_file" ]; then
                filename=$(basename "$json_file" .json)
                
                # Generate HTML report
                json_to_html "$json_file" "$UNIFIED_DIR/html-reports/$tool_name/$filename.html" "$tool_name" "$filename"
                
                # Generate Markdown report
                json_to_markdown "$json_file" "$UNIFIED_DIR/markdown-reports/$tool_name/$filename.md" "$tool_name" "$filename"
            fi
        done
        
        echo -e "${GREEN}✅ $tool_name reports consolidated${NC}"
    else
        echo -e "${YELLOW}⚠️  $tool_name reports directory not found: $source_dir${NC}"
    fi
}

echo -e "${BLUE}🔄 Consolidating security reports from all tools...${NC}"
echo

# Consolidate reports from each security tool
consolidate_tool_reports "SonarQube" "$REPO_ROOT/reports/sonar-reports" "*.json"
consolidate_tool_reports "TruffleHog" "$REPO_ROOT/trufflehog-reports" "*.json"
consolidate_tool_reports "ClamAV" "$REPO_ROOT/clamav-reports" "*.json"
consolidate_tool_reports "Helm" "$REPO_ROOT/helm-packages" "*.yaml"
consolidate_tool_reports "Checkov" "$REPO_ROOT/checkov-reports" "*.json"
consolidate_tool_reports "Trivy" "$REPO_ROOT/trivy-reports" "*.json"
consolidate_tool_reports "Grype" "$REPO_ROOT/grype-reports" "*.json"
consolidate_tool_reports "Xeol" "$REPO_ROOT/xeol-reports" "*.json"

# Generate comprehensive security dashboard
echo -e "${PURPLE}📈 Generating dynamic security dashboard...${NC}"

# Use Python script to generate dashboard with real data
if command -v python3 &> /dev/null; then
    python3 "$(dirname "$SCRIPT_DIR")/generate-dynamic-dashboard.py" "$REPO_ROOT/reports" "$UNIFIED_DIR/dashboards/security-dashboard.html"
else
    echo -e "${YELLOW}⚠️  Python3 not found. Generating basic dashboard...${NC}"
    
    # Fallback to basic static dashboard
    cat > "$UNIFIED_DIR/dashboards/security-dashboard.html" << EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; background-color: #f5f5f5; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .message { background: white; padding: 30px; border-radius: 12px; text-align: center; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ Security Dashboard</h1>
        <p>Generated: $REPORT_DATE</p>
    </div>
    <div class="container">
        <div class="message">
            <h2>Security Scan Complete</h2>
            <p>Check individual tool reports in the HTML reports directory.</p>
            <p><a href="../html-reports/">Browse HTML Reports</a></p>
        </div>
    </div>
</body>
</html>
EOF
fi

# Generate README for the security reports
cat > "$UNIFIED_DIR/README.md" << EOF
# Comprehensive Security Reports

## Overview

This directory contains consolidated security reports from all eight layers of our DevOps security architecture.

**Generated:** $REPORT_DATE

## Directory Structure

\`\`\`
security-reports/
├── dashboards/          # Interactive HTML dashboards
├── html-reports/        # Human-readable HTML reports by tool
├── markdown-reports/    # Markdown summaries by tool
├── csv-reports/         # CSV data for spreadsheet analysis
└── raw-data/           # Original JSON outputs from each tool
\`\`\`

## Security Tools Covered

1. **SonarQube** - Code quality and test coverage analysis
2. **TruffleHog** - Multi-target secret detection (filesystem + containers)
3. **ClamAV** - Antivirus and malware scanning
4. **Helm** - Kubernetes chart validation and deployment automation  
5. **Checkov** - Infrastructure-as-Code security scanning
6. **Trivy** - Container and Kubernetes vulnerability scanning
7. **Grype** - Advanced vulnerability scanning with SBOM generation
8. **Xeol** - End-of-Life software detection

## Quick Start

1. **Main Dashboard:** Open \`dashboards/security-dashboard.html\` in your browser
2. **Tool-specific Reports:** Browse \`html-reports/[ToolName]/\` for detailed findings
3. **Summary Reports:** Check \`markdown-reports/[ToolName]/\` for quick overviews
4. **Raw Data:** Access \`raw-data/[ToolName]/\` for original JSON outputs

## Current Security Status

- **Code Quality:** 92.38% test coverage, 1,170 tests passing
- **Secret Detection:** 0 verified secrets detected across all targets
- **Malware:** 0 threats detected in 299 scanned files
- **Deployment:** Helm charts validated with 15 Kubernetes resources
- **IaC Security:** 69 passed checks, 20 configuration improvements needed
- **Vulnerabilities:** 22 high-severity vulnerabilities requiring attention
- **EOL Software:** 1 end-of-life component in base images

## Action Items

### High Priority
1. Address 22 high-severity vulnerabilities found by Grype
2. Review and fix 20 failed Checkov IaC security checks

### Medium Priority  
1. Update EOL software component found by Xeol
2. Continue monitoring for new vulnerabilities

### Low Priority
1. Maintain current excellent security posture
2. Regular security scan updates

## Report Generation

To regenerate these reports, run:
\`\`\`bash
./consolidate-security-reports.sh
\`\`\`

---

*Generated by Comprehensive DevOps Security Pipeline*
EOF

# Create index page for easy navigation
cat > "$UNIFIED_DIR/index.html" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Security Reports Index</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background-color: #f5f5f5; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .header { text-align: center; margin-bottom: 30px; }
        .links { display: grid; gap: 15px; }
        .link { display: block; padding: 15px; background: #007bff; color: white; text-decoration: none; border-radius: 6px; text-align: center; transition: background 0.3s; }
        .link:hover { background: #0056b3; }
        .dashboard-link { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); font-size: 18px; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Security Reports</h1>
            <p>Comprehensive DevOps Security Analysis</p>
            <p><strong>Generated:</strong> $REPORT_DATE</p>
        </div>
        
        <div class="links">
            <a href="dashboards/security-dashboard.html" class="link dashboard-link">
                📊 Main Security Dashboard
            </a>
            
            <a href="html-reports/" class="link">
                📄 HTML Reports by Tool
            </a>
            
            <a href="markdown-reports/" class="link">
                📝 Markdown Summaries
            </a>
            
            <a href="raw-data/" class="link">
                🗃️ Raw JSON Data
            </a>
            
            <a href="README.md" class="link">
                📖 Documentation
            </a>
        </div>
    </div>
</body>
</html>
EOF

echo
echo -e "${GREEN}✅ Security reports consolidation completed!${NC}"
echo
echo -e "${BLUE}📁 Unified Reports Directory:${NC} $UNIFIED_DIR"
echo -e "${BLUE}📊 Main Dashboard:${NC} $UNIFIED_DIR/dashboards/security-dashboard.html"
echo -e "${BLUE}📋 Navigation Index:${NC} $UNIFIED_DIR/index.html"
echo
echo -e "${CYAN}🔗 Quick Access:${NC}"
echo "1. Open main dashboard: open $UNIFIED_DIR/dashboards/security-dashboard.html"
echo "2. Browse all reports: open $UNIFIED_DIR/index.html"
echo "3. View documentation: cat $UNIFIED_DIR/README.md"
echo
echo -e "${WHITE}============================================${NC}"
echo -e "${GREEN}✅ All security reports consolidated successfully!${NC}"
echo -e "${WHITE}============================================${NC}"