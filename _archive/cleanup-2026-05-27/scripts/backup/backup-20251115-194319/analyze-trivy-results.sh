#!/bin/bash

# Trivy Results Analysis Script
# Analyzes container and Kubernetes vulnerability scan results and provides detailed reporting

OUTPUT_DIR="../../reports/trivy-reports"
SCAN_LOG="$OUTPUT_DIR/trivy-scan.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo "============================================"
echo -e "${PURPLE}Trivy Vulnerability Analysis Report${NC}"
echo "============================================"
echo

# Check if results directory exists
if [ ! -d "$OUTPUT_DIR" ]; then
    echo -e "${YELLOW}⚠️  No Trivy results found at $OUTPUT_DIR${NC}"
    echo "Run 'npm run trivy:scan' first to generate vulnerability scan results."
    exit 1
fi

# Find all Trivy result files
RESULT_FILES=$(find "$OUTPUT_DIR" -name "trivy-*-results.json" 2>/dev/null)

if [ -z "$RESULT_FILES" ]; then
    echo -e "${YELLOW}⚠️  No Trivy result files found${NC}"
    echo "Run 'npm run trivy:scan' first to generate vulnerability scan results."
    exit 1
fi

echo -e "${BLUE}📊 Vulnerability Scan Overview:${NC}"
echo "==============================="

# Detailed analysis using Python if available
if command -v python3 &> /dev/null; then
    python3 << 'EOF'
import json
import glob
import os
from collections import Counter, defaultdict

try:
    output_dir = "./trivy-reports"
    result_files = glob.glob(f"{output_dir}/trivy-*-results.json")
    
    if not result_files:
        print("No Trivy result files found")
        exit(1)
    
    print(f"Scan Results Files: {len(result_files)}")
    
    # Initialize counters
    total_vulnerabilities = defaultdict(int)
    total_misconfigurations = 0
    scan_summary = {}
    vulnerability_details = []
    top_packages = Counter()
    cve_details = []
    
    for file_path in result_files:
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            filename = os.path.basename(file_path)
            scan_type = filename.replace('trivy-', '').replace('-results.json', '')
            scan_summary[scan_type] = {
                'vulnerabilities': defaultdict(int),
                'misconfigurations': 0,
                'packages_affected': 0,
                'status': 'clean'
            }
            
            print(f"\n📋 Processing: {scan_type}")
            
            # Handle different Trivy output formats
            if 'Results' in data and data['Results']:
                for result in data['Results']:
                    # Process vulnerabilities
                    vulnerabilities = result.get('Vulnerabilities', [])
                    if vulnerabilities:
                        for vuln in vulnerabilities:
                            severity = vuln.get('Severity', 'UNKNOWN')
                            total_vulnerabilities[severity] += 1
                            scan_summary[scan_type]['vulnerabilities'][severity] += 1
                            scan_summary[scan_type]['status'] = 'vulnerable'
                            
                            # Collect vulnerability details
                            vulnerability_details.append({
                                'scan_type': scan_type,
                                'cve_id': vuln.get('VulnerabilityID', 'Unknown'),
                                'severity': severity,
                                'package': vuln.get('PkgName', 'Unknown'),
                                'installed_version': vuln.get('InstalledVersion', 'Unknown'),
                                'fixed_version': vuln.get('FixedVersion', 'Not available'),
                                'title': vuln.get('Title', 'No title'),
                                'description': vuln.get('Description', 'No description')[:200] + '...' if vuln.get('Description', '') else 'No description'
                            })
                            
                            # Count affected packages
                            if vuln.get('PkgName'):
                                top_packages[vuln.get('PkgName')] += 1
                        
                        scan_summary[scan_type]['packages_affected'] = len(set([v.get('PkgName') for v in vulnerabilities if v.get('PkgName')]))
                    
                    # Process misconfigurations
                    misconfigs = result.get('Misconfigurations', [])
                    if misconfigs:
                        config_count = len(misconfigs)
                        total_misconfigurations += config_count
                        scan_summary[scan_type]['misconfigurations'] = config_count
                        scan_summary[scan_type]['status'] = 'misconfigured'
                        
                        for config in misconfigs:
                            vulnerability_details.append({
                                'scan_type': scan_type,
                                'cve_id': config.get('ID', 'CONFIG'),
                                'severity': config.get('Severity', 'MEDIUM'),
                                'package': 'Configuration',
                                'installed_version': 'N/A',
                                'fixed_version': 'Fix available',
                                'title': config.get('Title', 'Configuration Issue'),
                                'description': config.get('Description', 'No description')[:200] + '...' if config.get('Description', '') else 'No description'
                            })
            
        except Exception as e:
            print(f"  ⚠️  Could not parse {filename}: {str(e)}")
            continue
    
    # Print overall summary
    print(f"\n🎯 Overall Vulnerability Summary:")
    print("================================")
    
    if total_vulnerabilities:
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']:
            count = total_vulnerabilities.get(severity, 0)
            if count > 0:
                emoji = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢', 'UNKNOWN': '⚪'}
                print(f"  {emoji.get(severity, '⚪')} {severity}: {count}")
    
    if total_misconfigurations > 0:
        print(f"  ⚙️  Misconfigurations: {total_misconfigurations}")
    
    if not total_vulnerabilities and total_misconfigurations == 0:
        print("  ✅ No vulnerabilities or misconfigurations found")
    
    # Security assessment
    critical_high_count = total_vulnerabilities.get('CRITICAL', 0) + total_vulnerabilities.get('HIGH', 0)
    
    print(f"\n🛡️  Security Assessment:")
    print("======================")
    
    if critical_high_count == 0 and total_misconfigurations == 0:
        print("🟢 Security Status: EXCELLENT")
        print("✅ No critical or high severity issues detected")
    elif critical_high_count <= 5 and total_misconfigurations <= 2:
        print("🟡 Security Status: GOOD")
        print(f"⚠️  {critical_high_count} high/critical vulnerabilities, {total_misconfigurations} misconfigurations")
    elif critical_high_count <= 15:
        print("🟠 Security Status: NEEDS ATTENTION")
        print(f"⚠️  {critical_high_count} high/critical vulnerabilities found")
    else:
        print("🔴 Security Status: CRITICAL")
        print(f"🚨 {critical_high_count} critical/high vulnerabilities - immediate action required")
    
    # Detailed breakdown by scan type
    print(f"\n📊 Detailed Scan Breakdown:")
    print("===========================")
    
    for scan_type, details in scan_summary.items():
        status_emoji = {'clean': '✅', 'vulnerable': '⚠️', 'misconfigured': '🔧'}
        print(f"\n📋 {scan_type.replace('-', ' ').title()}:")
        print(f"   Status: {status_emoji.get(details['status'], '❓')} {details['status'].title()}")
        
        if details['vulnerabilities']:
            for severity, count in details['vulnerabilities'].items():
                if count > 0:
                    emoji = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'}
                    print(f"   {emoji.get(severity, '⚪')} {severity}: {count}")
        
        if details['misconfigurations'] > 0:
            print(f"   ⚙️  Misconfigurations: {details['misconfigurations']}")
        
        if details['packages_affected'] > 0:
            print(f"   📦 Packages affected: {details['packages_affected']}")
    
    # Top vulnerable packages
    if top_packages:
        print(f"\n📦 Most Vulnerable Packages:")
        print("===========================")
        for package, count in top_packages.most_common(10):
            print(f"  • {package}: {count} vulnerabilities")
    
    # Critical/High vulnerabilities details
    critical_high_vulns = [v for v in vulnerability_details if v['severity'] in ['CRITICAL', 'HIGH']]
    
    if critical_high_vulns:
        print(f"\n🚨 Critical & High Severity Issues ({len(critical_high_vulns)}):")
        print("============================================")
        
        for i, vuln in enumerate(critical_high_vulns[:10], 1):  # Show top 10
            severity_emoji = {'CRITICAL': '🔴', 'HIGH': '🟠'}
            print(f"\n{i}. {severity_emoji.get(vuln['severity'], '⚪')} {vuln['cve_id']} ({vuln['severity']})")
            print(f"   📦 Package: {vuln['package']}")
            print(f"   📍 Current: {vuln['installed_version']}")
            print(f"   🔄 Fix: {vuln['fixed_version']}")
            print(f"   📝 {vuln['title']}")
            if vuln['description'] != 'No description':
                print(f"   💭 {vuln['description']}")
        
        if len(critical_high_vulns) > 10:
            print(f"\n   ... and {len(critical_high_vulns) - 10} more critical/high issues")
    
    # Recommendations
    print(f"\n💡 Security Recommendations:")
    print("============================")
    
    if critical_high_count > 0:
        print("🔧 Immediate Actions:")
        print("  - Update vulnerable packages to fixed versions")
        print("  - Prioritize CRITICAL and HIGH severity vulnerabilities")
        print("  - Review container base images for security updates")
        print("  - Implement vulnerability scanning in CI/CD pipeline")
        
        if top_packages:
            most_vulnerable = top_packages.most_common(1)[0]
            print(f"  - Focus on {most_vulnerable[0]} package ({most_vulnerable[1]} vulnerabilities)")
    
    if total_misconfigurations > 0:
        print("\n⚙️  Configuration Security:")
        print("  - Review Kubernetes security configurations")
        print("  - Implement Pod Security Standards")
        print("  - Configure proper RBAC policies")
        print("  - Use security contexts and network policies")
    
    print("\n📚 General Best Practices:")
    print("  - Use minimal base images (alpine, distroless)")
    print("  - Regularly update dependencies and base images")
    print("  - Implement multi-stage Docker builds")
    print("  - Use container image signing and verification")
    print("  - Monitor for new vulnerabilities continuously")
    print("  - Follow principle of least privilege")
    
except Exception as e:
    print(f"Error analyzing results: {e}")
    import traceback
    traceback.print_exc()
EOF
else
    # Fallback analysis without Python
    echo -e "${YELLOW}Python not available for detailed analysis${NC}"
    echo "Basic results summary:"
    
    RESULT_COUNT=$(echo "$RESULT_FILES" | wc -l | xargs)
    echo "Result files found: $RESULT_COUNT"
    
    for file in $RESULT_FILES; do
        filename=$(basename "$file")
        echo "📄 $filename"
        
        if command -v jq &> /dev/null; then
            # Basic parsing with jq if available
            VULNERABILITIES=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "HIGH" or .Severity == "CRITICAL")] | length' "$file" 2>/dev/null || echo "0")
            MISCONFIGS=$(jq '[.Results[]?.Misconfigurations[]?] | length' "$file" 2>/dev/null || echo "0")
            
            if [ "$VULNERABILITIES" -gt 0 ] || [ "$MISCONFIGS" -gt 0 ]; then
                echo "  ⚠️  High/Critical vulnerabilities: $VULNERABILITIES"
                echo "  ⚙️  Misconfigurations: $MISCONFIGS"
            else
                echo "  ✅ No high/critical issues found"
            fi
        else
            echo "  📋 Install jq for detailed analysis"
        fi
    done
fi

echo
echo -e "${BLUE}🔍 Scan Details:${NC}"
echo "================"

if [ -f "$SCAN_LOG" ]; then
    echo "📅 Last Scan: $(grep "Timestamp:" "$SCAN_LOG" | cut -d: -f2- | xargs)"
    
    SCAN_TYPES=$(grep -o "Scan type: .*" "$SCAN_LOG" | sort | uniq | wc -l | xargs)
    echo "🎯 Scan Types: $SCAN_TYPES different scans performed"
    
    if grep -q "Image scan completed successfully" "$SCAN_LOG"; then
        echo "📦 Container Image: ✅ Scanned"
    fi
    
    if grep -q "Filesystem scan completed successfully" "$SCAN_LOG"; then
        echo "📁 Filesystem: ✅ Scanned"
    fi
    
    if grep -q "Kubernetes scan completed successfully" "$SCAN_LOG"; then
        echo "☸️  Kubernetes: ✅ Scanned"
    fi
else
    echo -e "${YELLOW}⚠️  No scan log available${NC}"
fi

echo
echo -e "${BLUE}📁 Output Files:${NC}"
echo "================"
for file in $RESULT_FILES; do
    echo "📄 $file"
done
echo "📝 Scan Log: $SCAN_LOG"
echo "📂 Reports Directory: $OUTPUT_DIR"

echo
echo -e "${BLUE}🔧 Available Commands:${NC}"
echo "===================="
echo "📊 Analyze results:        npm run trivy:analyze"
echo "🔍 Run new scan:           npm run trivy:scan"
echo "🏗️  Scan after build:       npm run build && npm run trivy:scan"
echo "🛡️  Full security suite:    npm run security:scan && npm run virus:scan && npm run trivy:scan"
echo "📋 View specific results:   cat ./trivy-reports/trivy-*-results.json | jq ."
echo "🔍 Filter by severity:      cat ./trivy-reports/trivy-*-results.json | jq '.Results[]?.Vulnerabilities[]? | select(.Severity == \"CRITICAL\")'"

echo
echo -e "${BLUE}🔗 Additional Resources:${NC}"
echo "======================="
echo "• Trivy Documentation: https://trivy.dev/"
echo "• CVE Database: https://cve.mitre.org/"
echo "• National Vulnerability Database: https://nvd.nist.gov/"
echo "• Container Security Best Practices: https://kubernetes.io/docs/concepts/security/"
echo "• Docker Security Guide: https://docs.docker.com/develop/security-best-practices/"

echo
echo "============================================"
echo "Trivy vulnerability analysis complete."
echo "============================================"