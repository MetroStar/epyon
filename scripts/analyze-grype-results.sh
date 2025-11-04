#!/bin/bash

# Grype Results Analysis Script
# Analyzes container image and filesystem vulnerability scan results with SBOM integration

OUTPUT_DIR="./grype-reports"
SCAN_LOG="$OUTPUT_DIR/grype-scan.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo "============================================"
echo -e "${PURPLE}Grype Vulnerability & SBOM Analysis Report${NC}"
echo "============================================"
echo

# Check if results directory exists
if [ ! -d "$OUTPUT_DIR" ]; then
    echo -e "${YELLOW}⚠️  No Grype results found at $OUTPUT_DIR${NC}"
    echo "Run 'npm run grype:scan' first to generate vulnerability scan results."
    exit 1
fi

# Find all Grype result files
RESULT_FILES=$(find "$OUTPUT_DIR" -name "grype-*-results.json" 2>/dev/null)
SBOM_FILES=$(find "$OUTPUT_DIR" -name "sbom-*.json" 2>/dev/null)

if [ -z "$RESULT_FILES" ]; then
    echo -e "${YELLOW}⚠️  No Grype result files found${NC}"
    echo "Run 'npm run grype:scan' first to generate vulnerability scan results."
    exit 1
fi

RESULT_COUNT=$(echo "$RESULT_FILES" | wc -l | xargs)
SBOM_COUNT=$(echo "$SBOM_FILES" | wc -l | xargs)

echo -e "${BLUE}📊 Vulnerability Scan Overview:${NC}"
echo "==============================="
echo -e "Vulnerability Reports: ${CYAN}$RESULT_COUNT${NC}"
echo -e "SBOM Reports: ${CYAN}$SBOM_COUNT${NC}"

# Detailed analysis using Python if available
if command -v python3 &> /dev/null; then
    python3 << 'EOF'
import json
import glob
import os
from collections import Counter, defaultdict

try:
    output_dir = "./grype-reports"
    result_files = glob.glob(f"{output_dir}/grype-*-results.json")
    sbom_files = glob.glob(f"{output_dir}/sbom-*.json")
    
    if not result_files:
        print("No Grype result files found")
        exit(1)
    
    print(f"\n🔍 Processing {len(result_files)} vulnerability reports...")
    
    # Initialize counters
    total_vulnerabilities = defaultdict(int)
    scan_summary = {}
    vulnerability_details = []
    package_vulnerabilities = Counter()
    cve_details = []
    ecosystem_stats = defaultdict(int)
    
    for file_path in result_files:
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            filename = os.path.basename(file_path)
            scan_type = filename.replace('grype-', '').replace('-results.json', '')
            scan_summary[scan_type] = {
                'vulnerabilities': defaultdict(int),
                'packages_affected': 0,
                'status': 'clean',
                'ecosystems': defaultdict(int)
            }
            
            print(f"📋 Processing: {scan_type}")
            
            # Handle Grype JSON format
            if 'matches' in data and data['matches']:
                matches = data['matches']
                
                for match in matches:
                    vuln = match.get('vulnerability', {})
                    artifact = match.get('artifact', {})
                    
                    severity = vuln.get('severity', 'Unknown')
                    total_vulnerabilities[severity] += 1
                    scan_summary[scan_type]['vulnerabilities'][severity] += 1
                    scan_summary[scan_type]['status'] = 'vulnerable'
                    
                    # Count ecosystems/languages
                    ecosystem = artifact.get('language', artifact.get('type', 'Unknown'))
                    ecosystem_stats[ecosystem] += 1
                    scan_summary[scan_type]['ecosystems'][ecosystem] += 1
                    
                    # Collect vulnerability details
                    package_name = artifact.get('name', 'Unknown')
                    package_version = artifact.get('version', 'Unknown')
                    cve_id = vuln.get('id', 'Unknown')
                    
                    vulnerability_details.append({
                        'scan_type': scan_type,
                        'cve_id': cve_id,
                        'severity': severity,
                        'package': package_name,
                        'version': package_version,
                        'ecosystem': ecosystem,
                        'description': vuln.get('description', 'No description')[:200] + '...' if vuln.get('description', '') else 'No description',
                        'fixed_in': vuln.get('fix', {}).get('versions', []) if vuln.get('fix') else [],
                        'urls': vuln.get('urls', [])
                    })
                    
                    # Count package vulnerabilities
                    package_vulnerabilities[f"{package_name} ({ecosystem})"] += 1
                
                scan_summary[scan_type]['packages_affected'] = len(set([
                    match.get('artifact', {}).get('name', '') 
                    for match in matches 
                    if match.get('artifact', {}).get('name')
                ]))
            
        except Exception as e:
            print(f"  ⚠️  Could not parse {filename}: {str(e)}")
            continue
    
    # Print overall summary
    print(f"\n🎯 Overall Vulnerability Summary:")
    print("================================")
    
    if total_vulnerabilities:
        for severity in ['Critical', 'High', 'Medium', 'Low', 'Negligible', 'Unknown']:
            count = total_vulnerabilities.get(severity, 0)
            if count > 0:
                emoji = {'Critical': '🔴', 'High': '🟠', 'Medium': '🟡', 'Low': '🟢', 'Negligible': '⚪', 'Unknown': '❓'}
                print(f"  {emoji.get(severity, '❓')} {severity}: {count}")
    else:
        print("  ✅ No vulnerabilities found across all scans")
    
    # Security assessment
    critical_high_count = total_vulnerabilities.get('Critical', 0) + total_vulnerabilities.get('High', 0)
    
    print(f"\n🛡️  Security Assessment:")
    print("======================")
    
    if critical_high_count == 0:
        print("🟢 Security Status: EXCELLENT")
        print("✅ No critical or high severity vulnerabilities detected")
    elif critical_high_count <= 5:
        print("🟡 Security Status: GOOD") 
        print(f"⚠️  {critical_high_count} critical/high vulnerabilities found")
    elif critical_high_count <= 15:
        print("🟠 Security Status: NEEDS ATTENTION")
        print(f"⚠️  {critical_high_count} critical/high vulnerabilities found")
    else:
        print("🔴 Security Status: CRITICAL")
        print(f"🚨 {critical_high_count} critical/high vulnerabilities - immediate action required")
    
    # Ecosystem breakdown
    if ecosystem_stats:
        print(f"\n📦 Ecosystem Vulnerability Breakdown:")
        print("=====================================")
        for ecosystem, count in ecosystem_stats.most_common():
            if count > 0:
                print(f"  • {ecosystem}: {count} vulnerabilities")
    
    # Detailed breakdown by scan type
    print(f"\n📊 Detailed Scan Breakdown:")
    print("===========================")
    
    for scan_type, details in scan_summary.items():
        status_emoji = {'clean': '✅', 'vulnerable': '⚠️'}
        print(f"\n📋 {scan_type.replace('-', ' ').title()}:")
        print(f"   Status: {status_emoji.get(details['status'], '❓')} {details['status'].title()}")
        
        if details['vulnerabilities']:
            for severity, count in details['vulnerabilities'].items():
                if count > 0:
                    emoji = {'Critical': '🔴', 'High': '🟠', 'Medium': '🟡', 'Low': '🟢', 'Negligible': '⚪'}
                    print(f"   {emoji.get(severity, '❓')} {severity}: {count}")
        
        if details['packages_affected'] > 0:
            print(f"   📦 Packages affected: {details['packages_affected']}")
        
        if details['ecosystems']:
            ecosystems = [f"{eco}({count})" for eco, count in details['ecosystems'].items() if count > 0]
            print(f"   🔧 Ecosystems: {', '.join(ecosystems[:3])}")
    
    # Most vulnerable packages
    if package_vulnerabilities:
        print(f"\n📦 Most Vulnerable Packages:")
        print("===========================")
        for package, count in package_vulnerabilities.most_common(10):
            print(f"  • {package}: {count} vulnerabilities")
    
    # Critical/High vulnerabilities details
    critical_high_vulns = [v for v in vulnerability_details if v['severity'] in ['Critical', 'High']]
    
    if critical_high_vulns:
        print(f"\n🚨 Critical & High Severity Vulnerabilities ({len(critical_high_vulns)}):")
        print("========================================================")
        
        for i, vuln in enumerate(critical_high_vulns[:10], 1):  # Show top 10
            severity_emoji = {'Critical': '🔴', 'High': '🟠'}
            print(f"\n{i}. {severity_emoji.get(vuln['severity'], '⚪')} {vuln['cve_id']} ({vuln['severity']})")
            print(f"   📦 Package: {vuln['package']} v{vuln['version']}")
            print(f"   🔧 Ecosystem: {vuln['ecosystem']}")
            if vuln['fixed_in']:
                fixed_versions = ', '.join(vuln['fixed_in'][:3])
                print(f"   🔄 Fixed in: {fixed_versions}")
            else:
                print(f"   🔄 Fix: Not available")
            print(f"   💭 {vuln['description']}")
            if vuln['urls']:
                print(f"   🔗 More info: {vuln['urls'][0]}")
        
        if len(critical_high_vulns) > 10:
            print(f"\n   ... and {len(critical_high_vulns) - 10} more critical/high vulnerabilities")
    
    # SBOM Analysis
    print(f"\n📋 Software Bill of Materials (SBOM) Analysis:")
    print("==============================================")
    
    if sbom_files:
        print(f"Found {len(sbom_files)} SBOM files for component analysis")
        
        total_components = 0
        ecosystems_found = set()
        
        for sbom_file in sbom_files:
            try:
                with open(sbom_file, 'r') as f:
                    sbom_data = json.load(f)
                
                sbom_filename = os.path.basename(sbom_file)
                
                # Handle SPDX format
                if 'packages' in sbom_data:
                    packages = sbom_data['packages']
                    component_count = len([p for p in packages if p.get('name') != 'DOCUMENT'])
                    total_components += component_count
                    
                    print(f"\n📦 {sbom_filename}:")
                    print(f"   Components: {component_count}")
                    
                    # Extract ecosystems from package info
                    for package in packages:
                        if package.get('name') != 'DOCUMENT':
                            # Try to determine ecosystem from external refs or supplier
                            external_refs = package.get('externalRefs', [])
                            for ref in external_refs:
                                if ref.get('referenceType') == 'purl':
                                    purl = ref.get('referenceLocator', '')
                                    if 'pkg:' in purl:
                                        ecosystem = purl.split(':')[1] if ':' in purl else 'unknown'
                                        ecosystems_found.add(ecosystem)
                
            except Exception as e:
                print(f"  ⚠️  Could not parse SBOM {sbom_filename}: {str(e)}")
        
        print(f"\n📊 SBOM Summary:")
        print(f"   Total Components: {total_components}")
        if ecosystems_found:
            print(f"   Ecosystems: {', '.join(sorted(ecosystems_found))}")
    else:
        print("⚠️  No SBOM files found - run scan to generate component inventory")
    
    # Recommendations
    print(f"\n💡 Security Recommendations:")
    print("============================")
    
    if critical_high_count > 0:
        print("🔧 Immediate Actions:")
        print("  - Update vulnerable packages to fixed versions")
        print("  - Prioritize Critical and High severity vulnerabilities")
        print("  - Review container base images for newer versions")
        print("  - Implement automated vulnerability monitoring")
        
        if package_vulnerabilities:
            most_vulnerable = package_vulnerabilities.most_common(1)[0]
            print(f"  - Focus on {most_vulnerable[0]} ({most_vulnerable[1]} vulnerabilities)")
    
    print("\n📚 General Best Practices:")
    print("  - Regularly update dependencies and base images")
    print("  - Use minimal base images (alpine, distroless)")
    print("  - Implement automated dependency scanning in CI/CD")
    print("  - Monitor vulnerability databases for new CVEs")
    print("  - Maintain up-to-date Software Bill of Materials (SBOM)")
    print("  - Use package managers with vulnerability scanning features")
    print("  - Implement security policies for dependency management")
    
    if ecosystem_stats:
        print(f"\n🔧 Ecosystem-Specific Recommendations:")
        for ecosystem, count in ecosystem_stats.most_common(3):
            if ecosystem.lower() == 'javascript' or ecosystem.lower() == 'npm':
                print("  • JavaScript/NPM: Use npm audit, Snyk, or similar tools")
                print("  • Consider using npm ci for production builds")
            elif ecosystem.lower() == 'python':
                print("  • Python: Use safety, bandit, or pip-audit for scanning")
                print("  • Pin dependency versions in requirements.txt")
            elif ecosystem.lower() == 'go':
                print("  • Go: Use govulncheck for Go-specific vulnerability scanning")
                print("  • Keep Go version updated for security patches")
        
except Exception as e:
    print(f"Error analyzing results: {e}")
    import traceback
    traceback.print_exc()
EOF
else
    # Fallback analysis without Python
    echo -e "${YELLOW}Python not available for detailed analysis${NC}"
    echo "Basic results summary:"
    
    for file in $RESULT_FILES; do
        filename=$(basename "$file")
        echo "📄 $filename"
        
        if command -v jq &> /dev/null; then
            # Basic parsing with jq if available
            TOTAL_MATCHES=$(jq '.matches | length' "$file" 2>/dev/null || echo "0")
            CRITICAL_HIGH=$(jq '[.matches[] | select(.vulnerability.severity == "Critical" or .vulnerability.severity == "High")] | length' "$file" 2>/dev/null || echo "0")
            
            if [ "$TOTAL_MATCHES" -gt 0 ]; then
                echo "  📊 Total vulnerabilities: $TOTAL_MATCHES"
                echo "  🚨 Critical/High: $CRITICAL_HIGH"
            else
                echo "  ✅ No vulnerabilities found"
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
    echo "🎯 Scan Types: $SCAN_TYPES different scan targets"
    
    if grep -q "Image scan completed successfully" "$SCAN_LOG"; then
        echo "📦 Container Images: ✅ Scanned"
    fi
    
    if grep -q "Filesystem scan completed successfully" "$SCAN_LOG"; then
        echo "📁 Filesystems: ✅ Scanned"
    fi
    
    if grep -q "Package scan completed" "$SCAN_LOG"; then
        echo "📋 Package Files: ✅ Analyzed"
    fi
else
    echo -e "${YELLOW}⚠️  No scan log available${NC}"
fi

echo
echo -e "${BLUE}📁 Output Files:${NC}"
echo "================"
echo "🔍 Vulnerability Reports:"
for file in $RESULT_FILES; do
    echo "  📄 $file"
done
if [ -n "$SBOM_FILES" ]; then
    echo "📋 SBOM Reports:"
    for file in $SBOM_FILES; do
        echo "  📦 $file"
    done
fi
echo "📝 Scan Log: $SCAN_LOG"
echo "📂 Reports Directory: $OUTPUT_DIR"

echo
echo -e "${BLUE}🔧 Available Commands:${NC}"
echo "===================="
echo "📊 Analyze results:         npm run grype:analyze"
echo "🔍 Run new scan:            npm run grype:scan"
echo "🏗️  Scan after build:        npm run build && npm run grype:scan"
echo "🛡️  Compare with Trivy:      npm run trivy:scan && npm run grype:scan"
echo "📋 View specific results:    cat ./grype-reports/grype-*-results.json | jq ."
echo "📦 View SBOM details:        cat ./grype-reports/sbom-*.json | jq '.packages[] | select(.name != \"DOCUMENT\")'"
echo "🔍 Filter by severity:       cat ./grype-reports/grype-*-results.json | jq '.matches[] | select(.vulnerability.severity == \"Critical\")'"

echo
echo -e "${BLUE}🔗 Additional Resources:${NC}"
echo "======================="
echo "• Grype Documentation: https://github.com/anchore/grype"
echo "• Syft SBOM Documentation: https://github.com/anchore/syft"
echo "• Anchore Security Blog: https://anchore.com/blog/"
echo "• SBOM Guidelines: https://www.cisa.gov/sbom"
echo "• CVE Database: https://cve.mitre.org/"
echo "• National Vulnerability Database: https://nvd.nist.gov/"
echo "• NIST Secure Software Development: https://csrc.nist.gov/Projects/ssdf"

echo
echo "============================================"
echo "Grype vulnerability and SBOM analysis complete."
echo "============================================"