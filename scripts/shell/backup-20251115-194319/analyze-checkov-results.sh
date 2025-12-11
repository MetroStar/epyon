#!/bin/bash

# Checkov Results Analysis Script
# Analyzes Infrastructure-as-Code security scan results and provides detailed reporting

OUTPUT_DIR="../../reports/checkov-reports"
RESULTS_FILE="$OUTPUT_DIR/checkov-results.json"
SCAN_LOG="$OUTPUT_DIR/checkov-scan.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo "============================================"
echo -e "${BLUE}Checkov Infrastructure-as-Code Security Analysis${NC}"
echo "============================================"
echo

# Check if results file exists
if [ ! -f "$RESULTS_FILE" ]; then
    echo -e "${YELLOW}⚠️  No Checkov results found at $RESULTS_FILE${NC}"
    echo "Run 'npm run checkov:scan' first to generate security scan results."
    exit 1
fi

echo -e "${BLUE}📊 Security Scan Overview:${NC}"
echo "=========================="

# Parse JSON results using Python if available, otherwise use basic parsing
if command -v python3 &> /dev/null; then
    python3 << 'EOF'
import json
import sys
from collections import Counter

try:
    with open('./checkov-reports/checkov-results.json', 'r') as f:
        data = json.load(f)
    
    # Extract summary information
    summary = data.get('summary', {})
    passed = summary.get('passed', 0)
    failed = summary.get('failed', 0)
    skipped = summary.get('skipped', 0)
    parsing_errors = summary.get('parsing_errors', 0)
    resource_count = summary.get('resource_count', 0)
    checkov_version = summary.get('checkov_version', 'Unknown')
    
    print(f"Checkov Version: {checkov_version}")
    print(f"Resources Scanned: {resource_count}")
    print(f"Total Checks: {passed + failed + skipped}")
    print(f"✅ Passed Checks: {passed}")
    print(f"❌ Failed Checks: {failed}")
    print(f"⏭️  Skipped Checks: {skipped}")
    if parsing_errors > 0:
        print(f"🚫 Parsing Errors: {parsing_errors}")
    
    print()
    
    # Security status assessment
    if failed == 0:
        print("🎉 Security Status: EXCELLENT")
        print("✅ No security issues detected!")
    elif failed <= 5:
        print("🟢 Security Status: GOOD")
        print(f"⚠️  {failed} minor security issues found")
    elif failed <= 15:
        print("🟡 Security Status: NEEDS ATTENTION")
        print(f"⚠️  {failed} security issues found - review recommended")
    else:
        print("🔴 Security Status: CRITICAL")
        print(f"🚨 {failed} security issues found - immediate attention required")
    
    print()
    
    # Analyze failed checks if any
    if 'results' in data and 'failed_checks' in data['results']:
        failed_checks = data['results']['failed_checks']
        if failed_checks:
            print("🔍 Security Issues Breakdown:")
            print("===========================")
            
            # Group by severity/category
            check_categories = {
                'Resource Management': [],
                'Security Context': [], 
                'Network Security': [],
                'Access Control': [],
                'Configuration': [],
                'Other': []
            }
            
            severity_mapping = {
                'high': [],
                'medium': [],
                'low': [],
                'info': []
            }
            
            for check in failed_checks:
                check_id = check.get('check_id', 'Unknown')
                check_name = check.get('check_name', 'Unknown Check')
                resource = check.get('resource', 'Unknown Resource')
                
                # Categorize checks
                if any(keyword in check_name.lower() for keyword in ['cpu', 'memory', 'resource', 'limit']):
                    check_categories['Resource Management'].append((check_id, check_name, resource))
                elif any(keyword in check_name.lower() for keyword in ['security', 'root', 'uid', 'capabilities', 'privileged']):
                    check_categories['Security Context'].append((check_id, check_name, resource))
                elif any(keyword in check_name.lower() for keyword in ['network', 'policy', 'ingress', 'egress']):
                    check_categories['Network Security'].append((check_id, check_name, resource))
                elif any(keyword in check_name.lower() for keyword in ['admission', 'rbac', 'service', 'account']):
                    check_categories['Access Control'].append((check_id, check_name, resource))
                elif any(keyword in check_name.lower() for keyword in ['probe', 'liveness', 'readiness', 'namespace', 'label']):
                    check_categories['Configuration'].append((check_id, check_name, resource))
                else:
                    check_categories['Other'].append((check_id, check_name, resource))
            
            # Display by category
            for category, checks in check_categories.items():
                if checks:
                    print(f"\n📋 {category} ({len(checks)} issues):")
                    for check_id, check_name, resource in checks[:5]:  # Show top 5 per category
                        print(f"  • {check_id}: {check_name}")
                        print(f"    Resource: {resource}")
                    if len(checks) > 5:
                        print(f"    ... and {len(checks) - 5} more issues")
            
            print(f"\n🔗 Most Common Security Issues:")
            print("==============================")
            
            # Count most common check types
            check_counts = Counter()
            for check in failed_checks:
                check_name = check.get('check_name', 'Unknown')
                check_counts[check_name] += 1
            
            for check_name, count in check_counts.most_common(10):
                print(f"  • {check_name} ({count} occurrences)")
    
    print(f"\n💡 Security Recommendations:")
    print("============================")
    
    if failed > 0:
        print("🔧 Immediate Actions:")
        
        # Provide specific recommendations based on common issues
        resource_issues = len([c for c in failed_checks if any(kw in c.get('check_name', '').lower() for kw in ['cpu', 'memory', 'resource'])])
        security_issues = len([c for c in failed_checks if any(kw in c.get('check_name', '').lower() for kw in ['security', 'root', 'privileged'])])
        network_issues = len([c for c in failed_checks if any(kw in c.get('check_name', '').lower() for kw in ['network', 'policy'])])
        
        if resource_issues > 0:
            print(f"  - Add resource limits and requests to {resource_issues} containers")
            print("  - Define CPU and memory constraints for all pods")
        
        if security_issues > 0:
            print(f"  - Configure security contexts for {security_issues} resources")
            print("  - Implement non-root user policies")
            print("  - Drop unnecessary container capabilities")
        
        if network_issues > 0:
            print(f"  - Implement NetworkPolicies for {network_issues} resources")
            print("  - Restrict pod-to-pod communication")
        
        print("\n📚 General Best Practices:")
        print("  - Use dedicated namespaces (avoid 'default')")
        print("  - Configure liveness and readiness probes")
        print("  - Implement Pod Security Standards")
        print("  - Regular security policy reviews")
        print("  - Use security scanning in CI/CD pipeline")
    else:
        print("🎉 Excellent security posture!")
        print("  - Continue regular security scanning")
        print("  - Monitor for new security best practices")
        print("  - Keep Kubernetes and container images updated")
        print("  - Implement security policy as code")
    
except Exception as e:
    print(f"Error parsing results: {e}")
    sys.exit(1)
EOF
else
    # Fallback parsing without Python
    echo -e "${YELLOW}Python not available for detailed analysis${NC}"
    echo "Basic results summary:"
    
    if grep -q '"failed":' "$RESULTS_FILE"; then
        FAILED=$(grep -o '"failed":[0-9]*' "$RESULTS_FILE" | cut -d':' -f2 | head -1)
        PASSED=$(grep -o '"passed":[0-9]*' "$RESULTS_FILE" | cut -d':' -f2 | head -1)
        
        echo "Passed checks: ${PASSED:-0}"
        echo "Failed checks: ${FAILED:-0}"
        
        if [ "${FAILED:-0}" -gt 0 ]; then
            echo -e "${YELLOW}⚠️  Security issues detected${NC}"
        else
            echo -e "${GREEN}✅ No security issues found${NC}"
        fi
    fi
fi

echo
echo -e "${BLUE}🔍 Scan Details:${NC}"
echo "================"

if [ -f "$SCAN_LOG" ]; then
    echo "📅 Last Scan: $(grep "Timestamp:" "$SCAN_LOG" | cut -d: -f2- | xargs)"
    
    if grep -q "Scan target:" "$SCAN_LOG"; then
        SCAN_TARGET=$(grep "Scan target:" "$SCAN_LOG" | cut -d: -f2- | xargs)
        echo "🎯 Scan Target: $SCAN_TARGET"
    fi
    
    if grep -q "Scan type:" "$SCAN_LOG"; then
        SCAN_TYPE=$(grep "Scan type:" "$SCAN_LOG" | cut -d: -f2- | xargs)
        echo "📋 Scan Type: $SCAN_TYPE"
    fi
else
    echo -e "${YELLOW}⚠️  No scan log available${NC}"
fi

echo
echo -e "${BLUE}📁 Output Files:${NC}"
echo "================"
echo "📄 Results JSON: $RESULTS_FILE"
if [ -f "$SCAN_LOG" ]; then
    echo "📝 Scan Log: $SCAN_LOG"
fi
echo "📂 Reports Directory: $OUTPUT_DIR"

echo
echo -e "${BLUE}🔧 Available Commands:${NC}"
echo "===================="
echo "📊 Analyze results:       npm run checkov:analyze"
echo "🔍 Run new scan:          npm run checkov:scan"
echo "🏗️  Scan after Helm build: npm run helm:build && npm run checkov:scan"
echo "🛡️  Full security suite:   npm run security:scan && npm run virus:scan && npm run checkov:scan"
echo "📋 View raw results:      cat $RESULTS_FILE | jq ."

echo
echo -e "${BLUE}🔗 Additional Resources:${NC}"
echo "======================="
echo "• Kubernetes Security Best Practices: https://kubernetes.io/docs/concepts/security/"
echo "• Pod Security Standards: https://kubernetes.io/docs/concepts/security/pod-security-standards/"
echo "• Checkov Documentation: https://www.checkov.io/5.Policy%20Index/kubernetes.html"
echo "• CIS Kubernetes Benchmark: https://www.cisecurity.org/benchmark/kubernetes"

echo
echo "============================================"
echo "Analysis complete."
echo "============================================"