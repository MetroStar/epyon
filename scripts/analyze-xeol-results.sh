#!/bin/bash

# Color definitions for enhanced output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

echo -e "${WHITE}============================================${NC}"
echo -e "${WHITE}Xeol End-of-Life Software Analysis${NC}"
echo -e "${WHITE}============================================${NC}"
echo

# Check for results files
FILESYSTEM_RESULTS="./xeol-reports/xeol-filesystem-results.json"
CONTAINER_RESULTS="./xeol-reports/xeol-dockerfile-*-results.json"
BASE_IMAGE_RESULTS="./xeol-reports/xeol-base-*-results.json"
REGISTRY_RESULTS="./xeol-reports/xeol-registry-*-results.json"

# Function to analyze a specific results file
analyze_results_file() {
    local file=$1
    local scan_type=$2
    local color=$3
    
    if [ ! -f "$file" ]; then
        echo -e "${YELLOW}⚠️  No results file found for $scan_type at $file${NC}"
        return 1
    fi
    
    # Use Python to get detailed analysis
    python3 -c "
import json
import sys
from collections import defaultdict

try:
    with open('$file', 'r') as f:
        data = json.load(f)
    
    matches = data.get('matches', [])
    total_eol = len(matches)
    
    print('$color📊 $scan_type Analysis ($total_eol EOL software found):$NC')
    print('=' * 50)
    
    if total_eol == 0:
        print('$GREEN✅ No end-of-life software found in $scan_type$NC')
        print()
        return
    
    # Analyze by package type
    package_types = defaultdict(int)
    package_details = defaultdict(list)
    critical_packages = []
    
    for match in matches:
        artifact = match.get('artifact', {})
        pkg_name = artifact.get('name', 'unknown')
        pkg_version = artifact.get('version', 'unknown')
        pkg_type = artifact.get('type', 'unknown')
        
        package_types[pkg_type] += 1
        package_details[pkg_type].append(f'{pkg_name}@{pkg_version}')
        
        # Check for critical EOL packages
        eol_data = match.get('eolData', {})
        if eol_data.get('isEOL', False):
            cycle = eol_data.get('cycle', 'unknown')
            eol_date = eol_data.get('eolDate', 'unknown')
            critical_packages.append({
                'name': pkg_name,
                'version': pkg_version,
                'type': pkg_type,
                'cycle': cycle,
                'eol_date': eol_date
            })
    
    print('$BLUE🔍 Package Types with EOL Software:$NC')
    for pkg_type, count in sorted(package_types.items()):
        print(f'  📦 {pkg_type}: {count} packages')
    print()
    
    print('$RED🚨 Critical EOL Software (Top 5):$NC')
    for i, pkg in enumerate(critical_packages[:5]):
        print(f'  {i+1}. {pkg[\"name\"]}@{pkg[\"version\"]} ({pkg[\"type\"]})')
        print(f'     EOL Date: {pkg[\"eol_date\"]} | Cycle: {pkg[\"cycle\"]}')
    
    if len(critical_packages) > 5:
        print(f'  ... and {len(critical_packages) - 5} more')
    
    print()
    
    # Risk assessment
    if total_eol > 10:
        print('$RED⚠️  HIGH RISK: Many EOL software components found$NC')
    elif total_eol > 5:
        print('$YELLOW⚠️  MEDIUM RISK: Several EOL software components found$NC')
    elif total_eol > 0:
        print('$YELLOW⚠️  LOW RISK: Few EOL software components found$NC')
    
    print()
    
except Exception as e:
    print(f'❌ Error analyzing $scan_type: {str(e)}')
    print()
" 2>/dev/null
}

# Function to analyze filesystem results
analyze_filesystem() {
    if [ -f "$FILESYSTEM_RESULTS" ]; then
        analyze_results_file "$FILESYSTEM_RESULTS" "Filesystem" "$CYAN"
    else
        echo -e "${YELLOW}⚠️  No filesystem results found${NC}"
        echo
    fi
}

# Function to analyze container results
analyze_containers() {
    local found_any=false
    
    for file in $CONTAINER_RESULTS; do
        if [ -f "$file" ]; then
            container_name=$(basename "$file" .json | sed 's/xeol-//' | sed 's/-results//')
            analyze_results_file "$file" "Container ($container_name)" "$PURPLE"
            found_any=true
        fi
    done
    
    if [ "$found_any" = false ]; then
        echo -e "${YELLOW}⚠️  No container image results found${NC}"
        echo
    fi
}

# Function to analyze base images
analyze_base_images() {
    local found_any=false
    
    for file in $BASE_IMAGE_RESULTS; do
        if [ -f "$file" ]; then
            image_name=$(basename "$file" .json | sed 's/xeol-base-//' | sed 's/-results//' | tr '-' ':')
            analyze_results_file "$file" "Base Image ($image_name)" "$BLUE"
            found_any=true
        fi
    done
    
    if [ "$found_any" = false ]; then
        echo -e "${YELLOW}⚠️  No base image results found${NC}"
        echo
    fi
}

# Function to analyze registry images
analyze_registry_images() {
    local found_any=false
    
    for file in $REGISTRY_RESULTS; do
        if [ -f "$file" ]; then
            registry_name=$(basename "$file" .json | sed 's/xeol-registry-//' | sed 's/-results//')
            analyze_results_file "$file" "Registry ($registry_name)" "$GREEN"
            found_any=true
        fi
    done
    
    if [ "$found_any" = false ]; then
        echo -e "${YELLOW}⚠️  No registry image results found${NC}"
        echo
    fi
}

# Main analysis sections
analyze_filesystem
analyze_containers  
analyze_base_images
analyze_registry_images

# Overall summary and recommendations
echo -e "${WHITE}📈 OVERALL EOL SOFTWARE ASSESSMENT${NC}"
echo "=================================="

# Calculate total EOL software across all scans
total_eol=0
high_risk_count=0

for file in ./xeol-reports/xeol-*-results.json; do
    if [ -f "$file" ]; then
        file_count=$(python3 -c "
import json
try:
    with open('$file', 'r') as f:
        data = json.load(f)
    matches = data.get('matches', [])
    print(len(matches))
    
    # Count high-risk EOL software (very old)
    high_risk = 0
    for match in matches:
        eol_data = match.get('eolData', {})
        if eol_data.get('isEOL', False):
            # Simple heuristic: if EOL date contains '2020' or earlier, it's high risk
            eol_date = eol_data.get('eolDate', '')
            if any(year in str(eol_date) for year in ['2019', '2020', '2018', '2017']):
                high_risk += 1
    print(high_risk, file=sys.stderr)
except Exception as e:
    print('0')
    print('0', file=sys.stderr)
" 2>/tmp/high_risk_count || echo "0")
        
        high_risk_from_file=$(cat /tmp/high_risk_count 2>/dev/null || echo "0")
        total_eol=$((total_eol + file_count))
        high_risk_count=$((high_risk_count + high_risk_from_file))
    fi
done

# Clean up temp file
rm -f /tmp/high_risk_count

if [ "$total_eol" -eq 0 ]; then
    echo -e "${GREEN}✅ EOL SOFTWARE STATUS: EXCELLENT${NC}"
    echo -e "${GREEN}   No end-of-life software detected across all scan targets${NC}"
    echo -e "${GREEN}   Your software stack is up-to-date and secure${NC}"
elif [ "$high_risk_count" -gt 5 ] || [ "$total_eol" -gt 20 ]; then
    echo -e "${RED}❌ EOL SOFTWARE STATUS: HIGH RISK${NC}"
    echo -e "${RED}   Total EOL software: $total_eol (High risk: $high_risk_count)${NC}"
    echo -e "${RED}   IMMEDIATE ACTION REQUIRED - Update critical components${NC}"
elif [ "$total_eol" -gt 10 ]; then
    echo -e "${YELLOW}⚠️  EOL SOFTWARE STATUS: MEDIUM RISK${NC}"
    echo -e "${YELLOW}   Total EOL software: $total_eol (High risk: $high_risk_count)${NC}"
    echo -e "${YELLOW}   Plan updates for end-of-life components${NC}"
else
    echo -e "${BLUE}ℹ️  EOL SOFTWARE STATUS: LOW RISK${NC}"
    echo -e "${BLUE}   Total EOL software: $total_eol (High risk: $high_risk_count)${NC}"
    echo -e "${BLUE}   Monitor and plan updates when convenient${NC}"
fi

echo
echo -e "${BLUE}🔗 Recommended Actions:${NC}"
echo "1. 📋 Review individual EOL components in ./xeol-reports/"
echo "2. 🔄 Update packages to supported versions where possible"
echo "3. 📝 Document EOL software that cannot be immediately updated"
echo "4. 🛡️  Implement additional security measures for legacy components"
echo "5. 📅 Create update schedule for remaining EOL software"

echo
echo -e "${YELLOW}⚠️  Priority Update Recommendations:${NC}"
echo "• Update base Docker images to latest LTS versions"
echo "• Replace EOL Node.js/Python/etc. versions with supported releases"
echo "• Review and update npm/pip/etc. dependencies"
echo "• Consider containerization for isolating legacy components"

echo
echo -e "${WHITE}============================================${NC}"
echo -e "${GREEN}✅ EOL software analysis complete.${NC}"
echo -e "${WHITE}============================================${NC}"