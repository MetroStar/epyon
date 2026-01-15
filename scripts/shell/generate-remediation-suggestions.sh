#!/bin/bash

# Remediation Suggestions Generator
# Analyzes vulnerability scan results and generates actionable fix recommendations

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Display EPYON banner
echo -e "${CYAN}"
cat << "EOF"
███████╗██████╗ ██╗   ██╗ ██████╗ ███╗   ██╗
██╔════╝██╔══██╗╚██╗ ██╔╝██╔═══██╗████╗  ██║
█████╗  ██████╔╝ ╚████╔╝ ██║   ██║██╔██╗ ██║
██╔══╝  ██╔═══╝   ╚██╔╝  ██║   ██║██║╚██╗██║
███████╗██║        ██║   ╚██████╔╝██║ ╚████║
╚══════╝╚═╝        ╚═╝    ╚═════╝ ╚═╝  ╚═══╝
EOF
echo -e "${NC}"
echo -e "${GREEN}Absolute Security Control - Remediation Engine${NC}"
echo ""

# Help function
show_help() {
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}  Automated Remediation Suggestions Generator${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo ""
    echo "Usage: $0 [OPTIONS] [SCAN_DIRECTORY]"
    echo ""
    echo "Analyzes vulnerability scan results and generates actionable remediation suggestions"
    echo "including version upgrades, alternative packages, and commands to fix issues."
    echo ""
    echo "Arguments:"
    echo "  SCAN_DIRECTORY    Path to scan results directory (default: latest scan)"
    echo ""
    echo "Options:"
    echo "  -h, --help        Show this help message"
    echo "  -o, --output FILE Output recommendations to file"
    echo "  --json            Output in JSON format"
    echo "  --html            Generate HTML report"
    echo "  --severity LEVEL  Only show fixes for severity level and above"
    echo "                    (CRITICAL, HIGH, MEDIUM, LOW)"
    echo ""
    echo "Examples:"
    echo "  $0                                    # Use latest scan"
    echo "  $0 scans/myproject_2026-01-15/       # Specific scan"
    echo "  $0 --severity HIGH --output fixes.md # High+ only, save to file"
    echo ""
    exit 0
}

# Parse arguments
OUTPUT_FILE=""
OUTPUT_FORMAT="text"
MIN_SEVERITY="MEDIUM"
SCAN_DIR=""

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_help
            ;;
        -o|--output)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        --json)
            OUTPUT_FORMAT="json"
            shift
            ;;
        --html)
            OUTPUT_FORMAT="html"
            shift
            ;;
        --severity)
            MIN_SEVERITY="$2"
            shift 2
            ;;
        *)
            SCAN_DIR="$1"
            shift
            ;;
    esac
done

# Find latest scan if not specified
if [ -z "$SCAN_DIR" ]; then
    SCAN_DIR=$(find "$SCRIPT_DIR/../../scans" -type d -name "*_*_20*" 2>/dev/null | sort -r | head -1)
    if [ -z "$SCAN_DIR" ]; then
        echo -e "${RED}❌ No scan results found${NC}"
        exit 1
    fi
    echo -e "${CYAN}📂 Using latest scan: $(basename "$SCAN_DIR")${NC}"
fi

# Validate scan directory
if [ ! -d "$SCAN_DIR" ]; then
    echo -e "${RED}❌ Scan directory not found: $SCAN_DIR${NC}"
    exit 1
fi

# Find scan result files
TRIVY_FILES=$(find "$SCAN_DIR/trivy" -name "*.json" -type f 2>/dev/null || echo "")
GRYPE_FILES=$(find "$SCAN_DIR/grype" -name "*.json" -type f 2>/dev/null || echo "")

if [ -z "$TRIVY_FILES" ] && [ -z "$GRYPE_FILES" ]; then
    echo -e "${RED}❌ No vulnerability scan results found in $SCAN_DIR${NC}"
    exit 1
fi

echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  Generating Remediation Suggestions${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo ""

# Function to get severity priority
get_severity_priority() {
    case "$1" in
        CRITICAL) echo 4 ;;
        HIGH) echo 3 ;;
        MEDIUM) echo 2 ;;
        LOW) echo 1 ;;
        *) echo 0 ;;
    esac
}

MIN_PRIORITY=$(get_severity_priority "$MIN_SEVERITY")

# Function to determine package manager from package type
get_package_manager() {
    local pkg_type="$1"
    local pkg_name="${2:-}"
    
    # Check package type first
    case "$pkg_type" in
        npm|node-pkg|javascript) echo "npm" ;;
        pip|python-pkg|python) echo "pip" ;;
        gem|ruby) echo "gem" ;;
        cargo|rust) echo "cargo" ;;
        go-module|golang|go) echo "go" ;;
        maven|java-archive) echo "mvn" ;;
        apk|alpine) echo "apk" ;;
        deb|debian) echo "apt" ;;
        rpm|redhat) echo "yum" ;;
        *)
            # Try to infer from package name patterns if provided
            if [ -n "$pkg_name" ]; then
                if [[ "$pkg_name" =~ ^@.*/ ]] || [[ "$pkg_name" =~ (react|vue|angular|webpack|babel|eslint|jest|glob) ]]; then
                    echo "npm"
                elif [[ "$pkg_name" =~ -py$ ]] || [[ "$pkg_name" =~ ^python ]]; then
                    echo "pip"
                else
                    echo "unknown"
                fi
            else
                echo "unknown"
            fi
            ;;
    esac
}

# Function to generate update command
generate_update_command() {
    local pkg_manager="$1"
    local pkg_name="$2"
    local fixed_version="$3"
    
    case "$pkg_manager" in
        npm)
            # Handle multiple versions (e.g., "11.1.0, 10.5.0")
            local first_version=$(echo "$fixed_version" | cut -d',' -f1 | tr -d ' ')
            if [ "$fixed_version" != "N/A" ]; then
                echo "npm update $pkg_name@$first_version  # or: npm install $pkg_name@$first_version"
            else
                echo "npm update $pkg_name"
            fi
            ;;
        pip)
            local first_version=$(echo "$fixed_version" | cut -d',' -f1 | tr -d ' ')
            if [ "$fixed_version" != "N/A" ]; then
                echo "pip install --upgrade $pkg_name==$first_version"
            else
                echo "pip install --upgrade $pkg_name"
            fi
            ;;
        gem)
            echo "bundle update $pkg_name"
            ;;
        cargo)
            echo "cargo update $pkg_name"
            ;;
        go)
            echo "go get -u $pkg_name"
            ;;
        mvn)
            echo "# Update version in pom.xml to $fixed_version"
            ;;
        apk)
            echo "apk upgrade $pkg_name  # Update base image: docker pull bitnami/node:latest"
            ;;
        apt)
            echo "apt-get update && apt-get install --only-upgrade $pkg_name  # Update base image recommended"
            ;;
        yum)
            echo "yum update $pkg_name  # Update base image recommended"
            ;;
        unknown)
            if [[ "$pkg_name" =~ \.(so|dll|dylib) ]]; then
                echo "# System library - update base container image"
            else
                echo "# Check package manager documentation for: $pkg_name"
            fi
            ;;
        *)
            echo "# Manual update required - check package manager for $pkg_name"
            ;;
    esac
}

# Temporary file for collecting remediation data
TEMP_DATA=$(mktemp)
trap 'rm -f $TEMP_DATA' EXIT

echo -e "${CYAN}🔍 Analyzing vulnerability scan results...${NC}"
echo ""

# Process Trivy results
if [ -n "$TRIVY_FILES" ]; then
    for file in $TRIVY_FILES; do
        echo -e "${BLUE}  📄 Processing $(basename "$file")${NC}"
        
        # Extract vulnerabilities with fixes
        jq -r '.Results[]? | select(.Vulnerabilities) | .Vulnerabilities[] | 
            select(.Severity) | 
            {
                cve: (.VulnerabilityID // "UNKNOWN"),
                severity: .Severity,
                package: .PkgName,
                version: .InstalledVersion,
                fixed_version: (.FixedVersion // "N/A"),
                title: (.Title // .Description // "No description"),
                pkg_type: (.PkgType // "unknown"),
                cvss: (.CVSS.nvd.V3Score // .CVSS.redhat.V3Score // 0)
            } | 
            @json' "$file" 2>/dev/null >> "$TEMP_DATA" || true
    done
fi

# Process Grype results
if [ -n "$GRYPE_FILES" ]; then
    for file in $GRYPE_FILES; do
        echo -e "${BLUE}  📄 Processing $(basename "$file")${NC}"
        
        # Extract vulnerabilities with fixes
        jq -r '.matches[]? | 
            select(.vulnerability.severity) |
            {
                cve: .vulnerability.id,
                severity: .vulnerability.severity,
                package: .artifact.name,
                version: .artifact.version,
                fixed_version: (.vulnerability.fix.versions[0] // "N/A"),
                title: (.vulnerability.description // "No description"),
                pkg_type: .artifact.type,
                cvss: (.vulnerability.cvss[0].metrics.baseScore // 0)
            } | 
            @json' "$file" 2>/dev/null >> "$TEMP_DATA" || true
    done
fi

# Deduplicate and sort by severity
echo -e "${CYAN}📊 Deduplicating and prioritizing findings...${NC}"
echo ""

# Count total vulnerabilities
TOTAL_VULNS=$(cat "$TEMP_DATA" | wc -l | tr -d ' ')

if [ "$TOTAL_VULNS" -eq 0 ]; then
    echo -e "${GREEN}✅ No vulnerabilities found requiring remediation!${NC}"
    exit 0
fi

# Group by package and CVE, keep highest severity
REMEDIATION_DATA=$(jq -s '
    group_by(.package + .cve) | 
    map({
        cve: .[0].cve,
        severity: (map(.severity) | max),
        package: .[0].package,
        version: .[0].version,
        fixed_version: .[0].fixed_version,
        title: .[0].title,
        pkg_type: .[0].pkg_type,
        cvss: (map(.cvss) | max)
    }) |
    sort_by(.severity) | 
    reverse
' "$TEMP_DATA")

# Filter by minimum severity
FILTERED_DATA=$(echo "$REMEDIATION_DATA" | jq --arg min_sev "$MIN_SEVERITY" '
    map(select(
        (if .severity == "CRITICAL" then 4 
         elif .severity == "HIGH" then 3 
         elif .severity == "MEDIUM" then 2 
         elif .severity == "LOW" then 1 
         else 0 end) >= 
        (if $min_sev == "CRITICAL" then 4 
         elif $min_sev == "HIGH" then 3 
         elif $min_sev == "MEDIUM" then 2 
         elif $min_sev == "LOW" then 1 
         else 0 end)
    ))
')

FILTERED_COUNT=$(echo "$FILTERED_DATA" | jq 'length')

if [ "$FILTERED_COUNT" -eq 0 ]; then
    echo -e "${GREEN}✅ No vulnerabilities found at $MIN_SEVERITY severity or higher!${NC}"
    exit 0
fi

echo -e "${YELLOW}⚠️  Found $FILTERED_COUNT unique vulnerabilities requiring attention${NC}"
echo -e "${CYAN}   (Filtered by: $MIN_SEVERITY and above)${NC}"
echo ""

# Generate output based on format
case "$OUTPUT_FORMAT" in
    json)
        # JSON output
        OUTPUT=$(echo "$FILTERED_DATA" | jq '{
            scan_directory: "'"$SCAN_DIR"'",
            generated_at: "'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'",
            total_vulnerabilities: '"$FILTERED_COUNT"',
            minimum_severity: "'"$MIN_SEVERITY"'",
            remediations: [.[] | {
                cve: .cve,
                severity: .severity,
                cvss_score: .cvss,
                package: {
                    name: .package,
                    current_version: .version,
                    fixed_version: .fixed_version,
                    type: .pkg_type,
                    package_manager: (if .pkg_type == "npm" or .pkg_type == "node-pkg" then "npm"
                                     elif .pkg_type == "pip" or .pkg_type == "python-pkg" then "pip"
                                     elif .pkg_type == "gem" then "gem"
                                     elif .pkg_type == "cargo" then "cargo"
                                     elif .pkg_type == "go-module" then "go"
                                     else "unknown" end)
                },
                description: .title,
                remediation: {
                    fix_available: (.fixed_version != "N/A"),
                    recommended_action: (if .fixed_version != "N/A" then "upgrade" else "investigate" end),
                    update_command: (if .fixed_version != "N/A" then 
                                     (if .pkg_type == "npm" or .pkg_type == "node-pkg" then "npm update " + .package + "@" + .fixed_version
                                      elif .pkg_type == "pip" or .pkg_type == "python-pkg" then "pip install --upgrade " + .package + "==" + .fixed_version
                                      else "See package manager documentation" end)
                                     else "No fix available yet" end)
                },
                priority: (if .severity == "CRITICAL" then "P0"
                          elif .severity == "HIGH" then "P1"
                          elif .severity == "MEDIUM" then "P2"
                          else "P3" end)
            }]
        }')
        
        if [ -n "$OUTPUT_FILE" ]; then
            echo "$OUTPUT" > "$OUTPUT_FILE"
            echo -e "${GREEN}✅ JSON remediation report saved to: $OUTPUT_FILE${NC}"
        else
            echo "$OUTPUT"
        fi
        ;;
        
    text|*)
        # Text output
        {
            echo "╔═══════════════════════════════════════════════════════════════════════════╗"
            echo "║                    VULNERABILITY REMEDIATION REPORT                        ║"
            echo "╚═══════════════════════════════════════════════════════════════════════════╝"
            echo ""
            echo "📅 Generated: $(date '+%Y-%m-%d %H:%M:%S')"
            echo "📂 Scan: $(basename "$SCAN_DIR")"
            echo "🎯 Filter: $MIN_SEVERITY and above"
            echo "📊 Vulnerabilities: $FILTERED_COUNT"
            echo ""
            echo "═══════════════════════════════════════════════════════════════════════════"
            echo ""
            
            # Process each vulnerability
            COUNTER=1
            echo "$FILTERED_DATA" | jq -r '.[] | @json' | while read -r vuln; do
                CVE=$(echo "$vuln" | jq -r '.cve')
                SEVERITY=$(echo "$vuln" | jq -r '.severity')
                PACKAGE=$(echo "$vuln" | jq -r '.package')
                VERSION=$(echo "$vuln" | jq -r '.version')
                FIXED=$(echo "$vuln" | jq -r '.fixed_version')
                TITLE=$(echo "$vuln" | jq -r '.title' | head -c 100)
                PKG_TYPE=$(echo "$vuln" | jq -r '.pkg_type')
                CVSS=$(echo "$vuln" | jq -r '.cvss')
                
                # Determine priority
                case "$SEVERITY" in
                    CRITICAL) PRIORITY="P0 🔴" ;;
                    HIGH) PRIORITY="P1 🟠" ;;
                    MEDIUM) PRIORITY="P2 🟡" ;;
                    LOW) PRIORITY="P3 🟢" ;;
                    *) PRIORITY="P4 ⚪" ;;
                esac
                
                PKG_MGR=$(get_package_manager "$PKG_TYPE")
                
                echo "┌─────────────────────────────────────────────────────────────────────────┐"
                echo "│ #$COUNTER - $CVE"
                echo "├─────────────────────────────────────────────────────────────────────────┤"
                echo "│ 📦 Package:    $PACKAGE@$VERSION"
                echo "│ ⚠️  Severity:   $SEVERITY (CVSS: $CVSS) - Priority: $PRIORITY"
                echo "│ 📝 Summary:    $TITLE"
                
                if [ "$FIXED" != "N/A" ]; then
                    echo "│"
                    echo "│ ✅ FIX AVAILABLE"
                    echo "│ ├─ Fixed Version: $FIXED"
                    
                    UPDATE_CMD=$(generate_update_command "$PKG_MGR" "$PACKAGE" "$FIXED")
                    echo "│ ├─ Package Manager: $PKG_MGR"
                    echo "│ └─ Command:"
                    echo "│    $UPDATE_CMD"
                    echo "│"
                    echo "│ 🔧 Recommended Actions:"
                    echo "│    1. Review changelog for breaking changes"
                    echo "│    2. Run: $UPDATE_CMD"
                    echo "│    3. Test application thoroughly"
                    echo "│    4. Commit updated lock file"
                else
                    echo "│"
                    echo "│ ⚠️  NO FIX AVAILABLE YET"
                    echo "│ 🔧 Recommended Actions:"
                    echo "│    1. Monitor for security updates"
                    echo "│    2. Check if vulnerability applies to your usage"
                    echo "│    3. Consider alternative packages"
                    echo "│    4. Implement compensating controls if critical"
                fi
                
                echo "│"
                echo "│ 🔗 More Info:"
                echo "│    https://nvd.nist.gov/vuln/detail/$CVE"
                echo "└─────────────────────────────────────────────────────────────────────────┘"
                echo ""
                
                COUNTER=$((COUNTER + 1))
            done
            
            echo "═══════════════════════════════════════════════════════════════════════════"
            echo ""
            echo "📋 SUMMARY OF ACTIONS"
            echo "─────────────────────────────────────────────────────────────────────────"
            
            # Count fixable vs non-fixable
            FIXABLE=$(echo "$FILTERED_DATA" | jq '[.[] | select(.fixed_version != "N/A")] | length')
            NOT_FIXABLE=$((FILTERED_COUNT - FIXABLE))
            
            echo "✅ Fixable vulnerabilities: $FIXABLE"
            echo "⚠️  Awaiting fixes: $NOT_FIXABLE"
            echo ""
            
            if [ "$FIXABLE" -gt 0 ]; then
                echo "🚀 Quick Fix Commands (review before running):"
                echo "─────────────────────────────────────────────────────────────────────────"
                
                # Generate batch update commands
                echo "$FILTERED_DATA" | jq -r '.[] | select(.fixed_version != "N/A") | 
                    {pkg: .package, ver: .fixed_version, type: .pkg_type} | 
                    @json' | while read -r pkg_info; do
                    PKG=$(echo "$pkg_info" | jq -r '.pkg')
                    VER=$(echo "$pkg_info" | jq -r '.ver')
                    TYPE=$(echo "$pkg_info" | jq -r '.type')
                    MGR=$(get_package_manager "$TYPE" "$PKG")
                    echo "  $(generate_update_command "$MGR" "$PKG" "$VER")"
                done
                
                echo ""
                echo "💡 TIP: Review each package changelog before updating to check for"
                echo "   breaking changes. Run your test suite after updates."
            fi
            
            echo ""
            echo "═══════════════════════════════════════════════════════════════════════════"
            echo ""
            echo "📝 Next Steps:"
            echo "  1. Review each vulnerability and its fix"
            echo "  2. Check package changelogs for breaking changes"
            echo "  3. Update packages in a development environment first"
            echo "  4. Run comprehensive test suite"
            echo "  5. Deploy to staging for validation"
            echo "  6. Re-run security scan to verify fixes"
            echo ""
            echo "🔄 To re-scan after fixes:"
            echo "   ./scripts/shell/orchestrator-v2.sh"
            echo ""
            
        } | if [ -n "$OUTPUT_FILE" ]; then
            tee "$OUTPUT_FILE"
            echo -e "${GREEN}✅ Remediation report saved to: $OUTPUT_FILE${NC}"
        else
            cat
        fi
        ;;
esac

echo -e "${GREEN}✅ Remediation suggestions generated successfully!${NC}"
