#!/bin/bash

# Portable Application Security Scanner
# Usage: ./portable-app-scanner.sh /path/to/application [scan-type]
# Scan Types: full, quick, code-only, container-only, secrets-only

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
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
SCAN_DATE=$(date)

# Default scan type
SCAN_TYPE="full"

# Function to display usage
show_usage() {
    echo -e "${WHITE}============================================${NC}"
    echo -e "${WHITE}Portable Application Security Scanner${NC}"
    echo -e "${WHITE}============================================${NC}"
    echo
    echo "Usage: $0 [target_directory] [scan_type] [options]"
    echo
    echo "Target Directory:"
    echo "  /path/to/app    Path to the application directory to scan"
    echo "                  (defaults to ~/Desktop if not specified)"
    echo
    echo "Scan Types:"
    echo "  full           Complete security scan (all tools) [default]"
    echo "  quick          Fast scan (secrets, malware, basic vulns)"
    echo "  code-only      Code quality and test coverage only"
    echo "  container-only Container and image security only"
    echo "  secrets-only   Secret detection only"
    echo "  vulns-only     Vulnerability scanning only"
    echo "  iac-only       Infrastructure-as-Code security only"
    echo
    echo "Options:"
    echo "  --output-dir   Custom output directory (default: target_dir/security-scan-results)"
    echo "  --no-docker    Skip Docker-based scans"
    echo "  --verbose      Enable verbose output"
    echo "  --help         Show this help message"
    echo
    echo "Examples:"
    echo "  $0                                    # Scan Desktop directory (default)"
    echo "  $0 quick                             # Quick scan of Desktop directory"
    echo "  $0 /path/to/my-app                   # Scan specific application"
    echo "  $0 /path/to/my-app full --output-dir /tmp/scan-results"
    echo "  $0 /path/to/my-app quick --verbose"
    echo "  $0 secrets-only                      # Secrets-only scan of Desktop"
    echo
}

# Function to validate target directory
validate_target() {
    local target_dir="$1"
    
    if [ -z "$target_dir" ]; then
        echo -e "${RED}❌ Error: Target directory not specified${NC}"
        show_usage
        exit 1
    fi
    
    if [ ! -d "$target_dir" ]; then
        echo -e "${RED}❌ Error: Target directory does not exist: $target_dir${NC}"
        exit 1
    fi
    
    if [ ! -r "$target_dir" ]; then
        echo -e "${RED}❌ Error: Cannot read target directory: $target_dir${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}✅ Target directory validated: $target_dir${NC}"
}

# Function to setup output directory
setup_output_dir() {
    local target_dir="$1"
    local custom_output="$2"
    
    if [ -n "$custom_output" ]; then
        OUTPUT_DIR="$custom_output"
    else
        OUTPUT_DIR="$target_dir/security-scan-results-$TIMESTAMP"
    fi
    
    mkdir -p "$OUTPUT_DIR"/{reports,logs,raw-data}
    
    echo -e "${BLUE}📁 Output directory: $OUTPUT_DIR${NC}"
}

# Function to detect application type
detect_app_type() {
    local target_dir="$1"
    local app_types=()
    
    echo -e "${CYAN}🔍 Detecting application type...${NC}"
    
    # Check for various application indicators
    if [ -f "$target_dir/package.json" ]; then
        app_types+=("Node.js")
    fi
    
    if [ -f "$target_dir/requirements.txt" ] || [ -f "$target_dir/setup.py" ] || [ -f "$target_dir/pyproject.toml" ]; then
        app_types+=("Python")
    fi
    
    if [ -f "$target_dir/pom.xml" ] || [ -f "$target_dir/build.gradle" ]; then
        app_types+=("Java")
    fi
    
    if [ -f "$target_dir/Dockerfile" ] || [ -f "$target_dir/docker-compose.yml" ]; then
        app_types+=("Docker")
    fi
    
    if [ -d "$target_dir/chart" ] || find "$target_dir" -name "*.yaml" -o -name "*.yml" | grep -E "(deployment|service|configmap)" > /dev/null 2>&1; then
        app_types+=("Kubernetes")
    fi
    
    if [ -f "$target_dir/go.mod" ]; then
        app_types+=("Go")
    fi
    
    if [ -f "$target_dir/Cargo.toml" ]; then
        app_types+=("Rust")
    fi
    
    if [ ${#app_types[@]} -eq 0 ]; then
        app_types+=("Generic")
    fi
    
    echo -e "${GREEN}📋 Detected application types: ${app_types[*]}${NC}"
    APP_TYPES=("${app_types[@]}")
}

# Function to run TruffleHog secret detection
run_trufflehog_scan() {
    local target_dir="$1"
    
    echo -e "${PURPLE}🔍 Running TruffleHog secret detection...${NC}"
    
    # Create TruffleHog exclusions file
    cat > "$OUTPUT_DIR/trufflehog-exclusions.txt" << 'EOF'
# Common false positives
test/
tests/
__tests__/
spec/
__pycache__/
node_modules/
.git/
.env.example
.env.template
README.md
*.md
*.log
*.lock
package-lock.json
yarn.lock
EOF
    
    docker run --rm \
        -v "$target_dir:/workdir" \
        -v "$OUTPUT_DIR:/output" \
        trufflesecurity/trufflehog:latest \
        filesystem /workdir \
        --json \
        --exclude-paths="/output/trufflehog-exclusions.txt" \
        > "$OUTPUT_DIR/raw-data/trufflehog-results.json" 2> "$OUTPUT_DIR/logs/trufflehog.log"
    
    # Analyze results
    local secrets_count=$(cat "$OUTPUT_DIR/raw-data/trufflehog-results.json" | jq '. | length' 2>/dev/null || echo "0")
    echo -e "${GREEN}✅ TruffleHog scan completed: $secrets_count potential secrets found${NC}"
}

# Function to run ClamAV malware scan
run_clamav_scan() {
    local target_dir="$1"
    
    echo -e "${PURPLE}🦠 Running ClamAV malware scan...${NC}"
    
    docker run --rm \
        -v "$target_dir:/workdir" \
        -v "$OUTPUT_DIR:/output" \
        clamav/clamav:latest \
        bash -c "
        freshclam --quiet
        clamscan -r /workdir --log=/output/logs/clamav.log --infected --allmatch
        " > "$OUTPUT_DIR/raw-data/clamav-results.txt" 2>&1
    
    local infected_files=$(grep "FOUND" "$OUTPUT_DIR/raw-data/clamav-results.txt" | wc -l || echo "0")
    echo -e "${GREEN}✅ ClamAV scan completed: $infected_files infected files found${NC}"
}

# Function to run Trivy vulnerability scan
run_trivy_scan() {
    local target_dir="$1"
    
    echo -e "${PURPLE}🐳 Running Trivy vulnerability scan...${NC}"
    
    # Filesystem scan
    docker run --rm \
        -v "$target_dir:/workdir" \
        -v "$OUTPUT_DIR:/output" \
        aquasec/trivy:latest \
        fs /workdir \
        --format json \
        --output /output/raw-data/trivy-filesystem-results.json \
        2> "$OUTPUT_DIR/logs/trivy.log"
    
    # If Docker files exist, scan them
    if [ -f "$target_dir/Dockerfile" ]; then
        docker run --rm \
            -v "$target_dir:/workdir" \
            -v "$OUTPUT_DIR:/output" \
            aquasec/trivy:latest \
            config /workdir \
            --format json \
            --output /output/raw-data/trivy-config-results.json \
            2>> "$OUTPUT_DIR/logs/trivy.log"
    fi
    
    echo -e "${GREEN}✅ Trivy scan completed${NC}"
}

# Function to run Grype vulnerability scan
run_grype_scan() {
    local target_dir="$1"
    
    echo -e "${PURPLE}🎯 Running Grype vulnerability scan...${NC}"
    
    # Filesystem scan
    docker run --rm \
        -v "$target_dir:/workdir" \
        -v "$OUTPUT_DIR:/output" \
        anchore/grype:latest \
        /workdir \
        -o json \
        > "$OUTPUT_DIR/raw-data/grype-results.json" 2> "$OUTPUT_DIR/logs/grype.log"
    
    # Generate SBOM if Syft is available
    docker run --rm \
        -v "$target_dir:/workdir" \
        -v "$OUTPUT_DIR:/output" \
        anchore/syft:latest \
        /workdir \
        -o json \
        > "$OUTPUT_DIR/raw-data/sbom.json" 2> "$OUTPUT_DIR/logs/syft.log"
    
    local vuln_count=$(cat "$OUTPUT_DIR/raw-data/grype-results.json" | jq '.matches | length' 2>/dev/null || echo "0")
    echo -e "${GREEN}✅ Grype scan completed: $vuln_count vulnerabilities found${NC}"
}

# Function to run Checkov IaC scan
run_checkov_scan() {
    local target_dir="$1"
    
    echo -e "${PURPLE}🔒 Running Checkov IaC security scan...${NC}"
    
    # Check if there are IaC files to scan
    local iac_files=$(find "$target_dir" -type f \( -name "*.yaml" -o -name "*.yml" -o -name "*.tf" -o -name "Dockerfile" \) | wc -l)
    
    if [ "$iac_files" -gt 0 ]; then
        docker run --rm \
            -v "$target_dir:/workdir" \
            -v "$OUTPUT_DIR:/output" \
            bridgecrew/checkov:latest \
            -d /workdir \
            --framework kubernetes,dockerfile,terraform \
            --output json \
            --output-file-path /output/raw-data/checkov-results.json \
            2> "$OUTPUT_DIR/logs/checkov.log"
        
        echo -e "${GREEN}✅ Checkov scan completed${NC}"
    else
        echo -e "${YELLOW}⚠️  No IaC files found, skipping Checkov scan${NC}"
    fi
}

# Function to run Xeol EOL detection
run_xeol_scan() {
    local target_dir="$1"
    
    echo -e "${PURPLE}⏰ Running Xeol EOL detection...${NC}"
    
    docker run --rm \
        -v "$target_dir:/workdir" \
        -v "$OUTPUT_DIR:/output" \
        noqcks/xeol:latest \
        /workdir \
        -o json \
        > "$OUTPUT_DIR/raw-data/xeol-results.json" 2> "$OUTPUT_DIR/logs/xeol.log"
    
    local eol_count=$(cat "$OUTPUT_DIR/raw-data/xeol-results.json" | jq '.matches | length' 2>/dev/null || echo "0")
    echo -e "${GREEN}✅ Xeol scan completed: $eol_count EOL components found${NC}"
}

# Function to run code quality analysis (if applicable)
run_code_quality_scan() {
    local target_dir="$1"
    
    echo -e "${PURPLE}📊 Running code quality analysis...${NC}"
    
    # Node.js projects
    if [ -f "$target_dir/package.json" ]; then
        echo -e "${BLUE}🔍 Analyzing Node.js project...${NC}"
        
        # Check and install dependencies if needed
        if command -v npm >/dev/null 2>&1; then
            cd "$target_dir"
            
            # Check if node_modules exists and has content
            if [ ! -d "node_modules" ] || [ -z "$(ls -A node_modules 2>/dev/null)" ]; then
                echo -e "${YELLOW}📦 Installing Node.js dependencies...${NC}"
                echo -e "${CYAN}Running: npm install${NC}"
                
                if npm install 2>&1 | tee "$OUTPUT_DIR/logs/npm-install.log"; then
                    echo -e "${GREEN}✅ Dependencies installed successfully${NC}"
                else
                    echo -e "${YELLOW}⚠️ npm install failed, trying npm ci...${NC}"
                    if npm ci 2>&1 | tee -a "$OUTPUT_DIR/logs/npm-install.log"; then
                        echo -e "${GREEN}✅ Dependencies installed with npm ci${NC}"
                    else
                        echo -e "${RED}❌ Failed to install dependencies. Continuing without tests...${NC}"
                        echo -e "${BLUE}💡 You may need to run 'npm install' manually${NC}"
                        cd - >/dev/null
                        return
                    fi
                fi
            else
                echo -e "${GREEN}✅ Node modules already present${NC}"
            fi
            
            # Check for test coverage
            if npm list --depth=0 | grep -E "(vitest|jest|mocha)" >/dev/null 2>&1; then
                echo -e "${BLUE}🧪 Running tests...${NC}"
                npm test 2>&1 | tee "$OUTPUT_DIR/logs/npm-test.log" || true
            else
                echo -e "${YELLOW}⚠️ No test framework detected in package.json${NC}"
            fi
            cd - >/dev/null
        fi
        
        # ESLint if available
        if [ -f "$target_dir/.eslintrc.js" ] || [ -f "$target_dir/.eslintrc.json" ]; then
            cd "$target_dir"
            npx eslint . --format json --output-file "$OUTPUT_DIR/raw-data/eslint-results.json" 2>/dev/null || true
            cd - >/dev/null
        fi
    fi
    
    # Python projects
    if [ -f "$target_dir/requirements.txt" ] || [ -f "$target_dir/setup.py" ]; then
        echo -e "${BLUE}🔍 Analyzing Python project...${NC}"
        
        # Bandit security scan for Python
        docker run --rm \
            -v "$target_dir:/workdir" \
            -v "$OUTPUT_DIR:/output" \
            python:3.11-slim \
            bash -c "
            pip install bandit >/dev/null 2>&1
            bandit -r /workdir -f json -o /output/raw-data/bandit-results.json 2>/dev/null || true
            " 2> "$OUTPUT_DIR/logs/bandit.log"
    fi
    
    echo -e "${GREEN}✅ Code quality analysis completed${NC}"
}

# Function to generate summary report
generate_summary_report() {
    local target_dir="$1"
    
    echo -e "${CYAN}📊 Generating security scan summary...${NC}"
    
    cat > "$OUTPUT_DIR/reports/SECURITY_SCAN_SUMMARY.md" << EOF
# Security Scan Summary

**Target Application:** $(basename "$target_dir")  
**Scan Date:** $SCAN_DATE  
**Scan Type:** $SCAN_TYPE  
**Output Directory:** $OUTPUT_DIR  

## Application Details

**Path:** $target_dir  
**Detected Types:** ${APP_TYPES[*]}  

## Scan Results Overview

### 🔍 Secret Detection (TruffleHog)
$(if [ -f "$OUTPUT_DIR/raw-data/trufflehog-results.json" ]; then
    local secrets=$(cat "$OUTPUT_DIR/raw-data/trufflehog-results.json" | jq '. | length' 2>/dev/null || echo "0")
    echo "- **Potential Secrets Found:** $secrets"
    if [ "$secrets" -gt 0 ]; then
        echo "- **Status:** ⚠️ REVIEW REQUIRED"
    else
        echo "- **Status:** ✅ CLEAN"
    fi
else
    echo "- **Status:** ❌ SCAN FAILED"
fi)

### 🦠 Malware Detection (ClamAV)
$(if [ -f "$OUTPUT_DIR/raw-data/clamav-results.txt" ]; then
    local infected=$(grep "FOUND" "$OUTPUT_DIR/raw-data/clamav-results.txt" | wc -l || echo "0")
    local scanned=$(grep "scanned" "$OUTPUT_DIR/raw-data/clamav-results.txt" | tail -1 | grep -o '[0-9]\+' | head -1 || echo "0")
    echo "- **Files Scanned:** $scanned"
    echo "- **Infected Files:** $infected"
    if [ "$infected" -gt 0 ]; then
        echo "- **Status:** 🚨 MALWARE DETECTED"
    else
        echo "- **Status:** ✅ CLEAN"
    fi
else
    echo "- **Status:** ❌ SCAN FAILED"
fi)

### 🐳 Vulnerability Assessment (Trivy)
$(if [ -f "$OUTPUT_DIR/raw-data/trivy-filesystem-results.json" ]; then
    echo "- **Filesystem Scan:** ✅ Completed"
    if [ -f "$OUTPUT_DIR/raw-data/trivy-config-results.json" ]; then
        echo "- **Configuration Scan:** ✅ Completed"
    fi
    echo "- **Status:** ✅ SCAN COMPLETED"
else
    echo "- **Status:** ❌ SCAN FAILED"
fi)

### 🎯 Advanced Vulnerabilities (Grype)
$(if [ -f "$OUTPUT_DIR/raw-data/grype-results.json" ]; then
    local vulns=$(cat "$OUTPUT_DIR/raw-data/grype-results.json" | jq '.matches | length' 2>/dev/null || echo "0")
    echo "- **Vulnerabilities Found:** $vulns"
    if [ -f "$OUTPUT_DIR/raw-data/sbom.json" ]; then
        echo "- **SBOM Generated:** ✅ Yes"
    fi
    if [ "$vulns" -gt 0 ]; then
        echo "- **Status:** ⚠️ VULNERABILITIES FOUND"
    else
        echo "- **Status:** ✅ CLEAN"
    fi
else
    echo "- **Status:** ❌ SCAN FAILED"
fi)

### 🔒 Infrastructure Security (Checkov)
$(if [ -f "$OUTPUT_DIR/raw-data/checkov-results.json" ]; then
    echo "- **IaC Security Scan:** ✅ Completed"
    echo "- **Status:** ✅ SCAN COMPLETED"
else
    echo "- **Status:** ℹ️ NO IAC FILES OR SCAN SKIPPED"
fi)

### ⏰ End-of-Life Detection (Xeol)
$(if [ -f "$OUTPUT_DIR/raw-data/xeol-results.json" ]; then
    local eol=$(cat "$OUTPUT_DIR/raw-data/xeol-results.json" | jq '.matches | length' 2>/dev/null || echo "0")
    echo "- **EOL Components:** $eol"
    if [ "$eol" -gt 0 ]; then
        echo "- **Status:** ⚠️ EOL COMPONENTS FOUND"
    else
        echo "- **Status:** ✅ UP TO DATE"
    fi
else
    echo "- **Status:** ❌ SCAN FAILED"
fi)

## Next Steps

### Immediate Actions Required
1. **Review Secret Detection Results** - Check TruffleHog findings for false positives
2. **Address Security Vulnerabilities** - Prioritize high/critical severity findings
3. **Update EOL Components** - Plan updates for end-of-life software

### Recommended Follow-up
1. **Integrate into CI/CD** - Automate security scanning in deployment pipeline  
2. **Regular Scanning** - Schedule weekly security scans
3. **Team Training** - Ensure development team understands security findings

## File Locations

- **Raw Scan Data:** \`$OUTPUT_DIR/raw-data/\`
- **Scan Logs:** \`$OUTPUT_DIR/logs/\`
- **Reports:** \`$OUTPUT_DIR/reports/\`

---

*Generated by Portable Application Security Scanner*  
*Scan completed at: $(date)*
EOF

    echo -e "${GREEN}✅ Summary report generated: $OUTPUT_DIR/reports/SECURITY_SCAN_SUMMARY.md${NC}"
}

# Function to create quick reference commands
create_reference_commands() {
    cat > "$OUTPUT_DIR/QUICK_REFERENCE.md" << EOF
# Quick Reference - Security Scan Results

## View Results

\`\`\`bash
# View summary report
cat "$OUTPUT_DIR/reports/SECURITY_SCAN_SUMMARY.md"

# View raw results
ls -la "$OUTPUT_DIR/raw-data/"

# Check scan logs
ls -la "$OUTPUT_DIR/logs/"
\`\`\`

## Re-run Specific Scans

\`\`\`bash
# Re-run full scan
$0 "$TARGET_DIR" full

# Run only secrets scan
$0 "$TARGET_DIR" secrets-only

# Run only vulnerability scan  
$0 "$TARGET_DIR" vulns-only
\`\`\`

## Analyze Specific Results

\`\`\`bash
# View TruffleHog secrets (if any)
jq '.' "$OUTPUT_DIR/raw-data/trufflehog-results.json"

# View Grype vulnerabilities
jq '.matches[] | {id: .vulnerability.id, severity: .vulnerability.severity, package: .artifact.name}' "$OUTPUT_DIR/raw-data/grype-results.json"

# View EOL components
jq '.matches[] | {name: .artifact.name, version: .artifact.version, eol: .eolData}' "$OUTPUT_DIR/raw-data/xeol-results.json"
\`\`\`
EOF

    echo -e "${GREEN}✅ Quick reference created: $OUTPUT_DIR/QUICK_REFERENCE.md${NC}"
}

# Main execution function
main() {
    local target_dir=""
    local custom_output=""
    local verbose=false
    local no_docker=false
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --help|-h)
                show_usage
                exit 0
                ;;
            --output-dir)
                custom_output="$2"
                shift 2
                ;;
            --verbose|-v)
                verbose=true
                shift
                ;;
            --no-docker)
                no_docker=true
                shift
                ;;
            -*)
                echo -e "${RED}❌ Unknown option: $1${NC}"
                show_usage
                exit 1
                ;;
            *)
                # Check if argument is a scan type
                case "$1" in
                    full|quick|code-only|container-only|secrets-only|vulns-only|iac-only)
                        if [ -z "$SCAN_TYPE" ] || [ "$SCAN_TYPE" = "full" ]; then
                            SCAN_TYPE="$1"
                        fi
                        ;;
                    *)
                        # Treat as target directory
                        if [ -z "$target_dir" ]; then
                            target_dir="$1"
                        elif [ -z "$SCAN_TYPE" ] || [ "$SCAN_TYPE" = "full" ]; then
                            SCAN_TYPE="$1"
                        fi
                        ;;
                esac
                shift
                ;;
        esac
    done
    
    # Set default target directory if none provided
    if [ -z "$target_dir" ]; then
        # Default to Desktop directory
        target_dir="$HOME/Desktop"
        echo -e "${YELLOW}ℹ️  No target directory specified, defaulting to: $target_dir${NC}"
        echo
    fi
    
    # Header
    echo -e "${WHITE}============================================${NC}"
    echo -e "${WHITE}🛡️  Portable Application Security Scanner${NC}"
    echo -e "${WHITE}============================================${NC}"
    echo -e "${BLUE}Target: $target_dir${NC}"
    echo -e "${BLUE}Scan Type: $SCAN_TYPE${NC}"
    echo -e "${BLUE}Timestamp: $SCAN_DATE${NC}"
    echo
    
    # Validate inputs
    validate_target "$target_dir"
    setup_output_dir "$target_dir" "$custom_output"
    detect_app_type "$target_dir"
    
    # Store target for reference commands
    TARGET_DIR="$target_dir"
    
    echo -e "${CYAN}🚀 Starting security scan...${NC}"
    echo
    
    # Run scans based on scan type
    case $SCAN_TYPE in
        "full")
            run_trufflehog_scan "$target_dir"
            run_clamav_scan "$target_dir"
            run_trivy_scan "$target_dir"
            run_grype_scan "$target_dir"
            run_checkov_scan "$target_dir"
            run_xeol_scan "$target_dir"
            run_code_quality_scan "$target_dir"
            ;;
        "quick")
            run_trufflehog_scan "$target_dir"
            run_clamav_scan "$target_dir"
            run_grype_scan "$target_dir"
            ;;
        "secrets-only")
            run_trufflehog_scan "$target_dir"
            ;;
        "container-only")
            run_trivy_scan "$target_dir"
            run_grype_scan "$target_dir"
            ;;
        "vulns-only")
            run_trivy_scan "$target_dir"
            run_grype_scan "$target_dir"
            run_xeol_scan "$target_dir"
            ;;
        "code-only")
            run_code_quality_scan "$target_dir"
            ;;
        "iac-only")
            run_checkov_scan "$target_dir"
            ;;
        *)
            echo -e "${RED}❌ Unknown scan type: $SCAN_TYPE${NC}"
            show_usage
            exit 1
            ;;
    esac
    
    # Generate reports
    echo
    echo -e "${CYAN}📊 Generating reports...${NC}"
    generate_summary_report "$target_dir"
    create_reference_commands
    
    # Final summary
    echo
    echo -e "${WHITE}============================================${NC}"
    echo -e "${GREEN}✅ Security scan completed successfully!${NC}"
    echo -e "${WHITE}============================================${NC}"
    echo
    echo -e "${BLUE}📊 Results Summary:${NC}"
    echo -e "${BLUE}📁 Output Directory: $OUTPUT_DIR${NC}"
    echo -e "${BLUE}📋 Summary Report: $OUTPUT_DIR/reports/SECURITY_SCAN_SUMMARY.md${NC}"
    echo -e "${BLUE}🔍 Raw Data: $OUTPUT_DIR/raw-data/${NC}"
    echo -e "${BLUE}📝 Scan Logs: $OUTPUT_DIR/logs/${NC}"
    echo
    echo -e "${YELLOW}💡 Next Steps:${NC}"
    echo "1. Review the summary report: cat '$OUTPUT_DIR/reports/SECURITY_SCAN_SUMMARY.md'"
    echo "2. Check for high-priority security issues"
    echo "3. Address any vulnerabilities or security findings"
    echo
    echo -e "${GREEN}🎉 Scan completed at $(date)${NC}"
}

# Run main function if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi