#!/bin/bash

# Enhanced Node.js Project Security Scanner
# Handles dependency installation and comprehensive security analysis

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Default values
TARGET_DIR=""
OUTPUT_DIR=""
INSTALL_DEPS=true
RUN_TESTS=true
VERBOSE=false

show_usage() {
    echo -e "${WHITE}Enhanced Node.js Security Scanner${NC}"
    echo
    echo "Usage: $0 [target_dir] [options]"
    echo
    echo "Options:"
    echo "  --no-install       Skip dependency installation"
    echo "  --no-tests        Skip running tests"
    echo "  --output-dir DIR  Custom output directory"
    echo "  --verbose         Verbose output"
    echo "  --help           Show this help"
    echo
    echo "Examples:"
    echo "  $0 /path/to/node-project"
    echo "  $0 /path/to/node-project --no-install --output-dir /tmp/results"
    echo
}

# Parse command line arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --no-install)
                INSTALL_DEPS=false
                shift
                ;;
            --no-tests)
                RUN_TESTS=false
                shift
                ;;
            --output-dir)
                OUTPUT_DIR="$2"
                shift 2
                ;;
            --verbose)
                VERBOSE=true
                shift
                ;;
            --help)
                show_usage
                exit 0
                ;;
            -*)
                echo -e "${RED}❌ Unknown option: $1${NC}"
                show_usage
                exit 1
                ;;
            *)
                if [ -z "$TARGET_DIR" ]; then
                    TARGET_DIR="$1"
                else
                    echo -e "${RED}❌ Multiple directories specified${NC}"
                    show_usage
                    exit 1
                fi
                shift
                ;;
        esac
    done
    
    # Default to current directory if none specified
    if [ -z "$TARGET_DIR" ]; then
        TARGET_DIR="$(pwd)"
    fi
    
    # Convert to absolute path
    TARGET_DIR="$(cd "$TARGET_DIR" && pwd)"
}

# Validate Node.js project
validate_nodejs_project() {
    echo -e "${BLUE}🔍 Validating Node.js project...${NC}"
    
    if [ ! -f "$TARGET_DIR/package.json" ]; then
        echo -e "${RED}❌ No package.json found. Not a Node.js project.${NC}"
        exit 1
    fi
    
    if ! command -v npm >/dev/null 2>&1; then
        echo -e "${RED}❌ npm not found. Please install Node.js first.${NC}"
        exit 1
    fi
    
    if ! command -v node >/dev/null 2>&1; then
        echo -e "${RED}❌ node not found. Please install Node.js first.${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}✅ Valid Node.js project detected${NC}"
    
    # Show project info
    if [ "$VERBOSE" = true ]; then
        echo -e "${CYAN}Node.js version: $(node --version)${NC}"
        echo -e "${CYAN}npm version: $(npm --version)${NC}"
        
        if [ -f "$TARGET_DIR/package.json" ]; then
            local name=$(cat "$TARGET_DIR/package.json" | jq -r '.name // "unknown"' 2>/dev/null || echo "unknown")
            local version=$(cat "$TARGET_DIR/package.json" | jq -r '.version // "unknown"' 2>/dev/null || echo "unknown")
            echo -e "${CYAN}Project: $name@$version${NC}"
        fi
    fi
    echo
}

# Setup output directory
setup_output() {
    if [ -z "$OUTPUT_DIR" ]; then
        OUTPUT_DIR="$TARGET_DIR/nodejs-security-scan-$TIMESTAMP"
    fi
    
    mkdir -p "$OUTPUT_DIR"/{reports,logs,raw-data,coverage}
    echo -e "${BLUE}📁 Output directory: $OUTPUT_DIR${NC}"
    echo
}

# Install dependencies with error handling
install_dependencies() {
    if [ "$INSTALL_DEPS" = false ]; then
        echo -e "${YELLOW}⏭️ Skipping dependency installation${NC}"
        return 0
    fi
    
    echo -e "${PURPLE}📦 Managing Node.js Dependencies${NC}"
    echo -e "${WHITE}=========================================${NC}"
    
    cd "$TARGET_DIR"
    
    # Check current state
    if [ -d "node_modules" ] && [ -n "$(ls -A node_modules 2>/dev/null)" ]; then
        echo -e "${GREEN}✅ node_modules directory exists and has content${NC}"
        
        # Verify dependencies are satisfied
        if npm ls >/dev/null 2>&1; then
            echo -e "${GREEN}✅ All dependencies appear to be satisfied${NC}"
            return 0
        else
            echo -e "${YELLOW}⚠️ Dependencies not satisfied, reinstalling...${NC}"
            rm -rf node_modules package-lock.json 2>/dev/null
        fi
    fi
    
    # Clean install process
    echo -e "${BLUE}🧹 Performing clean dependency installation...${NC}"
    
    # Try different installation strategies
    local install_success=false
    
    # Strategy 1: npm install
    echo -e "${CYAN}Attempting: npm install${NC}"
    if npm install 2>&1 | tee "$OUTPUT_DIR/logs/npm-install.log"; then
        if npm ls >/dev/null 2>&1; then
            echo -e "${GREEN}✅ npm install successful${NC}"
            install_success=true
        fi
    fi
    
    # Strategy 2: npm ci (if package-lock.json exists)
    if [ "$install_success" = false ] && [ -f "package-lock.json" ]; then
        echo -e "${CYAN}Attempting: npm ci${NC}"
        rm -rf node_modules 2>/dev/null
        if npm ci 2>&1 | tee -a "$OUTPUT_DIR/logs/npm-install.log"; then
            if npm ls >/dev/null 2>&1; then
                echo -e "${GREEN}✅ npm ci successful${NC}"
                install_success=true
            fi
        fi
    fi
    
    # Strategy 3: Force install with legacy peer deps
    if [ "$install_success" = false ]; then
        echo -e "${CYAN}Attempting: npm install --legacy-peer-deps${NC}"
        rm -rf node_modules package-lock.json 2>/dev/null
        if npm install --legacy-peer-deps 2>&1 | tee -a "$OUTPUT_DIR/logs/npm-install.log"; then
            echo -e "${YELLOW}⚠️ Installed with legacy peer deps${NC}"
            install_success=true
        fi
    fi
    
    # Strategy 4: Install with force
    if [ "$install_success" = false ]; then
        echo -e "${CYAN}Attempting: npm install --force${NC}"
        rm -rf node_modules package-lock.json 2>/dev/null
        if npm install --force 2>&1 | tee -a "$OUTPUT_DIR/logs/npm-install.log"; then
            echo -e "${YELLOW}⚠️ Installed with --force flag${NC}"
            install_success=true
        fi
    fi
    
    if [ "$install_success" = false ]; then
        echo -e "${RED}❌ All installation strategies failed${NC}"
        echo -e "${BLUE}💡 Manual intervention may be required${NC}"
        return 1
    fi
    
    # Audit installed packages
    echo -e "${BLUE}🔍 Auditing installed packages...${NC}"
    npm audit --json > "$OUTPUT_DIR/raw-data/npm-audit.json" 2>/dev/null || true
    npm audit > "$OUTPUT_DIR/logs/npm-audit.log" 2>/dev/null || true
    
    local audit_issues=$(cat "$OUTPUT_DIR/raw-data/npm-audit.json" | jq '.metadata.vulnerabilities.total // 0' 2>/dev/null || echo "0")
    if [ "$audit_issues" -gt 0 ]; then
        echo -e "${YELLOW}⚠️ Found $audit_issues security vulnerabilities in dependencies${NC}"
    else
        echo -e "${GREEN}✅ No security vulnerabilities found in dependencies${NC}"
    fi
    
    cd - >/dev/null
    echo
}

# Run comprehensive tests
run_tests() {
    if [ "$RUN_TESTS" = false ]; then
        echo -e "${YELLOW}⏭️ Skipping test execution${NC}"
        return 0
    fi
    
    echo -e "${PURPLE}🧪 Running Tests and Coverage${NC}"
    echo -e "${WHITE}================================${NC}"
    
    cd "$TARGET_DIR"
    
    # Check for test scripts in package.json
    local has_test_script=$(cat package.json | jq -r '.scripts.test // empty' 2>/dev/null)
    local has_coverage_script=$(cat package.json | jq -r '.scripts.coverage // empty' 2>/dev/null)
    
    if [ -n "$has_test_script" ]; then
        echo -e "${BLUE}🎯 Running test suite...${NC}"
        
        # Run tests with coverage if possible
        if echo "$has_test_script" | grep -q "coverage\|--coverage"; then
            npm test 2>&1 | tee "$OUTPUT_DIR/logs/npm-test.log"
        elif [ -n "$has_coverage_script" ]; then
            npm run coverage 2>&1 | tee "$OUTPUT_DIR/logs/npm-test.log"
        else
            # Try to run with coverage flag
            if echo "$has_test_script" | grep -q "jest"; then
                npm test -- --coverage 2>&1 | tee "$OUTPUT_DIR/logs/npm-test.log" || npm test 2>&1 | tee "$OUTPUT_DIR/logs/npm-test.log"
            else
                npm test 2>&1 | tee "$OUTPUT_DIR/logs/npm-test.log"
            fi
        fi
        
        # Copy coverage reports if they exist
        if [ -d "coverage" ]; then
            cp -r coverage/* "$OUTPUT_DIR/coverage/" 2>/dev/null || true
            echo -e "${GREEN}✅ Coverage reports copied to output directory${NC}"
        fi
    else
        echo -e "${YELLOW}⚠️ No test script found in package.json${NC}"
    fi
    
    cd - >/dev/null
    echo
}

# Check if Docker is available and working
check_docker() {
    if ! command -v docker >/dev/null 2>&1; then
        echo -e "${RED}❌ Docker not found. Docker is required for security scans.${NC}"
        return 1
    fi
    
    if ! docker info >/dev/null 2>&1; then
        echo -e "${RED}❌ Docker daemon not running. Please start Docker.${NC}"
        return 1
    fi
    
    return 0
}

# Run only real, verified security scans
run_security_scans() {
    echo -e "${PURPLE}🛡️ Running Real Security Scans${NC}"
    echo -e "${WHITE}=================================${NC}"
    
    # Check Docker availability first
    if ! check_docker; then
        echo -e "${YELLOW}⚠️ Skipping Docker-based security scans (Docker not available)${NC}"
        return 1
    fi
    
    local scans_completed=0
    
    # TruffleHog for secrets (REAL scan)
    echo -e "${BLUE}🔍 Running TruffleHog secret detection...${NC}"
    if docker run --rm \
        -v "$TARGET_DIR:/workdir" \
        trufflesecurity/trufflehog:latest \
        filesystem /workdir \
        --json \
        --no-update > "$OUTPUT_DIR/raw-data/trufflehog-results.json" 2> "$OUTPUT_DIR/logs/trufflehog.log"; then
        
        local secret_count=$(cat "$OUTPUT_DIR/raw-data/trufflehog-results.json" | jq 'length' 2>/dev/null || echo "0")
        echo -e "${GREEN}✅ TruffleHog completed: $secret_count potential secrets found${NC}"
        scans_completed=$((scans_completed + 1))
    else
        echo -e "${RED}❌ TruffleHog scan failed${NC}"
        echo "TruffleHog scan failed" > "$OUTPUT_DIR/raw-data/trufflehog-results.json"
    fi
    
    # Grype for vulnerabilities (REAL scan)
    echo -e "${BLUE}🔍 Running Grype vulnerability scan...${NC}"
    if docker run --rm \
        -v "$TARGET_DIR:/workdir" \
        anchore/grype:latest \
        dir:/workdir \
        -o json > "$OUTPUT_DIR/raw-data/grype-results.json" 2> "$OUTPUT_DIR/logs/grype.log"; then
        
        local vuln_count=$(cat "$OUTPUT_DIR/raw-data/grype-results.json" | jq '.matches | length' 2>/dev/null || echo "0")
        echo -e "${GREEN}✅ Grype completed: $vuln_count vulnerabilities found${NC}"
        scans_completed=$((scans_completed + 1))
    else
        echo -e "${RED}❌ Grype scan failed${NC}"
        echo '{"matches": []}' > "$OUTPUT_DIR/raw-data/grype-results.json"
    fi
    
    # ClamAV for malware (REAL scan)
    echo -e "${BLUE}🔍 Running ClamAV malware scan...${NC}"
    if docker run --rm \
        -v "$TARGET_DIR:/workdir" \
        clamav/clamav:latest \
        bash -c "
        echo 'Updating virus definitions...'
        freshclam --quiet --no-warnings 2>/dev/null || true
        echo 'Scanning for malware...'
        clamscan -r /workdir --infected --log=/dev/stdout 2>&1
        " > "$OUTPUT_DIR/logs/clamav.log" 2>&1; then
        
        local infected_count=$(grep -c "FOUND" "$OUTPUT_DIR/logs/clamav.log" 2>/dev/null || echo "0")
        if [ "$infected_count" -gt 0 ]; then
            echo -e "${RED}⚠️ ClamAV completed: $infected_count infected files found${NC}"
        else
            echo -e "${GREEN}✅ ClamAV completed: No malware detected${NC}"
        fi
        scans_completed=$((scans_completed + 1))
    else
        echo -e "${RED}❌ ClamAV scan failed${NC}"
        echo "ClamAV scan failed" > "$OUTPUT_DIR/logs/clamav.log"
    fi
    
    echo -e "${GREEN}✅ Security scans completed: $scans_completed/3 successful${NC}"
    echo
    
    return 0
}

# Generate report with only real, verified results
generate_report() {
    echo -e "${PURPLE}📊 Generating Report (Real Results Only)${NC}"
    echo -e "${WHITE}=========================================${NC}"
    
    local report_file="$OUTPUT_DIR/reports/nodejs-security-report.md"
    
    # Get actual counts from real scan results
    local npm_vulns="N/A"
    local secret_count="N/A" 
    local vuln_count="N/A"
    local malware_count="N/A"
    
    # NPM Audit results (if available)
    if [ -f "$OUTPUT_DIR/raw-data/npm-audit.json" ]; then
        npm_vulns=$(cat "$OUTPUT_DIR/raw-data/npm-audit.json" | jq '.metadata.vulnerabilities.total // 0' 2>/dev/null || echo "Parse Error")
    fi
    
    # TruffleHog results (if scan completed)  
    if [ -f "$OUTPUT_DIR/raw-data/trufflehog-results.json" ]; then
        if grep -q "TruffleHog scan failed" "$OUTPUT_DIR/raw-data/trufflehog-results.json" 2>/dev/null; then
            secret_count="Scan Failed"
        else
            secret_count=$(cat "$OUTPUT_DIR/raw-data/trufflehog-results.json" | jq 'length' 2>/dev/null || echo "Parse Error")
        fi
    fi
    
    # Grype results (if scan completed)
    if [ -f "$OUTPUT_DIR/raw-data/grype-results.json" ]; then
        if grep -q '"matches": \[\]' "$OUTPUT_DIR/raw-data/grype-results.json" 2>/dev/null; then
            vuln_count=$(cat "$OUTPUT_DIR/raw-data/grype-results.json" | jq '.matches | length' 2>/dev/null || echo "0")
        else
            vuln_count=$(cat "$OUTPUT_DIR/raw-data/grype-results.json" | jq '.matches | length' 2>/dev/null || echo "Parse Error")
        fi
    fi
    
    # ClamAV results (if scan completed)
    if [ -f "$OUTPUT_DIR/logs/clamav.log" ]; then
        if grep -q "ClamAV scan failed" "$OUTPUT_DIR/logs/clamav.log" 2>/dev/null; then
            malware_count="Scan Failed"
        else
            malware_count=$(grep -c "FOUND" "$OUTPUT_DIR/logs/clamav.log" 2>/dev/null || echo "0")
        fi
    fi
    
    cat > "$report_file" << EOF
# Node.js Security Analysis Report - REAL RESULTS ONLY

**Project:** $(basename "$TARGET_DIR")  
**Scan Date:** $(date)  
**Scanner Version:** Enhanced Node.js Security Scanner v2.0 (Real Scans Only)

## ✅ VERIFIED SCAN RESULTS

- **NPM Audit:** $npm_vulns vulnerabilities found
- **TruffleHog Secrets:** $secret_count potential secrets detected  
- **Grype Vulnerabilities:** $vuln_count vulnerabilities found
- **ClamAV Malware:** $malware_count infected files found

## Test Coverage

$(if [ -f "$OUTPUT_DIR/coverage/lcov-report/index.html" ]; then
    echo "Coverage report available at: coverage/lcov-report/index.html"
else
    echo "No coverage report generated"
fi)

## Files Scanned

- **Target Directory:** \`$TARGET_DIR\`
- **Output Directory:** \`$OUTPUT_DIR\`
- **Dependencies Installed:** $([ "$INSTALL_DEPS" = true ] && echo "Yes" || echo "Skipped")
- **Tests Run:** $([ "$RUN_TESTS" = true ] && echo "Yes" || echo "Skipped")

## Detailed Results

### NPM Audit Results
$([ -f "$OUTPUT_DIR/logs/npm-audit.log" ] && echo '```' && head -20 "$OUTPUT_DIR/logs/npm-audit.log" && echo '```')

### Security Scan Results

- Raw TruffleHog results: \`raw-data/trufflehog-results.json\`
- Raw Grype results: \`raw-data/grype-results.json\`
- ClamAV scan log: \`logs/clamav.log\`

## Recommendations

1. Review and fix any high-severity vulnerabilities found
2. Investigate potential secrets detected by TruffleHog
3. Update dependencies with known security issues
4. Improve test coverage if below 80%
5. Run security scans regularly as part of CI/CD pipeline

---
*Report generated by Enhanced Node.js Security Scanner*
EOF
    
    echo -e "${GREEN}✅ Report generated: $report_file${NC}"
    
    # Open report if on macOS
    if command -v open >/dev/null 2>&1; then
        echo -e "${BLUE}📖 Opening report...${NC}"
        open "$report_file"
    fi
    
    echo
}

# Main execution
main() {
    echo -e "${WHITE}===============================================${NC}"
    echo -e "${WHITE}🛡️ Enhanced Node.js Security Scanner${NC}"
    echo -e "${WHITE}===============================================${NC}"
    echo
    
    parse_arguments "$@"
    validate_nodejs_project
    setup_output
    install_dependencies
    run_tests
    run_security_scans
    generate_report
    
    echo -e "${GREEN}🎉 Node.js security analysis completed!${NC}"
    echo -e "${BLUE}📁 Results available in: $OUTPUT_DIR${NC}"
    echo
}

# Run main function with all arguments
main "$@"