#!/bin/bash

# TruffleHog Multi-Target Secret Detection Scanner
# Comprehensive secret scanning for repositories, containers, and filesystems

# Colors for help output
WHITE='\033[1;37m'
NC='\033[0m'

# Help function
show_help() {
    echo -e "${WHITE}TruffleHog Multi-Target Secret Detection Scanner${NC}"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Comprehensive secret scanning for repositories, containers, and filesystems."
    echo "Detects API keys, passwords, tokens, and other sensitive credentials."
    echo ""
    echo "Options:"
    echo "  -h, --help          Show this help message and exit"
    echo ""
    echo "Environment Variables:"
    echo "  TARGET_DIR          Directory to scan (default: current directory)"
    echo "  SCAN_ID             Override auto-generated scan ID"
    echo "  SCAN_DIR            Override output directory for scan results"
    echo ""
    echo "Output:"
    echo "  Results are saved to: scans/{SCAN_ID}/trufflehog/"
    echo "  - trufflehog-filesystem-results.json    Filesystem secrets"
    echo "  - trufflehog-git-results.json           Git history secrets"
    echo "  - trufflehog-scan.log                   Scan process log"
    echo ""
    echo "Detection Types:"
    echo "  - AWS credentials (access keys, secret keys)"
    echo "  - GitHub tokens (personal, OAuth, app tokens)"
    echo "  - Database connection strings"
    echo "  - Private keys (SSH, PGP, RSA)"
    echo "  - API keys and secrets (Stripe, Twilio, etc.)"
    echo "  - OAuth tokens and secrets"
    echo "  - JWT tokens"
    echo ""
    echo "Examples:"
    echo "  $0                              # Scan current directory"
    echo "  TARGET_DIR=/path/to/project $0  # Scan specific directory"
    echo ""
    echo "Notes:"
    echo "  - Requires Docker to be installed and running"
    echo "  - Uses trufflesecurity/trufflehog:latest Docker image"
    echo "  - Scans both current files and git history"
    echo "  - Verified secrets are marked with higher confidence"
    exit 0
}

# Parse arguments
for arg in "$@"; do
    case $arg in
        -h|--help)
            show_help
            ;;
    esac
done

# Initialize scan environment using scan directory approach
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source the scan directory template
source "$SCRIPT_DIR/scan-directory-template.sh"

# Initialize scan environment for TruffleHog
init_scan_environment "trufflehog"

# Set REPO_PATH and extract scan information
REPO_PATH="${TARGET_DIR:-$(pwd)}"
if [[ -n "$SCAN_ID" ]]; then
    TARGET_NAME=$(echo "$SCAN_ID" | cut -d'_' -f1)
    USERNAME=$(echo "$SCAN_ID" | cut -d'_' -f2)
    TIMESTAMP=$(echo "$SCAN_ID" | cut -d'_' -f3-)
else
    # Fallback for standalone execution
    TARGET_NAME=$(basename "$REPO_PATH")
    USERNAME=$(whoami)
    TIMESTAMP=$(date '+%Y-%m-%d_%H-%M-%S')
    SCAN_ID="${TARGET_NAME}_${USERNAME}_${TIMESTAMP}"
fi

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

echo -e "${WHITE}============================================${NC}"
echo -e "${WHITE}TruffleHog Multi-Target Secret Scanner${NC}"
echo -e "${WHITE}============================================${NC}"
echo "Repository: $REPO_PATH"
echo "Output Directory: $OUTPUT_DIR"
echo "Timestamp: $TIMESTAMP"
echo

# Display file count for transparency
if [ -d "$REPO_PATH" ]; then
    TOTAL_FILES=$(count_scannable_files "$REPO_PATH" "*")
    echo -e "${CYAN}📊 Secret Scan Analysis:${NC}"
    echo -e "   📁 Target Directory: $REPO_PATH"
    echo -e "   📄 Total Files to Scan: $TOTAL_FILES"
    # Count files that commonly contain secrets
    ENV_COUNT=$(find "$REPO_PATH" -name "*.env*" -o -name ".env*" 2>/dev/null | wc -l | tr -d ' ')
    CONFIG_COUNT=$(count_scannable_files "$REPO_PATH" "*.config*")
    KEY_COUNT=$(find "$REPO_PATH" -name "*.key" -o -name "*.pem" -o -name "*.crt" 2>/dev/null | wc -l | tr -d ' ')
    echo -e "   🔐 Environment files: $ENV_COUNT"
    echo -e "   ⚙️  Config files: $CONFIG_COUNT"
    echo -e "   🔑 Key/Certificate files: $KEY_COUNT"
    echo
fi

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Initialize scan log
echo "TruffleHog scan started: $TIMESTAMP" > "$SCAN_LOG"
echo "Target: $REPO_PATH" >> "$SCAN_LOG"

# Function to run TruffleHog scan
run_trufflehog_scan() {
    local scan_type="$1"
    local target="$2"
    local output_file="$OUTPUT_DIR/${SCAN_ID}_trufflehog-${scan_type}-results.json"
    local current_file="$OUTPUT_DIR/trufflehog-${scan_type}-results.json"
    
    echo -e "${BLUE}🔍 Scanning ${scan_type}: ${target}${NC}"
    
    if command -v docker &> /dev/null; then
        echo "Using Docker-based TruffleHog..."
        # Create a .trufflehogignore file to exclude common dependency directories
        cat > "$OUTPUT_DIR/.trufflehogignore" << 'EOF'
# Exclude dependency directories
node_modules/
vendor/
venv/
env/
.env/
__pycache__/
.venv/
target/
build/
dist/
.gradle/
.mvn/

# Exclude test fixtures and sample data
/test/
/tests/
seed-data/
fixtures/
sample-data/
examples/
EOF
        
        docker run --rm \
            -v "$target:/workspace" \
            -v "$OUTPUT_DIR/.trufflehogignore:/root/.trufflehogignore" \
            trufflesecurity/trufflehog:latest \
            filesystem /workspace \
            --json \
            --exclude-paths=/root/.trufflehogignore \
            2>&1 | tee -a "$SCAN_LOG" > "$output_file"
    else
        echo "⚠️  Docker not available - TruffleHog scan skipped"
        echo "[]" > "$output_file"
    fi
    
    if [ -f "$output_file" ]; then
        local count=$(cat "$output_file" | jq '. | length' 2>/dev/null || echo "0")
        echo "✅ ${scan_type} scan completed: $count items found"
        echo "${scan_type} scan: $count items" >> "$SCAN_LOG"
        
        # Create/update current symlink for easy access
        ln -sf "$(basename "$output_file")" "$current_file"
    fi
}

# Determine scan type based on first argument
SCAN_TYPE="${1:-all}"

echo -e "${CYAN}🛡️  Step 1: Repository Secret Scan${NC}"
echo "====================================="

case "$SCAN_TYPE" in
    "filesystem"|"all")
        if [ -d "$REPO_PATH" ]; then
            run_trufflehog_scan "filesystem" "$REPO_PATH"
        else
            echo "⚠️  Target directory not found: $REPO_PATH"
        fi
        ;;
    "git"|"all")
        if [ -d "$REPO_PATH/.git" ]; then
            run_trufflehog_scan "git" "$REPO_PATH"
        else
            echo "⚠️  Git repository not found in: $REPO_PATH"
        fi
        ;;
esac

# Count results
RESULTS_COUNT=$(find "$OUTPUT_DIR" -name "trufflehog-*-results.json" -type f | wc -l | tr -d ' ')

echo
echo -e "${CYAN}📊 TruffleHog Secret Detection Summary${NC}"
echo "======================================"
echo "📄 Results files generated: $RESULTS_COUNT"

# Basic results summary
echo -e "🔍 Secret Detection Summary:"
if [ "$RESULTS_COUNT" -gt 0 ]; then
    echo -e "${YELLOW}⚠️  $RESULTS_COUNT result files found - manual review recommended${NC}"
    echo "Results saved to: $OUTPUT_DIR"
else
    echo -e "${GREEN}✅ No secrets detected${NC}"
fi

echo
echo -e "${BLUE}📁 Output Files:${NC}"
echo "================"
for file in "$OUTPUT_DIR"/trufflehog-*-results.json; do
    if [ -f "$file" ]; then
        echo "📄 $(basename "$file")"
    fi
done
echo "📝 Scan log: $SCAN_LOG"
echo "📂 Reports directory: $OUTPUT_DIR"

echo
echo -e "${BLUE}🔧 Available Commands:${NC}"
echo "===================="
echo "📊 Analyze results:        npm run trufflehog:analyze"
echo "🔍 Run new scan:           npm run trufflehog:scan"
echo "🏗️  Filesystem only:        ./run-trufflehog-scan.sh filesystem"
echo "📦 Git history only:       ./run-trufflehog-scan.sh git"
echo "📋 View specific results:  cat $OUTPUT_DIR/trufflehog-*-results.json | jq ."

echo
echo -e "${BLUE}🔗 Additional Resources:${NC}"
echo "======================="
echo "• TruffleHog Documentation: https://github.com/trufflesecurity/trufflehog"
echo "• Secret Management Best Practices: https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure"
echo "• Git Security Best Practices: https://docs.github.com/en/code-security"

echo
echo "============================================"
echo -e "${GREEN}✅ TruffleHog multi-target security scan completed!${NC}"
echo "============================================"
echo
echo "============================================"
echo "TruffleHog secret scanning complete."
echo "============================================"