#!/bin/bash

# Checkov Infrastructure-as-Code Security Scan Script
# Scans Helm charts and Kubernetes manifests for security best practices

# Colors for help output
WHITE='\033[1;37m'
NC='\033[0m'

# Help function
show_help() {
    echo -e "${WHITE}Checkov Infrastructure-as-Code Security Scanner${NC}"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Scans Helm charts, Kubernetes manifests, Terraform, CloudFormation,"
    echo "and other IaC files for security misconfigurations and best practices."
    echo ""
    echo "Options:"
    echo "  -h, --help          Show this help message and exit"
    echo ""
    echo "Environment Variables:"
    echo "  TARGET_DIR              Directory to scan (default: current directory)"
    echo "  SCAN_ID                 Override auto-generated scan ID"
    echo "  SCAN_DIR                Override output directory for scan results"
    echo "  AWS_ACCESS_KEY_ID       AWS credentials for cloud policy checks"
    echo "  AWS_SECRET_ACCESS_KEY   AWS credentials for cloud policy checks"
    echo "  AWS_DEFAULT_REGION      AWS region (default: us-gov-west-1)"
    echo "  AWS_PROFILE             AWS profile name"
    echo ""
    echo "Output:"
    echo "  Results are saved to: scans/{SCAN_ID}/checkov/"
    echo "  - checkov-results.json          Full scan results"
    echo "  - checkov-scan.log              Scan log file"
    echo ""
    echo "Supported Frameworks:"
    echo "  - Kubernetes manifests (YAML)"
    echo "  - Helm charts"
    echo "  - Terraform (.tf files)"
    echo "  - CloudFormation templates"
    echo "  - Dockerfiles"
    echo "  - Serverless framework"
    echo ""
    echo "Examples:"
    echo "  $0                              # Scan current directory"
    echo "  TARGET_DIR=/path/to/project $0  # Scan specific directory"
    echo ""
    echo "Notes:"
    echo "  - Requires Docker to be installed and running"
    echo "  - Automatically skips node_modules directories"
    echo "  - Uses bridgecrew/checkov:latest Docker image"
    echo "  - Uses --skip-download to scan Helm templates without private registry access"
    echo "  - Scans Helm templates directly as Kubernetes manifests if dependencies fail"
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

# Configuration - Support target directory override
TARGET_SCAN_DIR="${TARGET_DIR:-$(pwd)}"
TARGET_SCAN_DIR=$(realpath "${TARGET_SCAN_DIR}" 2>/dev/null) || { echo "ERROR: Target path does not exist or is invalid: ${TARGET_SCAN_DIR}" >&2; exit 1; }
CHART_DIR="${TARGET_SCAN_DIR}/chart"

# Initialize scan environment using scan directory approach
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source the scan directory template
source "$SCRIPT_DIR/scan-directory-template.sh"

# Source container runtime detection utility if available
if [ -f "$SCRIPT_DIR/container-runtime.sh" ]; then
    # shellcheck source=/dev/null
    set +e
    source "$SCRIPT_DIR/container-runtime.sh"
    set -e
fi
if [ -z "${CONTAINER_CLI:-}" ]; then
    CONTAINER_CLI=docker
fi

# Initialize scan environment for Checkov
init_scan_environment "checkov"

# Capture start time for duration calculation
SCAN_START_TIME=$(date +%s)

# Extract scan information
if [[ -n "$SCAN_ID" ]]; then
    TARGET_NAME=$(echo "$SCAN_ID" | cut -d'_' -f1)
    USERNAME=$(echo "$SCAN_ID" | cut -d'_' -f2)
    TIMESTAMP=$(echo "$SCAN_ID" | cut -d'_' -f3-)
else
    # Fallback for standalone execution
    TARGET_NAME=$(basename "${TARGET_DIR:-$(pwd)}")
    USERNAME=$(whoami)
    TIMESTAMP=$(date '+%Y-%m-%d_%H-%M-%S')
    SCAN_ID="${TARGET_NAME}_${USERNAME}_${TIMESTAMP}"
fi
RESULTS_FILE="$OUTPUT_DIR/${SCAN_ID}_checkov-results.json"
CURRENT_FILE="$OUTPUT_DIR/checkov-results.json"
SCAN_LOG="$OUTPUT_DIR/${SCAN_ID}_checkov-scan.log"

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
echo -e "${WHITE}Checkov Infrastructure Security Scanner${NC}"
echo -e "${WHITE}============================================${NC}"
echo "Target Directory: $TARGET_SCAN_DIR"
echo "Chart Directory: $CHART_DIR"
echo "Output Directory: $OUTPUT_DIR"
echo "Timestamp: $TIMESTAMP"
echo

# Display IaC file count for transparency
if [ -d "$TARGET_SCAN_DIR" ]; then
    echo -e "${CYAN}📊 Infrastructure-as-Code Analysis:${NC}"
    YAML_COUNT_1=$(count_scannable_files "$TARGET_SCAN_DIR" "*.yaml")
    YAML_COUNT_2=$(count_scannable_files "$TARGET_SCAN_DIR" "*.yml")
    YAML_COUNT=$((YAML_COUNT_1 + YAML_COUNT_2))
    TF_COUNT=$(count_scannable_files "$TARGET_SCAN_DIR" "*.tf")
    DOCKERFILE_COUNT=$(find "$TARGET_SCAN_DIR" -name "Dockerfile*" 2>/dev/null | wc -l | tr -d ' ')
    JSON_COUNT=$(count_scannable_files "$TARGET_SCAN_DIR" "*.json")
    HELM_COUNT=0
    if [ -d "$CHART_DIR" ]; then
        HELM_COUNT=$(find "$CHART_DIR" -name "*.yaml" -o -name "*.yml" 2>/dev/null | wc -l | tr -d ' ')
    fi
    echo -e "   📄 YAML/YML files: $YAML_COUNT"
    echo -e "   📄 Terraform files: $TF_COUNT"
    echo -e "   🐳 Dockerfiles: $DOCKERFILE_COUNT"
    echo -e "   📄 JSON files: $JSON_COUNT"
    echo -e "   ⎈ Helm chart files: $HELM_COUNT"
    echo
fi

# Initialize authentication status
AWS_AUTHENTICATED=false

# Get AWS credentials from environment variables
AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID:-}"
AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY:-}"
AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION:-us-gov-west-1}"

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Initialize scan log
echo "Checkov scan started: $TIMESTAMP" > "$SCAN_LOG"
echo "Target: $TARGET_SCAN_DIR" >> "$SCAN_LOG"

echo -e "${CYAN}🏗️  Infrastructure Security Analysis${NC}"
echo "===================================="

# Check if Docker is available for Checkov
if [ -n "${CONTAINER_CLI:-}" ]; then
    echo "🐳 Using Docker-based Checkov..."
    
    # Pull Checkov Docker image
    echo "📥 Pulling Checkov Docker image..."
    ${CONTAINER_CLI} pull bridgecrew/checkov:latest 2>&1 | tee -a "$SCAN_LOG"
    
    # Scan for various IaC files
    echo -e "${BLUE}🔍 Scanning Infrastructure as Code files...${NC}"
    
    # Debug: Show CI environment detection
    echo "Debug: CI=${CI:-not set}, GITHUB_ACTIONS=${GITHUB_ACTIONS:-not set}" >&2
    
    # Check for AWS credentials and prompt if needed (skip prompts in CI mode)
    if [[ -z "$AWS_ACCESS_KEY_ID" || -z "$AWS_SECRET_ACCESS_KEY" ]] && [[ "${CI:-false}" != "true" ]] && [[ "${GITHUB_ACTIONS:-false}" != "true" ]]; then
        echo
        echo -e "${YELLOW}🔐 AWS Credentials not found in environment variables${NC}"
        echo "Checkov can perform enhanced security checks with AWS credentials."
        echo
        echo "Options:"
        echo "  1) Continue without AWS integration (local scan only)"
        echo "  2) Set up AWS SSO/CLI authentication"
        echo "  3) Enter AWS credentials manually"
        echo
        echo "(will auto-select option 1 in 30 seconds if no input)"
        read -t 30 -p "Choose option [1-3] (default: 1): " aws_choice || true
        
        case "${aws_choice:-1}" in
            2)
                echo
                echo -e "${CYAN}🔧 AWS SSO/CLI Setup Instructions:${NC}"
                echo "1. Configure AWS CLI profile:"
                echo "   ${GREEN}aws configure sso${NC}"
                echo "2. Login to AWS SSO:"
                echo "   ${GREEN}aws sso login --profile <your-profile>${NC}"
                echo "3. Export credentials:"
                echo "   ${GREEN}export AWS_PROFILE=<your-profile>${NC}"
                echo "   ${GREEN}aws sts get-caller-identity${NC}"
                echo
                echo "(will continue automatically in 30 seconds)"
                read -t 30 -p "Press Enter after setting up AWS credentials..." || true
                
                # Re-check environment after user setup
                AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID:-}"
                AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY:-}"
                if [[ -n "$AWS_PROFILE" ]]; then
                    echo "✅ Using AWS Profile: $AWS_PROFILE"
                fi
                ;;
            3)
                echo
                echo -e "${CYAN}📝 Manual AWS Credentials Entry:${NC}"
                echo "(will skip if no input in 30 seconds)"
                read -t 30 -p "AWS Access Key ID: " AWS_ACCESS_KEY_ID || true
                read -s -p "AWS Secret Access Key: " AWS_SECRET_ACCESS_KEY
                echo
                read -t 30 -p "AWS Region (default: us-gov-west-1): " input_region || true
                AWS_DEFAULT_REGION="${input_region:-us-gov-west-1}"
                echo "✅ AWS credentials configured"
                ;;
            *)
                echo "✅ Continuing with local scan only"
                ;;
        esac
    elif [[ -z "$AWS_ACCESS_KEY_ID" || -z "$AWS_SECRET_ACCESS_KEY" ]]; then
        echo "ℹ️  Running in CI mode - skipping AWS credential prompts"
        echo "✅ Continuing with local scan only"
    else
        echo "✅ Using AWS credentials from environment"
    fi
    
    # Build Docker command with AWS credentials and profile support
    AWS_MOUNT_ARGS=""
    if [[ -d "$HOME/.aws" ]]; then
        AWS_MOUNT_ARGS="-v $HOME/.aws:/root/.aws"
        echo "✅ Mounting AWS credentials directory"
    fi
    
    # Pre-validate YAML files to identify malformed ones — build dynamic --skip-path args
    # This prevents Checkov from aborting/erroring on YAML syntax errors in the target repo
    YAML_SKIP_ARGS=()
    if command -v python3 &>/dev/null && python3 -c "import yaml" 2>/dev/null; then
        echo -e "${BLUE}🔍 Pre-validating YAML files for syntax errors...${NC}"
        while IFS= read -r yaml_file; do
            relative_path="${yaml_file#${TARGET_SCAN_DIR}/}"
            if ! python3 - "$yaml_file" <<'PYEOF' 2>/dev/null
import sys, yaml

# Register a no-op constructor for every unknown tag (e.g. CloudFormation !Ref, !Sub, !If)
# so that YAML structural errors are caught without false-positives on custom tags.
class _IgnoreUnknownTags(yaml.SafeLoader):
    pass

def _ignore_tag(loader, tag_suffix, node):
    if isinstance(node, yaml.ScalarNode):
        return loader.construct_scalar(node)
    elif isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node)
    return loader.construct_mapping(node)

_IgnoreUnknownTags.add_multi_constructor('', _ignore_tag)

try:
    with open(sys.argv[1], 'r', errors='replace') as f:
        list(yaml.load_all(f, Loader=_IgnoreUnknownTags))
except yaml.YAMLError:
    sys.exit(1)
PYEOF
            then
                echo "  ⚠️  Skipping malformed YAML: $relative_path" | tee -a "$SCAN_LOG"
                YAML_SKIP_ARGS+=(--skip-path "$relative_path")
            fi
        done < <(find "$TARGET_SCAN_DIR" -type f \( -name "*.yaml" -o -name "*.yml" \) \
            ! -path "*/node_modules/*" ! -path "*/.git/*" ! -path "*/scans/*" 2>/dev/null)
        if [ "${#YAML_SKIP_ARGS[@]}" -eq 0 ]; then
            echo "  ✅ All YAML files passed syntax validation"
        else
            echo "  ⚠️  ${#YAML_SKIP_ARGS[@]} malformed path(s) will be excluded from Checkov scan" | tee -a "$SCAN_LOG"
        fi
    else
        echo "  ℹ️  python3 or pyyaml not available — skipping YAML pre-validation"
    fi

    # Run Checkov scan with AWS credentials
    # Using --skip-download to scan Helm templates even without access to private registries
    # This allows scanning of raw templates without requiring helm dependency resolution
    echo -e "${BLUE}🔍 Running Checkov scan (skipping external dependencies)...${NC}"

    # Stage paths to /tmp — Docker Desktop on macOS cannot mount paths under ~/Desktop
    # due to a known VirtioFS metadata bug where /host_mnt/Users/<user>/Desktop is a
    # file instead of a directory in the Docker VM.
    _CK_SRC="/tmp/epyon-checkov-src-$$"
    _CK_OUT="/tmp/epyon-checkov-out-$$"
    rm -rf "$_CK_SRC" "$_CK_OUT"
    rsync -a --quiet "$TARGET_SCAN_DIR/" "$_CK_SRC/" 2>/dev/null || cp -rL "$TARGET_SCAN_DIR" "$_CK_SRC"
    mkdir -p "$_CK_OUT"
    _checkov_cleanup() { cp -r "$_CK_OUT/." "$OUTPUT_DIR/" 2>/dev/null || true; rm -rf "$_CK_SRC" "$_CK_OUT"; }

    # Disable exit-on-error for Checkov command since it may return non-zero when findings exist
    set +e
    ${CONTAINER_CLI} run --rm \
        --user "$(id -u):$(id -g)" \
        -e AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID" \
        -e AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY" \
        -e AWS_DEFAULT_REGION="$AWS_DEFAULT_REGION" \
        -e AWS_PROFILE="$AWS_PROFILE" \
        $AWS_MOUNT_ARGS \
        -v "$_CK_SRC:/workspace" \
        -v "$_CK_OUT:/output" \
        bridgecrew/checkov:latest \
        --directory /workspace \
        --skip-path node_modules \
        --skip-path scans \
        --skip-path scripts/anchore-results.json \
        --skip-path scripts/shell/scans \
        "${YAML_SKIP_ARGS[@]}" \
        --skip-download \
        --output json \
        --output-file /output/checkov-results.json \
        2>&1 | tee -a "$SCAN_LOG"

    SCAN_RESULT=$?
    set -e
    
    # Debug: Check what files were created
    echo "Debug: Checking for Checkov output files..." >&2
    ls -la "$OUTPUT_DIR/" | grep -i checkov || echo "No checkov files found" >&2
    
    # If Helm chart exists but wasn't fully scanned, try scanning templates directly
    if [[ -d "$CHART_DIR/templates" ]]; then
        echo -e "${BLUE}🔍 Scanning Helm templates directly (Kubernetes framework)...${NC}"
        set +e
        ${CONTAINER_CLI} run --rm \
            --user "$(id -u):$(id -g)" \
            -e AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID" \
            -e AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY" \
            -e AWS_DEFAULT_REGION="$AWS_DEFAULT_REGION" \
            -e AWS_PROFILE="$AWS_PROFILE" \
            $AWS_MOUNT_ARGS \
            -v "$_CK_SRC:/workspace" \
            -v "$_CK_OUT:/output" \
            bridgecrew/checkov:latest \
            --directory /workspace/chart/templates \
            --framework kubernetes \
            --output json \
            --output-file /output/checkov-kubernetes-results.json \
            2>&1 | tee -a "$SCAN_LOG"
        set -e

        # Also scan values.yaml and secrets.yaml for secrets detection
        echo -e "${BLUE}🔍 Scanning Helm values for secrets...${NC}"
        set +e
        ${CONTAINER_CLI} run --rm \
            --user "$(id -u):$(id -g)" \
            -v "$_CK_SRC:/workspace" \
            -v "$_CK_OUT:/output" \
            bridgecrew/checkov:latest \
            --directory /workspace/chart \
            --framework secrets \
            --skip-download \
            --output json \
            --output-file /output/checkov-secrets-results.json \
            2>&1 | tee -a "$SCAN_LOG"
        set -e

        echo "✅ Additional Helm template scans completed"
    fi

    # Scan GitHub Actions workflows
    if find "$TARGET_SCAN_DIR" -path "$TARGET_SCAN_DIR/.github/workflows/*.yml" -o -path "$TARGET_SCAN_DIR/.github/workflows/*.yaml" -o -name "*workflow*.yml" -o -name "*workflow*.yaml" | grep -q .; then
        echo -e "${BLUE}🔍 Scanning GitHub Actions workflows...${NC}"
        set +e
        ${CONTAINER_CLI} run --rm \
            --user "$(id -u):$(id -g)" \
            -v "$_CK_SRC:/workspace" \
            -v "$_CK_OUT:/output" \
            bridgecrew/checkov:latest \
            --directory /workspace \
            --framework github_actions \
            --skip-path node_modules \
            --skip-path scans \
            --output json \
            --output-file /output/checkov-github-actions-results.json \
            2>&1 | tee -a "$SCAN_LOG"
        set -e
        echo "✅ GitHub Actions workflow scan completed"
    fi

    # Copy staged output back to OUTPUT_DIR and clean up /tmp staging dirs
    _checkov_cleanup

    # Checkov creates a directory with results_json.json inside when using --output-file
    # Handle this by finding the actual results file
    echo "Debug: Checking Checkov output structure..." >&2
    echo "Debug: Looking for directory: $OUTPUT_DIR/checkov-results.json" >&2

    # Permissions are already correct: Docker containers run with --user $(id -u):$(id -g)
    # so output files are owned by the current user — no sudo chown needed.

    CHECKOV_OUTPUT_DIR="$OUTPUT_DIR/checkov-results.json"
    if [ -d "$CHECKOV_OUTPUT_DIR" ] && [ -f "$CHECKOV_OUTPUT_DIR/results_json.json" ]; then
        echo "Debug: Found results_json.json inside directory structure" >&2
        # Move the actual results file to the correct location
        mv "$CHECKOV_OUTPUT_DIR/results_json.json" "$RESULTS_FILE"
        rm -rf "$CHECKOV_OUTPUT_DIR"
        echo "✅ Infrastructure scan completed"
        
        # Handle kubernetes results directory
        if [ -d "$OUTPUT_DIR/checkov-kubernetes-results.json" ] && [ -f "$OUTPUT_DIR/checkov-kubernetes-results.json/results_json.json" ]; then
            mv "$OUTPUT_DIR/checkov-kubernetes-results.json/results_json.json" "$OUTPUT_DIR/checkov-kubernetes-results-temp.json"
            rm -rf "$OUTPUT_DIR/checkov-kubernetes-results.json"
            mv "$OUTPUT_DIR/checkov-kubernetes-results-temp.json" "$OUTPUT_DIR/checkov-kubernetes-results.json"
        fi
        
        # Handle secrets results directory
        if [ -d "$OUTPUT_DIR/checkov-secrets-results.json" ] && [ -f "$OUTPUT_DIR/checkov-secrets-results.json/results_json.json" ]; then
            mv "$OUTPUT_DIR/checkov-secrets-results.json/results_json.json" "$OUTPUT_DIR/checkov-secrets-results-temp.json"
            rm -rf "$OUTPUT_DIR/checkov-secrets-results.json"
            mv "$OUTPUT_DIR/checkov-secrets-results-temp.json" "$OUTPUT_DIR/checkov-secrets-results.json"
        fi
        
        # Handle github-actions results directory
        if [ -d "$OUTPUT_DIR/checkov-github-actions-results.json" ] && [ -f "$OUTPUT_DIR/checkov-github-actions-results.json/results_json.json" ]; then
            mv "$OUTPUT_DIR/checkov-github-actions-results.json/results_json.json" "$OUTPUT_DIR/checkov-github-actions-results-temp.json"
            rm -rf "$OUTPUT_DIR/checkov-github-actions-results.json"
            mv "$OUTPUT_DIR/checkov-github-actions-results-temp.json" "$OUTPUT_DIR/checkov-github-actions-results.json"
        fi
        
        # Merge additional scan results if they exist
        if [ -f "$OUTPUT_DIR/checkov-kubernetes-results.json" ] || [ -f "$OUTPUT_DIR/checkov-secrets-results.json" ] || [ -f "$OUTPUT_DIR/checkov-github-actions-results.json" ]; then
            echo -e "${BLUE}📦 Merging scan results...${NC}"
            
            # Create a merged results file using jq if available
            if command -v jq &> /dev/null; then
                # Collect all result files
                RESULT_FILES=("$RESULTS_FILE")
                [ -f "$OUTPUT_DIR/checkov-kubernetes-results.json" ] && RESULT_FILES+=("$OUTPUT_DIR/checkov-kubernetes-results.json")
                [ -f "$OUTPUT_DIR/checkov-secrets-results.json" ] && RESULT_FILES+=("$OUTPUT_DIR/checkov-secrets-results.json")
                [ -f "$OUTPUT_DIR/checkov-github-actions-results.json" ] && RESULT_FILES+=("$OUTPUT_DIR/checkov-github-actions-results.json")
                
                # Merge all JSON arrays into one, removing duplicates by check_type
                jq -s 'flatten | group_by(.check_type) | map(.[0])' "${RESULT_FILES[@]}" > "$OUTPUT_DIR/merged-results.json" 2>/dev/null
                
                if [ -f "$OUTPUT_DIR/merged-results.json" ] && [ -s "$OUTPUT_DIR/merged-results.json" ]; then
                    mv "$OUTPUT_DIR/merged-results.json" "$RESULTS_FILE"
                    echo "✅ Merged all scan results"
                fi
                
                # Cleanup temporary files
                rm -f "$OUTPUT_DIR/checkov-kubernetes-results.json" "$OUTPUT_DIR/checkov-secrets-results.json" "$OUTPUT_DIR/checkov-github-actions-results.json" 2>/dev/null
            fi
        fi
    elif [ -f "$OUTPUT_DIR/checkov-results.json" ]; then
        echo "Debug: Found checkov-results.json as a file (not directory)" >&2
        # Standard file output (older Checkov versions)
        mv "$OUTPUT_DIR/checkov-results.json" "$RESULTS_FILE"
        echo "✅ Infrastructure scan completed"
    else
        echo "Debug: No results file or directory found!" >&2
        echo "Debug: Creating placeholder results" >&2
        echo "⚠️  No results file generated"
        echo '{"summary": {"passed": 0, "failed": 0, "skipped": 0}, "results": {"failed_checks": []}}' > "$RESULTS_FILE"
    fi
    
else
    echo -e "${YELLOW}⚠️  Docker not available${NC}"
    echo "Creating placeholder results..."
    
    # Create empty results
    echo '{"summary": {"passed": 0, "failed": 0, "skipped": 0}, "results": {"failed_checks": []}}' > "$RESULTS_FILE"
    echo "Checkov scan skipped - Docker not available" >> "$SCAN_LOG"
    SCAN_RESULT=0
fi

# Debug: Verify final results file
echo "Debug: Expected results file: $RESULTS_FILE" >&2
if [ -f "$RESULTS_FILE" ]; then
    echo "Debug: Results file exists, size: $(wc -c < "$RESULTS_FILE") bytes" >&2
    echo "Debug: First 200 chars: $(head -c 200 "$RESULTS_FILE")" >&2
else
    echo "Debug: WARNING - Results file does not exist!" >&2
fi

# Calculate scan duration
SCAN_END_TIME=$(date +%s)
SCAN_DURATION=$((SCAN_END_TIME - SCAN_START_TIME))

echo
echo -e "${CYAN}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║                 📊 CHECKOV SCAN STATISTICS                     ║${NC}"
echo -e "${CYAN}╠════════════════════════════════════════════════════════════════╣${NC}"

# File type statistics
if command -v jq &> /dev/null && [ -f "$RESULTS_FILE" ]; then
    IS_ARRAY=$(jq -r 'if type == "array" then "yes" else "no" end' "$RESULTS_FILE" 2>/dev/null)
    
    if [ "$IS_ARRAY" == "yes" ]; then
        TOTAL_PASSED=$(jq '[.[] | .summary.passed // 0] | add // 0' "$RESULTS_FILE" 2>/dev/null)
        TOTAL_FAILED=$(jq '[.[] | .summary.failed // 0] | add // 0' "$RESULTS_FILE" 2>/dev/null)
        TOTAL_SKIPPED=$(jq '[.[] | .summary.skipped // 0] | add // 0' "$RESULTS_FILE" 2>/dev/null)
        FRAMEWORKS=$(jq -r '[.[] | .check_type] | join(", ")' "$RESULTS_FILE" 2>/dev/null)
    else
        TOTAL_PASSED=$(jq -r '.summary.passed // 0' "$RESULTS_FILE" 2>/dev/null)
        TOTAL_FAILED=$(jq -r '.summary.failed // 0' "$RESULTS_FILE" 2>/dev/null)
        TOTAL_SKIPPED=$(jq -r '.summary.skipped // 0' "$RESULTS_FILE" 2>/dev/null)
        FRAMEWORKS=$(jq -r '.check_type // "terraform"' "$RESULTS_FILE" 2>/dev/null)
    fi
    
    TOTAL_CHECKS=$((TOTAL_PASSED + TOTAL_FAILED + TOTAL_SKIPPED))
    
    # Display statistics
    printf "${CYAN}║${NC} ${WHITE}%-30s${NC} ${GREEN}%-30s${NC} ${CYAN}║${NC}\n" "Files Scanned:" "$((YAML_COUNT + TF_COUNT + DOCKERFILE_COUNT + JSON_COUNT + HELM_COUNT))"
    printf "${CYAN}║${NC}   ${BLUE}%-28s${NC} ${CYAN}%-30s${NC} ${CYAN}║${NC}\n" "• YAML/YML:" "$YAML_COUNT"
    printf "${CYAN}║${NC}   ${BLUE}%-28s${NC} ${CYAN}%-30s${NC} ${CYAN}║${NC}\n" "• Terraform:" "$TF_COUNT"
    printf "${CYAN}║${NC}   ${BLUE}%-28s${NC} ${CYAN}%-30s${NC} ${CYAN}║${NC}\n" "• Dockerfiles:" "$DOCKERFILE_COUNT"
    printf "${CYAN}║${NC}   ${BLUE}%-28s${NC} ${CYAN}%-30s${NC} ${CYAN}║${NC}\n" "• JSON:" "$JSON_COUNT"
    printf "${CYAN}║${NC}   ${BLUE}%-28s${NC} ${CYAN}%-30s${NC} ${CYAN}║${NC}\n" "• Helm Charts:" "$HELM_COUNT"
    echo -e "${CYAN}╠════════════════════════════════════════════════════════════════╣${NC}"
    printf "${CYAN}║${NC} ${WHITE}%-30s${NC} ${PURPLE}%-30s${NC} ${CYAN}║${NC}\n" "Frameworks Detected:" "$FRAMEWORKS"
    echo -e "${CYAN}╠════════════════════════════════════════════════════════════════╣${NC}"
    printf "${CYAN}║${NC} ${WHITE}%-30s${NC} ${CYAN}%-30s${NC} ${CYAN}║${NC}\n" "Total Checks Run:" "$TOTAL_CHECKS"
    printf "${CYAN}║${NC} ${WHITE}%-30s${NC} ${GREEN}%-30s${NC} ${CYAN}║${NC}\n" "Passed:" "$TOTAL_PASSED"
    printf "${CYAN}║${NC} ${WHITE}%-30s${NC} ${RED}%-30s${NC} ${CYAN}║${NC}\n" "Failed:" "$TOTAL_FAILED"
    printf "${CYAN}║${NC} ${WHITE}%-30s${NC} ${YELLOW}%-30s${NC} ${CYAN}║${NC}\n" "Skipped:" "$TOTAL_SKIPPED"
    echo -e "${CYAN}╠════════════════════════════════════════════════════════════════╣${NC}"
    printf "${CYAN}║${NC} ${WHITE}%-30s${NC} ${BLUE}%-30s${NC} ${CYAN}║${NC}\n" "Scan Duration:" "${SCAN_DURATION}s"
    echo -e "${CYAN}╠════════════════════════════════════════════════════════════════╣${NC}"
    
    # Security status
    if [ "$TOTAL_FAILED" -eq 0 ]; then
        printf "${CYAN}║${NC} ${WHITE}%-30s${NC} ${GREEN}%-30s${NC} ${CYAN}║${NC}\n" "Security Status:" "✅ COMPLIANT"
    else
        printf "${CYAN}║${NC} ${WHITE}%-30s${NC} ${YELLOW}%-30s${NC} ${CYAN}║${NC}\n" "Security Status:" "⚠️  ISSUES FOUND"
    fi
else
    # Fallback for systems without jq
    printf "${CYAN}║${NC} ${WHITE}%-30s${NC} ${YELLOW}%-30s${NC} ${CYAN}║${NC}\n" "Statistics:" "Install jq for details"
fi

echo -e "${CYAN}╚════════════════════════════════════════════════════════════════╝${NC}"

# Save statistics to JSON for dashboard
if command -v jq &> /dev/null && [ -f "$RESULTS_FILE" ]; then
    cat > "$OUTPUT_DIR/checkov-statistics.json" << STATS_EOF
{
  "files_scanned": $((YAML_COUNT + TF_COUNT + DOCKERFILE_COUNT + JSON_COUNT + HELM_COUNT)),
  "yaml_count": $YAML_COUNT,
  "terraform_count": $TF_COUNT,
  "dockerfile_count": $DOCKERFILE_COUNT,
  "json_count": $JSON_COUNT,
  "helm_count": $HELM_COUNT,
  "frameworks": "$FRAMEWORKS",
  "total_checks": $TOTAL_CHECKS,
  "passed": $TOTAL_PASSED,
  "failed": $TOTAL_FAILED,
  "skipped": $TOTAL_SKIPPED,
  "scan_duration": ${SCAN_DURATION},
  "security_status": "$([[ $TOTAL_FAILED -eq 0 ]] && echo "COMPLIANT" || echo "ISSUES_FOUND")"
}
STATS_EOF
fi

echo
echo -e "${CYAN}📊 Checkov Infrastructure Security Summary${NC}"
echo "========================================="

# Basic summary from results file
if [ -f "$RESULTS_FILE" ]; then
    echo "📄 Results file: $RESULTS_FILE"
    
    # Simple summary without complex Python parsing
    echo
    echo "Scan Summary:"
    echo "============="
    
    # Try to extract basic counts using jq if available
    if command -v jq &> /dev/null; then
        # Handle both single object format and array format (multiple check_types)
        IS_ARRAY=$(jq -r 'if type == "array" then "yes" else "no" end' "$RESULTS_FILE" 2>/dev/null)
        
        if [ "$IS_ARRAY" == "yes" ]; then
            # Array format - sum across all check_types
            PASSED=$(jq '[.[] | .summary.passed // 0] | add // 0' "$RESULTS_FILE" 2>/dev/null)
            FAILED=$(jq '[.[] | .summary.failed // 0] | add // 0' "$RESULTS_FILE" 2>/dev/null)
            SKIPPED=$(jq '[.[] | .summary.skipped // 0] | add // 0' "$RESULTS_FILE" 2>/dev/null)
            
            echo "Frameworks scanned:"
            jq -r '.[] | "  - \(.check_type): \(.summary.passed // 0) passed, \(.summary.failed // 0) failed"' "$RESULTS_FILE" 2>/dev/null
            echo
        else
            # Single object format
            PASSED=$(jq -r '.summary.passed // 0' "$RESULTS_FILE" 2>/dev/null)
            FAILED=$(jq -r '.summary.failed // 0' "$RESULTS_FILE" 2>/dev/null)
            SKIPPED=$(jq -r '.summary.skipped // 0' "$RESULTS_FILE" 2>/dev/null)
        fi
        
        echo "Total passed checks: $PASSED"
        echo "Total failed checks: $FAILED"
        echo "Total skipped checks: $SKIPPED"
        echo "Total checks: $((PASSED + FAILED + SKIPPED))"
        
        if [ "$FAILED" -gt 0 ]; then
            echo
            echo -e "${YELLOW}⚠️  $FAILED security issues found${NC}"
            echo "Review detailed results for specific recommendations"
            
            # Show top failed checks
            echo
            echo "Top failed checks:"
            if [ "$IS_ARRAY" == "yes" ]; then
                jq -r '.[] | .results.failed_checks[]? | "  ❌ \(.check_id): \(.check_name) (\(.file_path))"' "$RESULTS_FILE" 2>/dev/null | head -10
            else
                jq -r '.results.failed_checks[]? | "  ❌ \(.check_id): \(.check_name) (\(.file_path))"' "$RESULTS_FILE" 2>/dev/null | head -10
            fi
        else
            echo
            echo -e "${GREEN}🎉 No security issues detected!${NC}"
        fi
        
        # Create/update current symlink for easy access
        ln -sf "$(basename "$RESULTS_FILE")" "$CURRENT_FILE"
    else
        echo "Basic scan completed - install 'jq' for detailed summary"
    fi
    
else
    echo "⚠️  No results file generated"
fi

# Security status
if [ "$SCAN_RESULT" -eq 0 ]; then
    echo
    echo -e "${GREEN}✅ Infrastructure Security Status: Compliant${NC}"
else
    echo
    echo -e "${YELLOW}⚠️  Infrastructure Security Status: Issues Found${NC}"
fi

echo
echo -e "${BLUE}📁 Output Files:${NC}"
echo "================"
echo "📄 Results file: $RESULTS_FILE"
echo "📝 Scan log: $SCAN_LOG"
echo "📂 Reports directory: $OUTPUT_DIR"

echo
echo -e "${BLUE}🔧 Available Commands:${NC}"
echo "===================="
echo "📊 Analyze results:       npm run checkov:analyze"
echo "🔍 Run new scan:          npm run checkov:scan"
echo "📋 View results:          cat $RESULTS_FILE | jq ."
echo "📝 View scan log:         cat $SCAN_LOG"

echo
echo -e "${BLUE}🔗 Additional Resources:${NC}"
echo "======================="
echo "• Checkov Documentation: https://www.checkov.io/1.Introduction/Getting%20Started.html"
echo "• Infrastructure Security: https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration"
echo "• Kubernetes Security: https://kubernetes.io/docs/concepts/security/"

echo
echo "============================================"
echo -e "${GREEN}✅ Checkov infrastructure security completed!${NC}"
echo "============================================"
echo
echo "============================================"
echo "Checkov infrastructure scanning complete."
echo "============================================"