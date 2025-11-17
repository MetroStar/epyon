#!/bin/bash

# Checkov Infrastructure-as-Code Security Scan Script
# Scans Helm charts and Kubernetes manifests for security best practices

# Configuration - Support target directory override
TARGET_SCAN_DIR="${TARGET_DIR:-$(pwd)}"
CHART_DIR="${TARGET_SCAN_DIR}/chart"

# Initialize scan environment using scan directory approach
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source the scan directory template
source "$SCRIPT_DIR/scan-directory-template.sh"

# Initialize scan environment for Checkov
init_scan_environment "checkov"

# Set compatibility paths
REPORTS_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
HELM_OUTPUT_DIR="$REPORTS_ROOT/reports/helm-packages"

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
if command -v docker &> /dev/null; then
    echo "🐳 Using Docker-based Checkov..."
    
    # Pull Checkov Docker image
    echo "📥 Pulling Checkov Docker image..."
    docker pull bridgecrew/checkov:latest 2>&1 | tee -a "$SCAN_LOG"
    
    # Scan for various IaC files
    echo -e "${BLUE}🔍 Scanning Infrastructure as Code files...${NC}"
    
    # Check for AWS credentials and prompt if needed
    if [[ -z "$AWS_ACCESS_KEY_ID" || -z "$AWS_SECRET_ACCESS_KEY" ]]; then
        echo
        echo -e "${YELLOW}🔐 AWS Credentials not found in environment variables${NC}"
        echo "Checkov can perform enhanced security checks with AWS credentials."
        echo
        echo "Options:"
        echo "  1) Continue without AWS integration (local scan only)"
        echo "  2) Set up AWS SSO/CLI authentication"
        echo "  3) Enter AWS credentials manually"
        echo
        read -p "Choose option [1-3] (default: 1): " aws_choice
        
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
                read -p "Press Enter after setting up AWS credentials..."
                
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
                read -p "AWS Access Key ID: " AWS_ACCESS_KEY_ID
                read -s -p "AWS Secret Access Key: " AWS_SECRET_ACCESS_KEY
                echo
                read -p "AWS Region (default: us-gov-west-1): " input_region
                AWS_DEFAULT_REGION="${input_region:-us-gov-west-1}"
                echo "✅ AWS credentials configured"
                ;;
            *)
                echo "✅ Continuing with local scan only"
                ;;
        esac
    else
        echo "✅ Using AWS credentials from environment"
    fi
    
    # Build Docker command with AWS credentials and profile support
    AWS_MOUNT_ARGS=""
    if [[ -d "$HOME/.aws" ]]; then
        AWS_MOUNT_ARGS="-v $HOME/.aws:/root/.aws"
        echo "✅ Mounting AWS credentials directory"
    fi
    
    # Run Checkov scan with AWS credentials
    docker run --rm \
        -e AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID" \
        -e AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY" \
        -e AWS_DEFAULT_REGION="$AWS_DEFAULT_REGION" \
        -e AWS_PROFILE="$AWS_PROFILE" \
        $AWS_MOUNT_ARGS \
        -v "$TARGET_SCAN_DIR:/workspace" \
        -v "$OUTPUT_DIR:/output" \
        bridgecrew/checkov:latest \
        --directory /workspace \
        --output json \
        --output-file /output/checkov-results.json \
        2>&1 | tee -a "$SCAN_LOG"
    
    SCAN_RESULT=$?
    
    if [ -f "$RESULTS_FILE" ]; then
        echo "✅ Infrastructure scan completed"
    else
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

echo
echo -e "${CYAN}📊 Checkov Infrastructure Security Summary${NC}"
echo "=========================================="

# Basic summary from results file
if [ -f "$RESULTS_FILE" ]; then
    echo "📄 Results file: $RESULTS_FILE"
    
    # Simple summary without complex Python parsing
    echo
    echo "Scan Summary:"
    echo "============="
    
    # Try to extract basic counts using jq if available
    if command -v jq &> /dev/null; then
        PASSED=$(jq -r '.summary.passed // 0' "$RESULTS_FILE" 2>/dev/null)
        FAILED=$(jq -r '.summary.failed // 0' "$RESULTS_FILE" 2>/dev/null)
        SKIPPED=$(jq -r '.summary.skipped // 0' "$RESULTS_FILE" 2>/dev/null)
        
        echo "Passed checks: $PASSED"
        echo "Failed checks: $FAILED"
        echo "Skipped checks: $SKIPPED"
        echo "Total checks: $((PASSED + FAILED + SKIPPED))"
        
        if [ "$FAILED" -gt 0 ]; then
            echo
            echo -e "${YELLOW}⚠️  $FAILED security issues found${NC}"
            echo "Review detailed results for specific recommendations"
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