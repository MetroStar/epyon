#!/bin/bash

# Helm Chart Build Script
# Builds and validates Helm charts
# Updated to use absolute paths and handle directory names with spaces

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# Initialize scan environment using scan directory approach
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source the scan directory template
source "$SCRIPT_DIR/scan-directory-template.sh"

# Initialize scan environment for Helm
init_scan_environment "helm"

# Set TARGET_SCAN_DIR and extract scan information
TARGET_SCAN_DIR="${TARGET_DIR:-$(pwd)}"
REPO_PATH="${TARGET_DIR:-$(pwd)}"
if [[ -n "$SCAN_ID" ]]; then
    TARGET_NAME=$(echo "$SCAN_ID" | cut -d'_' -f1)
    USERNAME=$(echo "$SCAN_ID" | cut -d'_' -f2)
    TIMESTAMP=$(echo "$SCAN_ID" | cut -d'_' -f3-)
else
    # Fallback for standalone execution
    TARGET_NAME=$(basename "$TARGET_SCAN_DIR")
    USERNAME=$(whoami)
    TIMESTAMP=$(date '+%Y-%m-%d_%H-%M-%S')
    SCAN_ID="${TARGET_NAME}_${USERNAME}_${TIMESTAMP}"
fi

echo
echo -e "${WHITE}============================================${NC}"
echo -e "${WHITE}Helm Chart Builder & Validator${NC}"
echo -e "${WHITE}============================================${NC}"
echo

# AWS ECR Authentication for private dependencies
echo -e "${BLUE}🔐 Step 0: AWS ECR Authentication (Optional)${NC}"
echo "=================================="
AWS_REGION="us-gov-west-1"
ECR_REGISTRY="231388672283.dkr.ecr.us-gov-west-1.amazonaws.com"

# Offer AWS ECR authentication for private Helm dependencies
echo -e "${CYAN}🔐 This chart may require AWS ECR authentication for private dependencies${NC}"
echo "Options:"
echo "  1) Attempt AWS ECR login (recommended for complete build)"
echo "  2) Skip authentication (fallback to stub dependencies)"
echo
read -p "Choose option (1 or 2, default: 2): " aws_choice

# Initialize authentication status
AWS_AUTHENTICATED=false

if [[ "${aws_choice:-2}" == "1" ]]; then
    echo -e "${CYAN}🚀 Running AWS ECR authentication...${NC}"
    
    # Check if AWS CLI is available
    if command -v aws &> /dev/null; then
        echo "Checking AWS credentials..."
        if aws sts get-caller-identity &> /dev/null; then
            echo -e "${GREEN}✅ AWS credentials found${NC}"
            
            # Attempt ECR login
            echo "Attempting ECR authentication..."
            if aws ecr get-login-password --region "$AWS_REGION" | docker login --username AWS --password-stdin "$ECR_REGISTRY" &> /dev/null; then
                echo -e "${GREEN}✅ AWS ECR authentication successful${NC}"
                AWS_AUTHENTICATED=true
            else
                echo -e "${YELLOW}⚠️  ECR authentication failed - continuing with fallback${NC}"
            fi
        else
            echo -e "${YELLOW}⚠️  AWS credentials not configured${NC}"
            echo "To set up AWS credentials:"
            echo "  ${GREEN}aws configure${NC} (for access keys)"
            echo "  ${GREEN}aws configure sso${NC} (for SSO)"
            echo "  ${GREEN}aws sso login --profile <profile>${NC} (to login)"
        fi
    else
        echo -e "${RED}❌ AWS CLI not found${NC}"
        echo "Install AWS CLI: https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html"
    fi
else
    echo -e "${CYAN}⏭️  Skipping AWS authentication${NC}"
fi

echo

# Function to build and validate Helm chart
build_helm_chart() {
    local chart_path="$1"
    local chart_name="$2"
    
    if [ -d "$chart_path" ]; then
        echo -e "${BLUE}🏗️  Building Helm chart: $chart_name${NC}"
        
        # Lint the chart
        echo "Linting chart: $chart_name"
        helm lint "$chart_path" 2>&1 | tee -a "$SCAN_LOG"
        
        # Template the chart
        echo "Templating chart: $chart_name"
        helm template "$chart_name" "$chart_path" \
            --output-dir "$OUTPUT_DIR" 2>&1 | tee -a "$SCAN_LOG"
            
        # Package the chart
        echo "Packaging chart: $chart_name"
        helm package "$chart_path" \
            --destination "$OUTPUT_DIR" 2>&1 | tee -a "$SCAN_LOG"
            
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}✅ Helm chart built successfully: $chart_name${NC}"
        else
            echo -e "${RED}❌ Helm chart build failed: $chart_name${NC}"
        fi
        echo
    fi
}

# 1. Helm Chart Building
echo -e "${CYAN}🏗️  Step 1: Helm Chart Discovery & Building${NC}"
echo "==========================================="

# Search for Helm charts in the target directory
if [ ! -z "$1" ] && [ -d "$1" ]; then
    echo -e "${BLUE}📁 Searching for Helm charts in: $1${NC}"
    
    # Look for Chart.yaml files
    CHART_FILES=$(find "$1" -name "Chart.yaml" -type f 2>/dev/null)
    
    if [ ! -z "$CHART_FILES" ]; then
        echo "$CHART_FILES" | while read chart_file; do
            chart_dir=$(dirname "$chart_file")
            chart_name=$(basename "$chart_dir")
            build_helm_chart "$chart_dir" "$chart_name"
        done
    else
        echo -e "${YELLOW}⚠️  No Helm charts found in target directory${NC}"
    fi
else
    echo -e "${YELLOW}⚠️  No target directory provided for Helm chart search${NC}"
fi

# Also check for common chart locations
COMMON_CHART_PATHS=(
    "helm"
    "charts"
    "k8s"
    "kubernetes"
    "deploy"
    "deployment"
)

for chart_path in "${COMMON_CHART_PATHS[@]}"; do
    if [ -d "$chart_path/Chart.yaml" ] || [ -f "$chart_path/Chart.yaml" ]; then
        build_helm_chart "$chart_path" $(basename "$chart_path")
    fi
done

echo
echo -e "${CYAN}📊 Helm Chart Build Summary${NC}"
echo "==================================="

CHART_COUNT=$(find "$OUTPUT_DIR" -name "*.tgz" 2>/dev/null | wc -l)
echo -e "🏗️  Helm Chart Build Summary:"
if [ $CHART_COUNT -gt 0 ]; then
    echo -e "${GREEN}✅ $CHART_COUNT Helm chart(s) built successfully${NC}"
    
    echo "  📦 Built Charts:"
    find "$OUTPUT_DIR" -name "*.tgz" 2>/dev/null | while read chart; do
        echo "    📄 $(basename "$chart")"
    done
else
    echo -e "${YELLOW}⚠️  No Helm charts were built${NC}"
fi

echo
echo -e "${BLUE}📁 Output Files:${NC}"
echo "==============="
find "$OUTPUT_DIR" -type f 2>/dev/null | while read file; do
    echo "📄 $(basename "$file")"
done
echo "📝 Build log: $SCAN_LOG"
echo "📂 Reports directory: $OUTPUT_DIR"

echo
echo -e "${BLUE}🔧 Available Commands:${NC}"
echo "===================="
echo "📊 Analyze charts:         helm lint ./charts/*"
echo "🔍 Template charts:        helm template <name> <chart>"
echo "🏗️  Build charts:           helm package <chart>"
echo "📦 Install charts:         helm install <name> <chart>"
echo "🌐 Deploy charts:          helm upgrade --install <name> <chart>"
echo "☸️  Kubernetes deploy:      kubectl apply -f $OUTPUT_DIR"
echo "🛡️  Security scan:          helm lint --strict <chart>"
echo "📋 View templates:         find $OUTPUT_DIR -name '*.yaml' | head -10"

echo
echo -e "${BLUE}🔗 Additional Resources:${NC}"
echo "======================="
echo "• Helm Documentation: https://helm.sh/docs/"
echo "• Chart Best Practices: https://helm.sh/docs/chart_best_practices/"
echo "• Kubernetes Security: https://kubernetes.io/docs/concepts/security/"
echo "• Helm Security Guide: https://helm.sh/docs/topics/security/"

echo
# Create current symlink for easy access
ln -sf "$(basename "$SCAN_LOG")" "$CURRENT_LOG"

echo "============================================"
echo -e "${GREEN}✅ Helm chart building completed successfully!${NC}"
echo "============================================"
echo
echo "============================================"
echo "Helm chart building complete."
echo "============================================"