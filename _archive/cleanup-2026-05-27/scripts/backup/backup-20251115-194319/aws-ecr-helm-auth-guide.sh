#!/bin/bash

# AWS ECR Helm Authentication Demo Script
# Shows the complete process for resolving private Helm dependencies
# This is a demonstration version that doesn't require actual AWS credentials

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
CHART_DIR="${TARGET_DIR:-$(pwd)}/chart"
AWS_REGION="us-gov-west-1"
ECR_REGISTRY="231388672283.dkr.ecr.us-gov-west-1.amazonaws.com"

echo "============================================"
echo -e "${BLUE}🔐 AWS ECR Helm Authentication Guide${NC}"
echo "============================================"
echo ""
echo -e "${CYAN}This script shows you exactly how to resolve private Helm dependencies${NC}"
echo -e "${CYAN}for the advana-marketplace-monolith-node chart.${NC}"
echo ""
echo "Chart Directory: $CHART_DIR"
echo "AWS Region: $AWS_REGION"
echo "ECR Registry: $ECR_REGISTRY"
echo ""

# Check if chart exists
if [[ ! -f "$CHART_DIR/Chart.yaml" ]]; then
    echo -e "${RED}❌ Chart.yaml not found at: $CHART_DIR${NC}"
    exit 1
fi

echo -e "${BLUE}📋 Current Chart Dependencies${NC}"
echo "=============================="
echo ""
grep -A 20 "dependencies:" "$CHART_DIR/Chart.yaml" | head -15
echo ""

echo -e "${BLUE}🔧 Step-by-Step Resolution Guide${NC}"
echo "================================="
echo ""

echo -e "${YELLOW}Step 1: Configure AWS Credentials${NC}"
echo "=================================="
echo "You need AWS credentials for the government account: 231388672283"
echo ""
echo "Option A - AWS CLI Configure:"
echo -e "${CYAN}  aws configure${NC}"
echo ""
echo "Option B - Environment Variables:"
echo -e "${CYAN}  export AWS_ACCESS_KEY_ID=your-access-key${NC}"
echo -e "${CYAN}  export AWS_SECRET_ACCESS_KEY=your-secret-key${NC}"
echo -e "${CYAN}  export AWS_DEFAULT_REGION=$AWS_REGION${NC}"
echo ""
echo "Option C - AWS SSO:"
echo -e "${CYAN}  aws configure sso${NC}"
echo -e "${CYAN}  aws sso login${NC}"
echo ""

echo -e "${YELLOW}Step 2: Authenticate with ECR${NC}"
echo "=============================="
echo "Login to both Docker and Helm registries:"
echo ""
echo -e "${CYAN}# Docker ECR Login${NC}"
echo -e "${CYAN}aws ecr get-login-password --region $AWS_REGION | \\${NC}"
echo -e "${CYAN}  docker login --username AWS --password-stdin $ECR_REGISTRY${NC}"
echo ""
echo -e "${CYAN}# Helm Registry Login${NC}"
echo -e "${CYAN}aws ecr get-login-password --region $AWS_REGION | \\${NC}"
echo -e "${CYAN}  helm registry login --username AWS --password-stdin $ECR_REGISTRY${NC}"
echo ""

echo -e "${YELLOW}Step 3: Add Public Repositories${NC}"
echo "==============================="
echo -e "${CYAN}helm repo add bitnami https://charts.bitnami.com/bitnami${NC}"
echo -e "${CYAN}helm repo update${NC}"
echo ""

echo -e "${YELLOW}Step 4: Resolve Dependencies${NC}"
echo "============================"
echo "Navigate to chart directory and run:"
echo ""
echo -e "${CYAN}cd \"$CHART_DIR\"${NC}"
echo -e "${CYAN}helm dependency update${NC}"
echo ""
echo "This will download:"
echo "  ✅ postgresql-15.5.38.tgz (from Bitnami - public)"
echo "  ✅ advana-library-2.0.4.tgz (from ECR - private)"
echo ""

echo -e "${YELLOW}Step 5: Verify Resolution${NC}"
echo "========================="
echo "Check that dependencies were downloaded:"
echo ""
echo -e "${CYAN}ls -la \"$CHART_DIR/charts/\"${NC}"
echo ""
echo "You should see:"
echo "  📦 postgresql-15.5.38.tgz"
echo "  📦 advana-library-2.0.4.tgz"
echo ""

echo -e "${YELLOW}Step 6: Test Template Rendering${NC}"
echo "==============================="
echo -e "${CYAN}helm template test-render \"$CHART_DIR\" > rendered-templates.yaml${NC}"
echo ""
echo "This should generate actual Kubernetes manifests instead of template placeholders"
echo ""

echo -e "${YELLOW}Step 7: Run Security Scans${NC}"
echo "=========================="
echo "Now you can run Checkov and other security tools on the rendered templates:"
echo ""
echo -e "${CYAN}# Run Checkov on rendered templates${NC}"
echo -e "${CYAN}TARGET_DIR=\"$TARGET_DIR\" ./scripts/run-checkov-scan.sh${NC}"
echo ""
echo -e "${CYAN}# Run full security suite${NC}"
echo -e "${CYAN}./scripts/run-target-security-scan.sh \"$TARGET_DIR\" full${NC}"
echo ""

echo -e "${BLUE}🚨 Important Notes${NC}"
echo "=================="
echo ""
echo -e "${RED}⚠️  Private Repository Access Required${NC}"
echo "The advana-library chart is in a private AWS ECR repository."
echo "You need:"
echo "  • Valid AWS credentials for account 231388672283"
echo "  • ECR permissions for the tenant/advana-library repository"
echo "  • Access to us-gov-west-1 region"
echo ""
echo -e "${YELLOW}💡 Alternative: Use Stub Charts${NC}"
echo "If you don't have ECR access, you can create stub dependencies:"
echo -e "${CYAN}./scripts/create-stub-dependencies.sh${NC}"
echo ""

echo -e "${BLUE}🔧 Automated Script Available${NC}"
echo "=============================="
echo "To run the full authentication process automatically:"
echo -e "${CYAN}./scripts/aws-ecr-helm-auth.sh${NC}"
echo ""
echo "Or using npm:"
echo -e "${CYAN}npm run aws:ecr:auth${NC}"
echo ""

echo -e "${GREEN}📚 Complete Command Reference${NC}"
echo "============================="
echo ""
echo -e "${CYAN}# One-time setup${NC}"
echo -e "${CYAN}aws configure  # or aws sso login${NC}"
echo ""
echo -e "${CYAN}# ECR authentication${NC}"
echo -e "${CYAN}aws ecr get-login-password --region $AWS_REGION | \\${NC}"
echo -e "${CYAN}  docker login --username AWS --password-stdin $ECR_REGISTRY${NC}"
echo ""
echo -e "${CYAN}# Dependency resolution${NC}"
echo -e "${CYAN}cd \"$CHART_DIR\"${NC}"
echo -e "${CYAN}helm repo add bitnami https://charts.bitnami.com/bitnami${NC}"
echo -e "${CYAN}helm dependency update${NC}"
echo ""
echo -e "${CYAN}# Security scanning${NC}"
echo -e "${CYAN}cd -${NC}"
echo -e "${CYAN}TARGET_DIR=\"$TARGET_DIR\" ./scripts/run-target-security-scan.sh \"$TARGET_DIR\" full${NC}"
echo ""

echo -e "${BLUE}════════════════════════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}🎯 AWS ECR Helm Dependency Resolution Guide Complete!${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════════════════════════════${NC}"