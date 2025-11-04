#!/bin/bash

# AWS ECR Helm Authentication and Dependency Resolution Script
# Authenticates with AWS ECR and resolves private Helm chart dependencies

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
OUTPUT_DIR="./helm-dependency-resolution"
AWS_REGION="us-gov-west-1"
ECR_REGISTRY="231388672283.dkr.ecr.us-gov-west-1.amazonaws.com"
ECR_NAMESPACE="tenant"

echo "============================================"
echo -e "${BLUE}🔐 AWS ECR Helm Authentication Tool${NC}"
echo "============================================"
echo "Chart Directory: $CHART_DIR"
echo "AWS Region: $AWS_REGION"
echo "ECR Registry: $ECR_REGISTRY"
echo "Output Directory: $OUTPUT_DIR"
echo "Timestamp: $(date)"
echo ""

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Function to check command availability
check_command() {
    local cmd="$1"
    local desc="$2"
    
    if command -v "$cmd" &> /dev/null; then
        echo -e "${GREEN}✅ $desc found${NC}"
        return 0
    else
        echo -e "${RED}❌ $desc not found${NC}"
        return 1
    fi
}

# Function to check AWS credentials
check_aws_credentials() {
    echo -e "${CYAN}🔍 Checking AWS credentials...${NC}"
    
    if aws sts get-caller-identity &> /dev/null; then
        local account=$(aws sts get-caller-identity --query Account --output text)
        local user=$(aws sts get-caller-identity --query Arn --output text)
        echo -e "${GREEN}✅ AWS credentials configured${NC}"
        echo "Account: $account"
        echo "User/Role: $user"
        return 0
    else
        echo -e "${RED}❌ AWS credentials not configured${NC}"
        return 1
    fi
}

# Function to setup AWS credentials interactively
setup_aws_credentials() {
    echo -e "${YELLOW}⚠️  AWS credentials need to be configured${NC}"
    echo ""
    echo "Choose an option:"
    echo "1. Configure AWS CLI interactively"
    echo "2. Use environment variables"
    echo "3. Use AWS SSO"
    echo "4. Skip (assume role/instance profile)"
    echo ""
    
    read -p "Enter your choice (1-4): " choice
    
    case $choice in
        1)
            echo -e "${CYAN}🔧 Running AWS configure...${NC}"
            aws configure
            ;;
        2)
            echo -e "${CYAN}🔧 Setting up environment variables...${NC}"
            read -p "AWS Access Key ID: " access_key
            read -s -p "AWS Secret Access Key: " secret_key
            echo ""
            read -p "Default region [$AWS_REGION]: " region
            region=${region:-$AWS_REGION}
            
            export AWS_ACCESS_KEY_ID="$access_key"
            export AWS_SECRET_ACCESS_KEY="$secret_key"
            export AWS_DEFAULT_REGION="$region"
            
            echo -e "${GREEN}✅ Environment variables set${NC}"
            ;;
        3)
            echo -e "${CYAN}🔧 AWS SSO login...${NC}"
            echo "Make sure you have SSO configured first:"
            echo "aws configure sso"
            echo ""
            read -p "Press Enter to continue with SSO login..."
            aws sso login
            ;;
        4)
            echo -e "${YELLOW}⚠️  Assuming credentials are available via IAM role or instance profile${NC}"
            ;;
        *)
            echo -e "${RED}❌ Invalid choice${NC}"
            return 1
            ;;
    esac
}

# Function to authenticate with ECR
ecr_login() {
    echo -e "${CYAN}🔐 Authenticating with AWS ECR...${NC}"
    echo "Registry: $ECR_REGISTRY"
    echo ""
    
    # Get ECR login token and login to Docker
    if aws ecr get-login-password --region "$AWS_REGION" | docker login --username AWS --password-stdin "$ECR_REGISTRY"; then
        echo -e "${GREEN}✅ Docker ECR login successful${NC}"
        DOCKER_ECR_LOGIN=true
    else
        echo -e "${RED}❌ Docker ECR login failed${NC}"
        DOCKER_ECR_LOGIN=false
    fi
    
    # Login to Helm registry (if Helm is available)
    if command -v helm &> /dev/null; then
        if aws ecr get-login-password --region "$AWS_REGION" | helm registry login --username AWS --password-stdin "$ECR_REGISTRY"; then
            echo -e "${GREEN}✅ Helm ECR login successful${NC}"
            HELM_ECR_LOGIN=true
        else
            echo -e "${YELLOW}⚠️  Helm ECR login failed${NC}"
            HELM_ECR_LOGIN=false
        fi
    else
        echo -e "${YELLOW}⚠️  Helm not available locally${NC}"
        HELM_ECR_LOGIN=false
    fi
}

# Function to verify ECR access
verify_ecr_access() {
    echo -e "${CYAN}🔍 Verifying ECR repository access...${NC}"
    
    # List repositories to verify access
    if aws ecr describe-repositories --region "$AWS_REGION" --repository-names "$ECR_NAMESPACE/advana-library" &> /dev/null; then
        echo -e "${GREEN}✅ ECR repository access verified${NC}"
        
        # Get repository details
        local repo_uri=$(aws ecr describe-repositories --region "$AWS_REGION" --repository-names "$ECR_NAMESPACE/advana-library" --query 'repositories[0].repositoryUri' --output text)
        echo "Repository URI: $repo_uri"
        
        # List available tags/versions
        echo -e "${CYAN}📋 Available chart versions:${NC}"
        if aws ecr list-images --region "$AWS_REGION" --repository-name "$ECR_NAMESPACE/advana-library" --query 'imageIds[*].imageTag' --output table; then
            return 0
        else
            echo -e "${YELLOW}⚠️  Could not list image tags${NC}"
            return 0
        fi
    else
        echo -e "${RED}❌ ECR repository access failed${NC}"
        echo "Repository: $ECR_NAMESPACE/advana-library"
        echo ""
        echo "Possible issues:"
        echo "1. Repository does not exist"
        echo "2. Insufficient permissions"
        echo "3. Incorrect repository name"
        return 1
    fi
}

# Function to resolve Helm dependencies
resolve_dependencies() {
    echo -e "${CYAN}📦 Resolving Helm chart dependencies...${NC}"
    
    cd "$CHART_DIR"
    
    # Add public repositories first
    echo "Adding public Helm repositories..."
    if command -v helm &> /dev/null; then
        helm repo add bitnami https://charts.bitnami.com/bitnami 2>/dev/null || true
        helm repo add stable https://charts.helm.sh/stable 2>/dev/null || true
        helm repo update
    else
        echo "Using Docker Helm for repository management..."
        docker run --rm alpine/helm:latest repo add bitnami https://charts.bitnami.com/bitnami
        docker run --rm alpine/helm:latest repo add stable https://charts.helm.sh/stable
    fi
    
    # Resolve dependencies
    echo ""
    echo "Resolving chart dependencies..."
    
    if command -v helm &> /dev/null; then
        if helm dependency update 2>&1 | tee "$OUTPUT_DIR/dependency-resolution.log"; then
            echo -e "${GREEN}✅ Dependencies resolved successfully${NC}"
            DEPS_SUCCESS=true
        else
            echo -e "${RED}❌ Dependency resolution failed${NC}"
            DEPS_SUCCESS=false
        fi
    else
        # Use Docker Helm with mounted credentials
        if docker run --rm \
            -v "$HOME/.docker/config.json:/root/.docker/config.json:ro" \
            -v "$(pwd):/apps" -w /apps \
            alpine/helm:latest dependency update 2>&1 | tee "$OUTPUT_DIR/dependency-resolution.log"; then
            echo -e "${GREEN}✅ Dependencies resolved successfully${NC}"
            DEPS_SUCCESS=true
        else
            echo -e "${RED}❌ Dependency resolution failed${NC}"
            DEPS_SUCCESS=false
        fi
    fi
    
    cd - > /dev/null
    
    # Check what was downloaded
    if [ "$DEPS_SUCCESS" = true ]; then
        echo ""
        echo -e "${CYAN}📋 Downloaded dependencies:${NC}"
        if [[ -d "$CHART_DIR/charts" ]]; then
            ls -la "$CHART_DIR/charts/"
            echo ""
            find "$CHART_DIR/charts" -name "*.tgz" -exec basename {} \;
        fi
    fi
}

# Function to test template rendering
test_template_rendering() {
    echo -e "${CYAN}🧪 Testing Helm template rendering...${NC}"
    
    cd "$CHART_DIR"
    
    local test_output="$OUTPUT_DIR/rendered-templates.yaml"
    
    if command -v helm &> /dev/null; then
        if helm template test-render . > "$test_output" 2>&1; then
            local resource_count=$(grep -c "^kind:" "$test_output" 2>/dev/null || echo "0")
            echo -e "${GREEN}✅ Template rendering successful${NC}"
            echo "Generated Kubernetes resources: $resource_count"
            
            if [ "$resource_count" -gt 0 ]; then
                echo ""
                echo "Resource types generated:"
                grep "^kind:" "$test_output" | sort | uniq -c
                
                # Save a clean version for Checkov
                cp "$test_output" "$OUTPUT_DIR/checkov-ready-templates.yaml"
                echo ""
                echo -e "${GREEN}🎯 Templates ready for security scanning!${NC}"
                echo "File: $OUTPUT_DIR/checkov-ready-templates.yaml"
            fi
            
            TEMPLATE_SUCCESS=true
        else
            echo -e "${RED}❌ Template rendering failed${NC}"
            echo "Check $test_output for error details"
            TEMPLATE_SUCCESS=false
        fi
    else
        echo "Using Docker Helm for template rendering..."
        if docker run --rm \
            -v "$HOME/.docker/config.json:/root/.docker/config.json:ro" \
            -v "$(pwd):/apps" -w /apps \
            alpine/helm:latest template test-render . > "$test_output" 2>&1; then
            local resource_count=$(grep -c "^kind:" "$test_output" 2>/dev/null || echo "0")
            echo -e "${GREEN}✅ Template rendering successful${NC}"
            echo "Generated Kubernetes resources: $resource_count"
            TEMPLATE_SUCCESS=true
        else
            echo -e "${RED}❌ Template rendering failed${NC}"
            TEMPLATE_SUCCESS=false
        fi
    fi
    
    cd - > /dev/null
}

# Main execution
echo -e "${BLUE}🔍 Step 1: Prerequisites Check${NC}"
echo "================================"

# Check required tools
PREREQ_OK=true
check_command "aws" "AWS CLI" || PREREQ_OK=false
check_command "docker" "Docker" || PREREQ_OK=false

if ! command -v helm &> /dev/null; then
    echo -e "${YELLOW}⚠️  Helm not found locally - will use Docker${NC}"
fi

if [ "$PREREQ_OK" = false ]; then
    echo ""
    echo -e "${RED}❌ Missing required tools. Please install:${NC}"
    echo "- AWS CLI: https://aws.amazon.com/cli/"
    echo "- Docker: https://docker.com/"
    exit 1
fi

echo ""
echo -e "${BLUE}🔐 Step 2: AWS Authentication${NC}"
echo "================================"

# Check/setup AWS credentials
if ! check_aws_credentials; then
    setup_aws_credentials
    
    # Verify credentials after setup
    if ! check_aws_credentials; then
        echo -e "${RED}❌ AWS credential setup failed${NC}"
        exit 1
    fi
fi

echo ""
echo -e "${BLUE}🔐 Step 3: ECR Authentication${NC}"
echo "================================"

# Authenticate with ECR
ecr_login

if [ "$DOCKER_ECR_LOGIN" = false ] && [ "$HELM_ECR_LOGIN" = false ]; then
    echo -e "${RED}❌ ECR authentication failed${NC}"
    exit 1
fi

# Verify ECR access
verify_ecr_access

echo ""
echo -e "${BLUE}📦 Step 4: Dependency Resolution${NC}"
echo "================================="

# Resolve dependencies
resolve_dependencies

echo ""
echo -e "${BLUE}🧪 Step 5: Template Rendering Test${NC}"
echo "=================================="

# Test template rendering
test_template_rendering

echo ""
echo -e "${CYAN}📊 Summary${NC}"
echo "=============="
echo "Chart Directory: $CHART_DIR"
echo "Output Directory: $OUTPUT_DIR"
echo "AWS Region: $AWS_REGION"
echo "ECR Registry: $ECR_REGISTRY"
echo ""

if [ "$DEPS_SUCCESS" = true ] && [ "$TEMPLATE_SUCCESS" = true ]; then
    echo -e "${GREEN}✅ All operations completed successfully!${NC}"
    echo ""
    echo "Next steps:"
    echo "1. Run Checkov security scan:"
    echo "   TARGET_DIR=\"$TARGET_DIR\" ./scripts/run-checkov-scan.sh"
    echo ""
    echo "2. Run full security scan:"
    echo "   ./scripts/run-target-security-scan.sh \"$TARGET_DIR\" full"
    echo ""
    echo "3. Rendered templates available at:"
    echo "   $OUTPUT_DIR/checkov-ready-templates.yaml"
else
    echo -e "${YELLOW}⚠️  Some operations completed with warnings${NC}"
    echo ""
    echo "Check the logs in $OUTPUT_DIR/ for details"
fi

echo ""
echo -e "${BLUE}════════════════════════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}🎯 AWS ECR Helm Authentication Complete!${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════════════════════════════${NC}"