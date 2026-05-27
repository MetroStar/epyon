#!/bin/bash

# Helm Dependency Resolution Script
# Resolves Helm chart dependencies including private AWS ECR repositories

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
CHART_DIR="${TARGET_DIR:-$(pwd)}/chart"
OUTPUT_DIR="./helm-dependency-resolution"

echo "============================================"
echo -e "${BLUE}🔧 Helm Dependency Resolution Tool${NC}"
echo "============================================"
echo "Chart Directory: $CHART_DIR"
echo "Output Directory: $OUTPUT_DIR"
echo "Timestamp: $(date)"
echo ""

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Validate chart directory exists
if [[ ! -d "$CHART_DIR" ]]; then
    echo -e "${RED}❌ Chart directory not found: $CHART_DIR${NC}"
    exit 1
fi

if [[ ! -f "$CHART_DIR/Chart.yaml" ]]; then
    echo -e "${RED}❌ Chart.yaml not found in: $CHART_DIR${NC}"
    exit 1
fi

echo -e "${CYAN}📋 Analyzing Chart Dependencies${NC}"
echo "=================================="

# Show chart information
echo "Chart Name: $(grep '^name:' "$CHART_DIR/Chart.yaml" | cut -d' ' -f2)"
echo "Chart Version: $(grep '^version:' "$CHART_DIR/Chart.yaml" | cut -d' ' -f2)"
echo ""

# Check for dependencies
if grep -q "dependencies:" "$CHART_DIR/Chart.yaml"; then
    echo -e "${YELLOW}📦 Dependencies found:${NC}"
    grep -A 50 "dependencies:" "$CHART_DIR/Chart.yaml" | grep -E "name:|version:|repository:" | head -20
    echo ""
    
    echo -e "${CYAN}🔧 Dependency Resolution Steps${NC}"
    echo "================================="
    
    # Step 1: Add public repositories
    echo -e "${BLUE}Step 1: Adding public Helm repositories...${NC}"
    if command -v helm &> /dev/null; then
        echo "Adding Bitnami repository..."
        helm repo add bitnami https://charts.bitnami.com/bitnami 2>/dev/null || true
        helm repo add stable https://charts.helm.sh/stable 2>/dev/null || true
        helm repo update
        echo -e "${GREEN}✅ Public repositories added${NC}"
    else
        echo -e "${YELLOW}⚠️  Helm not found locally, using Docker...${NC}"
        docker run --rm alpine/helm:latest repo add bitnami https://charts.bitnami.com/bitnami
    fi
    echo ""
    
    # Step 2: Check for private repositories
    echo -e "${BLUE}Step 2: Checking for private repositories...${NC}"
    PRIVATE_REPOS=$(grep -A 50 "dependencies:" "$CHART_DIR/Chart.yaml" | grep "repository:" | grep -E "(ecr\.|amazonaws\.com|private)" || true)
    
    if [[ -n "$PRIVATE_REPOS" ]]; then
        echo -e "${YELLOW}⚠️  Private repositories detected:${NC}"
        echo "$PRIVATE_REPOS"
        echo ""
        echo -e "${CYAN}🔐 AWS ECR Authentication Required${NC}"
        echo "To resolve private ECR dependencies, you need:"
        echo "1. AWS CLI configured with proper credentials"
        echo "2. ECR login token for the registry"
        echo ""
        echo "Commands to run:"
        echo -e "${YELLOW}# Login to AWS ECR${NC}"
        echo "aws ecr get-login-password --region us-gov-west-1 | helm registry login --username AWS --password-stdin 231388672283.dkr.ecr.us-gov-west-1.amazonaws.com"
        echo ""
        echo -e "${YELLOW}# Or using Docker:${NC}"
        echo 'aws ecr get-login-password --region us-gov-west-1 | docker login --username AWS --password-stdin 231388672283.dkr.ecr.us-gov-west-1.amazonaws.com'
        echo ""
        
        # Check if AWS CLI is available
        if command -v aws &> /dev/null; then
            echo -e "${GREEN}✅ AWS CLI found - attempting ECR login...${NC}"
            ECR_REGISTRY="231388672283.dkr.ecr.us-gov-west-1.amazonaws.com"
            
            # Try to get ECR login token
            if aws sts get-caller-identity &> /dev/null; then
                echo "AWS credentials are configured"
                echo "Attempting ECR registry login..."
                
                # Try ECR login
                if aws ecr get-login-password --region us-gov-west-1 | helm registry login --username AWS --password-stdin "$ECR_REGISTRY" 2>/dev/null; then
                    echo -e "${GREEN}✅ ECR login successful${NC}"
                    ECR_AUTHENTICATED=true
                else
                    echo -e "${YELLOW}⚠️  ECR login failed - check permissions${NC}"
                    ECR_AUTHENTICATED=false
                fi
            else
                echo -e "${YELLOW}⚠️  AWS credentials not configured${NC}"
                ECR_AUTHENTICATED=false
            fi
        else
            echo -e "${YELLOW}⚠️  AWS CLI not found${NC}"
            ECR_AUTHENTICATED=false
        fi
    else
        echo -e "${GREEN}✅ No private repositories detected${NC}"
        ECR_AUTHENTICATED=true
    fi
    echo ""
    
    # Step 3: Attempt dependency resolution
    echo -e "${BLUE}Step 3: Resolving dependencies...${NC}"
    cd "$CHART_DIR"
    
    if command -v helm &> /dev/null; then
        echo "Using local Helm for dependency resolution..."
        if helm dependency update 2>&1 | tee "$OUTPUT_DIR/dependency-resolution.log"; then
            echo -e "${GREEN}✅ All dependencies resolved successfully${NC}"
            DEPS_RESOLVED=true
        else
            echo -e "${YELLOW}⚠️  Some dependencies failed to resolve${NC}"
            echo "Check the log for details: $OUTPUT_DIR/dependency-resolution.log"
            DEPS_RESOLVED=false
        fi
    else
        echo "Using Docker Helm for dependency resolution..."
        if docker run --rm -v "$(pwd):/apps" -w /apps alpine/helm:latest dependency update 2>&1 | tee "$OUTPUT_DIR/dependency-resolution.log"; then
            echo -e "${GREEN}✅ All dependencies resolved successfully${NC}"
            DEPS_RESOLVED=true
        else
            echo -e "${YELLOW}⚠️  Some dependencies failed to resolve${NC}"
            DEPS_RESOLVED=false
        fi
    fi
    
    cd - > /dev/null
    
    # Step 4: Check what was downloaded
    echo ""
    echo -e "${BLUE}Step 4: Checking resolved dependencies...${NC}"
    if [[ -d "$CHART_DIR/charts" ]]; then
        echo -e "${GREEN}✅ Dependencies directory found:${NC}"
        ls -la "$CHART_DIR/charts/"
        echo ""
        echo "Dependency chart files:"
        find "$CHART_DIR/charts" -name "*.tgz" -o -name "Chart.yaml" | head -10
    else
        echo -e "${YELLOW}⚠️  No charts directory found${NC}"
    fi
    
    # Step 5: Test template rendering
    echo ""
    echo -e "${BLUE}Step 5: Testing template rendering...${NC}"
    cd "$CHART_DIR"
    
    TEST_OUTPUT="$OUTPUT_DIR/test-template-render.yaml"
    if command -v helm &> /dev/null; then
        if helm template test-render . > "$TEST_OUTPUT" 2>&1; then
            RESOURCE_COUNT=$(grep -c "^kind:" "$TEST_OUTPUT" 2>/dev/null || echo "0")
            echo -e "${GREEN}✅ Template rendering successful${NC}"
            echo "Generated Kubernetes resources: $RESOURCE_COUNT"
            echo "Output saved to: $TEST_OUTPUT"
            
            # Show sample of rendered resources
            echo ""
            echo "Sample rendered resources:"
            grep "^kind:" "$TEST_OUTPUT" | sort | uniq -c | head -10
        else
            echo -e "${YELLOW}⚠️  Template rendering failed${NC}"
            echo "Error details saved to: $TEST_OUTPUT"
        fi
    else
        echo "Testing with Docker Helm..."
        if docker run --rm -v "$(pwd):/apps" -w /apps alpine/helm:latest template test-render . > "$TEST_OUTPUT" 2>&1; then
            RESOURCE_COUNT=$(grep -c "^kind:" "$TEST_OUTPUT" 2>/dev/null || echo "0")
            echo -e "${GREEN}✅ Template rendering successful${NC}"
            echo "Generated Kubernetes resources: $RESOURCE_COUNT"
        else
            echo -e "${YELLOW}⚠️  Template rendering failed${NC}"
        fi
    fi
    
    cd - > /dev/null
    
else
    echo -e "${GREEN}✅ No dependencies found in Chart.yaml${NC}"
    echo "This chart can be rendered without dependency resolution"
    DEPS_RESOLVED=true
fi

# Summary
echo ""
echo -e "${CYAN}📊 Dependency Resolution Summary${NC}"
echo "=================================="
echo "Chart Directory: $CHART_DIR"
echo "Output Directory: $OUTPUT_DIR"
echo "Timestamp: $(date)"
echo ""

if [[ "$DEPS_RESOLVED" == "true" ]]; then
    echo -e "${GREEN}✅ Dependency resolution completed successfully${NC}"
    echo "You can now run security scans on the rendered templates"
    echo ""
    echo "Next steps:"
    echo "1. Run Checkov scan: npm run checkov:scan"
    echo "2. Run full security scan: ./run-target-security-scan.sh"
else
    echo -e "${YELLOW}⚠️  Dependency resolution partially completed${NC}"
    echo "Some dependencies may require additional authentication"
    echo ""
    echo "Manual steps needed:"
    echo "1. Configure AWS credentials for ECR access"
    echo "2. Run: aws ecr get-login-password --region us-gov-west-1 | helm registry login --username AWS --password-stdin 231388672283.dkr.ecr.us-gov-west-1.amazonaws.com"
    echo "3. Re-run: helm dependency update in $CHART_DIR"
fi

echo ""
echo -e "${BLUE}════════════════════════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}🎯 Helm Dependency Resolution Complete!${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════════════════════════════${NC}"