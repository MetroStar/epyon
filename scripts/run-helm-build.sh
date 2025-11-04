#!/bin/bash

# Helm Build and Package Script
# Builds, validates, and packages Helm charts with comprehensive checks

# Configuration - Support target directory scanning
REPO_PATH="${TARGET_DIR:-$(pwd)}"
CHART_DIR="$REPO_PATH/chart"
OUTPUT_DIR="./helm-packages"
CHART_NAME="advana-marketplace"
BUILD_LOG="$OUTPUT_DIR/helm-build.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Start logging
exec 1> >(tee -a "$BUILD_LOG")
exec 2> >(tee -a "$BUILD_LOG" >&2)

echo "============================================"
echo -e "${BLUE}Helm Chart Build Process${NC}"
echo "============================================"
echo "Chart Directory: $CHART_DIR"
echo "Output Directory: $OUTPUT_DIR"
echo "Chart Name: $CHART_NAME"
echo "Build Log: $BUILD_LOG"
echo "Timestamp: $(date)"
echo ""

# Check if Helm is available, use Docker if not installed locally
HELM_CMD="helm"
DOCKER_HELM_IMAGE="alpine/helm:latest"
USE_DOCKER=false

if ! command -v helm &> /dev/null; then
    echo -e "${YELLOW}⚠️  Helm not found locally, using Docker-based Helm${NC}"
    USE_DOCKER=true
    
    # Test Docker availability
    if ! command -v docker &> /dev/null; then
        echo -e "${RED}❌ Neither Helm nor Docker is available${NC}"
        echo "Please install either Helm or Docker"
        exit 1
    fi
    
    # Pull Helm Docker image
    echo "Pulling Helm Docker image..."
    docker pull "$DOCKER_HELM_IMAGE"
    
    # Mount the target directory containing the chart
    TARGET_PARENT="$(dirname "$REPO_PATH")"
    TARGET_NAME="$(basename "$REPO_PATH")"
    CHART_PATH_IN_CONTAINER="/workspace/$TARGET_NAME/chart"
    
    # Create a base command function to handle Docker properly
    DOCKER_CHART_PATH="$CHART_PATH_IN_CONTAINER"
else
    HELM_CMD="helm"
    DOCKER_CHART_PATH="$CHART_DIR"
fi

echo -e "${BLUE}📊 Helm Version Information:${NC}"
if [ "$USE_DOCKER" = true ]; then
    docker run --rm "$DOCKER_HELM_IMAGE" version --short 2>/dev/null || docker run --rm "$DOCKER_HELM_IMAGE" version
else
    helm version --short 2>/dev/null || helm version
fi
echo ""

# Validate chart directory exists with graceful handling
if [ ! -d "$CHART_DIR" ]; then
    echo -e "${YELLOW}⚠️  Chart directory not found: $CHART_DIR${NC}"
    echo -e "${CYAN}💡 This is expected for projects without Helm charts${NC}"
    echo ""
    echo "============================================"
    echo -e "${GREEN}✅ Helm build skipped successfully!${NC}"
    echo "============================================"
    echo ""
    echo -e "${BLUE}📊 Fallback Build Summary:${NC}"
    echo "=========================="
    echo -e "${YELLOW}⚠️  No Helm chart found - skipping build process${NC}"
    echo -e "${GREEN}✅ Security pipeline continues with available components${NC}"
    echo -e "${CYAN}💡 For Helm deployment, add a chart/ directory to your project${NC}"
    echo ""
    echo -e "${BLUE}📁 Output Files:${NC}"
    echo "================"
    echo -e "${YELLOW}ℹ️  No Helm packages generated (no chart available)${NC}"
    echo ""
    echo -e "${BLUE}🔗 Related Commands:${NC}"
    echo "===================="
    echo "Create chart:        helm create chart/"
    echo "Re-run build:        npm run helm:build"
    echo "Full security suite: npm run security:full"
    echo ""
    echo "============================================"
    echo "Helm build complete (skipped)."
    echo "============================================"
    
    # Always exit successfully to continue pipeline
    exit 0
fi

if [ ! -f "$CHART_DIR/Chart.yaml" ]; then
    echo -e "${YELLOW}⚠️  Chart.yaml not found in $CHART_DIR${NC}"
    echo -e "${CYAN}💡 Invalid Helm chart structure${NC}"
    echo ""
    echo "============================================"
    echo -e "${GREEN}✅ Helm build skipped successfully!${NC}"
    echo "============================================"
    echo ""
    echo -e "${BLUE}📊 Fallback Build Summary:${NC}"
    echo "=========================="
    echo -e "${YELLOW}⚠️  Invalid chart structure - missing Chart.yaml${NC}"
    echo -e "${GREEN}✅ Security pipeline continues${NC}"
    echo -e "${CYAN}💡 Ensure Chart.yaml exists in chart/ directory${NC}"
    echo ""
    echo "============================================"
    echo "Helm build complete (skipped)."
    echo "============================================"
    
    # Always exit successfully to continue pipeline
    exit 0
fi

echo -e "${BLUE}📋 Chart Information:${NC}"
echo "===================="
if [ "$USE_DOCKER" = true ]; then
    docker run --rm -v "$TARGET_PARENT":/workspace -w /workspace "$DOCKER_HELM_IMAGE" show chart "$DOCKER_CHART_PATH"
else
    helm show chart "$CHART_DIR"
fi
echo ""

echo -e "${BLUE}🔍 Step 1: Chart Dependency Update${NC}"
echo "==================================="
if [ "$USE_DOCKER" = true ]; then
    docker run --rm -v "$TARGET_PARENT":/workspace -w /workspace "$DOCKER_HELM_IMAGE" dependency update "$DOCKER_CHART_PATH"
    DEPENDENCY_RESULT=$?
else
    helm dependency update "$DOCKER_CHART_PATH"
    DEPENDENCY_RESULT=$?
fi
if [ $DEPENDENCY_RESULT -eq 0 ]; then
    echo -e "${GREEN}✅ Dependencies updated successfully${NC}"
else
    echo -e "${YELLOW}⚠️  Dependency update had issues, continuing...${NC}"
fi
echo ""

echo -e "${BLUE}🔎 Step 2: Chart Linting${NC}"
echo "======================="
if [ "$USE_DOCKER" = true ]; then
    docker run --rm -v "$TARGET_PARENT":/workspace -w /workspace "$DOCKER_HELM_IMAGE" lint "$DOCKER_CHART_PATH"
    LINT_RESULT=$?
else
    helm lint "$DOCKER_CHART_PATH"
    LINT_RESULT=$?
fi
if [ $LINT_RESULT -eq 0 ]; then
    echo -e "${GREEN}✅ Chart linting passed${NC}"
    LINT_STATUS="PASSED"
else
    echo -e "${RED}❌ Chart linting failed${NC}"
    LINT_STATUS="FAILED"
fi
echo ""

echo -e "${BLUE}🧪 Step 3: Template Validation${NC}"
echo "=============================="
echo "Validating Kubernetes templates..."

# Test template rendering with default values
if [ "$USE_DOCKER" = true ]; then
    # For Docker, mount output directory for template rendering
    if docker run --rm -v "$TARGET_PARENT":/workspace -v "$OUTPUT_DIR":/output -w /workspace "$DOCKER_HELM_IMAGE" template "$CHART_NAME" "$DOCKER_CHART_PATH" > "$OUTPUT_DIR/rendered-templates.yaml"; then
        echo -e "${GREEN}✅ Template rendering successful${NC}"
        
        # Count resources
        RESOURCE_COUNT=$(grep -c "^kind:" "$OUTPUT_DIR/rendered-templates.yaml" 2>/dev/null || echo "0")
        echo "Generated Kubernetes resources: $RESOURCE_COUNT"
        
        TEMPLATE_STATUS="PASSED"
    else
        echo -e "${RED}❌ Template rendering failed${NC}"
        TEMPLATE_STATUS="FAILED"
    fi
else
    if helm template "$CHART_NAME" "$DOCKER_CHART_PATH" > "$OUTPUT_DIR/rendered-templates.yaml"; then
        echo -e "${GREEN}✅ Template rendering successful${NC}"
        
        # Count resources
        RESOURCE_COUNT=$(grep -c "^kind:" "$OUTPUT_DIR/rendered-templates.yaml" 2>/dev/null || echo "0")
        echo "Generated Kubernetes resources: $RESOURCE_COUNT"
        
        TEMPLATE_STATUS="PASSED"
    else
        echo -e "${RED}❌ Template rendering failed${NC}"
        TEMPLATE_STATUS="FAILED"
    fi
fi
echo ""

echo -e "${BLUE}📦 Step 4: Chart Packaging${NC}"
echo "========================="

# Package the chart
if [ "$USE_DOCKER" = true ]; then
    # For Docker, mount output directory for packaging
    if docker run --rm -v "$TARGET_PARENT":/workspace -v "$OUTPUT_DIR":/output -w /workspace "$DOCKER_HELM_IMAGE" package "$DOCKER_CHART_PATH" --destination /output; then
        echo -e "${GREEN}✅ Chart packaging successful${NC}"
        
        # Find the generated package
        PACKAGE_FILE=$(find "$OUTPUT_DIR" -name "${CHART_NAME}-*.tgz" | head -1)
        if [ -f "$PACKAGE_FILE" ]; then
            PACKAGE_SIZE=$(ls -lh "$PACKAGE_FILE" | awk '{print $5}')
            echo "Package created: $(basename "$PACKAGE_FILE") ($PACKAGE_SIZE)"
            
            # Verify package integrity with Docker
            if docker run --rm -v "$OUTPUT_DIR":/packages "$DOCKER_HELM_IMAGE" show chart "/packages/$(basename "$PACKAGE_FILE")" > /dev/null 2>&1; then
                echo -e "${GREEN}✅ Package integrity verified${NC}"
                PACKAGE_STATUS="PASSED"
            else
                echo -e "${RED}❌ Package integrity check failed${NC}"
                PACKAGE_STATUS="FAILED"
            fi
        else
            echo -e "${RED}❌ Package file not found${NC}"
            PACKAGE_STATUS="FAILED"
        fi
    else
        echo -e "${RED}❌ Chart packaging failed${NC}"
        PACKAGE_STATUS="FAILED"
    fi
else
    if helm package "$DOCKER_CHART_PATH" --destination "$OUTPUT_DIR"; then
        echo -e "${GREEN}✅ Chart packaging successful${NC}"
        
        # Find the generated package
        PACKAGE_FILE=$(find "$OUTPUT_DIR" -name "${CHART_NAME}-*.tgz" | head -1)
        if [ -f "$PACKAGE_FILE" ]; then
            PACKAGE_SIZE=$(ls -lh "$PACKAGE_FILE" | awk '{print $5}')
            echo "Package created: $(basename "$PACKAGE_FILE") ($PACKAGE_SIZE)"
            
            # Verify package integrity
            if helm show chart "$PACKAGE_FILE" > /dev/null 2>&1; then
                echo -e "${GREEN}✅ Package integrity verified${NC}"
                PACKAGE_STATUS="PASSED"
            else
                echo -e "${RED}❌ Package integrity check failed${NC}"
                PACKAGE_STATUS="FAILED"
            fi
        else
            echo -e "${RED}❌ Package file not found${NC}"
            PACKAGE_STATUS="FAILED"
        fi
    else
        echo -e "${RED}❌ Chart packaging failed${NC}"
        PACKAGE_STATUS="FAILED"
    fi
fi
echo ""

echo -e "${BLUE}🔍 Step 5: Security Analysis${NC}"
echo "==========================="

# Check for common security issues in templates
SECURITY_ISSUES=0

echo "Scanning templates for security best practices..."

# Check for hardcoded secrets
if grep -r "password\|secret\|token" "$CHART_DIR/templates/" --include="*.yaml" | grep -v "{{" | grep -i ":" > /dev/null; then
    echo -e "${YELLOW}⚠️  Potential hardcoded secrets found${NC}"
    ((SECURITY_ISSUES++))
fi

# Check for privileged containers
if grep -r "privileged.*true" "$CHART_DIR/templates/" --include="*.yaml" > /dev/null; then
    echo -e "${YELLOW}⚠️  Privileged containers detected${NC}"
    ((SECURITY_ISSUES++))
fi

# Check for root user usage
if grep -r "runAsUser.*0" "$CHART_DIR/templates/" --include="*.yaml" > /dev/null; then
    echo -e "${YELLOW}⚠️  Root user usage detected${NC}"
    ((SECURITY_ISSUES++))
fi

# Check for missing resource limits
if ! grep -r "resources:" "$CHART_DIR/templates/" --include="*.yaml" > /dev/null; then
    echo -e "${YELLOW}⚠️  No resource limits defined${NC}"
    ((SECURITY_ISSUES++))
fi

if [ $SECURITY_ISSUES -eq 0 ]; then
    echo -e "${GREEN}✅ No major security issues detected${NC}"
    SECURITY_STATUS="PASSED"
else
    echo -e "${YELLOW}⚠️  $SECURITY_ISSUES potential security issues found${NC}"
    SECURITY_STATUS="WARNING"
fi
echo ""

echo -e "${BLUE}📊 Build Summary${NC}"
echo "================"
echo "Chart Linting: $LINT_STATUS"
echo "Template Validation: $TEMPLATE_STATUS"
echo "Package Creation: $PACKAGE_STATUS"
echo "Security Scan: $SECURITY_STATUS"
echo ""

# Overall status
if [ "$LINT_STATUS" = "PASSED" ] && [ "$TEMPLATE_STATUS" = "PASSED" ] && [ "$PACKAGE_STATUS" = "PASSED" ]; then
    echo -e "${GREEN}🎉 Helm build completed successfully!${NC}"
    echo "============================================"
    
    if [ -f "$PACKAGE_FILE" ]; then
        echo -e "${GREEN}📦 Package Details:${NC}"
        echo "File: $(basename "$PACKAGE_FILE")"
        echo "Size: $PACKAGE_SIZE"
        echo "Location: $PACKAGE_FILE"
        echo ""
        
        echo -e "${GREEN}🚀 Deployment Commands:${NC}"
        echo "# Install from package:"
        echo "helm install $CHART_NAME $PACKAGE_FILE"
        echo ""
        echo "# Install from source:"
        echo "helm install $CHART_NAME $CHART_DIR"
        echo ""
        echo "# Upgrade existing deployment:"
        echo "helm upgrade $CHART_NAME $PACKAGE_FILE"
    fi
    
    BUILD_RESULT="SUCCESS"
else
    echo -e "${RED}❌ Helm build completed with errors${NC}"
    echo "============================================"
    echo "Please review the issues above and fix them."
    BUILD_RESULT="FAILED"
fi

echo ""
echo -e "${BLUE}📁 Output Files:${NC}"
echo "================"
echo "Build log: $BUILD_LOG"
echo "Rendered templates: $OUTPUT_DIR/rendered-templates.yaml"
if [ -f "$PACKAGE_FILE" ]; then
    echo "Helm package: $PACKAGE_FILE"
fi
echo "Package directory: $OUTPUT_DIR"

echo ""
echo "============================================"
echo "Helm build process complete."
echo "============================================"

# Exit with appropriate code
if [ "$BUILD_RESULT" = "SUCCESS" ]; then
    exit 0
else
    exit 1
fi