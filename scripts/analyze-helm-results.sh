#!/bin/bash

# Helm Build Analysis Script
# Analyzes Helm chart structure and provides detailed reporting

CHART_DIR="./chart"
OUTPUT_DIR="./helm-packages"
BUILD_LOG="$OUTPUT_DIR/helm-build.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo "============================================"
echo -e "${BLUE}Helm Chart Analysis${NC}"
echo "============================================"
echo

# Check if build log exists
if [ ! -f "$BUILD_LOG" ]; then
    echo -e "${YELLOW}⚠️  No build log found at $BUILD_LOG${NC}"
    echo "Run 'npm run helm:build' first to generate build results."
    echo
fi

echo -e "${BLUE}📊 Chart Structure Analysis:${NC}"
echo "============================"

if [ ! -d "$CHART_DIR" ]; then
    echo -e "${RED}❌ Chart directory not found: $CHART_DIR${NC}"
    exit 1
fi

# Analyze Chart.yaml
if [ -f "$CHART_DIR/Chart.yaml" ]; then
    echo -e "${GREEN}✅ Chart.yaml found${NC}"
    
    # Extract key information
    NAME=$(grep "^name:" "$CHART_DIR/Chart.yaml" | awk '{print $2}')
    VERSION=$(grep "^version:" "$CHART_DIR/Chart.yaml" | awk '{print $2}')
    APP_VERSION=$(grep "^appVersion:" "$CHART_DIR/Chart.yaml" | awk '{print $2}')
    DESCRIPTION=$(grep "^description:" "$CHART_DIR/Chart.yaml" | cut -d: -f2- | sed 's/^ *//')
    
    echo "  Chart Name: $NAME"
    echo "  Version: $VERSION"
    echo "  App Version: $APP_VERSION"
    echo "  Description:$DESCRIPTION"
    
    # Check for dependencies
    if grep -q "^dependencies:" "$CHART_DIR/Chart.yaml"; then
        echo -e "${BLUE}  Dependencies found:${NC}"
        grep -A 10 "^dependencies:" "$CHART_DIR/Chart.yaml" | grep -E "^\s*- name:|^\s*version:|^\s*repository:" | sed 's/^/    /'
    else
        echo "  Dependencies: None"
    fi
else
    echo -e "${RED}❌ Chart.yaml not found${NC}"
fi

echo

# Analyze templates
echo -e "${BLUE}📁 Template Analysis:${NC}"
echo "===================="

if [ -d "$CHART_DIR/templates" ]; then
    TEMPLATE_COUNT=$(find "$CHART_DIR/templates" -name "*.yaml" -o -name "*.yml" | wc -l)
    echo -e "${GREEN}✅ Templates directory found${NC}"
    echo "  Template files: $TEMPLATE_COUNT"
    
    echo "  Template breakdown:"
    find "$CHART_DIR/templates" -name "*.yaml" -o -name "*.yml" | while read template; do
        BASENAME=$(basename "$template")
        # Try to determine resource kind
        KIND=$(grep "^kind:" "$template" 2>/dev/null | head -1 | awk '{print $2}' || echo "Unknown")
        echo "    - $BASENAME ($KIND)"
    done
else
    echo -e "${RED}❌ Templates directory not found${NC}"
fi

echo

# Analyze values.yaml
echo -e "${BLUE}⚙️  Values Analysis:${NC}"
echo "=================="

if [ -f "$CHART_DIR/values.yaml" ]; then
    echo -e "${GREEN}✅ values.yaml found${NC}"
    
    FILE_SIZE=$(wc -l < "$CHART_DIR/values.yaml")
    echo "  Lines of configuration: $FILE_SIZE"
    
    # Check for common configurations
    if grep -q "image:" "$CHART_DIR/values.yaml"; then
        echo -e "${GREEN}  ✅ Container image configuration${NC}"
    fi
    
    if grep -q "service:" "$CHART_DIR/values.yaml"; then
        echo -e "${GREEN}  ✅ Service configuration${NC}"
    fi
    
    if grep -q "ingress:" "$CHART_DIR/values.yaml"; then
        echo -e "${GREEN}  ✅ Ingress configuration${NC}"
    fi
    
    if grep -q "resources:" "$CHART_DIR/values.yaml"; then
        echo -e "${GREEN}  ✅ Resource limits configuration${NC}"
    fi
    
    if grep -q "autoscaling:" "$CHART_DIR/values.yaml"; then
        echo -e "${GREEN}  ✅ Autoscaling configuration${NC}"
    fi
else
    echo -e "${YELLOW}⚠️  values.yaml not found${NC}"
fi

echo

# Build Status Analysis
echo -e "${BLUE}🔨 Build Status Analysis:${NC}"
echo "========================"

if [ -f "$BUILD_LOG" ]; then
    echo "Build log analysis:"
    
    # Check linting status
    if grep -q "Chart linting: PASSED" "$BUILD_LOG"; then
        echo -e "${GREEN}  ✅ Chart linting: PASSED${NC}"
    elif grep -q "Chart linting: FAILED" "$BUILD_LOG"; then
        echo -e "${RED}  ❌ Chart linting: FAILED${NC}"
        echo "    Common issues:"
        if grep -q "basic credential not found" "$BUILD_LOG"; then
            echo -e "${YELLOW}    - Missing registry credentials for dependencies${NC}"
        fi
        if grep -q "missing in charts/ directory" "$BUILD_LOG"; then
            echo -e "${YELLOW}    - Missing dependency charts${NC}"
        fi
    fi
    
    # Check template validation
    if grep -q "Template Validation: PASSED" "$BUILD_LOG"; then
        echo -e "${GREEN}  ✅ Template validation: PASSED${NC}"
    elif grep -q "Template Validation: FAILED" "$BUILD_LOG"; then
        echo -e "${RED}  ❌ Template validation: FAILED${NC}"
    fi
    
    # Check packaging
    if grep -q "Package Creation: PASSED" "$BUILD_LOG"; then
        echo -e "${GREEN}  ✅ Package creation: PASSED${NC}"
        
        # Find package file
        PACKAGE_FILE=$(find "$OUTPUT_DIR" -name "*.tgz" | head -1)
        if [ -f "$PACKAGE_FILE" ]; then
            PACKAGE_SIZE=$(ls -lh "$PACKAGE_FILE" | awk '{print $5}')
            echo "    Package: $(basename "$PACKAGE_FILE") ($PACKAGE_SIZE)"
        fi
    elif grep -q "Package Creation: FAILED" "$BUILD_LOG"; then
        echo -e "${RED}  ❌ Package creation: FAILED${NC}"
    fi
    
    # Security analysis
    if grep -q "Security Scan: PASSED" "$BUILD_LOG"; then
        echo -e "${GREEN}  ✅ Security scan: PASSED${NC}"
    elif grep -q "Security Scan: WARNING" "$BUILD_LOG"; then
        echo -e "${YELLOW}  ⚠️  Security scan: WARNING${NC}"
        echo "    Review security recommendations in build log"
    fi
else
    echo -e "${YELLOW}⚠️  No build log available${NC}"
fi

echo

# Recommendations
echo -e "${BLUE}💡 Recommendations:${NC}"
echo "=================="

ISSUES_FOUND=0

# Check for common issues and provide recommendations
if [ -f "$BUILD_LOG" ] && grep -q "basic credential not found" "$BUILD_LOG"; then
    echo -e "${YELLOW}📋 Dependency Authentication:${NC}"
    echo "   - Configure registry authentication for private dependencies"
    echo "   - Consider using 'helm registry login' or Docker credential helpers"
    echo "   - For CI/CD, use service account credentials"
    echo
    ((ISSUES_FOUND++))
fi

if [ -f "$BUILD_LOG" ] && grep -q "missing in charts/ directory" "$BUILD_LOG"; then
    echo -e "${YELLOW}📦 Missing Dependencies:${NC}"
    echo "   - Run 'helm dependency build' to download dependencies"
    echo "   - Ensure all required repositories are accessible"
    echo "   - Consider creating a standalone version without external dependencies"
    echo
    ((ISSUES_FOUND++))
fi

if [ -f "$BUILD_LOG" ] && grep -q "No resource limits defined" "$BUILD_LOG"; then
    echo -e "${YELLOW}🛡️  Security Improvements:${NC}"
    echo "   - Add resource limits to deployment templates"
    echo "   - Define memory and CPU constraints"
    echo "   - Consider adding security contexts"
    echo
    ((ISSUES_FOUND++))
fi

if [ $ISSUES_FOUND -eq 0 ]; then
    echo -e "${GREEN}🎉 No major issues found!${NC}"
    echo "   - Chart structure looks good"
    echo "   - Consider running regular builds to catch issues early"
    echo "   - Keep dependencies updated"
fi

echo

# Available commands
echo -e "${BLUE}🔧 Available Commands:${NC}"
echo "===================="
echo "Build chart:          npm run helm:build"
echo "Lint only:           npm run helm:lint"
echo "Package only:        npm run helm:package"
echo "Template rendering:   npm run helm:template"
echo "Analyze results:      npm run helm:analyze"

echo

# File locations
echo -e "${BLUE}📁 File Locations:${NC}"
echo "=================="
echo "Chart source:        $CHART_DIR"
echo "Build outputs:       $OUTPUT_DIR"
if [ -f "$BUILD_LOG" ]; then
    echo "Build log:           $BUILD_LOG"
fi
if [ -f "$OUTPUT_DIR/rendered-templates.yaml" ]; then
    echo "Rendered templates:  $OUTPUT_DIR/rendered-templates.yaml"
fi

echo
echo "============================================"
echo "Analysis complete."
echo "============================================"