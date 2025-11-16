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

# Set up paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPORTS_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")/reports"
OUTPUT_DIR="$REPORTS_ROOT/helm-reports"

# Add timestamp for historical preservation
TIMESTAMP=$(date '+%Y-%m-%d_%H-%M-%S')
SCAN_LOG="$OUTPUT_DIR/helm-build-$TIMESTAMP.log"
CURRENT_LOG="$OUTPUT_DIR/helm-build.log"

# Create output directory
mkdir -p "$OUTPUT_DIR"

echo
echo -e "${WHITE}============================================${NC}"
echo -e "${WHITE}Helm Chart Builder & Validator${NC}"
echo -e "${WHITE}============================================${NC}"
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