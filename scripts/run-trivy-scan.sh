#!/bin/bash

# Trivy Multi-Target Vulnerability Scanner
# Comprehensive container image, Kubernetes, and filesystem security scanning

OUTPUT_DIR="./trivy-reports"
TIMESTAMP=$(date)
SCAN_LOG="$OUTPUT_DIR/trivy-scan.log"
REPO_PATH="${TARGET_DIR:-$(pwd)}"

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
echo -e "${WHITE}Trivy Multi-Target Security Scanner${NC}"
echo -e "${WHITE}============================================${NC}"
echo "Repository: $REPO_PATH"
echo "Output Directory: $OUTPUT_DIR"
echo "Timestamp: $TIMESTAMP"
echo

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Initialize scan log
echo "Trivy Security Scan Log" > "$SCAN_LOG"
echo "Timestamp: $TIMESTAMP" >> "$SCAN_LOG"
echo "Output Directory: $OUTPUT_DIR" >> "$SCAN_LOG"
echo "========================================" >> "$SCAN_LOG"

echo -e "Output Directory: ${BLUE}$OUTPUT_DIR${NC}"
echo -e "Scan Log: ${BLUE}$SCAN_LOG${NC}"
echo -e "Timestamp: ${CYAN}$TIMESTAMP${NC}"
echo

# Function to check Docker availability
check_docker() {
    if ! command -v docker &> /dev/null; then
        echo -e "${RED}❌ Docker not found${NC}"
        echo "Please install Docker to use Trivy security scanning."
        exit 1
    fi
    
    if ! docker info &> /dev/null; then
        echo -e "${RED}❌ Docker daemon not running${NC}"
        echo "Please start Docker daemon before running Trivy scan."
        exit 1
    fi
}

echo -e "${BLUE}🐳 Docker and Trivy Information:${NC}"
echo "Docker version:"
docker --version
echo "Pulling Trivy image..."
docker pull aquasec/trivy:latest
echo

# Function to scan Docker image
scan_docker_image() {
    local image_name="$1"
    local scan_type="$2"
    local output_file="$3"
    
    echo -e "${CYAN}🔍 Scanning Docker image: ${YELLOW}$image_name${NC}"
    echo "Scan type: $scan_type" >> "$SCAN_LOG"
    echo "Image: $image_name" >> "$SCAN_LOG"
    
    # Run Trivy scan on Docker image
    docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
        -v "$(pwd)/$OUTPUT_DIR:/output" \
        aquasec/trivy:latest image \
        --format json \
        --output "/output/$output_file" \
        --severity HIGH,CRITICAL \
        "$image_name" 2>&1 | tee -a "$SCAN_LOG"
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✅ Image scan completed${NC}"
        echo "Image scan completed successfully" >> "$SCAN_LOG"
    else
        echo -e "${YELLOW}⚠️  Image scan completed with warnings${NC}"
        echo "Image scan completed with warnings" >> "$SCAN_LOG"
    fi
}

# Function to scan built container images
scan_container_images() {
    echo -e "${PURPLE}🛡️  Step 2: Container Image Security Scan${NC}"
    echo "=========================================="
    
    # Check for Docker files (various naming patterns)
    DOCKER_FILES=($(find . -maxdepth 1 -name "Dockerfile*" -type f 2>/dev/null))
    
    if [ ${#DOCKER_FILES[@]} -gt 0 ]; then
        echo -e "📦 Found ${#DOCKER_FILES[@]} Docker file(s): ${DOCKER_FILES[*]}"
        echo "Found Docker files: ${DOCKER_FILES[*]}" >> "$SCAN_LOG"
        
        # Scan each Docker file found
        for dockerfile in "${DOCKER_FILES[@]}"; do
            echo -e "🔍 Processing Docker file: ${dockerfile}"
            
            # Extract a clean name for the image
            DOCKERFILE_NAME=$(basename "$dockerfile")
            CLEAN_NAME=$(echo "$DOCKERFILE_NAME" | tr '[:upper:]' '[:lower:]' | tr '.' '-')
            IMAGE_NAME="advana-marketplace:${CLEAN_NAME}-trivy-scan"
            
            echo -e "📦 Building image from ${dockerfile} for security scanning..."
            docker build -f "$dockerfile" -t "$IMAGE_NAME" . >> "$SCAN_LOG" 2>&1
            
            if [ $? -eq 0 ]; then
                echo -e "${GREEN}✅ Image built successfully from ${dockerfile}${NC}"
                echo -e "🔍 Scanning built image for security vulnerabilities..."
                
                # Scan the built image for vulnerabilities
                scan_docker_image "$IMAGE_NAME" "container-${CLEAN_NAME}" "trivy-${CLEAN_NAME}-results.json"
                
                # Clean up the built image to save space
                docker rmi "$IMAGE_NAME" >> "$SCAN_LOG" 2>&1 || true
                
            else
                echo -e "${RED}❌ Failed to build image from ${dockerfile}${NC}"
                echo "Failed to build image from ${dockerfile}" >> "$SCAN_LOG"
            fi
        done
        echo -e "${GREEN}✅ Built container image security scanning completed${NC}"
        
    else
        echo -e "${YELLOW}⚠️  No Docker files found (searched for: Dockerfile, Dockerfile.*, etc.)${NC}"
        echo -e "${BLUE}📋 Available files in repository root:${NC}"
        ls -la | grep -E "(Dockerfile|docker)" | head -5 || echo "  No Docker-related files found"
    fi
    
    # Always scan common base images regardless of whether we found Docker files
    scan_base_images
}

# Function to scan common base images for security vulnerabilities
scan_base_images() {
    echo -e "🔍 Scanning common base images for security vulnerabilities..."
    
    # Array of common base images to scan
    local base_images=("nginx:alpine" "node:18-alpine" "python:3.11-alpine" "ubuntu:22.04" "alpine:latest")
    
    for image in "${base_images[@]}"; do
        echo -e "📋 Scanning base image: ${CYAN}$image${NC} for security vulnerabilities"
        
        # Check if image exists locally, if not pull it
        if ! docker image inspect "$image" >/dev/null 2>&1; then
            echo -e "📥 Pulling image $image..."
            docker pull "$image" >> "$SCAN_LOG" 2>&1
        fi
        
        # Scan the base image for security vulnerabilities
        local safe_image_name=$(echo "$image" | tr ':/' '-')
        scan_docker_image "$image" "base-image" "trivy-base-$safe_image_name-results.json"
        
        echo -e "${GREEN}✅ Base image $image security scan completed${NC}"
        echo "Base image $image security scan completed" >> "$SCAN_LOG"
    done
}

# Function to scan specific registry images
scan_registry_images() {
    echo -e "${GREEN}🛡️  Step 3: Registry Image Security Scan${NC}"
    echo "======================================="
    
    # Array of specific images to scan (can be customized)
    local registry_images=()
    
    # Add common production images if they exist
    if docker image inspect "node:lts-alpine" >/dev/null 2>&1; then
        registry_images+=("node:lts-alpine")
    fi
    
    # Add any custom registry images based on your needs
    # registry_images+=("your-registry/your-image:tag")
    
    if [ ${#registry_images[@]} -eq 0 ]; then
        echo -e "${YELLOW}⚠️  No registry images found to scan${NC}"
        return 0
    fi
    
    for image in "${registry_images[@]}"; do
        echo -e "🌐 Scanning registry image: ${GREEN}$image${NC}"
        
        local safe_image_name=$(echo "$image" | tr ':/' '-')
        scan_docker_image "$image" "registry-image" "trivy-registry-$safe_image_name-results.json"
        
        echo -e "${GREEN}✅ Registry image $image security scan completed${NC}"
    done
}

# Function to scan filesystem
scan_filesystem() {
    local target_dir="$1"
    local output_file="$2"
    
    echo -e "${CYAN}🔍 Scanning filesystem: ${YELLOW}$target_dir${NC}"
    echo "Filesystem scan target: $target_dir" >> "$SCAN_LOG"
    
    # Run Trivy filesystem scan
    docker run --rm -v "$(pwd):/workspace" \
        -v "$(pwd)/$OUTPUT_DIR:/output" \
        aquasec/trivy:latest fs \
        --format json \
        --output "/output/$output_file" \
        --severity HIGH,CRITICAL \
        "/workspace/$target_dir" 2>&1 | tee -a "$SCAN_LOG"
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✅ Filesystem scan completed${NC}"
        echo "Filesystem scan completed successfully" >> "$SCAN_LOG"
    else
        echo -e "${YELLOW}⚠️  Filesystem scan completed with warnings${NC}"
        echo "Filesystem scan completed with warnings" >> "$SCAN_LOG"
    fi
}

# Function to scan Kubernetes manifests
scan_kubernetes() {
    local target_dir="$1"
    local output_file="$2"
    
    echo -e "${CYAN}🔍 Scanning Kubernetes manifests: ${YELLOW}$target_dir${NC}"
    echo "Kubernetes scan target: $target_dir" >> "$SCAN_LOG"
    
    # Run Trivy Kubernetes configuration scan
    docker run --rm -v "$(pwd):/workspace" \
        -v "$(pwd)/$OUTPUT_DIR:/output" \
        aquasec/trivy:latest config \
        --format json \
        --output "/output/$output_file" \
        --severity HIGH,CRITICAL \
        "/workspace/$target_dir" 2>&1 | tee -a "$SCAN_LOG"
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✅ Kubernetes scan completed${NC}"
        echo "Kubernetes scan completed successfully" >> "$SCAN_LOG"
    else
        echo -e "${YELLOW}⚠️  Kubernetes scan completed with warnings${NC}"
        echo "Kubernetes scan completed with warnings" >> "$SCAN_LOG"
    fi
}

# Check Docker availability
check_docker

# Main execution logic based on command line argument
case "${1:-all}" in
    "filesystem")
        echo -e "${CYAN}🛡️  Step 1: Filesystem Security Scan${NC}"
        echo "====================================="
        scan_filesystem "." "trivy-filesystem-results.json"
        if [ -d "frontend" ]; then
            scan_filesystem "frontend" "trivy-frontend-results.json"
        fi
        ;;
    "images"|"containers")
        scan_container_images
        ;;
    "base")
        scan_base_images
        ;;
    "registry")
        scan_registry_images
        ;;
    "kubernetes"|"k8s")
        echo -e "${BLUE}🛡️  Step 1: Kubernetes Security Scan${NC}"
        echo "====================================="
        if [ -d "chart" ]; then
            scan_kubernetes "chart" "trivy-kubernetes-results.json"
        else
            echo -e "${YELLOW}⚠️  No Kubernetes manifests found${NC}"
        fi
        ;;
    "all"|*)
        # Step 1: Filesystem scanning
        echo -e "${CYAN}🛡️  Step 1: Filesystem Security Scan${NC}"
        echo "====================================="
        echo -e "📂 Scanning root directory for security issues..."
        scan_filesystem "." "trivy-root-results.json"
        
        # Scan frontend if exists
        if [ -d "frontend" ]; then
            echo -e "📁 Scanning frontend directory for security issues..."
            scan_filesystem "frontend" "trivy-frontend-results.json"
        fi
        
        echo
        
        # Step 2: Container image scanning
        scan_container_images
        
        echo
        
        # Step 3: Registry image scanning  
        scan_registry_images
        
        echo
        
        # Step 4: Kubernetes scanning
        echo -e "${BLUE}🛡️  Step 4: Kubernetes Security Scan${NC}"
        echo "====================================="
        if [ -d "chart" ]; then
            scan_kubernetes "chart" "trivy-kubernetes-results.json"
        else
            echo -e "${YELLOW}⚠️  No Kubernetes manifests found${NC}"
        fi
        ;;
esac

echo

# Scan 3: Kubernetes configuration security
echo -e "${BLUE}🛡️  Step 3: Kubernetes Security Configuration Scan${NC}"
echo "=================================================="

# Scan Helm charts
if [ -d "chart" ]; then
    echo -e "🏗️  Scanning Helm chart templates..."
    
    # First try to render templates with Helm, then scan
    if command -v helm &> /dev/null; then
        echo -e "📋 Rendering Helm templates for scanning..."
        mkdir -p "$OUTPUT_DIR/rendered"
        helm template advana-marketplace ./chart > "$OUTPUT_DIR/rendered/all-manifests.yaml" 2>> "$SCAN_LOG"
        
        if [ -s "$OUTPUT_DIR/rendered/all-manifests.yaml" ]; then
            scan_kubernetes "$OUTPUT_DIR/rendered" "trivy-k8s-helm-results.json"
        else
            echo -e "${YELLOW}⚠️  Template rendering failed, scanning chart templates directly${NC}"
            scan_kubernetes "chart/templates" "trivy-k8s-chart-results.json"
        fi
    else
        echo -e "${YELLOW}⚠️  Helm not available, using Docker-based approach${NC}"
        
        # Use Docker-based Helm for template rendering
        docker run --rm -v "$(pwd):/workspace" alpine/helm:latest \
            template advana-marketplace /workspace/chart > "$OUTPUT_DIR/helm-rendered.yaml" 2>> "$SCAN_LOG"
        
        if [ -s "$OUTPUT_DIR/helm-rendered.yaml" ]; then
            # Scan the rendered templates
            docker run --rm -v "$(pwd)/$OUTPUT_DIR:/workspace" \
                -v "$(pwd)/$OUTPUT_DIR:/output" \
                aquasec/trivy:latest config \
                --format json \
                --output "/output/trivy-k8s-helm-results.json" \
                --severity HIGH,CRITICAL \
                "/workspace/helm-rendered.yaml" 2>&1 | tee -a "$SCAN_LOG"
        else
            scan_kubernetes "chart" "trivy-k8s-chart-results.json"
        fi
    fi
else
    echo -e "${YELLOW}⚠️  No Helm chart found${NC}"
    
    # Scan test Kubernetes manifests if they exist
    if [ -d "test-k8s" ]; then
        scan_kubernetes "test-k8s" "trivy-k8s-test-results.json"
    else
        echo -e "${YELLOW}⚠️  No Kubernetes manifests found to scan${NC}"
        echo "No Kubernetes manifests found" >> "$SCAN_LOG"
    fi
fi

echo

# Generate summary
echo -e "${BLUE}📊 Trivy Security Scan Summary${NC}"
echo "================================"

# Count results files
RESULTS_COUNT=$(find "$OUTPUT_DIR" -name "trivy-*-results.json" | wc -l | xargs)
echo -e "📄 Results files generated: ${CYAN}$RESULTS_COUNT${NC}"

# Parse JSON results for quick summary (if Python is available)
if command -v python3 &> /dev/null && [ "$RESULTS_COUNT" -gt 0 ]; then
    echo -e "🔍 Vulnerability Summary:"
    
    python3 << 'EOF'
import json
import glob
import os

try:
    output_dir = "./trivy-reports"
    result_files = glob.glob(f"{output_dir}/trivy-*-results.json")
    
    total_high = 0
    total_critical = 0
    total_medium = 0
    total_low = 0
    
    for file_path in result_files:
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            filename = os.path.basename(file_path)
            print(f"\n📋 {filename}:")
            
            # Handle different Trivy output formats
            if 'Results' in data and data['Results']:
                for result in data['Results']:
                    vulnerabilities = result.get('Vulnerabilities', [])
                    misconfigs = result.get('Misconfigurations', [])
                    
                    if vulnerabilities:
                        high_count = len([v for v in vulnerabilities if v.get('Severity') == 'HIGH'])
                        critical_count = len([v for v in vulnerabilities if v.get('Severity') == 'CRITICAL'])
                        medium_count = len([v for v in vulnerabilities if v.get('Severity') == 'MEDIUM'])
                        low_count = len([v for v in vulnerabilities if v.get('Severity') == 'LOW'])
                        
                        print(f"  🔴 Critical: {critical_count}")
                        print(f"  🟠 High: {high_count}")
                        print(f"  🟡 Medium: {medium_count}")
                        print(f"  🟢 Low: {low_count}")
                        
                        total_critical += critical_count
                        total_high += high_count
                        total_medium += medium_count
                        total_low += low_count
                    
                    if misconfigs:
                        config_count = len(misconfigs)
                        print(f"  ⚙️  Misconfigurations: {config_count}")
                    
                    if not vulnerabilities and not misconfigs:
                        print("  ✅ No high/critical issues found")
            else:
                print("  ✅ No vulnerabilities detected")
                
        except Exception as e:
            print(f"  ⚠️  Could not parse {filename}: {str(e)}")
    
    print(f"\n🎯 Total Security Issues:")
    print(f"  🔴 Critical: {total_critical}")
    print(f"  🟠 High: {total_high}")
    print(f"  🟡 Medium: {total_medium}")
    print(f"  🟢 Low: {total_low}")
    
    if total_critical > 0 or total_high > 0:
        print("\n🚨 Action Required: Critical or High severity vulnerabilities found")
    else:
        print("\n✅ Security Status: No critical or high severity issues detected")
        
except Exception as e:
    print(f"Error analyzing results: {e}")
EOF
else
    echo -e "${YELLOW}⚠️  Python not available for detailed analysis${NC}"
    echo "Check individual result files for detailed vulnerability information."
fi

echo
echo -e "${BLUE}📁 Output Files:${NC}"
echo "================"
find "$OUTPUT_DIR" -name "*.json" -exec echo "📄 {}" \;
echo "📝 Scan log: $SCAN_LOG"
echo "📂 Reports directory: $OUTPUT_DIR"

echo
echo -e "${BLUE}🔧 Available Commands:${NC}"
echo "===================="
echo "📊 Analyze results:        npm run trivy:analyze"
echo "🔍 Run new scan:           npm run trivy:scan"
echo "🏗️  Filesystem only:        ./run-trivy-scan.sh filesystem"
echo "📦 Images only:            ./run-trivy-scan.sh images"
echo "🖼️  Base images only:       ./run-trivy-scan.sh base"
echo "🌐 Registry images only:   ./run-trivy-scan.sh registry"
echo "☸️  Kubernetes only:       ./run-trivy-scan.sh kubernetes"
echo "🛡️  Full security suite:    npm run security:scan && npm run virus:scan && npm run trivy:scan"
echo "📋 View specific results:   cat $OUTPUT_DIR/trivy-*-results.json | jq ."

echo
echo -e "${BLUE}🔗 Additional Resources:${NC}"
echo "======================="
echo "• Trivy Documentation: https://trivy.dev/"
echo "• Container Security Best Practices: https://kubernetes.io/docs/concepts/security/"
echo "• NIST Container Security Guide: https://csrc.nist.gov/publications/detail/sp/800-190/final"
echo "• Docker Security Best Practices: https://docs.docker.com/develop/security-best-practices/"

echo
if [ "$RESULTS_COUNT" -gt 0 ]; then
    echo "============================================"
    echo -e "${GREEN}✅ Trivy security scan completed successfully!${NC}"
    echo "============================================"
else
    echo "============================================"
    echo -e "${YELLOW}⚠️  Trivy scan completed with limited results${NC}"
    echo -e "Check configuration and try again"
    echo "============================================"
    exit 1
fi

echo
echo "============================================"
echo "Trivy vulnerability scanning complete."
echo "============================================"