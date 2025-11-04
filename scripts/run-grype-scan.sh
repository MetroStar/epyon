#!/bin/bash

# Grype Multi-Target Vulnerability Scanner
# Advanced container image and filesystem vulnerability scanning with SBOM generation

OUTPUT_DIR="./grype-reports"
TIMESTAMP=$(date)
SCAN_LOG="$OUTPUT_DIR/grype-scan.log"
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
echo -e "${WHITE}Grype Multi-Target Vulnerability Scanner${NC}"
echo -e "${WHITE}============================================${NC}"
echo "Repository: $REPO_PATH"
echo "Output Directory: $OUTPUT_DIR"
echo "Timestamp: $TIMESTAMP"
echo

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Initialize scan log
echo "Grype Vulnerability Scan Log" > "$SCAN_LOG"
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
        echo "Please install Docker to use Grype vulnerability scanning."
        exit 1
    fi
    
    if ! docker info &> /dev/null; then
        echo -e "${RED}❌ Docker daemon not running${NC}"
        echo "Please start Docker daemon before running Grype scan."
        exit 1
    fi
}

echo -e "${BLUE}🐳 Docker and Grype Information:${NC}"
echo "Docker version:"
docker --version
echo "Pulling Grype image..."
docker pull anchore/grype:latest
echo

# Function to scan Docker image with SBOM generation
scan_docker_image() {
    local image_name="$1"
    local scan_type="$2"
    local output_file="$3"
    local sbom_file="$4"
    
    echo -e "${CYAN}🔍 Scanning Docker image: ${YELLOW}$image_name${NC}"
    echo "Scan type: $scan_type" >> "$SCAN_LOG"
    echo "Image: $image_name" >> "$SCAN_LOG"
    
    # Generate SBOM first using Syft (built into Grype)
    echo -e "📋 Generating Software Bill of Materials (SBOM)..."
    docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
        -v "$(pwd)/$OUTPUT_DIR:/output" \
        anchore/grype:latest \
        "$image_name" \
        -o json \
        --file "/output/$output_file" \
        --add-cpes-if-none \
        --by-cve 2>&1 | tee -a "$SCAN_LOG"
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✅ Image scan completed${NC}"
        echo "Image scan completed successfully" >> "$SCAN_LOG"
        
        # Generate SBOM separately for detailed component analysis
        echo -e "📦 Generating detailed SBOM..."
        docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
            -v "$(pwd)/$OUTPUT_DIR:/output" \
            anchore/syft:latest \
            "$image_name" \
            -o spdx-json="/output/$sbom_file" 2>&1 | tee -a "$SCAN_LOG"
    else
        echo -e "${YELLOW}⚠️  Image scan completed with warnings${NC}"
        echo "Image scan completed with warnings" >> "$SCAN_LOG"
    fi
}

# Function to scan built container images
scan_container_images() {
    echo -e "${PURPLE}🛡️  Step 2: Container Image Vulnerability Scan${NC}"
    echo "=============================================="
    
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
            IMAGE_NAME="advana-marketplace:${CLEAN_NAME}-grype-scan"
            
            echo -e "📦 Building image from ${dockerfile} for vulnerability scanning..."
            docker build -f "$dockerfile" -t "$IMAGE_NAME" . >> "$SCAN_LOG" 2>&1
            
            if [ $? -eq 0 ]; then
                echo -e "${GREEN}✅ Image built successfully from ${dockerfile}${NC}"
                echo -e "🔍 Scanning built image for vulnerabilities..."
                
                # Scan the built image for vulnerabilities
                scan_docker_image "$IMAGE_NAME" "container-${CLEAN_NAME}" "grype-${CLEAN_NAME}-results.json" "sbom-${CLEAN_NAME}.json"
                
                # Clean up the built image to save space
                docker rmi "$IMAGE_NAME" >> "$SCAN_LOG" 2>&1 || true
                
            else
                echo -e "${RED}❌ Failed to build image from ${dockerfile}${NC}"
                echo "Failed to build image from ${dockerfile}" >> "$SCAN_LOG"
            fi
        done
        echo -e "${GREEN}✅ Built container image vulnerability scanning completed${NC}"
        
    else
        echo -e "${YELLOW}⚠️  No Docker files found (searched for: Dockerfile, Dockerfile.*, etc.)${NC}"
        echo -e "${BLUE}📋 Available files in repository root:${NC}"
        ls -la | grep -E "(Dockerfile|docker)" | head -5 || echo "  No Docker-related files found"
    fi
    
    # Always scan common base images regardless of whether we found Docker files
    scan_base_images
}

# Function to scan common base images for vulnerabilities
scan_base_images() {
    echo -e "🔍 Scanning common base images for vulnerabilities..."
    
    # Array of common base images to scan
    local base_images=("nginx:alpine" "node:18-alpine" "python:3.11-alpine" "ubuntu:22.04" "alpine:latest")
    
    for image in "${base_images[@]}"; do
        echo -e "📋 Scanning base image: ${CYAN}$image${NC} for vulnerabilities"
        
        # Check if image exists locally, if not pull it
        if ! docker image inspect "$image" >/dev/null 2>&1; then
            echo -e "📥 Pulling image $image..."
            docker pull "$image" >> "$SCAN_LOG" 2>&1
        fi
        
        # Scan the base image for vulnerabilities
        local safe_image_name=$(echo "$image" | tr ':/' '-')
        scan_docker_image "$image" "base-image" "grype-base-$safe_image_name-results.json" "sbom-base-$safe_image_name.json"
        
        echo -e "${GREEN}✅ Base image $image vulnerability scan completed${NC}"
        echo "Base image $image vulnerability scan completed" >> "$SCAN_LOG"
    done
}

# Function to scan specific registry images
scan_registry_images() {
    echo -e "${GREEN}🛡️  Step 3: Registry Image Vulnerability Scan${NC}"
    echo "============================================="
    
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
        scan_docker_image "$image" "registry-image" "grype-registry-$safe_image_name-results.json" "sbom-registry-$safe_image_name.json"
        
        echo -e "${GREEN}✅ Registry image $image vulnerability scan completed${NC}"
    done
}

# Function to scan filesystem/directory
scan_filesystem() {
    local target_dir="$1"
    local output_file="$2"
    local sbom_file="$3"
    
    echo -e "${CYAN}🔍 Scanning filesystem: ${YELLOW}$target_dir${NC}"
    echo "Filesystem scan target: $target_dir" >> "$SCAN_LOG"
    
    # Run Grype filesystem scan
    docker run --rm -v "$(pwd):/workspace" \
        -v "$(pwd)/$OUTPUT_DIR:/output" \
        anchore/grype:latest \
        "dir:/workspace/$target_dir" \
        -o json \
        --file "/output/$output_file" \
        --add-cpes-if-none \
        --by-cve 2>&1 | tee -a "$SCAN_LOG"
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✅ Filesystem scan completed${NC}"
        echo "Filesystem scan completed successfully" >> "$SCAN_LOG"
        
        # Generate SBOM for filesystem
        echo -e "📦 Generating filesystem SBOM..."
        docker run --rm -v "$(pwd):/workspace" \
            -v "$(pwd)/$OUTPUT_DIR:/output" \
            anchore/syft:latest \
            "dir:/workspace/$target_dir" \
            -o spdx-json="/output/$sbom_file" 2>&1 | tee -a "$SCAN_LOG"
    else
        echo -e "${YELLOW}⚠️  Filesystem scan completed with warnings${NC}"
        echo "Filesystem scan completed with warnings" >> "$SCAN_LOG"
    fi
}

# Function to scan package manager files
scan_package_files() {
    local target_dir="$1"
    local output_file="$2"
    
    echo -e "${CYAN}🔍 Scanning package manager files in: ${YELLOW}$target_dir${NC}"
    echo "Package scan target: $target_dir" >> "$SCAN_LOG"
    
    # Look for package files (package.json, requirements.txt, go.mod, etc.)
    local package_files=""
    if [ -f "$target_dir/package.json" ]; then
        package_files="$package_files package.json"
    fi
    if [ -f "$target_dir/requirements.txt" ]; then
        package_files="$package_files requirements.txt"
    fi
    if [ -f "$target_dir/go.mod" ]; then
        package_files="$package_files go.mod"
    fi
    if [ -f "$target_dir/Cargo.toml" ]; then
        package_files="$package_files Cargo.toml"
    fi
    
    if [ -n "$package_files" ]; then
        echo -e "📦 Found package files: $package_files"
        
        # Scan with Grype focusing on package files
        docker run --rm -v "$(pwd):/workspace" \
            -v "$(pwd)/$OUTPUT_DIR:/output" \
            anchore/grype:latest \
            "dir:/workspace/$target_dir" \
            -o json \
            --file "/output/$output_file" \
            --add-cpes-if-none \
            --by-cve \
            --scope all-layers 2>&1 | tee -a "$SCAN_LOG"
        
        echo -e "${GREEN}✅ Package scan completed${NC}"
    else
        echo -e "${YELLOW}⚠️  No package manager files found${NC}"
        echo "No package manager files found" >> "$SCAN_LOG"
    fi
}

# Check Docker availability
check_docker

# Main execution logic based on command line argument
case "${1:-all}" in
    "filesystem")
        echo -e "${CYAN}🛡️  Step 1: Filesystem Vulnerability Scan${NC}"
        echo "========================================="
        scan_filesystem "." "grype-filesystem-results.json" "sbom-filesystem.json"
        if [ -d "frontend" ]; then
            scan_filesystem "frontend" "grype-frontend-results.json" "sbom-frontend.json"
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
    "all"|*)
        # Step 1: Filesystem scanning
        echo -e "${CYAN}🛡️  Step 1: Filesystem Vulnerability Scan${NC}"
        echo "========================================="
        echo -e "📂 Scanning root directory for vulnerabilities..."
        scan_filesystem "." "grype-root-results.json" "sbom-root.json"
        
        # Scan frontend if exists
        if [ -d "frontend" ]; then
            echo -e "📁 Scanning frontend directory for vulnerabilities..."
            scan_filesystem "frontend" "grype-frontend-results.json" "sbom-frontend.json"
            
            # Additional package-specific scan
            if [ -f "frontend/package.json" ]; then
                echo -e "📦 Performing focused package.json analysis..."
                scan_package_files "frontend" "grype-frontend-packages.json"
            fi
        fi
        
        echo
        
        # Step 2: Container image scanning
        scan_container_images
        
        echo
        
        # Step 3: Registry image scanning  
        scan_registry_images
        ;;
esac

echo

# Scan 3: Root level dependencies and configuration
echo -e "${BLUE}🛡️  Step 3: Root Level Dependencies Scan${NC}"
echo "=============================================="

echo -e "📂 Scanning root directory for vulnerabilities..."
scan_filesystem "." "grype-root-results.json" "sbom-root.json"

echo

# Scan 4: Specific technology stack scanning
echo -e "${BLUE}🛡️  Step 4: Technology Stack Analysis${NC}"
echo "========================================"

# Check for different technology stacks and scan appropriately
if [ -f "package.json" ]; then
    echo -e "🟢 Node.js project detected - scanning npm dependencies"
    scan_package_files "." "grype-nodejs-results.json"
fi

if [ -f "requirements.txt" ] || [ -f "setup.py" ] || [ -f "pyproject.toml" ]; then
    echo -e "🐍 Python project detected - scanning Python dependencies"
    scan_package_files "." "grype-python-results.json"
fi

if [ -f "go.mod" ] || [ -f "go.sum" ]; then
    echo -e "🔵 Go project detected - scanning Go modules"
    scan_package_files "." "grype-golang-results.json"
fi

if [ -f "Cargo.toml" ] || [ -f "Cargo.lock" ]; then
    echo -e "🦀 Rust project detected - scanning Cargo dependencies"
    scan_package_files "." "grype-rust-results.json"
fi

echo

# Generate summary
echo -e "${BLUE}📊 Grype Vulnerability Scan Summary${NC}"
echo "===================================="

# Count results files
RESULTS_COUNT=$(find "$OUTPUT_DIR" -name "grype-*-results.json" | wc -l | xargs)
SBOM_COUNT=$(find "$OUTPUT_DIR" -name "sbom-*.json" | wc -l | xargs)

echo -e "📄 Vulnerability reports generated: ${CYAN}$RESULTS_COUNT${NC}"
echo -e "📋 SBOM files generated: ${CYAN}$SBOM_COUNT${NC}"

# Parse JSON results for quick summary (if Python is available)
if command -v python3 &> /dev/null && [ "$RESULTS_COUNT" -gt 0 ]; then
    echo -e "🔍 Vulnerability Summary:"
    
    python3 << 'EOF'
import json
import glob
import os

try:
    output_dir = "./grype-reports"
    result_files = glob.glob(f"{output_dir}/grype-*-results.json")
    
    total_critical = 0
    total_high = 0
    total_medium = 0
    total_low = 0
    total_negligible = 0
    total_unknown = 0
    
    for file_path in result_files:
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            filename = os.path.basename(file_path)
            print(f"\n📋 {filename}:")
            
            # Handle Grype JSON format
            if 'matches' in data:
                matches = data['matches']
                
                if matches:
                    critical_count = len([m for m in matches if m.get('vulnerability', {}).get('severity') == 'Critical'])
                    high_count = len([m for m in matches if m.get('vulnerability', {}).get('severity') == 'High'])
                    medium_count = len([m for m in matches if m.get('vulnerability', {}).get('severity') == 'Medium'])
                    low_count = len([m for m in matches if m.get('vulnerability', {}).get('severity') == 'Low'])
                    negligible_count = len([m for m in matches if m.get('vulnerability', {}).get('severity') == 'Negligible'])
                    unknown_count = len([m for m in matches if m.get('vulnerability', {}).get('severity') not in ['Critical', 'High', 'Medium', 'Low', 'Negligible']])
                    
                    print(f"  🔴 Critical: {critical_count}")
                    print(f"  🟠 High: {high_count}")
                    print(f"  🟡 Medium: {medium_count}")
                    print(f"  🟢 Low: {low_count}")
                    if negligible_count > 0:
                        print(f"  ⚪ Negligible: {negligible_count}")
                    if unknown_count > 0:
                        print(f"  ❓ Unknown: {unknown_count}")
                    
                    total_critical += critical_count
                    total_high += high_count
                    total_medium += medium_count
                    total_low += low_count
                    total_negligible += negligible_count
                    total_unknown += unknown_count
                else:
                    print("  ✅ No vulnerabilities found")
            else:
                print("  ⚠️  Could not parse vulnerability data")
                
        except Exception as e:
            print(f"  ⚠️  Could not parse {filename}: {str(e)}")
    
    print(f"\n🎯 Total Vulnerability Summary:")
    print("==============================")
    print(f"  🔴 Critical: {total_critical}")
    print(f"  🟠 High: {total_high}")
    print(f"  🟡 Medium: {total_medium}")
    print(f"  🟢 Low: {total_low}")
    if total_negligible > 0:
        print(f"  ⚪ Negligible: {total_negligible}")
    if total_unknown > 0:
        print(f"  ❓ Unknown: {total_unknown}")
    
    critical_high_count = total_critical + total_high
    
    if critical_high_count == 0:
        print("\n✅ Security Status: EXCELLENT")
        print("🎉 No critical or high severity vulnerabilities detected")
    elif critical_high_count <= 5:
        print("\n🟡 Security Status: GOOD")
        print(f"⚠️  {critical_high_count} critical/high vulnerabilities found - review recommended")
    elif critical_high_count <= 15:
        print("\n🟠 Security Status: NEEDS ATTENTION")
        print(f"⚠️  {critical_high_count} critical/high vulnerabilities found - action required")
    else:
        print("\n🔴 Security Status: CRITICAL")
        print(f"🚨 {critical_high_count} critical/high vulnerabilities - immediate action required")
        
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
echo "🔍 Vulnerability Reports:"
find "$OUTPUT_DIR" -name "grype-*-results.json" -exec echo "  📄 {}" \;
echo "📋 SBOM Reports:"
find "$OUTPUT_DIR" -name "sbom-*.json" -exec echo "  📦 {}" \;
echo "📝 Scan log: $SCAN_LOG"
echo "📂 Reports directory: $OUTPUT_DIR"

echo
echo -e "${BLUE}🔧 Available Commands:${NC}"
echo "===================="
echo "📊 Analyze results:         npm run grype:analyze"
echo "🔍 Run new scan:            npm run grype:scan"
echo "🏗️  Filesystem only:         ./run-grype-scan.sh filesystem"
echo "📦 Images only:             ./run-grype-scan.sh images"
echo "🖼️  Base images only:        ./run-grype-scan.sh base"
echo "🌐 Registry images only:    ./run-grype-scan.sh registry"
echo "🛡️  Full vulnerability suite: npm run trivy:scan && npm run grype:scan"
echo "📋 View specific results:    cat $OUTPUT_DIR/grype-*-results.json | jq ."
echo "📦 View SBOM details:        cat $OUTPUT_DIR/sbom-*.json | jq ."

echo
echo -e "${BLUE}🔗 Additional Resources:${NC}"
echo "======================="
echo "• Grype Documentation: https://github.com/anchore/grype"
echo "• Syft SBOM Generator: https://github.com/anchore/syft"
echo "• Anchore Security Best Practices: https://anchore.com/blog/"
echo "• Software Bill of Materials (SBOM): https://www.cisa.gov/sbom"
echo "• CVE Database: https://cve.mitre.org/"
echo "• National Vulnerability Database: https://nvd.nist.gov/"

echo
if [ "$RESULTS_COUNT" -gt 0 ]; then
    echo "============================================"
    echo -e "${GREEN}✅ Grype vulnerability scan completed successfully!${NC}"
    echo "============================================"
else
    echo "============================================"
    echo -e "${YELLOW}⚠️  Grype scan completed with limited results${NC}"
    echo -e "Check configuration and try again"
    echo "============================================"
    exit 1
fi

echo
echo "============================================"
echo "Grype vulnerability scanning complete."
echo "============================================"