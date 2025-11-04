#!/bin/bash

# Color definitions for enhanced output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

# Configuration - Support target directory override
REPO_PATH="${TARGET_DIR:-$(pwd)}"
OUTPUT_DIR="./xeol-reports"
REPORT_FORMAT="json"
SCAN_LOG="$OUTPUT_DIR/xeol-scan.log"

# Create output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

echo -e "${WHITE}============================================${NC}"
echo -e "${WHITE}Xeol End-of-Life Software Detection Scan${NC}"
echo -e "${WHITE}============================================${NC}"
echo "Repository: $REPO_PATH"
echo "Output Directory: $OUTPUT_DIR"
echo "Report Format: $REPORT_FORMAT"
echo "Timestamp: $(date)"
echo

# Initialize scan log
echo "Xeol EOL scan started at $(date)" > "$SCAN_LOG"
echo "Repository: $REPO_PATH" >> "$SCAN_LOG"

echo -e "${BLUE}🐳 Docker and Xeol Information:${NC}"
echo "Docker version:"
docker --version
echo "Pulling Xeol image..."
docker pull noqcks/xeol:latest
echo

# Function to scan directory/filesystem for EOL software
scan_filesystem() {
    echo -e "${CYAN}🛡️  Step 1: Filesystem EOL Software Scan${NC}"
    echo "=========================================="
    echo -e "🔍 Scanning repository filesystem for end-of-life software..."
    echo "Filesystem EOL scan started at $(date)" >> "$SCAN_LOG"
    
    # Run Xeol filesystem scan using Docker
    docker run --rm \
      -v "$REPO_PATH:/repo" \
      noqcks/xeol:latest \
      /repo \
      -o json \
      > "$OUTPUT_DIR/xeol-filesystem-results.json" 2>> "$SCAN_LOG"
    
    local exit_code=$?
    if [ $exit_code -eq 0 ]; then
        echo -e "${GREEN}✅ Filesystem EOL scan completed${NC}"
        echo "Filesystem EOL scan completed successfully" >> "$SCAN_LOG"
        return 0
    else
        echo -e "${YELLOW}⚠️  Filesystem EOL scan completed with warnings${NC}"
        echo "Filesystem EOL scan completed with warnings" >> "$SCAN_LOG"
        return $exit_code
    fi
}

# Function to scan container images for EOL software
scan_container_images() {
    echo -e "${PURPLE}🛡️  Step 2: Container Image EOL Software Scan${NC}"
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
            IMAGE_NAME="advana-marketplace:${CLEAN_NAME}-xeol-scan"
            
            echo -e "📦 Building image from ${dockerfile} for EOL scanning..."
            docker build -f "$dockerfile" -t "$IMAGE_NAME" . >> "$SCAN_LOG" 2>&1
            
            if [ $? -eq 0 ]; then
                echo -e "${GREEN}✅ Image built successfully from ${dockerfile}${NC}"
                echo -e "🔍 Scanning built image for EOL software..."
                
                # Create specific output file for this Docker file
                DOCKER_RESULTS_FILE="$OUTPUT_DIR/xeol-${CLEAN_NAME}-results.json"
                
                # Scan the built image for EOL software
                docker run --rm \
                  -v /var/run/docker.sock:/var/run/docker.sock \
                  noqcks/xeol:latest \
                  "$IMAGE_NAME" \
                  -o json \
                  > "$DOCKER_RESULTS_FILE" 2>> "$SCAN_LOG"
                
                local exit_code=$?
                if [ $exit_code -eq 0 ]; then
                    echo -e "${GREEN}✅ Image EOL scan completed for ${dockerfile}${NC}"
                    echo "Image EOL scan completed successfully for ${dockerfile}" >> "$SCAN_LOG"
                else
                    echo -e "${YELLOW}⚠️  Image EOL scan completed with warnings for ${dockerfile}${NC}"
                    echo "Image EOL scan completed with warnings for ${dockerfile}" >> "$SCAN_LOG"
                fi
                
                # Clean up the built image to save space
                docker rmi "$IMAGE_NAME" >> "$SCAN_LOG" 2>&1 || true
                
            else
                echo -e "${RED}❌ Failed to build image from ${dockerfile}${NC}"
                echo "Failed to build image from ${dockerfile}" >> "$SCAN_LOG"
            fi
        done
        echo -e "${GREEN}✅ Built container image EOL scanning completed${NC}"
        
    else
        echo -e "${YELLOW}⚠️  No Docker files found (searched for: Dockerfile, Dockerfile.*, etc.)${NC}"
        echo -e "${BLUE}📋 Available files in repository root:${NC}"
        ls -la | grep -E "(Dockerfile|docker)" | head -5 || echo "  No Docker-related files found"
    fi
    
    # Always scan common base images regardless of whether we found Docker files
    scan_base_images
}

# Function to scan common base images for EOL software
scan_base_images() {
    echo -e "🔍 Scanning common base images for EOL software..."
    
    # Array of common base images to scan
    local base_images=("nginx:alpine" "node:18-alpine" "python:3.11-alpine")
    
    for image in "${base_images[@]}"; do
        echo -e "📋 Scanning base image: ${CYAN}$image${NC} for EOL software"
        
        # Check if image exists locally, if not pull it
        if ! docker image inspect "$image" >/dev/null 2>&1; then
            echo -e "📥 Pulling image $image..."
            docker pull "$image" >> "$SCAN_LOG" 2>&1
        fi
        
        # Scan the base image for EOL software
        local safe_image_name=$(echo "$image" | tr ':/' '-')
        docker run --rm \
          noqcks/xeol:latest \
          "$image" \
          -o json \
          > "$OUTPUT_DIR/xeol-base-$safe_image_name-results.json" 2>> "$SCAN_LOG"
        
        local exit_code=$?
        if [ $exit_code -eq 0 ]; then
            echo -e "${GREEN}✅ Base image $image EOL scan completed${NC}"
            echo "Base image $image EOL scan completed" >> "$SCAN_LOG"
        else
            echo -e "${YELLOW}⚠️  Base image $image EOL scan completed with warnings${NC}"
            echo "Base image $image EOL scan completed with warnings" >> "$SCAN_LOG"
        fi
    done
}

# Function to scan specific registry images
scan_registry_images() {
    echo -e "${GREEN}🛡️  Step 3: Registry Image EOL Software Scan${NC}"
    echo "============================================="
    
    # Array of specific images to scan (can be customized)
    local registry_images=()
    
    # Add common production images if they exist
    if docker image inspect "node:lts-alpine" >/dev/null 2>&1; then
        registry_images+=("node:lts-alpine")
    fi
    
    if [ ${#registry_images[@]} -eq 0 ]; then
        echo -e "${YELLOW}⚠️  No registry images found to scan${NC}"
        return 0
    fi
    
    for image in "${registry_images[@]}"; do
        echo -e "🌐 Scanning registry image: ${GREEN}$image${NC}"
        
        local safe_image_name=$(echo "$image" | tr ':/' '-')
        docker run --rm \
          noqcks/xeol:latest \
          "$image" \
          -o json \
          > "$OUTPUT_DIR/xeol-registry-$safe_image_name-results.json" 2>> "$SCAN_LOG"
        
        echo -e "${GREEN}✅ Registry image $image EOL scan completed${NC}"
    done
}

# Function to generate comprehensive summary using Python
generate_comprehensive_summary() {
    echo -e "${WHITE}📊 Xeol End-of-Life Software Summary${NC}"
    echo "===================================="
    
    # Count results files
    local results_count=$(find "$OUTPUT_DIR" -name "xeol-*-results.json" | wc -l | tr -d ' ')
    echo "📄 Results files generated: $results_count"
    
    echo -e "${CYAN}🔍 Comprehensive EOL Software Analysis:${NC}"
    echo
    
    # Analyze each results file
    for results_file in "$OUTPUT_DIR"/xeol-*-results.json; do
        if [ -f "$results_file" ]; then
            filename=$(basename "$results_file" .json)
            scan_type=$(echo "$filename" | sed 's/xeol-//' | sed 's/-results//')
            
            # Use Python to analyze JSON results
            python3 -c "
import json
import sys
import os

try:
    with open('$results_file', 'r') as f:
        data = json.load(f)
    
    scan_name = '$scan_type'.replace('-', ' ').title()
    
    # Extract matches (EOL software findings)
    matches = data.get('matches', [])
    total_eol = len(matches)
    
    print(f'📋 {scan_name}:')
    
    if total_eol == 0:
        print(f'  ✅ No EOL software detected')
    else:
        # Count by package type
        package_types = {}
        severities = {}
        
        for match in matches:
            pkg_type = match.get('artifact', {}).get('type', 'unknown')
            package_types[pkg_type] = package_types.get(pkg_type, 0) + 1
            
        print(f'  🔴 EOL software found: {total_eol}')
        
        if package_types:
            print(f'  📦 Package types:')
            for pkg_type, count in sorted(package_types.items()):
                print(f'    - {pkg_type}: {count}')
    
    print(f'  📊 Total: {total_eol}')
    print()
    
except Exception as e:
    print(f'❌ Error analyzing {scan_name}: {str(e)}')
    print()
" 2>/dev/null || echo "⚠️  Could not analyze $results_file"
        fi
    done
}

# Main execution logic
case "${1:-all}" in
    "filesystem")
        scan_filesystem
        ;;
    "images"|"containers")
        scan_container_images
        ;;
    "registry")
        scan_registry_images  
        ;;
    "all"|*)
        scan_filesystem
        scan_container_images
        scan_registry_images
        ;;
esac

# Generate comprehensive summary
generate_comprehensive_summary

# Overall summary
echo -e "${WHITE}🎯 Overall EOL Software Security Summary:${NC}"
echo "======================================"

# Count total EOL software across all scans
total_eol=0
for results_file in "$OUTPUT_DIR"/xeol-*-results.json; do
    if [ -f "$results_file" ]; then
        count=$(python3 -c "
import json
try:
    with open('$results_file', 'r') as f:
        data = json.load(f)
    print(len(data.get('matches', [])))
except:
    print('0')
" 2>/dev/null || echo "0")
        total_eol=$((total_eol + count))
    fi
done

if [ "$total_eol" -eq 0 ]; then
    echo -e "${GREEN}✅ EOL SOFTWARE STATUS: CLEAN${NC}"
    echo -e "${GREEN}   No end-of-life software detected across all scan targets${NC}"
else
    echo -e "${YELLOW}⚠️  EOL SOFTWARE STATUS: REQUIRES ATTENTION${NC}"
    echo -e "${YELLOW}   Total EOL software found: $total_eol${NC}"
    echo -e "${YELLOW}   Review and update end-of-life components${NC}"
fi

echo
echo -e "${BLUE}📁 Output Files:${NC}"
echo "================"
for file in "$OUTPUT_DIR"/xeol-*.json; do
    if [ -f "$file" ]; then
        echo -e "📄 $(basename "$file")"
    fi
done
echo -e "📝 Scan log: $SCAN_LOG"
echo -e "📂 Reports directory: $OUTPUT_DIR"

echo
echo -e "${BLUE}🔧 Available Commands:${NC}"
echo "===================="
echo -e "📊 Analyze results:       npm run eol:analyze"
echo -e "🔍 Run new scan:          npm run eol:scan"  
echo -e "🏗️  Filesystem only:       ./run-xeol-scan.sh filesystem"
echo -e "📦 Images only:           ./run-xeol-scan.sh images"
echo -e "🌐 Registry only:         ./run-xeol-scan.sh registry"
echo -e "📋 View specific results: cat ./xeol-reports/xeol-*-results.json | jq ."

echo
echo -e "${BLUE}🔗 Additional Resources:${NC}"
echo "======================="
echo "• Xeol Documentation: https://github.com/anchore/xeol"
echo "• End-of-Life Software Risks: https://owasp.org/www-project-dependency-check/"
echo "• Software Lifecycle Management: https://csrc.nist.gov/glossary/term/software_lifecycle"
echo "• Container Security Best Practices: https://kubernetes.io/docs/concepts/security/"

echo
echo -e "${WHITE}============================================${NC}"
echo -e "${GREEN}✅ Xeol end-of-life software scan completed!${NC}"
echo -e "${WHITE}============================================${NC}"

echo
echo -e "${WHITE}============================================${NC}"
echo -e "${WHITE}Xeol EOL software scanning complete.${NC}"
echo -e "${WHITE}============================================${NC}"