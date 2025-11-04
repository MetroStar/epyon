#!/bin/bash

# TruffleHog Security Scan Script
# Comprehensive secret scanning for filesystems and container images

# Configuration - Support target directory override
REPO_PATH="${TARGET_DIR:-$(pwd)}"
OUTPUT_DIR="./trufflehog-reports"
REPORT_FORMAT="json"  # Options: json, sarif, github
TIMESTAMP=$(date)
SCAN_LOG="$OUTPUT_DIR/trufflehog-scan.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Create output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

# Initialize scan log
echo "TruffleHog Security Scan Log" > "$SCAN_LOG"
echo "Timestamp: $TIMESTAMP" >> "$SCAN_LOG"
echo "Repository Path: $REPO_PATH" >> "$SCAN_LOG"
echo "Output Directory: $OUTPUT_DIR" >> "$SCAN_LOG"
echo "========================================" >> "$SCAN_LOG"

echo "============================================"
echo -e "${PURPLE}TruffleHog Multi-Target Security Scan${NC}"
echo "============================================"
echo -e "Repository: ${BLUE}$REPO_PATH${NC}"
echo -e "Output Directory: ${BLUE}$OUTPUT_DIR${NC}"
echo -e "Report Format: ${CYAN}$REPORT_FORMAT${NC}"
echo -e "Timestamp: ${CYAN}$TIMESTAMP${NC}"
echo ""

# Function to check Docker availability
check_docker() {
    if ! command -v docker &> /dev/null; then
        echo -e "${RED}❌ Docker not found${NC}"
        echo "Please install Docker to use TruffleHog scanning."
        exit 1
    fi
    
    if ! docker info &> /dev/null; then
        echo -e "${RED}❌ Docker daemon not running${NC}"
        echo "Please start Docker daemon before running TruffleHog scan."
        exit 1
    fi
}

# Function to scan filesystem
scan_filesystem() {
    echo -e "${BLUE}🛡️  Step 1: Filesystem Secret Scan${NC}"
    echo "=================================="
    echo -e "🔍 Scanning repository filesystem for secrets..."
    echo "Filesystem scan started" >> "$SCAN_LOG"
    
    # Run TruffleHog filesystem scan using Docker with exclusions
    docker run --rm \
      -v "$REPO_PATH:/repo" \
      -v "$REPO_PATH/exclude-paths.txt:/exclude-paths.txt" \
      trufflesecurity/trufflehog:latest \
      filesystem /repo \
      --json \
      --no-update \
      --exclude-paths=/exclude-paths.txt \
      > "$OUTPUT_DIR/trufflehog-filesystem-results.json" 2>&1
    
    local exit_code=$?
    if [ $exit_code -eq 0 ]; then
        echo -e "${GREEN}✅ Filesystem scan completed${NC}"
        echo "Filesystem scan completed successfully" >> "$SCAN_LOG"
        return 0
    else
        echo -e "${YELLOW}⚠️  Filesystem scan completed with warnings${NC}"
        echo "Filesystem scan completed with warnings" >> "$SCAN_LOG"
        return $exit_code
    fi
}

# Function to scan container images
scan_container_images() {
    echo -e "${BLUE}🛡️  Step 2: Container Image Secret Scan${NC}"
    echo "======================================="
    
    # Check for Docker files (various naming patterns)
    DOCKER_FILES=($(find . -maxdepth 1 -name "Dockerfile*" -type f 2>/dev/null))
    
    if [ ${#DOCKER_FILES[@]} -gt 0 ]; then
        echo -e "📦 Found ${#DOCKER_FILES[@]} Docker file(s): ${DOCKER_FILES[*]}"
        echo "Found Docker files: ${DOCKER_FILES[*]}" >> "$SCAN_LOG"
        
        # Scan each Docker file found
        for dockerfile in "${DOCKER_FILES[@]}"; do
            echo -e "� Processing Docker file: ${dockerfile}"
            
            # Extract a clean name for the image
            DOCKERFILE_NAME=$(basename "$dockerfile")
            CLEAN_NAME=$(echo "$DOCKERFILE_NAME" | tr '[:upper:]' '[:lower:]' | tr '.' '-')
            IMAGE_NAME="advana-marketplace:${CLEAN_NAME}-scan"
            
            echo -e "📦 Building image from ${dockerfile}..."
            docker build -f "$dockerfile" -t "$IMAGE_NAME" . >> "$SCAN_LOG" 2>&1
            
            if [ $? -eq 0 ]; then
                echo -e "${GREEN}✅ Image built successfully from ${dockerfile}${NC}"
                echo -e "🔍 Scanning built image for embedded secrets..."
                
                # Create specific output file for this Docker file
                DOCKER_RESULTS_FILE="$OUTPUT_DIR/trufflehog-${CLEAN_NAME}-results.json"
                
                # Scan the built image
                docker run --rm \
                  -v /var/run/docker.sock:/var/run/docker.sock \
                  trufflesecurity/trufflehog:latest \
                  docker --image="$IMAGE_NAME" \
                  --json \
                  --no-update \
                  > "$DOCKER_RESULTS_FILE" 2>&1
                
                local exit_code=$?
                if [ $exit_code -eq 0 ]; then
                    echo -e "${GREEN}✅ Image scan completed for ${dockerfile}${NC}"
                    echo "Image scan completed successfully for ${dockerfile}" >> "$SCAN_LOG"
                else
                    echo -e "${YELLOW}⚠️  Image scan completed with warnings for ${dockerfile}${NC}"
                    echo "Image scan completed with warnings for ${dockerfile}" >> "$SCAN_LOG"
                fi
                
                # Clean up the built image to save space
                docker rmi "$IMAGE_NAME" >> "$SCAN_LOG" 2>&1 || true
                
            else
                echo -e "${RED}❌ Failed to build image from ${dockerfile}${NC}"
                echo "Failed to build image from ${dockerfile}" >> "$SCAN_LOG"
            fi
        done
        echo -e "${GREEN}✅ Built container image scanning completed${NC}"
        
    else
        echo -e "${YELLOW}⚠️  No Docker files found (searched for: Dockerfile, Dockerfile.*, etc.)${NC}"
        echo -e "${BLUE}📋 Available files in repository root:${NC}"
        ls -la | grep -E "(Dockerfile|docker)" | head -5 || echo "  No Docker-related files found"
    fi
    
    # Always scan common base images regardless of whether we found Docker files
    scan_base_images
}

# Function to scan common base images
scan_base_images() {
    echo -e "🔍 Scanning common base images for secrets..."
    
    # Array of common base images to scan
    local base_images=("nginx:alpine" "node:18-alpine" "python:3.11-alpine")
    
    for image in "${base_images[@]}"; do
        echo -e "📋 Scanning base image: ${CYAN}$image${NC}"
        
        # Check if image exists locally, if not pull it
        if ! docker image inspect "$image" >/dev/null 2>&1; then
            echo -e "📥 Pulling image $image..."
            docker pull "$image" >> "$SCAN_LOG" 2>&1
        fi
        
        # Scan the base image
        local safe_image_name=$(echo "$image" | tr ':/' '-')
        docker run --rm \
          -v /var/run/docker.sock:/var/run/docker.sock \
          trufflesecurity/trufflehog:latest \
          docker --image="$image" \
          --json \
          --no-update \
          > "$OUTPUT_DIR/trufflehog-base-$safe_image_name-results.json" 2>&1
        
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}✅ Base image $image scan completed${NC}"
        else
            echo -e "${YELLOW}⚠️  Base image $image scan had warnings${NC}"
        fi
    done
    
    echo "Base image scanning completed" >> "$SCAN_LOG"
}

# Function to scan specific Docker images by name
scan_specific_images() {
    echo -e "${BLUE}🛡️  Step 3: Registry Image Secret Scan${NC}"
    echo "====================================="
    
    # Look for common registry references in the project
    local registry_images=()
    
    # Check for references in Dockerfile
    if [ -f "Dockerfile" ]; then
        while IFS= read -r line; do
            if [[ $line =~ ^FROM[[:space:]]+([^[:space:]]+) ]]; then
                local image="${BASH_REMATCH[1]}"
                if [[ ! "$image" =~ ^(scratch|alpine|ubuntu|debian|centos|node|python|nginx)$ ]]; then
                    registry_images+=("$image")
                fi
            fi
        done < "Dockerfile"
    fi
    
    # Check for references in Kubernetes/Helm files
    if [ -d "chart" ]; then
        while IFS= read -r -d '' file; do
            if grep -q "image:" "$file"; then
                while IFS= read -r line; do
                    if [[ $line =~ image:[[:space:]]*([^[:space:]]+) ]]; then
                        local image="${BASH_REMATCH[1]}"
                        # Remove quotes and template syntax
                        image=$(echo "$image" | sed 's/["{}\[\]]//g' | sed 's/{{.*}}//' | tr -d '"')
                        if [[ "$image" != "" && ! "$image" =~ ^(scratch|alpine|ubuntu|debian|centos)$ ]]; then
                            registry_images+=("$image")
                        fi
                    fi
                done < "$file"
            fi
        done < <(find chart -name "*.yaml" -print0 2>/dev/null)
    fi
    
    # Remove duplicates and scan unique images
    if [ ${#registry_images[@]} -gt 0 ]; then
        local unique_images=($(printf "%s\n" "${registry_images[@]}" | sort -u))
        
        echo -e "📋 Found ${#unique_images[@]} unique registry images to scan"
        
        for image in "${unique_images[@]}"; do
            if [[ "$image" != *"{{"* && "$image" != "" ]]; then
                echo -e "🔍 Scanning registry image: ${CYAN}$image${NC}"
                
                # Try to pull and scan the image
                if docker pull "$image" >> "$SCAN_LOG" 2>&1; then
                    local safe_image_name=$(echo "$image" | tr ':/.' '-')
                    docker run --rm \
                      -v /var/run/docker.sock:/var/run/docker.sock \
                      trufflesecurity/trufflehog:latest \
                      docker --image="$image" \
                      --json \
                      --no-update \
                      > "$OUTPUT_DIR/trufflehog-registry-$safe_image_name-results.json" 2>&1
                    
                    if [ $? -eq 0 ]; then
                        echo -e "${GREEN}✅ Registry image $image scan completed${NC}"
                    else
                        echo -e "${YELLOW}⚠️  Registry image $image scan had warnings${NC}"
                    fi
                else
                    echo -e "${YELLOW}⚠️  Could not pull image $image, skipping...${NC}"
                fi
            fi
        done
    else
        echo -e "${YELLOW}⚠️  No registry images found to scan${NC}"
    fi
    
    echo "Registry image scanning completed" >> "$SCAN_LOG"
}

# Check Docker availability
check_docker

echo -e "${BLUE}🐳 Docker and TruffleHog Information:${NC}"
echo "Docker version:"
docker --version
echo "Pulling TruffleHog image..."
docker pull trufflesecurity/trufflehog:latest
echo

# Execute all scan types
scan_filesystem
echo
scan_container_images  
echo
scan_specific_images

echo

# Generate comprehensive summary
echo -e "${BLUE}📊 TruffleHog Multi-Target Security Summary${NC}"
echo "=========================================="

# Count results files
RESULTS_COUNT=$(find "$OUTPUT_DIR" -name "trufflehog-*-results.json" | wc -l | xargs)
echo -e "📄 Results files generated: ${CYAN}$RESULTS_COUNT${NC}"

# Parse all results for comprehensive summary
if command -v python3 &> /dev/null && [ "$RESULTS_COUNT" -gt 0 ]; then
    echo -e "🔍 Comprehensive Secret Analysis:"
    
    python3 << 'EOF'
import json
import glob
import os

try:
    output_dir = "./trufflehog-reports"
    result_files = glob.glob(f"{output_dir}/trufflehog-*-results.json")
    
    total_verified = 0
    total_unverified = 0
    scan_summary = {}
    
    for file_path in result_files:
        try:
            with open(file_path, 'r') as f:
                content = f.read().strip()
            
            filename = os.path.basename(file_path)
            scan_type = filename.replace('trufflehog-', '').replace('-results.json', '')
            
            verified_count = 0
            unverified_count = 0
            
            # Parse each line as separate JSON (TruffleHog output format)
            for line in content.split('\n'):
                line = line.strip()
                if line and line.startswith('{'):
                    try:
                        data = json.loads(line)
                        if 'Verified' in data:
                            if data['Verified']:
                                verified_count += 1
                            else:
                                unverified_count += 1
                    except json.JSONDecodeError:
                        continue
            
            scan_summary[scan_type] = {
                'verified': verified_count,
                'unverified': unverified_count,
                'total': verified_count + unverified_count
            }
            
            total_verified += verified_count
            total_unverified += unverified_count
            
            print(f"\n📋 {scan_type.replace('-', ' ').title()}:")
            if verified_count + unverified_count > 0:
                print(f"  🔴 Verified secrets: {verified_count}")
                print(f"  🟡 Unverified secrets: {unverified_count}")
                print(f"  📊 Total: {verified_count + unverified_count}")
            else:
                print("  ✅ No secrets detected")
                
        except Exception as e:
            print(f"  ⚠️  Could not parse {filename}: {str(e)}")
    
    print(f"\n🎯 Overall Security Summary:")
    print("===========================")
    print(f"🔴 Total verified secrets: {total_verified}")
    print(f"🟡 Total unverified secrets: {total_unverified}")
    print(f"📊 Total secrets found: {total_verified + total_unverified}")
    
    if total_verified > 0:
        print(f"\n🚨 CRITICAL: {total_verified} verified secrets found - immediate action required!")
    elif total_unverified > 0:
        print(f"\n⚠️  WARNING: {total_unverified} unverified potential secrets found - review recommended")
    else:
        print(f"\n🎉 EXCELLENT: No secrets detected across all scan targets!")
        
except Exception as e:
    print(f"Error analyzing results: {e}")
EOF
else
    echo -e "${YELLOW}⚠️  Python not available for detailed analysis${NC}"
    echo "Check individual result files for detailed secret information."
fi

echo
echo -e "${BLUE}📁 Output Files:${NC}"
echo "================"
find "$OUTPUT_DIR" -name "trufflehog-*-results.json" -exec echo "📄 {}" \;
echo "📝 Scan log: $SCAN_LOG"
echo "📂 Reports directory: $OUTPUT_DIR"

echo
echo -e "${BLUE}🔧 Available Commands:${NC}"
echo "===================="
echo "📊 Analyze results:       npm run security:analyze"
echo "🔍 Run new scan:          npm run security:scan"
echo "🏗️  Filesystem only:       ./run-trufflehog-scan.sh filesystem"
echo "📦 Images only:           ./run-trufflehog-scan.sh images"
echo "📋 View specific results: cat $OUTPUT_DIR/trufflehog-*-results.json | jq ."

echo
echo -e "${BLUE}🔗 Additional Resources:${NC}"
echo "======================="
echo "• TruffleHog Documentation: https://github.com/trufflesecurity/trufflehog"
echo "• Secret Management Best Practices: https://owasp.org/www-project-secrets-management-cheat-sheet/"
echo "• Container Security Guide: https://kubernetes.io/docs/concepts/security/"
echo "• Git Security Best Practices: https://docs.github.com/en/code-security"

echo
echo "============================================"
echo -e "${GREEN}✅ TruffleHog multi-target security scan completed!${NC}"
echo "============================================"
echo
echo "============================================"
echo "TruffleHog secret scanning complete."
echo "============================================"