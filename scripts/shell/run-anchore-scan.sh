#!/bin/bash

# Anchore Enterprise/Engine Multi-Target Vulnerability Scanner
# Comprehensive container and software composition analysis

# Colors for help output
WHITE='\033[1;37m'
NC='\033[0m'

# Help function
show_help() {
    echo -e "${WHITE}Anchore Multi-Target Vulnerability Scanner${NC}"
    echo ""
    echo "Usage: $0 [OPTIONS] [TARGET_DIRECTORY|SCAN_MODE]"
    echo ""
    echo "Comprehensive container and software composition analysis using Anchore Engine."
    echo "Provides policy-based compliance validation and detailed vulnerability reports."
    echo ""
    echo "Arguments:"
    echo "  TARGET_DIRECTORY    Path to directory to scan (default: current directory)"
    echo "  SCAN_MODE           Scan mode: filesystem, images, base, or all (default: all)"
    echo ""
    echo "Options:"
    echo "  -h, --help          Show this help message and exit"
    echo ""
    echo "Environment Variables:"
    echo "  TARGET_DIR          Alternative way to specify target directory"
    echo "  SCAN_ID             Override auto-generated scan ID"
    echo "  SCAN_DIR            Override output directory for scan results"
    echo ""
    echo "Output:"
    echo "  Results are saved to: scans/{SCAN_ID}/anchore/"
    echo "  - anchore-filesystem-results.json  Filesystem vulnerabilities"
    echo "  - anchore-sbom-results.json        SBOM-based vulnerabilities"
    echo "  - anchore-policy-evaluation.json   Policy compliance results"
    echo "  - anchore-scan.log                 Scan process log"
    echo ""
    echo "Scan Modes:"
    echo "  filesystem    Scan only the filesystem/directory"
    echo "  images        Scan container images from docker-compose"
    echo "  base          Scan base images only"
    echo "  all           Scan everything (default)"
    echo ""
    echo "Examples:"
    echo "  $0                              # Scan current directory (all modes)"
    echo "  $0 /path/to/project             # Scan specific directory"
    echo "  $0 filesystem                   # Filesystem scan only"
    echo "  TARGET_DIR=/app $0 images       # Scan container images"
    echo ""
    echo "Notes:"
    echo "  - Requires Docker to be installed and running"
    echo "  - Uses anchore/grype:latest for CLI-based scanning"
    echo "  - Compatible with Anchore Enterprise and Engine"
    echo "  - Provides policy compliance and detailed CVE analysis"
    exit 0
}

# Parse arguments
for arg in "$@"; do
    case $arg in
        -h|--help)
            show_help
            ;;
    esac
done

# Initialize scan environment using scan directory approach
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_DIR="$(cd "$SCRIPT_DIR/../../configuration" && pwd)"

# Source the scan directory template
source "$SCRIPT_DIR/scan-directory-template.sh"

# Source approved base images configuration only if PRIMARY_BASELINE_IMAGE is not already set
if [ -z "${PRIMARY_BASELINE_IMAGE:-}" ] && [ -f "$CONFIG_DIR/approved-base-images.conf" ]; then
    source "$CONFIG_DIR/approved-base-images.conf"
fi

# Initialize scan environment for Anchore
init_scan_environment "anchore"

# Set REPO_PATH and extract scan information
REPO_PATH="${1:-${TARGET_DIR:-$(pwd)}}"
# Handle special scan type keywords
if [[ "$REPO_PATH" == "filesystem" ]] || [[ "$REPO_PATH" == "images" ]] || [[ "$REPO_PATH" == "base" ]]; then
    SCAN_MODE="$REPO_PATH"
    REPO_PATH="${TARGET_DIR:-$(pwd)}"
else
    SCAN_MODE="all"
fi
if [[ -n "$SCAN_ID" ]]; then
    TARGET_NAME=$(echo "$SCAN_ID" | cut -d'_' -f1)
    USERNAME=$(echo "$SCAN_ID" | cut -d'_' -f2)
    TIMESTAMP=$(echo "$SCAN_ID" | cut -d'_' -f3-)
else
    # Fallback for standalone execution
    TARGET_NAME=$(basename "$REPO_PATH")
    USERNAME=$(whoami)
    TIMESTAMP=$(date '+%Y-%m-%d_%H-%M-%S')
    SCAN_ID="${TARGET_NAME}_${USERNAME}_${TIMESTAMP}"
fi

# Set output paths
OUTPUT_DIR="${SCAN_DIR}/anchore"
mkdir -p "$OUTPUT_DIR"

LOG_FILE="$OUTPUT_DIR/anchore-scan.log"
FILESYSTEM_RESULTS="$OUTPUT_DIR/anchore-filesystem-results.json"
SBOM_RESULTS="$OUTPUT_DIR/anchore-sbom-results.json"
POLICY_RESULTS="$OUTPUT_DIR/anchore-policy-evaluation.json"
IMAGE_RESULTS_DIR="$OUTPUT_DIR/images"
mkdir -p "$IMAGE_RESULTS_DIR"

# Logging function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Display banner
cat << 'EOF'

 █████╗ ███╗   ██╗ ██████╗██╗  ██╗ ██████╗ ██████╗ ███████╗
██╔══██╗████╗  ██║██╔════╝██║  ██║██╔═══██╗██╔══██╗██╔════╝
███████║██╔██╗ ██║██║     ███████║██║   ██║██████╔╝█████╗  
██╔══██║██║╚██╗██║██║     ██╔══██║██║   ██║██╔══██╗██╔══╝  
██║  ██║██║ ╚████║╚██████╗██║  ██║╚██████╔╝██║  ██║███████╗
╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝

Container & Software Composition Analysis

EOF

log "═══════════════════════════════════════════════════════════"
log "Starting Anchore vulnerability scan"
log "═══════════════════════════════════════════════════════════"
log "Target: $REPO_PATH"
log "Scan ID: $SCAN_ID"
log "Output Directory: $OUTPUT_DIR"
log "Scan Mode: $SCAN_MODE"
log "═══════════════════════════════════════════════════════════"

# Check Docker availability
if ! docker info > /dev/null 2>&1; then
    log "❌ ERROR: Docker is not running or not accessible"
    log "Please start Docker and try again"
    exit 1
fi

log "✅ Docker is available"

# Function to scan filesystem with Anchore (using Grype CLI)
scan_filesystem() {
    log ""
    log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    log "🔍 Scanning Filesystem with Anchore"
    log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    if [ ! -d "$REPO_PATH" ]; then
        log "⚠️  Target directory not found: $REPO_PATH"
        return 1
    fi
    
    log "ℹ Scanning directory: $REPO_PATH"
    log "ℹ This may take several minutes for large repositories..."
    
    # Run Anchore/Grype scan on filesystem
    docker run --rm \
        -v "$REPO_PATH:/scan:ro" \
        -v "$OUTPUT_DIR:/output" \
        anchore/grype:latest \
        dir:/scan \
        -o json \
        --file /output/anchore-filesystem-results.json \
        >> "$LOG_FILE" 2>&1
    
    if [ $? -eq 0 ] && [ -f "$FILESYSTEM_RESULTS" ]; then
        VULN_COUNT=$(jq -r '.matches | length' "$FILESYSTEM_RESULTS" 2>/dev/null || echo "0")
        log "✅ Filesystem scan complete: $VULN_COUNT vulnerabilities found"
        
        # Generate severity breakdown
        if command -v jq &> /dev/null && [ -f "$FILESYSTEM_RESULTS" ]; then
            CRITICAL=$(jq -r '[.matches[] | select(.vulnerability.severity=="Critical")] | length' "$FILESYSTEM_RESULTS" 2>/dev/null || echo "0")
            HIGH=$(jq -r '[.matches[] | select(.vulnerability.severity=="High")] | length' "$FILESYSTEM_RESULTS" 2>/dev/null || echo "0")
            MEDIUM=$(jq -r '[.matches[] | select(.vulnerability.severity=="Medium")] | length' "$FILESYSTEM_RESULTS" 2>/dev/null || echo "0")
            LOW=$(jq -r '[.matches[] | select(.vulnerability.severity=="Low")] | length' "$FILESYSTEM_RESULTS" 2>/dev/null || echo "0")
            
            log "  • Critical: $CRITICAL"
            log "  • High: $HIGH"
            log "  • Medium: $MEDIUM"
            log "  • Low: $LOW"
        fi
        
        return 0
    else
        log "⚠️  Filesystem scan failed or produced no results"
        return 1
    fi
}

# Function to scan SBOM with Anchore
scan_sbom() {
    log ""
    log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    log "📦 Scanning SBOM with Anchore"
    log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    # Check for existing SBOM in multiple locations
    SBOM_DIR="${SCAN_DIR}/sbom"
    SBOM_FILE=""
    
    # Priority order: Look for existing SBOM files
    if [ -f "$SBOM_DIR/sbom.json" ]; then
        SBOM_FILE="$SBOM_DIR/sbom.json"
        log "ℹ Found existing SBOM: sbom.json"
    elif [ -f "$SBOM_DIR/filesystem.json" ]; then
        SBOM_FILE="$SBOM_DIR/filesystem.json"
        log "ℹ Found existing SBOM: filesystem.json (from Grype/Syft)"
    elif [ -f "$SBOM_DIR/sbom.spdx.json" ]; then
        SBOM_FILE="$SBOM_DIR/sbom.spdx.json"
        log "ℹ Found existing SBOM: sbom.spdx.json"
    elif [ -f "$SBOM_DIR/sbom.cyclonedx.json" ]; then
        SBOM_FILE="$SBOM_DIR/sbom.cyclonedx.json"
        log "ℹ Found existing SBOM: sbom.cyclonedx.json"
    fi
    
    # If no SBOM found, generate one
    if [ -z "$SBOM_FILE" ]; then
        log "ℹ No existing SBOM found, generating new SBOM..."
        
        # Generate SBOM using Syft
        mkdir -p "$SBOM_DIR"
        docker run --rm \
            -v "$REPO_PATH:/scan:ro" \
            -v "$SBOM_DIR:/output" \
            anchore/syft:latest \
            dir:/scan \
            -o json \
            --file /output/sbom.json \
            >> "$LOG_FILE" 2>&1
        
        if [ ! -f "$SBOM_DIR/sbom.json" ]; then
            log "⚠️  Failed to generate SBOM"
            return 1
        fi
        
        SBOM_FILE="$SBOM_DIR/sbom.json"
        log "✅ SBOM generated successfully"
    fi
    
    # Scan the SBOM with Anchore/Grype
    if [ -f "$SBOM_FILE" ]; then
        log "ℹ Scanning SBOM for vulnerabilities: $(basename "$SBOM_FILE")"
        
        docker run --rm \
            -v "$(dirname "$SBOM_FILE"):/sbom:ro" \
            -v "$OUTPUT_DIR:/output" \
            anchore/grype:latest \
            "sbom:/sbom/$(basename "$SBOM_FILE")" \
            -o json \
            --file /output/anchore-sbom-results.json \
            >> "$LOG_FILE" 2>&1
        
        if [ $? -eq 0 ] && [ -f "$SBOM_RESULTS" ]; then
            VULN_COUNT=$(jq -r '.matches | length' "$SBOM_RESULTS" 2>/dev/null || echo "0")
            log "✅ SBOM scan complete: $VULN_COUNT vulnerabilities found"
            return 0
        else
            log "⚠️  SBOM scan failed"
            return 1
        fi
    else
        log "⚠️  No SBOM file found"
        return 1
    fi
}

# Function to scan container images
scan_images() {
    log ""
    log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    log "🐳 Scanning Container Images with Anchore"
    log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    # Look for docker-compose files
    COMPOSE_FILES=$(find "$REPO_PATH" -maxdepth 2 -name "docker-compose*.yml" -o -name "docker-compose*.yaml" 2>/dev/null)
    
    if [ -z "$COMPOSE_FILES" ]; then
        log "ℹ No docker-compose files found, skipping image scan"
        return 0
    fi

    # Attempt to build images defined in each compose file
    while IFS= read -r compose_file; do
        local compose_dir
        compose_dir="$(dirname "$compose_file")"
        local compose_cmd
        if docker compose version > /dev/null 2>&1; then
            compose_cmd="docker compose"
        else
            compose_cmd="docker-compose"
        fi
        log "ℹ Building images from: $compose_file"
        if (cd "$compose_dir" && $compose_cmd -f "$compose_file" build) >> "$LOG_FILE" 2>&1; then
            log "  ✅ Build succeeded: $compose_file"
        else
            log "  ⚠️  Build failed (will attempt registry pull): $compose_file"
        fi
    done <<< "$COMPOSE_FILES"

    # Extract image names from docker-compose files
    IMAGES=()
    while IFS= read -r compose_file; do
        log "ℹ Found compose file: $compose_file"
        
        # Extract images using grep and awk
        while IFS= read -r image; do
            if [ -n "$image" ] && [[ ! "$image" =~ ^\$ ]]; then
                IMAGES+=("$image")
            fi
        done < <(grep -E "^\s*image:" "$compose_file" | awk '{print $2}' | tr -d '"' | tr -d "'")
    done <<< "$COMPOSE_FILES"
    
    if [ ${#IMAGES[@]} -eq 0 ]; then
        log "ℹ No images found in docker-compose files"
        return 0
    fi
    
    log "ℹ Found ${#IMAGES[@]} image(s) to scan"
    
    # Scan each image
    local scan_count=0
    for image in "${IMAGES[@]}"; do
        log "ℹ Scanning image: $image"

        # Track whether we pulled/built this image so we can clean it up after
        local _image_was_local=true
        if ! docker image inspect "$image" > /dev/null 2>&1; then
            _image_was_local=false
            log "  ℹ Image not found locally, attempting to pull: $image"
            if docker pull "$image" >> "$LOG_FILE" 2>&1; then
                log "  ✅ Image pulled successfully: $image"
            else
                log "  ⚠️  Failed to pull image: $image"
                log "  💡 Tip: Build the image first with 'docker-compose build' or 'docker build'"
                continue
            fi
        fi

        IMAGE_SAFE_NAME=$(echo "$image" | tr '/:' '_')
        IMAGE_RESULT="$IMAGE_RESULTS_DIR/${IMAGE_SAFE_NAME}.json"

        docker run --rm \
            -v /var/run/docker.sock:/var/run/docker.sock \
            -v "$OUTPUT_DIR:/output" \
            anchore/grype:latest \
            "$image" \
            -o json \
            --file "/output/images/${IMAGE_SAFE_NAME}.json" \
            >> "$LOG_FILE" 2>&1

        if [ $? -eq 0 ] && [ -f "$IMAGE_RESULT" ]; then
            VULN_COUNT=$(jq -r '.matches | length' "$IMAGE_RESULT" 2>/dev/null || echo "0")
            log "  ✅ Scan complete: $VULN_COUNT vulnerabilities"
            ((scan_count++))
        else
            log "  ⚠️  Scan failed for $image"
        fi

        # Remove image immediately after scan to free disk space
        log "  🧹 Removing image to free disk space: $image"
        docker rmi "$image" >> "$LOG_FILE" 2>&1 || log "  ⚠️  Could not remove image (may be in use): $image"
    done
    
    if [ $scan_count -gt 0 ]; then
        log "✅ Scanned $scan_count image(s) successfully"
        return 0
    else
        log "⚠️  No images scanned - images may need to be built first"
        log "💡 Run 'docker-compose build' or 'docker build' to create images before scanning"
        return 0  # Changed from 1 to 0 - not having images to scan is not a failure
    fi
}

# Function to scan baseline/approved images
scan_base_images() {
    log ""
    log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    log "🏗️  Scanning Approved Base Images with Anchore"
    log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    if [ -z "${PRIMARY_BASELINE_IMAGE:-}" ]; then
        log "ℹ No approved base images configured, skipping"
        return 0
    fi
    
    log "ℹ Primary baseline image: $PRIMARY_BASELINE_IMAGE"

    # Check if baseline image exists locally; pull if not
    if ! docker image inspect "$PRIMARY_BASELINE_IMAGE" > /dev/null 2>&1; then
        log "ℹ Baseline image not found locally, attempting to pull: $PRIMARY_BASELINE_IMAGE"
        if docker pull "$PRIMARY_BASELINE_IMAGE" >> "$LOG_FILE" 2>&1; then
            log "✅ Baseline image pulled successfully"
        else
            log "⚠️  Failed to pull baseline image: $PRIMARY_BASELINE_IMAGE"
            return 1
        fi
    fi

    BASE_IMAGE_RESULT="$IMAGE_RESULTS_DIR/baseline-$(echo "$PRIMARY_BASELINE_IMAGE" | tr '/:' '_').json"

    docker run --rm \
        -v /var/run/docker.sock:/var/run/docker.sock \
        -v "$OUTPUT_DIR:/output" \
        anchore/grype:latest \
        "$PRIMARY_BASELINE_IMAGE" \
        -o json \
        --file "/output/images/baseline-$(echo "$PRIMARY_BASELINE_IMAGE" | tr '/:' '_').json" \
        >> "$LOG_FILE" 2>&1
    local _base_scan_exit=$?

    # Remove baseline image after scan to free disk space
    log "🧹 Removing baseline image to free disk space: $PRIMARY_BASELINE_IMAGE"
    docker rmi "$PRIMARY_BASELINE_IMAGE" >> "$LOG_FILE" 2>&1 || log "⚠️  Could not remove baseline image (may be in use): $PRIMARY_BASELINE_IMAGE"

    if [ $_base_scan_exit -eq 0 ] && [ -f "$BASE_IMAGE_RESULT" ]; then
        VULN_COUNT=$(jq -r '.matches | length' "$BASE_IMAGE_RESULT" 2>/dev/null || echo "0")
        log "✅ Baseline image scan complete: $VULN_COUNT vulnerabilities"
        return 0
    else
        log "⚠️  Baseline image scan failed"
        return 1
    fi
}

# Execute scans based on mode
SCAN_SUCCESS=0

case "$SCAN_MODE" in
    filesystem)
        scan_filesystem && SCAN_SUCCESS=1
        ;;
    images)
        scan_images && SCAN_SUCCESS=1
        ;;
    base)
        scan_base_images && SCAN_SUCCESS=1
        ;;
    all)
        # Run filesystem and SBOM scans in parallel (independent outputs)
        scan_filesystem &
        _pid_fs=$!
        scan_sbom &
        _pid_sbom=$!
        wait "$_pid_fs" || true
        wait "$_pid_sbom" || true
        # Image scans depend on docker socket; run sequentially
        scan_images
        scan_base_images
        SCAN_SUCCESS=1
        ;;
    *)
        log "❌ Unknown scan mode: $SCAN_MODE"
        log "Valid modes: filesystem, images, base, all"
        exit 1
        ;;
esac

# Generate summary
log ""
log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
log "📊 Anchore Scan Summary"
log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

TOTAL_VULNS=0

if [ -f "$FILESYSTEM_RESULTS" ]; then
    FS_VULNS=$(jq -r '.matches | length' "$FILESYSTEM_RESULTS" 2>/dev/null || echo "0")
    log "Filesystem: $FS_VULNS vulnerabilities"
    TOTAL_VULNS=$((TOTAL_VULNS + FS_VULNS))
fi

if [ -f "$SBOM_RESULTS" ]; then
    SBOM_VULNS=$(jq -r '.matches | length' "$SBOM_RESULTS" 2>/dev/null || echo "0")
    log "SBOM: $SBOM_VULNS vulnerabilities"
    TOTAL_VULNS=$((TOTAL_VULNS + SBOM_VULNS))
fi

IMAGE_COUNT=$(find "$IMAGE_RESULTS_DIR" -name "*.json" 2>/dev/null | wc -l)
if [ $IMAGE_COUNT -gt 0 ]; then
    log "Images: $IMAGE_COUNT scanned"
    for img_result in "$IMAGE_RESULTS_DIR"/*.json; do
        if [ -f "$img_result" ]; then
            IMG_VULNS=$(jq -r '.matches | length' "$img_result" 2>/dev/null || echo "0")
            TOTAL_VULNS=$((TOTAL_VULNS + IMG_VULNS))
        fi
    done
fi

log ""
log "Total Vulnerabilities: $TOTAL_VULNS"
log ""
log "Results saved to: $OUTPUT_DIR"
log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [ $SCAN_SUCCESS -eq 1 ]; then
    log "✅ Anchore scan complete!"
    exit 0
else
    log "⚠️  Anchore scan completed with warnings"
    exit 1
fi
