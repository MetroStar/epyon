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
    echo "  ANCHORE_PLATFORM    Force platform (linux/amd64, linux/arm64, linux/aarch64)"
    echo "  ANCHORE_EXCLUDE_TYPES   Exclude package types (comma-separated: python,go,java)"
    echo "  ANCHORE_SHOW_DISTRO     Show detected distro after each scan (true/false)"
    echo "  ANCHORE_SKIP_BUILD      Skip docker compose build, pull from registry (true/false)"
    echo "  ANCHORE_POLICY_MAX_CRITICAL   Critical CVEs allowed before gate STOPs (default: 0)"
    echo "  ANCHORE_POLICY_MAX_HIGH       High CVEs allowed before gate WARNs (default: 5)"
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
    echo "  - Auto-detects image architecture and runtime (Node.js/Python/Go/Java)"
    echo "  - Automatically excludes build-stage dependencies from production scans"
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
REPO_PATH=$(realpath "${REPO_PATH}" 2>/dev/null) || { echo "ERROR: Target path does not exist or is invalid: ${REPO_PATH}" >&2; exit 1; }
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

# status.json surfaces environment-dependent gaps (e.g. a baseline-image
# registry pull that fails due to missing `docker login` credentials, or an
# auto-exclusion filter removing package types) so the dashboard can explain
# *why* this run's counts differ from another environment's, instead of the
# difference being buried only in anchore-scan.log. Written once at the end
# of the script via write_status_json().
STATUS_FILE="$OUTPUT_DIR/status.json"
BASELINE_SCAN_STATUS="not_configured"
BASELINE_SCAN_REASON=""
BASELINE_IMAGE_NAME=""
BASELINE_IMAGE_SOURCE=""

# Logging function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Function to filter excluded package types from scan results
# Usage: filter_excluded_types <results_file>
filter_excluded_types() {
    local results_file="$1"
    
    # Skip if no exclusions configured or file doesn't exist
    [[ -z "$ANCHORE_EXCLUDE_TYPES" ]] && return 0
    [[ ! -f "$results_file" ]] && return 0
    
    # Convert comma-separated list to jq filter array
    local types_array
    IFS=',' read -ra types_array <<< "$ANCHORE_EXCLUDE_TYPES"
    
    # Build jq filter to exclude packages
    local filter='['
    for type in "${types_array[@]}"; do
        type=$(echo "$type" | xargs)  # trim whitespace
        # Match on artifact.type, artifact.language, or artifact.metadata.type
        filter+=".matches[] | select("
        filter+="(.artifact.type // \"\" | ascii_downcase) != \"$type\" and "
        filter+="(.artifact.language // \"\" | ascii_downcase) != \"$type\" and "
        filter+="(.artifact.metadata.type // \"\" | ascii_downcase) != \"$type\""
        filter+="),"
    done
    filter="${filter%,}]"  # remove trailing comma
    
    # Apply filter and count removed matches
    local original_count filtered_count removed_count
    original_count=$(jq -r '.matches | length' "$results_file" 2>/dev/null || echo "0")
    
    if [[ "$original_count" -gt 0 ]]; then
        local tmp_file="${results_file}.filtered"
        jq ".matches |= $filter" "$results_file" > "$tmp_file" 2>/dev/null
        
        if [[ -f "$tmp_file" ]]; then
            filtered_count=$(jq -r '.matches | length' "$tmp_file" 2>/dev/null || echo "0")
            removed_count=$((original_count - filtered_count))
            
            if [[ $removed_count -gt 0 ]]; then
                mv "$tmp_file" "$results_file"
                log "  🔧 Filtered $removed_count excluded package type(s) (${ANCHORE_EXCLUDE_TYPES})"
                return 0
            else
                rm -f "$tmp_file"
            fi
        fi
    fi
    
    return 0
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

# Ensure Docker is running (auto-starts Docker Desktop / Colima / OrbStack if needed)
ensure_docker_running
log "✅ Docker is available"

# Prefer local grype/syft installations to avoid Docker volume-mount issues on macOS
if command -v grype &>/dev/null; then
    GRYPE_CMD="grype"
    log "✅ Using local grype: $(grype version 2>/dev/null | head -1)"
else
    GRYPE_CMD="docker"
    log "ℹ Local grype not found, will use Docker image anchore/grype:latest"
fi

if command -v syft &>/dev/null; then
    SYFT_CMD="syft"
else
    SYFT_CMD="docker"
fi

# ── Platform Detection ────────────────────────────────────────────────────────
# Auto-detect platform for proper OS identification (prevents false positives)
if [[ -z "${ANCHORE_PLATFORM:-}" ]]; then
    # Auto-detect: Mac ARM64 → linux/arm64, otherwise linux/amd64
    if [[ "$(uname -s)" == "Darwin" ]] && [[ "$(uname -m)" == "arm64" ]]; then
        ANCHORE_PLATFORM="linux/arm64"
        log "ℹ Auto-detected platform: linux/arm64 (Apple Silicon)"
    else
        ANCHORE_PLATFORM="linux/amd64"
        log "ℹ Auto-detected platform: linux/amd64"
    fi
else
    log "ℹ Using configured platform: $ANCHORE_PLATFORM"
fi

# ── Package Filtering ─────────────────────────────────────────────────────────
# Exclude specific package ecosystems to reduce false positives
# Example: ANCHORE_EXCLUDE_TYPES="python,go,java" to skip build-stage deps
ANCHORE_EXCLUDE_TYPES="${ANCHORE_EXCLUDE_TYPES:-}"
if [[ -n "$ANCHORE_EXCLUDE_TYPES" ]]; then
    log "ℹ Excluding package types: $ANCHORE_EXCLUDE_TYPES"
fi

# ── Distro Detection Logging ──────────────────────────────────────────────────
ANCHORE_SHOW_DISTRO="${ANCHORE_SHOW_DISTRO:-true}"

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
    if [ "$GRYPE_CMD" = "grype" ]; then
        # grype's own --platform flag only applies to image sources
        # (docker:/registry:) — passing it for a dir: source errors with
        # "platform is not supported for this source type" and silently
        # produces an empty results file, which previously broke every
        # filesystem scan on arm64 machines (where ANCHORE_PLATFORM is
        # auto-detected and always set).
        GRYPE_ARGS=("dir:$REPO_PATH" "-o" "json" "--file" "$OUTPUT_DIR/anchore-filesystem-results.json")

        grype "${GRYPE_ARGS[@]}" >> "$LOG_FILE" 2>&1
    else
        docker run --rm \
            --platform "$ANCHORE_PLATFORM" \
            -v "$(to_host_path "$REPO_PATH"):/scan:ro" \
            -v "$(to_host_path "$OUTPUT_DIR"):/output" \
            anchore/grype:latest \
            dir:/scan \
            -o json \
            --file /output/anchore-filesystem-results.json \
            >> "$LOG_FILE" 2>&1
    fi
    
    if [ $? -eq 0 ] && [ -f "$FILESYSTEM_RESULTS" ]; then
        # Show detected distro for debugging false positives
        if [[ "$ANCHORE_SHOW_DISTRO" == "true" ]]; then
            local detected_distro
            detected_distro=$(jq -r '.distro.name // .distro.type // "unknown"' "$FILESYSTEM_RESULTS" 2>/dev/null || echo "unknown")
            local detected_version
            detected_version=$(jq -r '.distro.version // ""' "$FILESYSTEM_RESULTS" 2>/dev/null || echo "")
            log "ℹ Detected OS: $detected_distro $detected_version"
        fi
        
        VULN_COUNT=$(jq -r '.matches | length' "$FILESYSTEM_RESULTS" 2>/dev/null || echo "0")

        # Strip false-positive matches for unpinned packages (version=0.0.0)
        local zero_matches
        zero_matches=$(jq -r '[.matches[] | select(.artifact.version=="0.0.0")] | length' "$FILESYSTEM_RESULTS" 2>/dev/null || echo "0")
        if [[ "$zero_matches" -gt 0 ]]; then
            log "⚠️  Removing $zero_matches false-positive match(es) for unpinned packages (version=0.0.0)"
            jq -r '.matches[] | select(.artifact.version=="0.0.0") | "  - \(.artifact.name) \(.vulnerability.id // "")"' \
                "$FILESYSTEM_RESULTS" 2>/dev/null >> "$LOG_FILE"
            local tmp_fs="${FILESYSTEM_RESULTS}.tmp"
            jq 'del(.matches[] | select(.artifact.version=="0.0.0"))' "$FILESYSTEM_RESULTS" > "$tmp_fs" 2>/dev/null && mv "$tmp_fs" "$FILESYSTEM_RESULTS"
        fi
        
        # Filter excluded package types
        filter_excluded_types "$FILESYSTEM_RESULTS"
        
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
        if [ "$SYFT_CMD" = "syft" ]; then
            syft "dir:$REPO_PATH" \
                -o json \
                --file "$SBOM_DIR/sbom.json" \
                >> "$LOG_FILE" 2>&1
        else
            docker run --rm \
                -v "$(to_host_path "$REPO_PATH"):/scan:ro" \
                -v "$(to_host_path "$SBOM_DIR"):/output" \
                anchore/syft:latest \
                dir:/scan \
                -o json \
                --file /output/sbom.json \
                >> "$LOG_FILE" 2>&1
        fi
        
        if [ ! -f "$SBOM_DIR/sbom.json" ]; then
            log "⚠️  Failed to generate SBOM"
            return 1
        fi
        
        SBOM_FILE="$SBOM_DIR/sbom.json"
        log "✅ SBOM generated successfully"

        # Strip unpinned (0.0.0) packages from the newly-generated SBOM before
        # scanning — bare requirements entries produce false-positive matches.
        local zero_count
        zero_count=$(jq -r '[.artifacts[] | select(.version=="0.0.0")] | length' "$SBOM_FILE" 2>/dev/null || echo "0")
        if [[ "$zero_count" -gt 0 ]]; then
            log "⚠️  Removing $zero_count unpinned package(s) (version=0.0.0) from SBOM to prevent false positives"
            jq -r '.artifacts[] | select(.version=="0.0.0") | "  - \(.name) (\(.type))"' "$SBOM_FILE" 2>/dev/null >> "$LOG_FILE"
            local tmp_sbom="${SBOM_FILE}.tmp"
            jq 'del(.artifacts[] | select(.version=="0.0.0"))' "$SBOM_FILE" > "$tmp_sbom" 2>/dev/null && mv "$tmp_sbom" "$SBOM_FILE"
            log "✅ SBOM cleaned: $(jq '.artifacts | length' "$SBOM_FILE" 2>/dev/null) artifacts remaining"
        fi
    fi

    # Scan the SBOM with Anchore/Grype
    if [ -f "$SBOM_FILE" ]; then
        log "ℹ Scanning SBOM for vulnerabilities: $(basename "$SBOM_FILE")"

        if [ "$GRYPE_CMD" = "grype" ]; then
            # Same reasoning as the filesystem scan above: --platform is
            # invalid for a sbom: source and silently produces empty results.
            GRYPE_SBOM_ARGS=("sbom:$SBOM_FILE" "-o" "json" "--file" "$OUTPUT_DIR/anchore-sbom-results.json")

            grype "${GRYPE_SBOM_ARGS[@]}" >> "$LOG_FILE" 2>&1
        else
            docker run --rm \
                --platform "$ANCHORE_PLATFORM" \
                -v "$(to_host_path "$(dirname "$SBOM_FILE")"):/sbom:ro" \
                -v "$(to_host_path "$OUTPUT_DIR"):/output" \
                anchore/grype:latest \
                "sbom:/sbom/$(basename "$SBOM_FILE")" \
                -o json \
                --file /output/anchore-sbom-results.json \
                >> "$LOG_FILE" 2>&1
        fi

        if [ $? -eq 0 ] && [ -f "$SBOM_RESULTS" ]; then
            # Strip any residual 0.0.0 matches from the grype output
            # (can occur if grype scans the filesystem directly and encounters unpinned packages)
            local zero_matches
            zero_matches=$(jq -r '[.matches[] | select(.artifact.version=="0.0.0")] | length' "$SBOM_RESULTS" 2>/dev/null || echo "0")
            if [[ "$zero_matches" -gt 0 ]]; then
                log "⚠️  Removing $zero_matches false-positive match(es) for unpinned packages (version=0.0.0) from SBOM results"
                local tmp_res="${SBOM_RESULTS}.tmp"
                jq 'del(.matches[] | select(.artifact.version=="0.0.0"))' "$SBOM_RESULTS" > "$tmp_res" 2>/dev/null && mv "$tmp_res" "$SBOM_RESULTS"
            fi
            
            # Filter excluded package types
            filter_excluded_types "$SBOM_RESULTS"
            
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

# Function to auto-detect image characteristics and configure scanner
# Usage: auto_configure_scanner <image_name>
# Sets ANCHORE_PLATFORM and ANCHORE_EXCLUDE_TYPES based on image inspection
auto_configure_scanner() {
    local image="$1"
    
    # Skip if image doesn't exist locally (will be handled by pull logic)
    if ! docker image inspect "$image" > /dev/null 2>&1; then
        return 0
    fi
    
    # Detect architecture
    local arch
    arch=$(docker image inspect "$image" --format '{{.Architecture}}' 2>/dev/null || echo "amd64")
    
    # Override platform only if not already set by user
    if [[ -z "${ANCHORE_PLATFORM_OVERRIDE:-}" ]]; then
        case "$arch" in
            arm64|aarch64)
                export ANCHORE_PLATFORM="linux/arm64"
                log "  ℹ Auto-detected architecture: ARM64"
                ;;
            amd64|x86_64)
                export ANCHORE_PLATFORM="linux/amd64"
                log "  ℹ Auto-detected architecture: AMD64"
                ;;
            *)
                export ANCHORE_PLATFORM="linux/$arch"
                log "  ℹ Auto-detected architecture: $arch"
                ;;
        esac
    fi
    
    # Detect OS/distro from image labels and config
    local os_name os_family
    os_name=$(docker image inspect "$image" --format '{{index .Config.Labels "org.opencontainers.image.base.name"}}' 2>/dev/null || echo "")
    [[ -z "$os_name" ]] && os_name=$(docker image inspect "$image" --format '{{.Os}}' 2>/dev/null || echo "linux")
    
    # Try to detect distro from base image name
    if [[ "$os_name" =~ alpine ]]; then
        os_family="alpine"
    elif [[ "$os_name" =~ debian ]]; then
        os_family="debian"
    elif [[ "$os_name" =~ ubuntu ]]; then
        os_family="ubuntu"
    else
        # Try to detect from layers or image history
        local history
        history=$(docker image history --no-trunc "$image" 2>/dev/null | head -20 || echo "")
        if echo "$history" | grep -qi "alpine"; then
            os_family="alpine"
        elif echo "$history" | grep -qi "debian"; then
            os_family="debian"
        elif echo "$history" | grep -qi "ubuntu"; then
            os_family="ubuntu"
        else
            os_family="unknown"
        fi
    fi
    
    log "  ℹ Detected base OS: $os_family"
    
    # Auto-configure exclusions based on primary runtime
    # Only if user hasn't already set ANCHORE_EXCLUDE_TYPES
    if [[ -z "${ANCHORE_EXCLUDE_TYPES:-}" ]]; then
        local runtime_langs=()
        
        # Detect runtime languages from image
        local image_env
        image_env=$(docker image inspect "$image" --format '{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null || echo "")
        
        # Check for Node.js
        if echo "$image_env" | grep -q "NODE_VERSION" || \
           docker run --rm --entrypoint sh "$image" -c "which node 2>/dev/null" > /dev/null 2>&1; then
            runtime_langs+=("node")
            log "  ℹ Detected runtime: Node.js"
        fi
        
        # Check for Python
        if echo "$image_env" | grep -q "PYTHON_VERSION" || \
           docker run --rm --entrypoint sh "$image" -c "which python3 2>/dev/null || which python 2>/dev/null" > /dev/null 2>&1; then
            runtime_langs+=("python")
            log "  ℹ Detected runtime: Python"
        fi
        
        # Check for Go — both the toolchain (`go` binary) AND standalone
        # Go-compiled executables shipped without the toolchain (e.g. a
        # Python-base image that installs the Docker CLI or Helm CLI as a
        # downloaded static binary). `which go` alone misses the latter,
        # which previously caused images that genuinely ship Go binaries at
        # runtime to be misclassified as "Python-only" and have their real
        # Go-ecosystem vulnerabilities silently excluded. Go binaries embed
        # a plaintext "go1.XX" version marker regardless of toolchain
        # presence, so grep the binaries directly for it.
        if echo "$image_env" | grep -q "GOLANG_VERSION" || \
           docker run --rm --entrypoint sh "$image" -c "which go 2>/dev/null" > /dev/null 2>&1 || \
           docker run --rm --entrypoint sh "$image" -c \
               'for f in /usr/local/bin/* /usr/bin/* /bin/*; do [ -f "$f" ] && grep -aqE "go1\.[0-9]+" "$f" 2>/dev/null && exit 0; done; exit 1' \
               > /dev/null 2>&1; then
            runtime_langs+=("go")
            log "  ℹ Detected runtime: Go (toolchain or compiled binary)"
        fi

        # Check for Java — JDK/JRE presence OR any shipped .jar files, which
        # indicate a real Java runtime dependency even without `java` on PATH.
        if echo "$image_env" | grep -q "JAVA_VERSION" || \
           docker run --rm --entrypoint sh "$image" -c "which java 2>/dev/null" > /dev/null 2>&1 || \
           docker run --rm --entrypoint sh "$image" -c \
               'find / -xdev -maxdepth 6 -name "*.jar" 2>/dev/null | head -1 | grep -q .' \
               > /dev/null 2>&1; then
            runtime_langs+=("java")
            log "  ℹ Detected runtime: Java (toolchain, JRE, or shipped .jar)"
        fi
        
        # Smart exclusion: if ONLY Node.js is detected, exclude Python/Go/Java build deps
        if [[ ${#runtime_langs[@]} -eq 1 ]] && [[ "${runtime_langs[0]}" == "node" ]]; then
            export ANCHORE_EXCLUDE_TYPES="python,go,java,ruby"
            export ANCHORE_EXCLUDE_TYPES_SOURCE="auto-detected: Node.js-only runtime"
            log "  🔧 Auto-excluding build-stage deps: python,go,java,ruby (Node.js-only runtime)"
        # If ONLY Python is detected, exclude Go/Java/Node build deps
        elif [[ ${#runtime_langs[@]} -eq 1 ]] && [[ "${runtime_langs[0]}" == "python" ]]; then
            export ANCHORE_EXCLUDE_TYPES="go,java,node,ruby"
            export ANCHORE_EXCLUDE_TYPES_SOURCE="auto-detected: Python-only runtime"
            log "  🔧 Auto-excluding build-stage deps: go,java,node,ruby (Python-only runtime)"
        # If ONLY Go is detected, exclude Python/Java/Node build deps
        elif [[ ${#runtime_langs[@]} -eq 1 ]] && [[ "${runtime_langs[0]}" == "go" ]]; then
            export ANCHORE_EXCLUDE_TYPES="python,java,node,ruby"
            export ANCHORE_EXCLUDE_TYPES_SOURCE="auto-detected: Go-only runtime"
            log "  🔧 Auto-excluding build-stage deps: python,java,node,ruby (Go-only runtime)"
        # If multiple runtimes or none detected, don't auto-exclude
        else
            log "  ℹ Multiple or unknown runtimes detected ($(IFS=,; echo "${runtime_langs[*]}")), scanning all packages"
        fi
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

    # Attempt to build images defined in each compose file.
    # Set ANCHORE_SKIP_BUILD=true to skip the build step and go straight to
    # registry pull (appropriate in CI where the application build context is
    # unavailable; saves time and avoids misleading build-failure warnings).
    local build_timeout="${ANCHORE_BUILD_TIMEOUT:-300}"
    if [[ "${ANCHORE_SKIP_BUILD:-false}" == "true" ]]; then
        log "ℹ ANCHORE_SKIP_BUILD=true — skipping docker compose build, will pull images from registry"
    else
    while IFS= read -r compose_file; do
        local compose_dir
        compose_dir="$(dirname "$compose_file")"
        local compose_cmd
        if docker compose version > /dev/null 2>&1; then
            compose_cmd="docker compose"
        else
            compose_cmd="docker-compose"
        fi
        log "ℹ Building images from: $compose_file (timeout: ${build_timeout}s)"
        # --pull=false avoids re-downloading base layers that are already cached;
        # --no-cache would be slower. timeout kills hung builds cleanly.
        if (cd "$compose_dir" && timeout "$build_timeout" $compose_cmd -f "$compose_file" build --pull=false) >> "$LOG_FILE" 2>&1; then
            log "  ✅ Build succeeded: $compose_file"
        else
            local exit_code=$?
            if [ $exit_code -eq 124 ]; then
                log "  ⚠️  Build timed out after ${build_timeout}s (will attempt registry pull): $compose_file"
            else
                log "  ⚠️  Build failed (will attempt registry pull): $compose_file"
            fi
        fi
    done <<< "$COMPOSE_FILES"
    fi  # end: ANCHORE_SKIP_BUILD check

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
        
        # Auto-detect image characteristics and configure scanner
        auto_configure_scanner "$image"

        IMAGE_SAFE_NAME=$(echo "$image" | tr '/:' '_')
        IMAGE_RESULT="$IMAGE_RESULTS_DIR/${IMAGE_SAFE_NAME}.json"

        if [ "$GRYPE_CMD" = "grype" ]; then
            GRYPE_IMG_ARGS=("$image" "-o" "json" "--file" "$IMAGE_RESULTS_DIR/${IMAGE_SAFE_NAME}.json")
            [[ -n "$ANCHORE_PLATFORM" ]] && GRYPE_IMG_ARGS+=("--platform" "$ANCHORE_PLATFORM")
            
            grype "${GRYPE_IMG_ARGS[@]}" >> "$LOG_FILE" 2>&1
        else
            docker run --rm \
                --platform "$ANCHORE_PLATFORM" \
                -v /var/run/docker.sock:/var/run/docker.sock \
                -v "$(to_host_path "$OUTPUT_DIR"):/output" \
                anchore/grype:latest \
                "$image" \
                -o json \
                --file "/output/images/${IMAGE_SAFE_NAME}.json" \
                >> "$LOG_FILE" 2>&1
        fi

        if [ $? -eq 0 ] && [ -f "$IMAGE_RESULT" ]; then
            # Show detected distro for debugging false positives
            if [[ "$ANCHORE_SHOW_DISTRO" == "true" ]]; then
                local img_distro
                img_distro=$(jq -r '.distro.name // .distro.type // "unknown"' "$IMAGE_RESULT" 2>/dev/null || echo "unknown")
                local img_version
                img_version=$(jq -r '.distro.version // ""' "$IMAGE_RESULT" 2>/dev/null || echo "")
                log "  ℹ Image OS: $img_distro $img_version"
            fi
            
            # Filter excluded package types
            filter_excluded_types "$IMAGE_RESULT"
            
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

    if [ -n "${PRIMARY_BASELINE_IMAGE:-}" ]; then
        BASELINE_IMAGE_SOURCE="configured"
    else
        # No PRIMARY_BASELINE_IMAGE (not routed from a container build, and no
        # fixed PRIMARY_BASELINE_IMAGE in approved-base-images.conf) — auto-
        # discover the target's own actual Dockerfile FROM-line image instead
        # of skipping the baseline scan outright. Shared with run-trivy-
        # scan.sh via discover_dockerfile_base_images() (scan-directory-
        # template.sh) so both tools baseline against the same image(s) and
        # avoid depending on gated/irrelevant images (e.g. dhi/* tags
        # requiring a DHI registry entitlement) as the default for an
        # arbitrary repo.
        local _discovered_images=()
        mapfile -t _discovered_images < <(discover_dockerfile_base_images "$REPO_PATH")

        if [ ${#_discovered_images[@]} -gt 0 ]; then
            PRIMARY_BASELINE_IMAGE="${_discovered_images[0]}"
            BASELINE_IMAGE_SOURCE="auto-discovered from Dockerfile"
            log "📋 Auto-discovered baseline image from target's Dockerfile: $PRIMARY_BASELINE_IMAGE"
        fi
    fi

    if [ -z "${PRIMARY_BASELINE_IMAGE:-}" ]; then
        log "ℹ No approved base images configured and no Dockerfile found, skipping"
        BASELINE_SCAN_STATUS="not_configured"
        BASELINE_SCAN_REASON="No PRIMARY_BASELINE_IMAGE / approved-base-images.conf entry configured, and no Dockerfile FROM-line could be auto-discovered in this target."
        return 0
    fi

    BASELINE_IMAGE_NAME="$PRIMARY_BASELINE_IMAGE"
    log "ℹ Primary baseline image: $PRIMARY_BASELINE_IMAGE"

    # Check if baseline image exists locally; pull if not
    if ! docker image inspect "$PRIMARY_BASELINE_IMAGE" > /dev/null 2>&1; then
        log "ℹ Baseline image not found locally, attempting to pull: $PRIMARY_BASELINE_IMAGE"
        local _pull_output _pull_status
        _pull_output="$(docker pull "$PRIMARY_BASELINE_IMAGE" 2>&1)"
        _pull_status=$?
        echo "$_pull_output" >> "$LOG_FILE"
        if [ $_pull_status -eq 0 ]; then
            log "✅ Baseline image pulled successfully"
        else
            log "⚠️  Failed to pull baseline image: $PRIMARY_BASELINE_IMAGE"
            # Surfaced to the dashboard: classify the ACTUAL docker error
            # instead of always guessing "missing registry credentials" —
            # misleading for genuinely public images, whose most common pull
            # failure on shared CI runners is Docker Hub's anonymous-pull rate
            # limit, not a per-image access problem.
            BASELINE_SCAN_STATUS="failed_pull"
            BASELINE_SCAN_REASON="$(classify_docker_pull_failure "$PRIMARY_BASELINE_IMAGE" "$_pull_output") Baseline OS-level CVEs were NOT included in this run's totals."
            return 1
        fi
    fi
    
    # Auto-detect image characteristics and configure scanner
    auto_configure_scanner "$PRIMARY_BASELINE_IMAGE"

    BASE_IMAGE_RESULT="$IMAGE_RESULTS_DIR/baseline-$(echo "$PRIMARY_BASELINE_IMAGE" | tr '/:' '_').json"

    if [ "$GRYPE_CMD" = "grype" ]; then
        GRYPE_BASE_ARGS=("$PRIMARY_BASELINE_IMAGE" "-o" "json" "--file" "$BASE_IMAGE_RESULT")
        [[ -n "$ANCHORE_PLATFORM" ]] && GRYPE_BASE_ARGS+=("--platform" "$ANCHORE_PLATFORM")
        
        grype "${GRYPE_BASE_ARGS[@]}" >> "$LOG_FILE" 2>&1
        local _base_scan_exit=$?
    else
        docker run --rm \
            --platform "$ANCHORE_PLATFORM" \
            -v /var/run/docker.sock:/var/run/docker.sock \
            -v "$(to_host_path "$OUTPUT_DIR"):/output" \
            anchore/grype:latest \
            "$PRIMARY_BASELINE_IMAGE" \
            -o json \
            --file "/output/images/baseline-$(echo "$PRIMARY_BASELINE_IMAGE" | tr '/:' '_').json" \
            >> "$LOG_FILE" 2>&1
        local _base_scan_exit=$?
    fi

    # Remove baseline image after scan to free disk space
    log "🧹 Removing baseline image to free disk space: $PRIMARY_BASELINE_IMAGE"
    docker rmi "$PRIMARY_BASELINE_IMAGE" >> "$LOG_FILE" 2>&1 || log "⚠️  Could not remove baseline image (may be in use): $PRIMARY_BASELINE_IMAGE"

    if [ $_base_scan_exit -eq 0 ] && [ -f "$BASE_IMAGE_RESULT" ]; then
        VULN_COUNT=$(jq -r '.matches | length' "$BASE_IMAGE_RESULT" 2>/dev/null || echo "0")
        log "✅ Baseline image scan complete: $VULN_COUNT vulnerabilities"
        BASELINE_SCAN_STATUS="success"
        BASELINE_SCAN_REASON=""
        return 0
    else
        log "⚠️  Baseline image scan failed"
        BASELINE_SCAN_STATUS="scan_failed"
        BASELINE_SCAN_REASON="Baseline image was pulled but the grype scan of $PRIMARY_BASELINE_IMAGE did not complete successfully; see anchore-scan.log."
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

# ── Policy Evaluation (this is what differentiates "Anchore" from a plain
# Grype re-run: a pass/warn/stop compliance gate applied to the combined
# vulnerability data, mirroring Anchore Engine's classic policy bundle
# behavior). Aggregates severities across every result file this scan
# produced and writes anchore-policy-evaluation.json — a distinct artifact
# from anchore-filesystem-results.json / anchore-sbom-results.json, and the
# file the dashboard/self-assessment treat as this layer's source of truth.
write_policy_evaluation() {
    local max_critical="${ANCHORE_POLICY_MAX_CRITICAL:-0}"
    local max_high="${ANCHORE_POLICY_MAX_HIGH:-5}"
    local result_files=()
    [ -f "$FILESYSTEM_RESULTS" ] && result_files+=("$FILESYSTEM_RESULTS")
    [ -f "$SBOM_RESULTS" ] && result_files+=("$SBOM_RESULTS")
    if [ -d "$IMAGE_RESULTS_DIR" ]; then
        while IFS= read -r -d '' f; do
            result_files+=("$f")
        done < <(find "$IMAGE_RESULTS_DIR" -name "*.json" -print0 2>/dev/null)
    fi

    if [ ${#result_files[@]} -eq 0 ]; then
        log "⚠️  No result files available — skipping policy evaluation"
        return
    fi

    local critical_count high_count medium_count low_count
    critical_count=$(jq -s '[.[].matches[]? | select(.vulnerability.severity == "Critical")] | length' "${result_files[@]}" 2>/dev/null || echo "0")
    high_count=$(jq -s '[.[].matches[]? | select(.vulnerability.severity == "High")] | length' "${result_files[@]}" 2>/dev/null || echo "0")
    medium_count=$(jq -s '[.[].matches[]? | select(.vulnerability.severity == "Medium")] | length' "${result_files[@]}" 2>/dev/null || echo "0")
    low_count=$(jq -s '[.[].matches[]? | select(.vulnerability.severity == "Low")] | length' "${result_files[@]}" 2>/dev/null || echo "0")
    critical_count=${critical_count:-0}; high_count=${high_count:-0}
    medium_count=${medium_count:-0}; low_count=${low_count:-0}

    local gate_action="go"
    local critical_rule_result="pass"
    local high_rule_result="pass"
    if [ "$critical_count" -gt "$max_critical" ]; then
        gate_action="stop"
        critical_rule_result="fail"
    elif [ "$high_count" -gt "$max_high" ]; then
        gate_action="warn"
        high_rule_result="fail"
    fi

    jq -n \
        --arg gate_action "$gate_action" \
        --argjson critical_count "$critical_count" \
        --argjson high_count "$high_count" \
        --argjson medium_count "$medium_count" \
        --argjson low_count "$low_count" \
        --argjson max_critical "$max_critical" \
        --argjson max_high "$max_high" \
        --arg critical_rule_result "$critical_rule_result" \
        --arg high_rule_result "$high_rule_result" \
        '{
            gate_action: $gate_action,
            severity_counts: {
                critical: $critical_count,
                high: $high_count,
                medium: $medium_count,
                low: $low_count
            },
            rules_evaluated: [
                {
                    rule: "max_critical_vulnerabilities",
                    threshold: $max_critical,
                    actual: $critical_count,
                    result: $critical_rule_result,
                    gate_action: (if $critical_rule_result == "fail" then "stop" else "go" end)
                },
                {
                    rule: "max_high_vulnerabilities",
                    threshold: $max_high,
                    actual: $high_count,
                    result: $high_rule_result,
                    gate_action: (if $high_rule_result == "fail" then "warn" else "go" end)
                }
            ]
        }' > "$POLICY_RESULTS"

    log "📋 Policy Evaluation: gate_action=$gate_action (critical=$critical_count, high=$high_count, medium=$medium_count, low=$low_count)"
}

write_policy_evaluation

# Surface environment-dependent gaps in status.json so the web UI can warn
# that this run's totals may be lower than another environment's for reasons
# unrelated to the target's actual security posture (registry access gaps,
# auto-exclusion filters), rather than that difference only existing buried
# in anchore-scan.log.
write_status_json() {
    jq -n \
        --arg baseline_image "$BASELINE_IMAGE_NAME" \
        --arg baseline_status "$BASELINE_SCAN_STATUS" \
        --arg baseline_reason "$BASELINE_SCAN_REASON" \
        --arg baseline_source "${BASELINE_IMAGE_SOURCE:-}" \
        --arg exclude_types "${ANCHORE_EXCLUDE_TYPES:-}" \
        --arg exclude_source "${ANCHORE_EXCLUDE_TYPES_SOURCE:-}" \
        '{
            baseline_image: $baseline_image,
            baseline_scan_status: $baseline_status,
            baseline_scan_reason: $baseline_reason,
            baseline_image_source: $baseline_source,
            exclude_types_applied: (if $exclude_types == "" then [] else ($exclude_types | split(",")) end),
            exclude_types_source: $exclude_source
        }' > "$STATUS_FILE" 2>/dev/null || true
}

write_status_json

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
