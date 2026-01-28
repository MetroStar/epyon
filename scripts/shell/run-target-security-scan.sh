#!/bin/bash

# Target-Aware Complete Security Scan Orchestration Script
# Runs all ten security layers with multi-target scanning capabilities on external directories
# Usage: ./run-target-security-scan.sh <target_directory> [quick|full|images|analysis]

# Note: set -e removed to allow graceful error handling in security pipeline

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Display EPYON banner
echo -e "${CYAN}"
cat << "EOF"
███████╗██████╗ ██╗   ██╗ ██████╗ ███╗   ██╗
██╔════╝██╔══██╗╚██╗ ██╔╝██╔═══██╗████╗  ██║
█████╗  ██████╔╝ ╚████╔╝ ██║   ██║██╔██╗ ██║
██╔══╝  ██╔═══╝   ╚██╔╝  ██║   ██║██║╚██╗██║
███████╗██║        ██║   ╚██████╔╝██║ ╚████║
╚══════╝╚═╝        ╚═╝    ╚═════╝ ╚═╝  ╚═══╝
EOF
echo -e "${NC}"
echo -e "${GREEN}Absolute Security Control${NC}"
echo ""

# Help function
show_help() {
    echo -e "${GREEN}Ten-Layer Security Scan Orchestrator${NC}"
    echo ""
    echo "Usage: $0 [OPTIONS] <TARGET> [SCAN_TYPE]"
    echo ""
    echo "Comprehensive security scanning orchestrator that runs all security tools"
    echo "in a coordinated manner on any target directory or Git repository."
    echo ""
    echo "Arguments:"
    echo "  TARGET              Path to directory OR Git repository URL (REQUIRED)"
    echo "  SCAN_TYPE           Type of scan to run (default: full)"
    echo ""
    echo "Options:"
    echo "  -h, --help          Show this help message and exit"
    echo ""
    echo "Target Types:"
    echo "  Local Directory     /path/to/project or ./project"
    echo "  Git HTTPS           https://github.com/user/repo.git"
    echo "  Git SSH             git@github.com:user/repo.git"
    echo ""
    echo "Scan Types:"
    echo "  quick       Fast scan - Trivy, TruffleHog, basic checks"
    echo "  full        Complete scan - All 11 security layers (default)"
    echo "  images      Container-focused - Image vulnerability scanning"
    echo "  analysis    Code analysis - SonarQube, Checkov, quality checks"
    echo ""
    echo "Security Layers:"
    echo "  Layer 1:  Container Security (Trivy)"
    echo "  Layer 2:  Vulnerability Scanning (Grype)"
    echo "  Layer 3:  Secret Detection (TruffleHog)"
    echo "  Layer 4:  Malware Detection (ClamAV)"
    echo "  Layer 5:  IaC Security (Checkov)"
    echo "  Layer 6:  SBOM Generation (Syft)"
    echo "  Layer 7:  Code Quality (SonarQube)"
    echo "  Layer 8:  Helm Validation"
    echo "  Layer 9:  EOL Detection (Xeol)"
    echo "  Layer 10: Container Analysis (Anchore)"
    echo "  Layer 11: API Discovery (OpenAPI, REST, GraphQL)"
    echo ""
    echo "Output:"
    echo "  Results saved to: scans/{TARGET}_{USER}_{TIMESTAMP}/"
    echo "  - Individual tool subdirectories"
    echo "  - Consolidated reports and dashboard"
    echo "  - Security findings summary"
    echo ""
    echo "Examples:"
    echo "  # Local directory scans"
    echo "  $0 /path/to/project                              # Full scan"
    echo "  $0 /path/to/project quick                        # Quick scan"
    echo "  $0 '/path/with spaces/project' full              # Path with spaces"
    echo "  $0 ./my-app images                               # Image-focused scan"
    echo ""
    echo "  # Git repository scans"
    echo "  $0 https://github.com/user/repo.git              # Clone & scan"
    echo "  $0 git@github.com:user/private-repo.git full     # SSH clone & scan"
    echo ""
    echo "Notes:"
    echo "  - Requires Docker for most scanners"
    echo "  - Git repositories are cloned with --depth 1 for speed"
    echo "  - Cloned repositories are automatically cleaned up after scan"
    echo "  - Creates timestamped scan directory"
    echo "  - Generates interactive HTML dashboard"
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

# Configuration
TARGET_INPUT="$1"
SCAN_TYPE="${2:-full}"
# Get the script's directory to locate security tools
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
USERNAME=$(whoami)
TIMESTAMP=$(date '+%Y-%m-%d_%H-%M-%S')

# Flag to track if we cloned a repo (for cleanup)
CLONED_REPO=false
CLONE_DIR=""

# Validate inputs
if [[ -z "$TARGET_INPUT" ]]; then
    echo -e "${RED}❌ Error: Target directory or Git URL is required${NC}"
    echo "Usage: $0 <target_directory|git_url> [quick|full|images|analysis]"
    echo ""
    echo "Examples:"
    echo "  $0 '/Users/rnelson/Desktop/my-project' full"
    echo "  $0 './my-project' quick"
    echo "  $0 'https://github.com/user/repo.git' full"
    echo "  $0 'git@github.com:user/repo.git' images"
    exit 1
fi

# Determine if target is a Git URL or directory
if [[ "$TARGET_INPUT" =~ ^(https?://|git@|ssh://) ]] || [[ "$TARGET_INPUT" =~ \.git$ ]]; then
    echo -e "${CYAN}🔗 Git repository detected${NC}"
    echo -e "   URL: $TARGET_INPUT"
    
    # Extract repo name from URL
    REPO_NAME=$(basename "$TARGET_INPUT" .git)
    
    # Create temporary clone directory
    CLONE_DIR="$REPO_ROOT/scans/.tmp-clones/$REPO_NAME-$TIMESTAMP"
    mkdir -p "$CLONE_DIR"
    
    echo -e "${CYAN}📥 Cloning repository...${NC}"
    if git clone --depth 1 "$TARGET_INPUT" "$CLONE_DIR" 2>&1; then
        echo -e "${GREEN}✅ Repository cloned successfully${NC}"
        TARGET_DIR="$CLONE_DIR"
        TARGET_NAME="$REPO_NAME"
        CLONED_REPO=true
    else
        echo -e "${RED}❌ Error: Failed to clone repository${NC}"
        rm -rf "$CLONE_DIR"
        exit 1
    fi
elif [[ -d "$TARGET_INPUT" ]]; then
    # It's a directory path
    TARGET_DIR=$(realpath "$TARGET_INPUT" 2>/dev/null || (cd "$TARGET_INPUT" && pwd))
    TARGET_NAME=$(basename "$TARGET_DIR")
else
    echo -e "${RED}❌ Error: Target is neither a valid directory nor a Git URL${NC}"
    echo -e "   Provided: $TARGET_INPUT"
    exit 1
fi

SCAN_ID="${TARGET_NAME}_${USERNAME}_${TIMESTAMP}"

# Create dedicated scan directory
REPORTS_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
SCAN_DIR="$REPORTS_ROOT/scans/$SCAN_ID"
mkdir -p "$SCAN_DIR"

# Export variables for all child scripts
export SCAN_ID
export SCAN_DIR

# ============================================
# DOCKER VALIDATION AND STARTUP
# ============================================
echo -e "${CYAN}🐳 Checking Docker Status...${NC}"

check_docker_running() {
    docker info &>/dev/null
    return $?
}

start_docker() {
    echo -e "${YELLOW}⏳ Attempting to start Docker...${NC}"
    
    # Detect Docker runtime
    local docker_runtime="unknown"
    if docker context ls 2>/dev/null | grep -q "colima"; then
        docker_runtime="Colima"
    elif docker context ls 2>/dev/null | grep -q "desktop-linux"; then
        docker_runtime="Docker Desktop"
    elif docker context ls 2>/dev/null | grep -q "rancher-desktop"; then
        docker_runtime="Rancher Desktop"
    elif docker context ls 2>/dev/null | grep -q "orbstack"; then
        docker_runtime="OrbStack"
    elif command -v systemctl &>/dev/null && systemctl is-active docker &>/dev/null 2>&1; then
        docker_runtime="Docker Engine"
    fi
    
    # macOS - Try to start various Docker runtimes
    if [[ "$(uname)" == "Darwin" ]]; then
        # Try Colima first (most common alternative)
        if command -v colima &>/dev/null; then
            echo -e "${YELLOW}   Detected Colima, attempting to start...${NC}"
            colima start 2>/dev/null
            sleep 3
        fi
        
        # Try Docker Desktop if it exists
        if [[ -d "/Applications/Docker.app" ]]; then
            echo -e "${YELLOW}   Detected Docker Desktop, attempting to start...${NC}"
            open -a Docker 2>/dev/null
        fi
        
        # Try Rancher Desktop if it exists
        if [[ -d "/Applications/Rancher Desktop.app" ]]; then
            echo -e "${YELLOW}   Detected Rancher Desktop, attempting to start...${NC}"
            open -a "Rancher Desktop" 2>/dev/null
        fi
        
        # Try OrbStack if it exists
        if [[ -d "/Applications/OrbStack.app" ]]; then
            echo -e "${YELLOW}   Detected OrbStack, attempting to start...${NC}"
            open -a OrbStack 2>/dev/null
        fi
        
        # Wait for Docker to become available
        echo -n "   Waiting for Docker to start"
        local max_wait=60
        local waited=0
        
        while ! check_docker_running; do
            if [[ $waited -ge $max_wait ]]; then
                echo ""
                echo -e "${RED}❌ Docker failed to start within ${max_wait} seconds${NC}"
                echo -e "${YELLOW}💡 Please start your Docker runtime manually:${NC}"
                echo -e "${YELLOW}   - Docker Desktop: open -a Docker${NC}"
                echo -e "${YELLOW}   - Colima: colima start${NC}"
                echo -e "${YELLOW}   - Rancher Desktop: open -a 'Rancher Desktop'${NC}"
                echo -e "${YELLOW}   - OrbStack: open -a OrbStack${NC}"
                exit 1
            fi
            echo -n "."
            sleep 2
            waited=$((waited + 2))
        done
        echo ""
        echo -e "${GREEN}✅ Docker is now running ($docker_runtime)${NC}"
        
    # Linux - Try to start Docker Engine service
    elif [[ "$(uname)" == "Linux" ]]; then
        if command -v systemctl &>/dev/null; then
            echo -e "${YELLOW}   Starting Docker Engine service...${NC}"
            sudo systemctl start docker 2>/dev/null
            sleep 3
            if check_docker_running; then
                echo -e "${GREEN}✅ Docker service started${NC}"
            else
                echo -e "${RED}❌ Failed to start Docker service${NC}"
                echo -e "${YELLOW}💡 Try manually: sudo systemctl start docker${NC}"
                exit 1
            fi
        else
            echo -e "${RED}❌ Docker is not running and cannot be auto-started${NC}"
            echo -e "${YELLOW}💡 Please start Docker manually and try again${NC}"
            exit 1
        fi
    else
        echo -e "${RED}❌ Docker is not running${NC}"
        echo -e "${YELLOW}💡 Please start Docker and try again${NC}"
        exit 1
    fi
}

# Check if Docker is installed
if ! command -v docker &>/dev/null; then
    echo -e "${RED}❌ Error: Docker is not installed${NC}"
    echo -e "${YELLOW}💡 Install options:${NC}"
    echo -e "${YELLOW}   - Docker Engine: https://docs.docker.com/engine/install/${NC}"
    echo -e "${YELLOW}   - Docker Desktop: https://docker.com${NC}"
    echo -e "${YELLOW}   - Colima (macOS): brew install colima docker${NC}"
    echo -e "${YELLOW}   - Rancher Desktop: https://rancherdesktop.io/${NC}"
    exit 1
fi

# Check if Docker daemon is running
if check_docker_running; then
    echo -e "${GREEN}✅ Docker is running${NC}"
else
    echo -e "${YELLOW}⚠️  Docker is not running${NC}"
    start_docker
fi

# Verify Docker is working with a quick test
echo -n "   Verifying Docker connectivity... "
if docker ps &>/dev/null; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${RED}FAILED${NC}"
    echo -e "${RED}❌ Docker is running but not responding properly${NC}"
    exit 1
fi

echo ""

# Load approved base images configuration
CONFIG_DIR="$REPO_ROOT/configuration"
DEFAULT_BASELINE="dhi/caddy:debian-13-2-fips-dev@sha256:ba86d16733750c6fd7b8866981016d2479e234c842d77413f1bf41c4404e555c"

echo -e "${CYAN}🔧 Baseline Image Configuration${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${YELLOW}Which baseline image would you like to use?${NC}"
echo -e "  1) ${GREEN}dhi/caddy:debian-13-2-fips-dev${NC} (default - Docker Hardened with FIPS)"
echo -e "  2) bitnami/node:latest (JavaScript/TypeScript)"
echo -e "  3) bitnami/nginx:latest (Web server)"
echo -e "  4) bitnami/python:latest (Python applications)"
echo -e "  5) bitnami/postgresql:latest (Database)"
echo -e "  6) Custom image"
echo ""
echo -e "${CYAN}Default will be selected in 60 seconds: dhi/caddy:debian-13-2-fips-dev${NC}"
echo -n "Enter choice [1-6] or press Enter for default: "

# Read with 60 second timeout
USER_CHOICE=""
if read -t 60 USER_CHOICE; then
    case "$USER_CHOICE" in
        2)
            BASELINE_IMAGE="bitnami/node:latest"
            echo -e "${GREEN}✓ Selected: bitnami/node:latest${NC}"
            ;;
        3)
            BASELINE_IMAGE="bitnami/nginx:latest"
            echo -e "${GREEN}✓ Selected: bitnami/nginx:latest${NC}"
            ;;
        4)
            BASELINE_IMAGE="bitnami/python:latest"
            echo -e "${GREEN}✓ Selected: bitnami/python:latest${NC}"
            ;;
        5)
            BASELINE_IMAGE="bitnami/postgresql:latest"
            echo -e "${GREEN}✓ Selected: bitnami/postgresql:latest${NC}"
            ;;
        6)
            echo -n "Enter custom image (e.g., nginx:alpine, ubuntu:22.04): "
            read -t 60 CUSTOM_IMAGE
            if [ -n "$CUSTOM_IMAGE" ]; then
                BASELINE_IMAGE="$CUSTOM_IMAGE"
                echo -e "${GREEN}✓ Selected: $CUSTOM_IMAGE${NC}"
            else
                echo -e "${YELLOW}⚠️  No input - using default: $DEFAULT_BASELINE${NC}"
                BASELINE_IMAGE="$DEFAULT_BASELINE"
            fi
            ;;
        ""|1)
            BASELINE_IMAGE="$DEFAULT_BASELINE"
            echo -e "${GREEN}✓ Using default: dhi/caddy:debian-13-2-fips-dev${NC}"
            ;;
        *)
            echo -e "${YELLOW}⚠️  Invalid choice - using default: $DEFAULT_BASELINE${NC}"
            BASELINE_IMAGE="$DEFAULT_BASELINE"
            ;;
    esac
else
    # Timeout occurred
    echo ""
    echo -e "${YELLOW}⏱️  Timeout - using default: dhi/caddy:debian-13-2-fips-dev${NC}"
    BASELINE_IMAGE="$DEFAULT_BASELINE"
fi

echo ""

# Export PRIMARY_BASELINE_IMAGE for child scripts to use
export PRIMARY_BASELINE_IMAGE="$BASELINE_IMAGE"

echo -e "${GREEN}✅ Using selected baseline image${NC}"
echo -e "${CYAN}   Primary baseline: ${PRIMARY_BASELINE_IMAGE}${NC}"

# Validate that selected image is available if config exists
if [ -f "$CONFIG_DIR/approved-base-images.conf" ]; then
    echo ""
    echo -e "${CYAN}🔍 Validating Selected Base Image${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    # Validate primary baseline
    validate_latest_image "$PRIMARY_BASELINE_IMAGE"
    echo ""
fi

echo "============================================"
echo "🛡️  Ten-Layer Security Scan Orchestrator"
echo "============================================"
echo "Security Tools Dir: $REPO_ROOT"
echo "Target Directory: $TARGET_DIR"
echo "Scan Type: $SCAN_TYPE"
echo "Scan ID: $SCAN_ID"
echo "Scan Directory: $SCAN_DIR"
echo "Timestamp: $(date)"
echo ""

# Display comprehensive file analysis for transparency
echo -e "${CYAN}📊 Target Directory Analysis${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Count total files (excluding common dependency directories)
TOTAL_FILES=$(find "$TARGET_DIR" -type f \
    -not -path "*/node_modules/*" \
    -not -path "*/.git/*" \
    -not -path "*/venv/*" \
    -not -path "*/__pycache__/*" \
    -not -path "*/dist/*" \
    -not -path "*/build/*" \
    2>/dev/null | wc -l | tr -d ' ')

# Count specific file types
JS_FILES=$(find "$TARGET_DIR" -type f \( -name "*.js" -o -name "*.jsx" -o -name "*.ts" -o -name "*.tsx" \) \
    -not -path "*/node_modules/*" 2>/dev/null | wc -l | tr -d ' ')
PY_FILES=$(find "$TARGET_DIR" -type f -name "*.py" -not -path "*/venv/*" -not -path "*/__pycache__/*" 2>/dev/null | wc -l | tr -d ' ')
YAML_FILES=$(find "$TARGET_DIR" -type f \( -name "*.yaml" -o -name "*.yml" \) 2>/dev/null | wc -l | tr -d ' ')
TF_FILES=$(find "$TARGET_DIR" -type f -name "*.tf" 2>/dev/null | wc -l | tr -d ' ')
DOCKER_FILES=$(find "$TARGET_DIR" -type f -name "Dockerfile*" 2>/dev/null | wc -l | tr -d ' ')
SHELL_FILES=$(find "$TARGET_DIR" -type f \( -name "*.sh" -o -name "*.bash" \) 2>/dev/null | wc -l | tr -d ' ')
JSON_FILES=$(find "$TARGET_DIR" -type f -name "*.json" -not -path "*/node_modules/*" 2>/dev/null | wc -l | tr -d ' ')

echo -e "   📁 Total Files to Scan: ${WHITE}$TOTAL_FILES${NC}"
echo ""
echo -e "   ${WHITE}File Type Breakdown:${NC}"
[[ $JS_FILES -gt 0 ]] && echo -e "   • JavaScript/TypeScript: $JS_FILES files"
[[ $PY_FILES -gt 0 ]] && echo -e "   • Python: $PY_FILES files"
[[ $YAML_FILES -gt 0 ]] && echo -e "   • YAML/YML: $YAML_FILES files"
[[ $JSON_FILES -gt 0 ]] && echo -e "   • JSON: $JSON_FILES files"
[[ $TF_FILES -gt 0 ]] && echo -e "   • Terraform: $TF_FILES files"
[[ $DOCKER_FILES -gt 0 ]] && echo -e "   • Dockerfiles: $DOCKER_FILES files"
[[ $SHELL_FILES -gt 0 ]] && echo -e "   • Shell Scripts: $SHELL_FILES files"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Save scan metadata to JSON for dashboard use
SCAN_METADATA_FILE="$SCAN_DIR/scan-metadata.json"
cat > "$SCAN_METADATA_FILE" << EOF
{
  "scan_id": "$SCAN_ID",
  "target_directory": "$TARGET_DIR",
  "target_name": "$TARGET_NAME",
  "scan_type": "$SCAN_TYPE",
  "scan_user": "$USERNAME",
  "scan_timestamp": "$(date -u '+%Y-%m-%dT%H:%M:%SZ')",
  "scan_timestamp_local": "$(date '+%Y-%m-%d %H:%M:%S %Z')",
  "file_statistics": {
    "total_files": $TOTAL_FILES,
    "javascript_typescript": $JS_FILES,
    "python": $PY_FILES,
    "yaml_yml": $YAML_FILES,
    "json": $JSON_FILES,
    "terraform": $TF_FILES,
    "dockerfiles": $DOCKER_FILES,
    "shell_scripts": $SHELL_FILES
  }
}
EOF
echo -e "${GREEN}📄 Scan metadata saved to: $SCAN_METADATA_FILE${NC}"
echo ""

# Export TARGET_DIR for all child scripts
export TARGET_DIR

# Function to print section headers
print_section() {
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}🔹 $1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

# Function to run security tools with target directory
run_security_tool() {
    local tool_name="$1"
    local script_path="$2"
    local args="$3"
    
    echo -e "${YELLOW}🔍 Running $tool_name...${NC}"
    echo "Command: $script_path $args"
    echo "Target: $TARGET_DIR"
    echo "Started: $(date)"
    echo ""
    
    if [[ -x "$script_path" ]]; then
        # Change to security tools directory to run scripts
        cd "$REPO_ROOT"
        
        if [[ -n "$args" ]]; then
            env TARGET_DIR="$TARGET_DIR" SCAN_ID="$SCAN_ID" SCAN_DIR="$SCAN_DIR" PRIMARY_BASELINE_IMAGE="${PRIMARY_BASELINE_IMAGE:-}" "$script_path" $args
        else
            env TARGET_DIR="$TARGET_DIR" SCAN_ID="$SCAN_ID" SCAN_DIR="$SCAN_DIR" PRIMARY_BASELINE_IMAGE="${PRIMARY_BASELINE_IMAGE:-}" "$script_path"
        fi
        
        if [[ $? -eq 0 ]]; then
            echo -e "${GREEN}✅ $tool_name completed successfully${NC}"
        else
            echo -e "${YELLOW}⚠️  $tool_name completed with warnings${NC}"
        fi
    else
        echo -e "${RED}❌ $tool_name script not found or not executable: $script_path${NC}"
        return 1
    fi
    echo ""
}

# Function to run npm security commands with target
run_npm_command() {
    local command_name="$1"
    local npm_command="$2"
    
    echo -e "${YELLOW}🔍 Running $command_name...${NC}"
    echo "Command: npm run $npm_command"
    echo "Target: $TARGET_DIR"
    echo "Started: $(date)"
    echo ""
    
    cd "$REPO_ROOT"
    
    if TARGET_DIR="$TARGET_DIR" npm run "$npm_command"; then
        echo -e "${GREEN}✅ $command_name completed successfully${NC}"
    else
        echo -e "${RED}❌ $command_name failed or not available${NC}"
        return 1
    fi
    echo ""
}

# Validate target directory content
print_section "Target Directory Analysis"
echo -e "${CYAN}📂 Analyzing target directory...${NC}"
echo "Directory: $TARGET_DIR"
echo "Size: $(du -sh "$TARGET_DIR" | cut -f1)"
echo "Files: $(find "$TARGET_DIR" -type f | wc -l | xargs)"

if [[ -f "$TARGET_DIR/package.json" ]]; then
    echo -e "${GREEN}✅ Node.js project detected${NC}"
    echo "Package: $(cat "$TARGET_DIR/package.json" | jq -r '.name // "Unknown"' 2>/dev/null || echo "Unknown")"
    echo "Version: $(cat "$TARGET_DIR/package.json" | jq -r '.version // "Unknown"' 2>/dev/null || echo "Unknown")"
fi

if [[ -f "$TARGET_DIR/Dockerfile" ]]; then
    echo -e "${GREEN}✅ Docker project detected${NC}"
fi

if [[ -d "$TARGET_DIR/.git" ]]; then
    echo -e "${GREEN}✅ Git repository detected${NC}"
fi

echo ""

# Main security scan execution
case "$SCAN_TYPE" in
    "quick")
        print_section "Quick Security Scan (Core Tools Only) - Target: $(basename "$TARGET_DIR")"
        
        # SBOM first - foundation for vulnerability scanning (with dependency installation)
        run_security_tool "Complete SBOM Generation" "$SCRIPT_DIR/run-complete-sbom-scan.sh"
        export SBOM_FILE="$SCAN_DIR/sbom/filesystem.json"
        
        # Core security tools
        run_security_tool "TruffleHog Secret Detection" "$SCRIPT_DIR/run-trufflehog-scan.sh" "filesystem"
        run_security_tool "Grype Vulnerability Scanning (SBOM)" "$SCRIPT_DIR/run-grype-scan.sh" "sbom"
        run_security_tool "Trivy Security Analysis" "$SCRIPT_DIR/run-trivy-scan.sh" "filesystem"
        run_security_tool "ClamAV Antivirus Scan" "$SCRIPT_DIR/run-clamav-scan.sh"
        ;;
        
    "images")
        print_section "Container Image Security Scan (All Image Types) - Target: $(basename "$TARGET_DIR")"
        
        # Multi-target container image scanning
        run_security_tool "TruffleHog Container Images" "$SCRIPT_DIR/run-trufflehog-scan.sh" "images"
        run_security_tool "Grype Container Images" "$SCRIPT_DIR/run-grype-scan.sh" "images"
        run_security_tool "Grype Base Images" "$SCRIPT_DIR/run-grype-scan.sh" "base"
        run_security_tool "Trivy Container Images" "$SCRIPT_DIR/run-trivy-scan.sh" "images"
        run_security_tool "Trivy Base Images" "$SCRIPT_DIR/run-trivy-scan.sh" "base"
        run_security_tool "Xeol End-of-Life Detection" "$SCRIPT_DIR/run-xeol-scan.sh"
        ;;
        
    "analysis")
        print_section "Security Analysis & Reporting - Target: $(basename "$TARGET_DIR")"
        
        # Analysis mode - code analysis tools only
        echo -e "${BLUE}📊 Running code analysis and security reporting...${NC}"
        echo -e "${YELLOW}ℹ️  Analysis mode focuses on code quality and API discovery${NC}"
        echo ""
        
        echo -e "${PURPLE}📊 Code Quality Analysis${NC}"
        run_security_tool "SonarQube Analysis" "$SCRIPT_DIR/run-sonar-analysis.sh"
        
        echo -e "${PURPLE}☸️  Infrastructure Security${NC}"
        run_security_tool "Checkov IaC Security" "$SCRIPT_DIR/run-checkov-scan.sh"
        
        echo -e "${PURPLE}🌐 API Discovery${NC}"
        run_security_tool "API Discovery" "$SCRIPT_DIR/run-api-discovery.sh"
        ;;
        
    "full")
        print_section "Complete Ten-Layer Security Architecture Scan - Target: $(basename "$TARGET_DIR")"
        
        # SBOM FIRST - Generate bill of materials for all other tools to use (with dependency installation)
        echo -e "${PURPLE}📋 Layer 1: Software Bill of Materials (SBOM) - Foundation for all scans${NC}"
        run_security_tool "Complete SBOM Generation" "$SCRIPT_DIR/run-complete-sbom-scan.sh"
        
        # Export SBOM path for other tools to use
        export SBOM_FILE="$SCAN_DIR/sbom/filesystem.json"
        
        echo -e "${PURPLE}🔐 Layer 2: Secret Detection${NC}"
        run_security_tool "TruffleHog Filesystem" "$SCRIPT_DIR/run-trufflehog-scan.sh" "filesystem"
        
        echo -e "${PURPLE}📊 Layer 3: Code Quality Analysis${NC}"
        run_security_tool "SonarQube Analysis" "$SCRIPT_DIR/run-sonar-analysis.sh"
        
        echo -e "${PURPLE}🦠 Layer 4: Malware Detection${NC}"
        run_security_tool "ClamAV Antivirus Scan" "$SCRIPT_DIR/run-clamav-scan.sh"
        
        echo -e "${PURPLE}🏗️  Layer 5: Helm Chart Building${NC}"
        run_security_tool "Helm Chart Build" "$SCRIPT_DIR/run-helm-build.sh"
        
        echo -e "${PURPLE}☸️  Layer 6: Infrastructure Security${NC}"
        run_security_tool "Checkov IaC Security" "$SCRIPT_DIR/run-checkov-scan.sh"
        
        echo -e "${PURPLE}🛡️  Layer 7: Container Security (Trivy)${NC}"
        run_security_tool "Trivy Filesystem" "$SCRIPT_DIR/run-trivy-scan.sh" "filesystem"
        run_security_tool "Trivy Base Images" "$SCRIPT_DIR/run-trivy-scan.sh" "base"
        
        echo -e "${PURPLE}🔍 Layer 8: Vulnerability Detection (Grype - SBOM-based)${NC}"
        run_security_tool "Grype SBOM Scan" "$SCRIPT_DIR/run-grype-scan.sh" "sbom"
        run_security_tool "Grype Base Images" "$SCRIPT_DIR/run-grype-scan.sh" "images"
        
        echo -e "${PURPLE}⚰️  Layer 9: End-of-Life Detection${NC}"
        run_security_tool "Xeol EOL Detection" "$SCRIPT_DIR/run-xeol-scan.sh"
        
        echo -e "${PURPLE}⚓ Layer 10: Anchore Security Analysis${NC}"
        run_security_tool "Anchore Security Scan" "$SCRIPT_DIR/run-anchore-scan.sh"
        
        echo -e "${PURPLE}🌐 Layer 11: API Discovery${NC}"
        run_security_tool "API Discovery" "$SCRIPT_DIR/run-api-discovery.sh"
        ;;
        
    *)
        echo -e "${RED}❌ Invalid scan type: $SCAN_TYPE${NC}"
        echo "Available options:"
        echo "  quick    - Core security tools (filesystem only)"
        echo "  images   - Container image security (all image types)"
        echo "  analysis - Security analysis and reporting"
        echo "  full     - Complete security scan (default)"
        exit 1
        ;;
esac

# Change back to security tools directory for report generation
cd "$REPO_ROOT"

# Generate summary report
print_section "Security Scan Summary Report"

echo -e "${CYAN}📊 Scan Completion Summary${NC}"
echo "Scan Type: $SCAN_TYPE"
echo "Target Directory: $TARGET_DIR"
echo "Security Tools Directory: $REPO_ROOT"
echo "Timestamp: $(date)"
echo ""

echo -e "${CYAN}📁 Generated Reports:${NC}"
find "$SCAN_DIR" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort | while read -r dir; do
    if [[ -d "$dir" ]]; then
        report_count=$(find "$dir" -name "*.json" -o -name "*.html" -o -name "*.xml" | wc -l)
        tool_name=$(basename "$dir")
        echo "  📂 $tool_name ($report_count files)"
    fi
done
echo ""

echo -e "${CYAN}🔧 Available Analysis Commands:${NC}"
echo "  📊 TARGET_DIR=\"$TARGET_DIR\" npm run security:analyze    - Analyze all security results"
echo "  🔍 TARGET_DIR=\"$TARGET_DIR\" npm run grype:analyze       - Grype vulnerability analysis"
echo "  🛡️  TARGET_DIR=\"$TARGET_DIR\" npm run trivy:analyze       - Trivy security analysis"
echo "  🔐 TARGET_DIR=\"$TARGET_DIR\" npm run trufflehog:analyze  - TruffleHog secret analysis"
echo "  ⚰️  TARGET_DIR=\"$TARGET_DIR\" npm run xeol:analyze        - Xeol EOL analysis"
echo ""

echo -e "${CYAN}🚀 Quick Re-run Commands:${NC}"
echo "  🏃 ./run-target-security-scan.sh \"$TARGET_DIR\" quick    - Quick scan"
echo "  📦 ./run-target-security-scan.sh \"$TARGET_DIR\" images   - Image security"
echo "  📊 ./run-target-security-scan.sh \"$TARGET_DIR\" analysis - Analysis only"
echo "  🛡️  ./run-target-security-scan.sh \"$TARGET_DIR\" full     - Complete scan"
echo ""

# Check for high-priority issues in current scan
echo -e "${CYAN}🚨 High-Priority Security Issues (Current Scan):${NC}"
has_critical_issues=false

# Check Grype results for high/critical vulnerabilities
grype_files=(
    "$SCAN_DIR/grype/${SCAN_ID}_grype-filesystem-results.json"
    "$SCAN_DIR/grype/${SCAN_ID}_grype-images-results.json"
    "$SCAN_DIR/grype/${SCAN_ID}_grype-base-results.json"
)

grype_total=0
for grype_file in "${grype_files[@]}"; do
    if [[ -f "$grype_file" ]]; then
        high_count=$(jq -r '[.matches[] | select(.vulnerability.severity == "High" or .vulnerability.severity == "Critical")] | length' "$grype_file" 2>/dev/null || echo "0")
        grype_total=$((grype_total + high_count))
    fi
done

if [[ "$grype_total" -gt 0 ]]; then
    echo -e "  ${RED}🔴 Grype: $grype_total high/critical vulnerabilities found${NC}"
    has_critical_issues=true
fi

# Check Trivy results for high/critical vulnerabilities
trivy_files=(
    "$SCAN_DIR/trivy/${SCAN_ID}_trivy-filesystem-results.json"
    "$SCAN_DIR/trivy/${SCAN_ID}_trivy-images-results.json"
    "$SCAN_DIR/trivy/${SCAN_ID}_trivy-base-results.json"
)

trivy_total=0
for trivy_file in "${trivy_files[@]}"; do
    if [[ -f "$trivy_file" ]]; then
        trivy_critical=$(jq -r '[.Results[]?.Vulnerabilities[]? | select(.Severity == "HIGH" or .Severity == "CRITICAL")] | length' "$trivy_file" 2>/dev/null || echo "0")
        trivy_total=$((trivy_total + trivy_critical))
    fi
done

if [[ "$trivy_total" -gt 0 ]]; then
    echo -e "  ${RED}🔴 Trivy: $trivy_total high/critical vulnerabilities found${NC}"
    has_critical_issues=true
fi

# Check TruffleHog for secrets
trufflehog_files=(
    "$SCAN_DIR/trufflehog/${SCAN_ID}_trufflehog-filesystem-results.json"
    "$SCAN_DIR/trufflehog/${SCAN_ID}_trufflehog-images-results.json"
)

trufflehog_total=0
for trufflehog_file in "${trufflehog_files[@]}"; do
    if [[ -f "$trufflehog_file" ]]; then
        secrets_count=$(jq '. | length' "$trufflehog_file" 2>/dev/null || echo "0")
        trufflehog_total=$((trufflehog_total + secrets_count))
    fi
done

if [[ "$trufflehog_total" -gt 0 ]]; then
    echo -e "  ${YELLOW}🟡 TruffleHog: $trufflehog_total potential secrets detected${NC}"
fi

# Check Xeol for EOL components
if [[ -f "$SCAN_DIR/xeol/${SCAN_ID}_xeol-results.json" ]]; then
    eol_count=$(jq '[.matches[] | select(.eol == true)] | length' "$SCAN_DIR/xeol/${SCAN_ID}_xeol-results.json" 2>/dev/null || echo "0")
    if [[ "$eol_count" -gt 0 ]]; then
        echo -e "  ${YELLOW}🟡 Xeol: $eol_count end-of-life components detected${NC}"
    fi
fi

# Check Checkov for infrastructure issues
if [[ -f "$SCAN_DIR/checkov/${SCAN_ID}_checkov-results.json" ]]; then
    checkov_critical=$(jq -r '[(.results.failed_checks // []) | .[] | select(.severity == "CRITICAL" or .severity == "HIGH")] | length' "$SCAN_DIR/checkov/${SCAN_ID}_checkov-results.json" 2>/dev/null || echo "0")
    if [[ "$checkov_critical" -gt 0 ]]; then
        echo -e "  ${RED}🔴 Checkov: $checkov_critical high/critical infrastructure issues found${NC}"
        has_critical_issues=true
    fi
fi

if [[ "$has_critical_issues" == "false" ]]; then
    echo -e "  ${GREEN}✅ No high/critical security issues detected in current scan${NC}"
fi

echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}🔹 Report Analysis & Consolidation${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

echo -e "${BLUE}📊 Analyzing security scan results...${NC}"

# Run individual analysis scripts for generated reports
analysis_success=true

# TruffleHog Analysis
if [[ -d "$SCAN_DIR/trufflehog" ]] && ls "$SCAN_DIR/trufflehog"/*.json &>/dev/null; then
    echo -e "${CYAN}🔍 Analyzing TruffleHog secret detection results...${NC}"
    if [[ -f "$SCRIPT_DIR/analyze-trufflehog-results.sh" ]]; then
        SCAN_DIR="$SCAN_DIR" SCAN_ID="$SCAN_ID" "$SCRIPT_DIR/analyze-trufflehog-results.sh" || analysis_success=false
    fi
fi

# ClamAV Analysis  
if [[ -d "$SCAN_DIR/clamav" ]] && ls "$SCAN_DIR/clamav"/*.log &>/dev/null; then
    echo -e "${CYAN}🦠 Analyzing ClamAV antivirus results...${NC}"
    if [[ -f "$SCRIPT_DIR/analyze-clamav-results.sh" ]]; then
        SCAN_DIR="$SCAN_DIR" SCAN_ID="$SCAN_ID" "$SCRIPT_DIR/analyze-clamav-results.sh" || analysis_success=false
    fi
fi

# Checkov Analysis
if [[ -d "$SCAN_DIR/checkov" ]] && ls "$SCAN_DIR/checkov"/*.json &>/dev/null; then
    echo -e "${CYAN}🔒 Analyzing Checkov infrastructure security results...${NC}"
    if [[ -f "$SCRIPT_DIR/analyze-checkov-results.sh" ]]; then
        SCAN_DIR="$SCAN_DIR" SCAN_ID="$SCAN_ID" "$SCRIPT_DIR/analyze-checkov-results.sh" || analysis_success=false
    fi
fi

# Grype Analysis
if [[ -d "$SCAN_DIR/grype" ]] && ls "$SCAN_DIR/grype"/*.json &>/dev/null; then
    echo -e "${CYAN}🎯 Analyzing Grype vulnerability results...${NC}"
    if [[ -f "$SCRIPT_DIR/analyze-grype-results.sh" ]]; then
        SCAN_DIR="$SCAN_DIR" SCAN_ID="$SCAN_ID" "$SCRIPT_DIR/analyze-grype-results.sh" || analysis_success=false
    fi
fi

# Trivy Analysis
if [[ -d "$SCAN_DIR/trivy" ]] && ls "$SCAN_DIR/trivy"/*.json &>/dev/null; then
    echo -e "${CYAN}🐳 Analyzing Trivy security results...${NC}"
    if [[ -f "$SCRIPT_DIR/analyze-trivy-results.sh" ]]; then
        SCAN_DIR="$SCAN_DIR" SCAN_ID="$SCAN_ID" "$SCRIPT_DIR/analyze-trivy-results.sh" || analysis_success=false
    fi
fi

# Xeol Analysis
if [[ -d "$SCAN_DIR/xeol" ]] && ls "$SCAN_DIR/xeol"/*.json &>/dev/null; then
    echo -e "${CYAN}⏰ Analyzing Xeol EOL detection results...${NC}"
    if [[ -f "$SCRIPT_DIR/analyze-xeol-results.sh" ]]; then
        SCAN_DIR="$SCAN_DIR" SCAN_ID="$SCAN_ID" "$SCRIPT_DIR/analyze-xeol-results.sh" || analysis_success=false
    fi
fi

# Helm Analysis (if charts were built)
if [[ -d "$SCAN_DIR/helm" ]] && ls "$SCAN_DIR/helm"/*.log &>/dev/null; then
    echo -e "${CYAN}⚓ Analyzing Helm build results...${NC}"
    if [[ -f "$SCRIPT_DIR/analyze-helm-results.sh" ]]; then
        SCAN_DIR="$SCAN_DIR" SCAN_ID="$SCAN_ID" "$SCRIPT_DIR/analyze-helm-results.sh" || analysis_success=false
    fi
fi

echo ""
echo -e "${BLUE}📋 Consolidating all security reports...${NC}"

# Generate remediation suggestions before consolidation
echo ""
echo -e "${CYAN}💊 Generating Remediation Suggestions...${NC}"
if [[ -f "$SCRIPT_DIR/generate-remediation-suggestions.sh" ]]; then
    # Generate JSON output for dashboard integration
    "$SCRIPT_DIR/generate-remediation-suggestions.sh" "$SCAN_DIR" --json --severity MEDIUM --output "$SCAN_DIR/remediation-suggestions.json" 2>&1 | head -20
    
    if [[ -f "$SCAN_DIR/remediation-suggestions.json" ]]; then
        echo -e "${GREEN}✅ Remediation suggestions generated${NC}"
    else
        echo -e "${YELLOW}⚠️  Remediation suggestions generation had issues${NC}"
    fi
else
    echo -e "${YELLOW}⚠️  Remediation script not found${NC}"
fi

# Run the unified report consolidation
if [[ -f "$SCRIPT_DIR/consolidate-security-reports.sh" ]]; then
    SCAN_DIR="$SCAN_DIR" SCAN_ID="$SCAN_ID" "$SCRIPT_DIR/consolidate-security-reports.sh"
    consolidation_result=$?
    
    if [[ $consolidation_result -eq 0 ]]; then
        echo -e "${GREEN}✅ Security reports consolidated successfully${NC}"
        
        # Display scan directory information
        echo ""
        echo -e "${BLUE}📊 Scan Results Location:${NC}"
        echo -e "${CYAN}📁 Scan Directory: $SCAN_DIR${NC}"
        echo -e "${CYAN}📊 Consolidated Reports: $SCAN_DIR/consolidated-reports/${NC}"
        echo -e "${CYAN}🔍 View all scan artifacts: ls -la $SCAN_DIR/*/"${NC}
        
        echo ""
        echo -e "${BLUE}🔧 Quick Access:${NC}"
        echo -e "${YELLOW}cd $SCAN_DIR${NC}"
        if [[ -f "$SCAN_DIR/consolidated-reports/dashboards/security-dashboard.html" ]]; then
            echo -e "${YELLOW}open $SCAN_DIR/consolidated-reports/dashboards/security-dashboard.html${NC}"
        fi
    else
        echo -e "${YELLOW}⚠️  Report consolidation had issues${NC}"
        analysis_success=false
    fi
    
    # Generate Scan-Specific Security Findings Summary (Critical/High/Medium/Low)
    echo ""
    echo -e "${BLUE}🚨 Generating Security Findings Summary for Scan: ${SCAN_ID}...${NC}"
    if [[ -f "$SCRIPT_DIR/generate-scan-findings-summary.sh" ]]; then
        # Source the function and call it with scan parameters
        source "$SCRIPT_DIR/generate-scan-findings-summary.sh"
        generate_scan_findings_summary "$SCAN_ID" "$TARGET_DIR" "$REPORTS_ROOT"
        summary_result=$?
        
        if [[ $summary_result -eq 0 ]]; then
            echo -e "${GREEN}✅ Security findings summary generated successfully${NC}"
            
            # Display summary access information
            if [[ -f "$SCAN_DIR/security-findings-summary.json" ]]; then
                echo -e "${CYAN}📊 Scan Summary: $SCAN_DIR/security-findings-summary.json${NC}"
                
                # Show quick stats
                critical_count=$(jq -r '.summary.total_critical' "$SCAN_DIR/security-findings-summary.json" 2>/dev/null || echo "0")
                high_count=$(jq -r '.summary.total_high' "$SCAN_DIR/security-findings-summary.json" 2>/dev/null || echo "0")
                medium_count=$(jq -r '.summary.total_medium' "$SCAN_DIR/security-findings-summary.json" 2>/dev/null || echo "0")
                low_count=$(jq -r '.summary.total_low' "$SCAN_DIR/security-findings-summary.json" 2>/dev/null || echo "0")
                
                echo -e "${CYAN}📈 Findings Overview: Critical($critical_count) High($high_count) Medium($medium_count) Low($low_count)${NC}"
            fi
        else
            echo -e "${YELLOW}⚠️  Security findings summary generation had issues${NC}"
        fi
    else
        echo -e "${YELLOW}⚠️  Security findings summary script not found${NC}"
    fi
else
    echo -e "${YELLOW}⚠️  Report consolidation script not found${NC}"
fi

echo ""
if [[ "$analysis_success" == "true" ]]; then
    echo -e "${GREEN}✅ All security analysis and reporting completed successfully${NC}"
else
    echo -e "${YELLOW}⚠️  Some analysis steps had issues, but core scanning completed${NC}"
fi

echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}🎯 Target Security Scan Finished Successfully!${NC}"
echo -e "${CYAN}Target: $TARGET_DIR${NC}"
echo -e "${CYAN}Scan ID: $SCAN_ID${NC}"
echo -e "${CYAN}Scan Directory: $SCAN_DIR${NC}"
echo -e "${CYAN}All scan artifacts stored in: $SCAN_DIR${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Automatically open the dashboard
DASHBOARD_PATH="$SCAN_DIR/consolidated-reports/index.html"
if [[ -f "$DASHBOARD_PATH" ]]; then
    echo -e "${GREEN}🌐 Opening security dashboard...${NC}"
    # Cross-platform browser opening
    if [[ "$OSTYPE" == "darwin"* ]]; then
        open "$DASHBOARD_PATH"
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        xdg-open "$DASHBOARD_PATH" 2>/dev/null || echo -e "${YELLOW}Please open: $DASHBOARD_PATH${NC}"
    elif [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "cygwin" ]]; then
        start "$DASHBOARD_PATH"
    else
        echo -e "${YELLOW}Please open: $DASHBOARD_PATH${NC}"
    fi
else
    echo -e "${YELLOW}⚠️  Dashboard not found at: $DASHBOARD_PATH${NC}"
fi

# Cleanup cloned repository if applicable
if [[ "$CLONED_REPO" == "true" ]] && [[ -n "$CLONE_DIR" ]]; then
    echo ""
    echo -e "${CYAN}🧹 Cleaning up cloned repository...${NC}"
    rm -rf "$CLONE_DIR"
    echo -e "${GREEN}✅ Temporary clone removed: $CLONE_DIR${NC}"
fi