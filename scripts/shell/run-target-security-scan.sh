#!/bin/bash

# ══════════════════════════════════════════════════════════════════════════════
# SHELL COMPATIBILITY AUTO-DETECTION
# ══════════════════════════════════════════════════════════════════════════════
# This script requires bash 4+ for array operations and parameter expansion.
# If invoked from a non-bash shell (e.g., zsh via web UI), it will automatically
# re-execute itself in bash to ensure compatibility.
# ══════════════════════════════════════════════════════════════════════════════

# Check if we're already running in bash
if [ -z "${BASH_VERSION:-}" ]; then
    # Try common bash locations (prefer newer versions first)
    for bash_path in \
        /opt/homebrew/bin/bash \
        /usr/local/bin/bash \
        /home/linuxbrew/.linuxbrew/bin/bash \
        /usr/bin/bash \
        /bin/bash \
        bash; do
        if command -v "$bash_path" >/dev/null 2>&1; then
            # Check version before re-executing
            FOUND_VERSION=$("$bash_path" --version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+' | head -1)
            FOUND_MAJOR=$(echo "$FOUND_VERSION" | cut -d. -f1)
            
            # Only use bash 4.0+
            if [ -n "$FOUND_MAJOR" ] && [ "$FOUND_MAJOR" -ge 4 ]; then
                # Found suitable bash — re-execute this script with bash
                exec "$bash_path" "$0" "$@"
            fi
        fi
    done
    
    # Bash not found — print error and exit
    echo "ERROR: This script requires bash 4.0+ but it was not found."
    echo "Current shell: ${SHELL:-unknown}"
    echo "Please install bash 4+ or run: bash $0 \$@"
    exit 1
fi

# Verify bash version
BASH_VERSION_MAJOR="${BASH_VERSINFO[0]:-0}"
if [ "$BASH_VERSION_MAJOR" -lt 4 ]; then
    echo "ERROR: This script requires bash 4.0 or later (found: ${BASH_VERSION})"
    echo "macOS users: Install bash 4+ via Homebrew: brew install bash"
    exit 1
fi

# ══════════════════════════════════════════════════════════════════════════════
# Target-Aware Complete Security Scan Orchestration Script
# ══════════════════════════════════════════════════════════════════════════════
# Runs all security layers with multi-target scanning capabilities on external directories
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

print_banner() {
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
}

# Help function
show_help() {
    echo -e "${GREEN}Fifteen-Layer Security Scan Orchestrator${NC}"
    echo ""
    echo "Usage: $0 [OPTIONS] <TARGET> [SCAN_TYPE]"
    echo "       $0 --target <TARGET> --scan-type <SCAN_TYPE> [OPTIONS]"
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
    echo "  -t, --target PATH   Target path or Git URL (same as positional TARGET)"
    echo "  -m, --scan-type     Scan type: quick|full|images|analysis"
    echo "      --scan-mode     Alias of --scan-type"
    echo "      --list-modes    Print available scan types and exit"
    echo "  --subdir PATH       Scan only a specific subdirectory within a Git repository"
    echo "                      (only works with Git URLs, uses sparse-checkout)"
    echo "      --skip-tools    Comma-separated tools to skip (example: sonar,clamav,garak)"
    echo "      --no-garak      Skip Garak probing"
    echo "      --baseline-image IMAGE"
    echo "                      Override baseline image prompt/default"
    echo "      --non-interactive"
    echo "                      Disable prompts and use defaults"
    echo ""
    echo "Target Types:"
    echo "  Local Directory     /path/to/project or ./project"
    echo "  Git HTTPS           https://github.com/user/repo.git"
    echo "  Git SSH             git@github.com:user/repo.git"
    echo "  Git Subdirectory    --subdir path/to/subdir https://github.com/user/repo.git"
    echo ""
    echo "Scan Types:"
    echo "  quick       SBOM, TruffleHog, Helm, Trivy (fs+base), Grype (sbom+images), Xeol, API Discovery"
    echo "  full        All 15 layers: SBOM, Secrets, SonarQube, ClamAV, Helm, Checkov, Trivy, Grype, Xeol, Anchore, API, Garak, Network, Picklescan, ModelCard (default)"
    echo "  images      Container-focused: TruffleHog, Grype, Trivy, Xeol (image + base targets)"
    echo "  analysis    SonarQube, Checkov, API Discovery, Network Discovery [+Garak opt-in]"
    echo ""
    echo "Security Layers (full mode):"
    echo "  Layer 1:  SBOM Generation (Syft)"
    echo "  Layer 2:  Secret Detection (TruffleHog)"
    echo "  Layer 3:  Code Quality (SonarQube)"
    echo "  Layer 4:  Malware Detection (ClamAV)"
    echo "  Layer 5:  Helm Chart Build"
    echo "  Layer 6:  IaC Security (Checkov)"
    echo "  Layer 7:  Container Security (Trivy)"
    echo "  Layer 8:  Vulnerability Scanning (Grype)"
    echo "  Layer 9:  EOL Detection (Xeol)"
    echo "  Layer 10: Container Analysis (Anchore)"
    echo "  Layer 11: API Discovery (OpenAPI, REST, GraphQL)"
    echo "  Layer 12: LLM Security Probing (Garak, opt-in via RUN_GARAK=true)"
    echo "  Layer 13: Network Discovery (Ports, Protocols, Services)"
    echo "  Layer 14: Pickle/Serialization Safety (Picklescan)"
    echo "  Layer 15: Model Card Compliance (ModelCard)"
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
    echo "  $0 https://github.com/user/repo.git              # Clone & scan entire repo"
    echo "  $0 git@github.com:user/private-repo.git full     # SSH clone & scan"
    echo ""
    echo "  # Git subdirectory scans (sparse-checkout)"
    echo "  $0 --subdir apps/api https://github.com/user/repo.git full"
    echo "  $0 --subdir apps/sapphire-splunk/sapphire-ai-api https://github.com/MetroStar/sapphire.git"
    echo ""
    echo "  # Canonical option style"
    echo "  $0 --target ./my-app --scan-type quick --skip-tools sonar,garak"
    echo "  $0 --target https://github.com/user/repo.git --scan-type full --non-interactive"
    echo ""
    echo "Notes:"
    echo "  - Requires Docker for most scanners"
    echo "  - Git repositories are cloned with --depth 1 for speed"
    echo "  - Cloned repositories are automatically cleaned up after scan"
    echo "  - Creates timestamped scan directory"
    echo "  - Generates interactive HTML dashboard"
    exit 0
}

print_mode_help() {
    echo "Available scan types:"
    echo "  quick     Core security tools for fast feedback"
    echo "  full      Complete scan with all layers"
    echo "  images    Container image focused scan"
    echo "  analysis  Code and API analysis focused scan"
}

require_option_value() {
    local opt_name="$1"
    local opt_value="$2"
    if [[ -z "$opt_value" ]] || [[ "$opt_value" == -* ]]; then
        echo -e "${RED}❌ Error: $opt_name requires a value${NC}"
        echo -e "${YELLOW}Run with --help for usage examples.${NC}"
        exit 1
    fi
}

apply_skip_tools() {
    local skip_csv="$1"
    local raw_tool
    IFS=',' read -r -a raw_tools <<< "$skip_csv"
    for raw_tool in "${raw_tools[@]}"; do
        local tool
        tool=$(echo "$raw_tool" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')
        [[ -z "$tool" ]] && continue
        case "$tool" in
            sbom) SKIP_SBOM=true ;;
            trufflehog|secrets) SKIP_TRUFFLEHOG=true ;;
            sonar|sonarqube) SKIP_SONAR=true ;;
            clamav|malware) SKIP_CLAMAV=true ;;
            helm) SKIP_HELM=true ;;
            checkov|iac) SKIP_CHECKOV=true ;;
            trivy) SKIP_TRIVY=true ;;
            grype) SKIP_GRYPE=true ;;
            xeol|eol) SKIP_XEOL=true ;;
            anchore) SKIP_ANCHORE=true ;;
            api|api-discovery) SKIP_API_DISCOVERY=true ;;
            network|network-discovery) SKIP_NETWORK_DISCOVERY=true ;;
            garak) SKIP_GARAK=true ;;
            *)
                echo -e "${YELLOW}⚠️  Unknown tool in --skip-tools: $tool${NC}"
                ;;
        esac
    done
}

# Parse arguments
SUBDIR_PATH=""
SKIP_GARAK="${SKIP_GARAK:-false}"
SKIP_TOOLS=""
BASELINE_IMAGE_FLAG=""
NON_INTERACTIVE="false"
LIST_MODES="false"
TARGET_INPUT=""
SCAN_TYPE=""
POSITIONAL_ARGS=()

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_help
            ;;
        -t|--target)
            require_option_value "$1" "${2:-}"
            TARGET_INPUT="$2"
            shift 2
            ;;
        -m|--scan-type|--scan-mode)
            require_option_value "$1" "${2:-}"
            SCAN_TYPE="$2"
            shift 2
            ;;
        --list-modes)
            LIST_MODES=true
            shift
            ;;
        --subdir)
            require_option_value "$1" "${2:-}"
            SUBDIR_PATH="$2"
            shift 2
            ;;
        --skip-tools)
            require_option_value "$1" "${2:-}"
            SKIP_TOOLS="$2"
            shift 2
            ;;
        --no-garak)
            SKIP_GARAK=true
            shift
            ;;
        --baseline-image)
            require_option_value "$1" "${2:-}"
            BASELINE_IMAGE_FLAG="$2"
            shift 2
            ;;
        --non-interactive)
            NON_INTERACTIVE=true
            shift
            ;;
        -*)
            echo -e "${RED}❌ Error: Unknown option: $1${NC}"
            echo -e "${YELLOW}Run with --help for usage examples.${NC}"
            exit 1
            ;;
        *)
            POSITIONAL_ARGS+=("$1")
            shift
            ;;
    esac
done

# Restore positional parameters
set -- "${POSITIONAL_ARGS[@]}"

if [[ "$LIST_MODES" == "true" ]]; then
    print_mode_help
    exit 0
fi

# Configuration
if [[ -z "$TARGET_INPUT" ]] && [[ $# -ge 1 ]]; then
    TARGET_INPUT="$1"
fi

if [[ -z "$SCAN_TYPE" ]] && [[ $# -ge 2 ]]; then
    SCAN_TYPE="$2"
fi

if [[ $# -gt 2 ]]; then
    echo -e "${RED}❌ Error: Unexpected extra arguments${NC}"
    echo -e "${YELLOW}Run with --help for usage examples.${NC}"
    exit 1
fi

SCAN_TYPE="${SCAN_TYPE:-full}"
SCAN_TYPE=$(echo "$SCAN_TYPE" | tr '[:upper:]' '[:lower:]')

case "$SCAN_TYPE" in
    quick|full|images|analysis) ;;
    *)
        echo -e "${RED}❌ Invalid scan type: $SCAN_TYPE${NC}"
        print_mode_help
        exit 1
        ;;
esac

if [[ -n "$SKIP_TOOLS" ]]; then
    apply_skip_tools "$SKIP_TOOLS"
fi

if [[ ! -t 0 ]]; then
    NON_INTERACTIVE=true
fi

# Get the script's directory to locate security tools
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
# Use GITHUB_ACTOR if provided (from GitHub Actions), otherwise use whoami
USERNAME="${GITHUB_ACTOR:-$(whoami)}"
TIMESTAMP=$(date '+%Y-%m-%d_%H-%M-%S')
RUN_START_EPOCH=$(date +%s)

# ══════════════════════════════════════════════════════════════════════════════
# Webhook Helper Function
# ══════════════════════════════════════════════════════════════════════════════
# Calls send-webhook-notification.sh with conditional logging based on
# EPYON_WEBHOOK_DEBUG environment variable.
send_webhook() {
    local event_type="$1"
    local message="$2"
    local status="${3:-info}"
    local tool_name="${4:-}"
    
    if [[ "${EPYON_WEBHOOK_DEBUG:-0}" == "1" ]]; then
        # Debug mode - show all output including stderr
        "$SCRIPT_DIR/send-webhook-notification.sh" "$event_type" "$message" "$status" "$tool_name" || true
    else
        # Silent mode - suppress stderr, only show critical failures
        "$SCRIPT_DIR/send-webhook-notification.sh" "$event_type" "$message" "$status" "$tool_name" 2>/dev/null || true
    fi
}

# Ensure PyYAML is installed (needed for .epyon-ignore.yml parsing)
if ! python3 -c "import yaml" 2>/dev/null; then
    echo -e "${CYAN}📦 Installing PyYAML for ignore rule parsing...${NC}"
    pip3 install --quiet pyyaml 2>/dev/null || pip3 install --user --quiet pyyaml 2>/dev/null || {
        echo -e "${YELLOW}⚠️  Warning: Failed to install PyYAML. Ignore rules will not work.${NC}"
    }
fi

# Flag to track if we cloned a repo (for cleanup)
CLONED_REPO=false
CLONE_DIR=""

# Validate inputs
if [[ -z "$TARGET_INPUT" ]]; then
    echo -e "${RED}❌ Error: TARGET is required${NC}"
    echo "Usage: $0 [OPTIONS] <TARGET> [SCAN_TYPE]"
    echo "   or: $0 --target <TARGET> --scan-type <SCAN_TYPE>"
    echo ""
    echo "Examples:"
    echo "  $0 ./my-project full"
    echo "  $0 --target ./my-project --scan-type quick"
    echo "  $0 --target https://github.com/user/repo.git --subdir apps/api"
    echo "  $0 --target ./my-project --scan-type full --skip-tools sonar,garak"
    exit 1
fi

# Source webhook environment variables if they exist (set by GitHub Actions workflow)
if [[ -f /tmp/epyon-env ]]; then
    source /tmp/epyon-env
    if [[ "${EPYON_WEBHOOK_DEBUG:-0}" == "1" && -n "${EPYON_CALLBACK_URL:-}" ]]; then
        echo -e "${BLUE}🔔 Loaded webhook config from /tmp/epyon-env${NC}"
        echo "   Callback URL: ${EPYON_CALLBACK_URL}"
        echo "   Job ID: ${EPYON_JOB_ID:-<not set>}"
        echo "   Debug mode: enabled"
        echo ""
    fi
fi

print_banner
echo -e "${CYAN}Run Configuration${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Target input: $TARGET_INPUT"
echo "Scan type: $SCAN_TYPE"
echo "Subdirectory filter: ${SUBDIR_PATH:-<none>}"
echo "Non-interactive: $NON_INTERACTIVE"
echo "Skip tools: ${SKIP_TOOLS:-<none>}"
echo ""

# Validate --subdir only used with Git URLs
if [[ -n "$SUBDIR_PATH" ]] && ! [[ "$TARGET_INPUT" =~ ^(https?://|git@|ssh://) ]] && ! [[ "$TARGET_INPUT" =~ \.git$ ]]; then
    echo -e "${RED}❌ Error: --subdir option can only be used with Git repository URLs${NC}"
    echo "   Provided target: $TARGET_INPUT"
    echo "   To scan a local subdirectory, provide the full path:"
    echo "   $0 '/path/to/repo/$SUBDIR_PATH' full"
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
    
    if [[ -n "$SUBDIR_PATH" ]]; then
        # Sparse checkout for subdirectory only
        echo -e "${CYAN}📥 Cloning repository with sparse-checkout (subdirectory: $SUBDIR_PATH)...${NC}"
        
        # Initialize empty repo
        if ! git clone --filter=blob:none --sparse "$TARGET_INPUT" "$CLONE_DIR" 2>&1; then
            echo -e "${RED}❌ Error: Failed to initialize sparse clone${NC}"
            rm -rf "$CLONE_DIR"
            exit 1
        fi
        
        # Configure sparse-checkout for specific subdirectory
        cd "$CLONE_DIR"
        if ! git sparse-checkout set "$SUBDIR_PATH" 2>&1; then
            echo -e "${RED}❌ Error: Failed to configure sparse-checkout for path: $SUBDIR_PATH${NC}"
            cd - > /dev/null
            rm -rf "$CLONE_DIR"
            exit 1
        fi
        cd - > /dev/null
        
        # Verify subdirectory exists
        if [[ ! -d "$CLONE_DIR/$SUBDIR_PATH" ]]; then
            echo -e "${RED}❌ Error: Subdirectory '$SUBDIR_PATH' does not exist in repository${NC}"
            rm -rf "$CLONE_DIR"
            exit 1
        fi
        
        echo -e "${GREEN}✅ Subdirectory cloned successfully${NC}"
        TARGET_DIR="$CLONE_DIR/$SUBDIR_PATH"
        # Use subdirectory name for scan naming
        TARGET_NAME=$(basename "$SUBDIR_PATH")
        CLONED_REPO=true
    else
        # Full repository clone
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
    fi
elif [[ -d "$TARGET_INPUT" ]]; then
    # It's a directory path
    if [[ -n "$SUBDIR_PATH" ]]; then
        echo -e "${RED}❌ Error: --subdir option can only be used with Git repository URLs${NC}"
        echo -e "   Provided target: $TARGET_INPUT (local directory)"
        echo -e "   To scan a local subdirectory, provide the full path directly:"
        echo -e "   $0 '$TARGET_INPUT/$SUBDIR_PATH' full"
        exit 1
    fi
    TARGET_DIR=$(realpath "$TARGET_INPUT" 2>/dev/null || (cd "$TARGET_INPUT" && pwd))
    # Use TARGET_NAME env var if provided (from GitHub Actions), otherwise use directory name
    if [[ -z "${TARGET_NAME:-}" ]]; then
        TARGET_NAME=$(basename "$TARGET_DIR")
    fi
else
    echo -e "${RED}❌ Error: Target is neither a valid directory nor a Git URL${NC}"
    echo -e "   Provided: $TARGET_INPUT"
    if [[ -n "$SUBDIR_PATH" ]]; then
        echo -e "   Note: --subdir option requires a Git repository URL"
    fi
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
# REPORTS_ROOT is the repo root (parent of scripts/); REPO_ROOT is the scripts dir.
CONFIG_DIR="$REPORTS_ROOT/configuration"

# Validate that a given image tag appears in the approved-base-images.conf list.
validate_latest_image() {
    local image="$1"
    if grep -qF "$image" "$CONFIG_DIR/approved-base-images.conf" 2>/dev/null; then
        echo -e "${GREEN}✅ Image is in approved list: $image${NC}"
    else
        echo -e "${YELLOW}⚠️  Image not found in approved list: $image${NC}"
        echo -e "${YELLOW}   Review approved images in: $CONFIG_DIR/approved-base-images.conf${NC}"
    fi
}
DEFAULT_BASELINE="dhi/caddy:debian-13-2-fips-dev@sha256:ba86d16733750c6fd7b8866981016d2479e234c842d77413f1bf41c4404e555c"

choose_baseline_image() {
    if [[ -n "$BASELINE_IMAGE_FLAG" ]]; then
        BASELINE_IMAGE="$BASELINE_IMAGE_FLAG"
        echo -e "${GREEN}✓ Using --baseline-image override: $BASELINE_IMAGE${NC}"
        return
    fi

    if [[ "$NON_INTERACTIVE" == "true" ]]; then
        BASELINE_IMAGE="$DEFAULT_BASELINE"
        echo -e "${YELLOW}ℹ️  Non-interactive mode: using default baseline image${NC}"
        return
    fi

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
}

choose_baseline_image

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

# Send webhook notification: scan starting
send_webhook "scan_start" "Security scan started for $APP_NAME" "in_progress" ""

echo "============================================"
echo "🛡️  Twelve-Layer Security Scan Orchestrator"
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
echo -e "   ${YELLOW}Analyzing directory structure (this may take a moment)...${NC}"

TIMEOUT_BIN=""
if command -v timeout >/dev/null 2>&1; then
    TIMEOUT_BIN="timeout"
elif command -v gtimeout >/dev/null 2>&1; then
    TIMEOUT_BIN="gtimeout"
fi

# Single optimized find with timeout to prevent hanging
# Use a single pass through the filesystem and count everything at once
if [[ -n "$TIMEOUT_BIN" ]]; then
    FILE_LIST=$($TIMEOUT_BIN 30s find "$TARGET_DIR" -type f \
        -not -path "*/node_modules/*" \
        -not -path "*/.git/*" \
        -not -path "*/venv/*" \
        -not -path "*/__pycache__/*" \
        -not -path "*/dist/*" \
        -not -path "*/build/*" \
        -not -path "*/vendor/*" \
        -not -path "*/.next/*" \
        -not -path "*/.venv/*" \
        2>/dev/null || echo "TIMEOUT")
else
    FILE_LIST=$(find "$TARGET_DIR" -type f \
        -not -path "*/node_modules/*" \
        -not -path "*/.git/*" \
        -not -path "*/venv/*" \
        -not -path "*/__pycache__/*" \
        -not -path "*/dist/*" \
        -not -path "*/build/*" \
        -not -path "*/vendor/*" \
        -not -path "*/.next/*" \
        -not -path "*/.venv/*" \
        2>/dev/null)
fi

if [[ -z "$TIMEOUT_BIN" ]]; then
    echo -e "   ${YELLOW}ℹ️  Timeout command not available; running full directory analysis without timeout${NC}"
fi

if [[ -z "$FILE_LIST" ]]; then
    FILE_LIST="TIMEOUT"
fi

if [[ "$FILE_LIST" == "TIMEOUT" ]]; then
    echo -e "   ${YELLOW}⚠ Directory analysis timed out (large directory)${NC}"
    echo -e "   ${WHITE}Proceeding with scan...${NC}"
    TOTAL_FILES="0"
    JS_FILES=0
    PY_FILES=0
    YAML_FILES=0
    JSON_FILES=0
    TF_FILES=0
    DOCKER_FILES=0
    SHELL_FILES=0
else
    # Count files efficiently using grep and clean up output
    TOTAL_FILES=$(echo "$FILE_LIST" | grep -c '^' 2>/dev/null | tr -d '\r\n' || echo "0")
    JS_FILES=$(echo "$FILE_LIST" | grep -cE '\.(js|jsx|ts|tsx)$' 2>/dev/null | tr -d '\r\n' || echo "0")
    PY_FILES=$(echo "$FILE_LIST" | grep -cE '\.py$' 2>/dev/null | tr -d '\r\n' || echo "0")
    YAML_FILES=$(echo "$FILE_LIST" | grep -cE '\.(yaml|yml)$' 2>/dev/null | tr -d '\r\n' || echo "0")
    JSON_FILES=$(echo "$FILE_LIST" | grep -cE '\.json$' 2>/dev/null | tr -d '\r\n' || echo "0")
    TF_FILES=$(echo "$FILE_LIST" | grep -cE '\.tf$' 2>/dev/null | tr -d '\r\n' || echo "0")
    DOCKER_FILES=$(echo "$FILE_LIST" | grep -cE 'Dockerfile' 2>/dev/null | tr -d '\r\n' || echo "0")
    SHELL_FILES=$(echo "$FILE_LIST" | grep -cE '\.(sh|bash)$' 2>/dev/null | tr -d '\r\n' || echo "0")

    # Ensure numeric values
    TOTAL_FILES=${TOTAL_FILES//[^0-9]/}
    JS_FILES=${JS_FILES//[^0-9]/}
    PY_FILES=${PY_FILES//[^0-9]/}
    YAML_FILES=${YAML_FILES//[^0-9]/}
    JSON_FILES=${JSON_FILES//[^0-9]/}
    TF_FILES=${TF_FILES//[^0-9]/}
    DOCKER_FILES=${DOCKER_FILES//[^0-9]/}
    SHELL_FILES=${SHELL_FILES//[^0-9]/}

    echo -e "   📁 Total Files to Scan: ${WHITE}$TOTAL_FILES${NC}"
    echo ""
    echo -e "   ${WHITE}File Type Breakdown:${NC}"
    [[ ${TOTAL_FILES:-0} -gt 0 ]] && {
        [[ ${JS_FILES:-0} -gt 0 ]] && echo -e "   • JavaScript/TypeScript: $JS_FILES files"
        [[ ${PY_FILES:-0} -gt 0 ]] && echo -e "   • Python: $PY_FILES files"
        [[ ${YAML_FILES:-0} -gt 0 ]] && echo -e "   • YAML/YML: $YAML_FILES files"
        [[ ${JSON_FILES:-0} -gt 0 ]] && echo -e "   • JSON: $JSON_FILES files"
        [[ ${TF_FILES:-0} -gt 0 ]] && echo -e "   • Terraform: $TF_FILES files"
        [[ ${DOCKER_FILES:-0} -gt 0 ]] && echo -e "   • Dockerfiles: $DOCKER_FILES files"
        [[ ${SHELL_FILES:-0} -gt 0 ]] && echo -e "   • Shell Scripts: $SHELL_FILES files"
    }
fi
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

# Export TARGET_DIR and TARGET_NAME for all child scripts
export TARGET_DIR
export TARGET_NAME

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
    
    # Extract tool name for webhook (e.g., "trivy" from "Trivy Security Analysis")
    local tool_slug=$(echo "$tool_name" | tr '[:upper:]' '[:lower:]' | tr ' ' '-' | sed 's/[^a-z0-9-]//g')
    
    echo -e "${YELLOW}🔍 Running $tool_name...${NC}"
    echo "Command: $script_path $args"
    echo "Target: $TARGET_DIR"
    echo "Started: $(date)"
    echo ""
    
    # Send webhook notification: tool starting
    send_webhook "tool_start" "Starting $tool_name" "in_progress" "$tool_slug"
    
    if [[ -x "$script_path" ]]; then
        # Change to security tools directory to run scripts
        cd "$REPO_ROOT"
        
        if [[ -n "$args" ]]; then
            env TARGET_DIR="$TARGET_DIR" SCAN_ID="$SCAN_ID" SCAN_DIR="$SCAN_DIR" PRIMARY_BASELINE_IMAGE="${PRIMARY_BASELINE_IMAGE:-}" "$script_path" $args
        else
            env TARGET_DIR="$TARGET_DIR" SCAN_ID="$SCAN_ID" SCAN_DIR="$SCAN_DIR" PRIMARY_BASELINE_IMAGE="${PRIMARY_BASELINE_IMAGE:-}" "$script_path"
        fi
        
        local exit_code=$?
        
        if [[ $exit_code -eq 0 ]]; then
            echo -e "${GREEN}✅ $tool_name completed successfully${NC}"
            # Send webhook notification: tool completed successfully
            send_webhook "tool_complete" "$tool_name completed successfully" "success" "$tool_slug"
        else
            echo -e "${YELLOW}⚠️  $tool_name completed with warnings${NC}"
            # Send webhook notification: tool completed with warnings
            send_webhook "tool_complete" "$tool_name completed with warnings" "warning" "$tool_slug"
        fi
    else
        echo -e "${RED}❌ $tool_name script not found or not executable: $script_path${NC}"
        # Send webhook notification: tool failed
        send_webhook "tool_error" "$tool_name script not found" "error" "$tool_slug"
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
        echo -e "${YELLOW}ℹ️  Quick mode matches CI layer set: SBOM, Secrets, Helm, Trivy(fs+base), Grype(sbom+images), Xeol, API${NC}"
        echo -e "${YELLOW}ℹ️  Skipped in quick mode: SonarQube, ClamAV, Checkov, Anchore, Garak${NC}"
        echo ""

        # SBOM first - foundation for vulnerability scanning (with dependency installation)
        [[ "${SKIP_SBOM:-false}" != "true" ]] && run_security_tool "Complete SBOM Generation" "$SCRIPT_DIR/run-complete-sbom-scan.sh" || echo -e "${YELLOW}⏭️  Skipping SBOM (SKIP_SBOM=true)${NC}"
        export SBOM_FILE="$SCAN_DIR/sbom/filesystem.json"

        # Layer 2: Secret Detection
        [[ "${SKIP_TRUFFLEHOG:-false}" != "true" ]] && run_security_tool "TruffleHog Secret Detection" "$SCRIPT_DIR/run-trufflehog-scan.sh" "filesystem" || echo -e "${YELLOW}⏭️  Skipping TruffleHog (SKIP_TRUFFLEHOG=true)${NC}"

        # Layer 5: Helm (quick includes this, unlike ClamAV/Sonar/Checkov/Anchore)
        [[ "${SKIP_HELM:-false}" != "true" ]] && run_security_tool "Helm Chart Build" "$SCRIPT_DIR/run-helm-build.sh" || echo -e "${YELLOW}⏭️  Skipping Helm (SKIP_HELM=true)${NC}"

        # Layer 7: Trivy (filesystem + base image)
        if [[ "${SKIP_TRIVY:-false}" != "true" ]]; then
            run_security_tool "Trivy Security Analysis (Filesystem)" "$SCRIPT_DIR/run-trivy-scan.sh" "filesystem"
            run_security_tool "Trivy Base Image Analysis" "$SCRIPT_DIR/run-trivy-scan.sh" "base"
        else
            echo -e "${YELLOW}⏭️  Skipping Trivy (SKIP_TRIVY=true)${NC}"
        fi

        # Layer 8: Grype (SBOM + images)
        if [[ "${SKIP_GRYPE:-false}" != "true" ]]; then
            run_security_tool "Grype Vulnerability Scanning (SBOM)" "$SCRIPT_DIR/run-grype-scan.sh" "sbom"
            run_security_tool "Grype Vulnerability Scanning (Images)" "$SCRIPT_DIR/run-grype-scan.sh" "images"
        else
            echo -e "${YELLOW}⏭️  Skipping Grype (SKIP_GRYPE=true)${NC}"
        fi

        # Layer 9: Xeol EOL detection
        [[ "${SKIP_XEOL:-false}" != "true" ]] && run_security_tool "Xeol End-of-Life Detection" "$SCRIPT_DIR/run-xeol-scan.sh" || echo -e "${YELLOW}⏭️  Skipping Xeol (SKIP_XEOL=true)${NC}"

        # Layer 11: API Discovery
        [[ "${SKIP_API_DISCOVERY:-false}" != "true" ]] && run_security_tool "API Discovery" "$SCRIPT_DIR/run-api-discovery.sh" || echo -e "${YELLOW}⏭️  Skipping API Discovery (SKIP_API_DISCOVERY=true)${NC}"

        # Layer 12: Garak — skipped in quick mode (opt-in via RUN_GARAK=true)
        if [[ "${RUN_GARAK:-false}" == "true" ]] && [[ "${SKIP_GARAK:-false}" != "true" ]]; then
            run_security_tool "Garak LLM Security Probing" "$SCRIPT_DIR/run-garak-scan.sh"
        else
            echo -e "${YELLOW}⏭️  Skipping Garak LLM Security Probing (quick mode; set RUN_GARAK=true to enable)${NC}"
        fi
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
        if [[ "${SKIP_SONAR:-false}" != "true" ]]; then
            run_security_tool "SonarQube Analysis" "$SCRIPT_DIR/run-sonar-analysis.sh"
        else
            echo -e "${YELLOW}⏭️  Skipping SonarQube (SKIP_SONAR=true)${NC}"
        fi
        
        echo -e "${PURPLE}☸️  Infrastructure Security${NC}"
        if [[ "${SKIP_CHECKOV:-false}" != "true" ]]; then
            run_security_tool "Checkov IaC Security" "$SCRIPT_DIR/run-checkov-scan.sh"
        else
            echo -e "${YELLOW}⏭️  Skipping Checkov (SKIP_CHECKOV=true)${NC}"
        fi
        
        echo -e "${PURPLE}🌐 API Discovery${NC}"
        if [[ "${SKIP_API_DISCOVERY:-false}" != "true" ]]; then
            run_security_tool "API Discovery" "$SCRIPT_DIR/run-api-discovery.sh"
        else
            echo -e "${YELLOW}⏭️  Skipping API Discovery (SKIP_API_DISCOVERY=true)${NC}"
        fi

        echo -e "${PURPLE}🔌 Network Discovery${NC}"
        if [[ "${SKIP_NETWORK_DISCOVERY:-false}" != "true" ]]; then
            run_security_tool "Network Discovery" "$SCRIPT_DIR/run-network-discovery.sh"
        else
            echo -e "${YELLOW}⏭️  Skipping Network Discovery (SKIP_NETWORK_DISCOVERY=true)${NC}"
        fi

        echo -e "${PURPLE}🤖 LLM Security Probing${NC}"
        if [[ "${RUN_GARAK:-false}" == "true" ]] && [[ "${SKIP_GARAK:-false}" != "true" ]]; then
            run_security_tool "Garak LLM Security Probing" "$SCRIPT_DIR/run-garak-scan.sh"
        else
            echo -e "${YELLOW}⏭️  Skipping Garak LLM Security Probing (set RUN_GARAK=true to enable)${NC}"
        fi
        ;;
        
    "full")
        print_section "Complete Twelve-Layer Security Architecture Scan - Target: $(basename "$TARGET_DIR")"
        
        # SBOM FIRST - Generate bill of materials for all other tools to use (with dependency installation)
        echo -e "${PURPLE}📋 Layer 1: Software Bill of Materials (SBOM) - Foundation for all scans${NC}"
        if [[ "${SKIP_SBOM:-false}" != "true" ]]; then
            run_security_tool "Complete SBOM Generation" "$SCRIPT_DIR/run-complete-sbom-scan.sh"
        else
            echo -e "${YELLOW}⏭️  Skipping Layer 1 - SBOM (SKIP_SBOM=true)${NC}"
        fi
        
        # Export SBOM path for other tools to use
        export SBOM_FILE="$SCAN_DIR/sbom/filesystem.json"
        
        echo -e "${PURPLE}🔐 Layer 2: Secret Detection${NC}"
        if [[ "${SKIP_TRUFFLEHOG:-false}" != "true" ]]; then
            run_security_tool "TruffleHog Filesystem" "$SCRIPT_DIR/run-trufflehog-scan.sh" "filesystem"
        else
            echo -e "${YELLOW}⏭️  Skipping Layer 2 - TruffleHog (SKIP_TRUFFLEHOG=true)${NC}"
        fi
        
        echo -e "${PURPLE}📊 Layer 3: Code Quality Analysis${NC}"
        if [[ "${SKIP_SONAR:-false}" != "true" ]]; then
            run_security_tool "SonarQube Analysis" "$SCRIPT_DIR/run-sonar-analysis.sh"
        else
            echo -e "${YELLOW}⏭️  Skipping Layer 3 - SonarQube (SKIP_SONAR=true)${NC}"
        fi
        
        echo -e "${PURPLE}🦠 Layer 4: Malware Detection${NC}"
        if [[ "${SKIP_CLAMAV:-false}" != "true" ]]; then
            run_security_tool "ClamAV Antivirus Scan" "$SCRIPT_DIR/run-clamav-scan.sh"
        else
            echo -e "${YELLOW}⏭️  Skipping Layer 4 - ClamAV (SKIP_CLAMAV=true)${NC}"
        fi
        
        echo -e "${PURPLE}🏗️  Layer 5: Helm Chart Building${NC}"
        if [[ "${SKIP_HELM:-false}" != "true" ]]; then
            run_security_tool "Helm Chart Build" "$SCRIPT_DIR/run-helm-build.sh"
        else
            echo -e "${YELLOW}⏭️  Skipping Layer 5 - Helm (SKIP_HELM=true)${NC}"
        fi
        
        echo -e "${PURPLE}☸️  Layer 6: Infrastructure Security${NC}"
        if [[ "${SKIP_CHECKOV:-false}" != "true" ]]; then
            run_security_tool "Checkov IaC Security" "$SCRIPT_DIR/run-checkov-scan.sh"
        else
            echo -e "${YELLOW}⏭️  Skipping Layer 6 - Checkov (SKIP_CHECKOV=true)${NC}"
        fi
        
        echo -e "${PURPLE}🛡️  Layer 7: Container Security (Trivy)${NC}"
        if [[ "${SKIP_TRIVY:-false}" != "true" ]]; then
            run_security_tool "Trivy Filesystem" "$SCRIPT_DIR/run-trivy-scan.sh" "filesystem"
            run_security_tool "Trivy Base Images" "$SCRIPT_DIR/run-trivy-scan.sh" "base"
        else
            echo -e "${YELLOW}⏭️  Skipping Layer 7 - Trivy (SKIP_TRIVY=true)${NC}"
        fi
        
        echo -e "${PURPLE}🔍 Layer 8: Vulnerability Detection (Grype - SBOM-based)${NC}"
        if [[ "${SKIP_GRYPE:-false}" != "true" ]]; then
            run_security_tool "Grype SBOM Scan" "$SCRIPT_DIR/run-grype-scan.sh" "sbom"
            run_security_tool "Grype Base Images" "$SCRIPT_DIR/run-grype-scan.sh" "images"
        else
            echo -e "${YELLOW}⏭️  Skipping Layer 8 - Grype (SKIP_GRYPE=true)${NC}"
        fi
        
        echo -e "${PURPLE}⚰️  Layer 9: End-of-Life Detection${NC}"
        if [[ "${SKIP_XEOL:-false}" != "true" ]]; then
            run_security_tool "Xeol EOL Detection" "$SCRIPT_DIR/run-xeol-scan.sh"
        else
            echo -e "${YELLOW}⏭️  Skipping Layer 9 - Xeol (SKIP_XEOL=true)${NC}"
        fi
        
        echo -e "${PURPLE}⚓ Layer 10: Anchore Security Analysis${NC}"
        if [[ "${SKIP_ANCHORE:-false}" != "true" ]]; then
            run_security_tool "Anchore Security Scan" "$SCRIPT_DIR/run-anchore-scan.sh"
        else
            echo -e "${YELLOW}⏭️  Skipping Layer 10 - Anchore (SKIP_ANCHORE=true)${NC}"
        fi
        
        echo -e "${PURPLE}🌐 Layer 11: API Discovery${NC}"
        if [[ "${SKIP_API_DISCOVERY:-false}" != "true" ]]; then
            run_security_tool "API Discovery" "$SCRIPT_DIR/run-api-discovery.sh"
        else
            echo -e "${YELLOW}⏭️  Skipping Layer 11 - API Discovery (SKIP_API_DISCOVERY=true)${NC}"
        fi

        echo -e "${PURPLE}🤖 Layer 12: LLM Security Probing${NC}"
        # Garak is skipped by default in full mode to match CI behavior.
        # Set RUN_GARAK=true to opt-in, or use SKIP_GARAK=true / --no-garak to force-skip.
        if [[ "${RUN_GARAK:-false}" == "true" ]] && [[ "${SKIP_GARAK:-false}" != "true" ]]; then
            run_security_tool "Garak LLM Security Probing" "$SCRIPT_DIR/run-garak-scan.sh"
        else
            echo -e "${YELLOW}⏭️  Skipping Garak LLM Security Probing (set RUN_GARAK=true to enable)${NC}"
        fi

        echo -e "${PURPLE}🔌 Layer 13: Network Discovery (Ports, Protocols, Services)${NC}"
        if [[ "${SKIP_NETWORK_DISCOVERY:-false}" != "true" ]]; then
            run_security_tool "Network Discovery" "$SCRIPT_DIR/run-network-discovery.sh"
        else
            echo -e "${YELLOW}⏭️  Skipping Layer 13 - Network Discovery (SKIP_NETWORK_DISCOVERY=true)${NC}"
        fi

        echo -e "${PURPLE}🥒 Layer 14: Pickle/Serialization Safety${NC}"
        if [[ "${SKIP_PICKLESCAN:-false}" != "true" ]]; then
            run_security_tool "Picklescan ML Safety" "$SCRIPT_DIR/run-picklescan.sh"
        else
            echo -e "${YELLOW}⏭️  Skipping Layer 14 - Picklescan (SKIP_PICKLESCAN=true)${NC}"
        fi

        echo -e "${PURPLE}📋 Layer 15: Model Card Compliance${NC}"
        if [[ "${SKIP_MODELCARD:-false}" != "true" ]]; then
            run_security_tool "Model Card Compliance" "$SCRIPT_DIR/run-modelcard-check.sh"
        else
            echo -e "${YELLOW}⏭️  Skipping Layer 15 - ModelCard (SKIP_MODELCARD=true)${NC}"
        fi
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
echo "  🤖 GARAK_TARGET_TYPE=openai GARAK_TARGET_NAME=gpt-5-nano OPENAI_API_KEY=... ./scripts/shell/run-garak-scan.sh"
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

# Check Garak summary for LLM security probe status
if [[ -f "$SCAN_DIR/garak/${SCAN_ID}_garak-results.json" ]]; then
    garak_status=$(jq -r '.status // "unknown"' "$SCAN_DIR/garak/${SCAN_ID}_garak-results.json" 2>/dev/null || echo "unknown")
    if [[ "$garak_status" != "success" ]]; then
        echo -e "  ${YELLOW}🟡 Garak: LLM probe run reported status '$garak_status'${NC}"
    else
        echo -e "  ${GREEN}🟢 Garak: LLM probe run completed successfully${NC}"
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

# ── Step 1: Generate findings summary FIRST (CI order) ────────────────────────
# In CI, generate-scan-findings-summary runs before the dashboard so the
# dashboard can read accurate deduplicated counts from the JSON file.
echo ""
echo -e "${BLUE}🚨 Generating Security Findings Summary for Scan: ${SCAN_ID}...${NC}"
if [[ -f "$SCRIPT_DIR/generate-scan-findings-summary.sh" ]]; then
    # shellcheck disable=SC1090
    source "$SCRIPT_DIR/generate-scan-findings-summary.sh"
    generate_scan_findings_summary "$SCAN_ID" "$TARGET_DIR" "$REPORTS_ROOT"
    summary_result=$?

    if [[ $summary_result -eq 0 ]]; then
        echo -e "${GREEN}✅ Security findings summary generated successfully${NC}"
        if [[ -f "$SCAN_DIR/security-findings-summary.json" ]]; then
            echo -e "${CYAN}📊 Scan Summary: $SCAN_DIR/security-findings-summary.json${NC}"
            critical_count=$(jq -r '.summary.total_critical' "$SCAN_DIR/security-findings-summary.json" 2>/dev/null || echo "0")
            high_count=$(jq -r     '.summary.total_high'     "$SCAN_DIR/security-findings-summary.json" 2>/dev/null || echo "0")
            medium_count=$(jq -r   '.summary.total_medium'   "$SCAN_DIR/security-findings-summary.json" 2>/dev/null || echo "0")
            low_count=$(jq -r      '.summary.total_low'      "$SCAN_DIR/security-findings-summary.json" 2>/dev/null || echo "0")
            echo -e "${CYAN}📈 Findings Overview: Critical($critical_count) High($high_count) Medium($medium_count) Low($low_count)${NC}"
        fi
    else
        echo -e "${YELLOW}⚠️  Security findings summary generation had issues${NC}"
    fi
else
    echo -e "${YELLOW}⚠️  generate-scan-findings-summary.sh not found${NC}"
fi

# ── Step 2: Apply suppression rules + write suppressed-findings.md (CI order) ─
# check-severity-gate.sh parses .epyon-ignore.yml, logs per-CVE/package
# suppressions to suppressed-findings.md, and writes *-filtered.json.
# This MUST run before the dashboard so the dashboard reads the suppression data.
echo ""
echo -e "${BLUE}🔇 Applying suppression rules and checking severity gate...${NC}"
if [[ -f "$SCRIPT_DIR/check-severity-gate.sh" ]]; then
    FAIL_ON_CRITICAL="${FAIL_ON_CRITICAL:-false}" \
    FAIL_ON_HIGH="${FAIL_ON_HIGH:-false}" \
    WARNING_ONLY="${WARNING_ONLY:-true}" \
    SCAN_DIR="$SCAN_DIR" TARGET_DIR="$TARGET_DIR" \
    "$SCRIPT_DIR/check-severity-gate.sh" || true
    echo -e "${GREEN}✅ Severity gate and suppression check complete${NC}"
fi

# ── Coverage gate ──────────────────────────────────────────────────────────────
if [[ -f "$SCRIPT_DIR/check-coverage-gate.sh" ]] && [[ "${SKIP_COVERAGE:-false}" != "true" ]]; then
    echo ""
    echo -e "${BLUE}📊 Checking coverage gate...${NC}"
    SCAN_DIR="$SCAN_DIR" \
    COVERAGE_THRESHOLD="${COVERAGE_THRESHOLD:-80}" \
    FAIL_ON_COVERAGE="${FAIL_ON_COVERAGE:-false}" \
    WARNING_ONLY="${COVERAGE_WARNING_ONLY:-true}" \
    "$SCRIPT_DIR/check-coverage-gate.sh" || true
fi

if [[ ! -f "$SCRIPT_DIR/check-severity-gate.sh" ]]; then
    # Fallback: apply tool-level suppression without per-CVE logging
    echo -e "${YELLOW}⚠️  check-severity-gate.sh not found — applying tool-level suppression only${NC}"
    FINDINGS_SUMMARY="$SCAN_DIR/security-findings-summary.json"
    if [[ -f "$FINDINGS_SUMMARY" ]]; then
        IGNORE_CACHE="${IGNORE_CACHE:-/tmp/epyon-ignore-cache.json}"
        if [[ -f "$SCRIPT_DIR/parse-epyon-ignore.sh" ]]; then
            # shellcheck disable=SC1090
            source "$SCRIPT_DIR/parse-epyon-ignore.sh"
            parse_ignore_rules "${TARGET_DIR}/.epyon-ignore.yml" 2>/dev/null || true
        else
            echo "{\"ignores\": []}" > "$IGNORE_CACHE"
        fi

        if [[ -f "$SCRIPT_DIR/filter-ignored-findings.sh" ]]; then
            # shellcheck disable=SC1090
            source "$SCRIPT_DIR/filter-ignored-findings.sh" 2>/dev/null || true
            init_suppressed_log 2>/dev/null || true
        fi

        SUPPRESSED_TOOLS_JQ=""
        for tool_name in grype trivy trufflehog checkov clamav anchore xeol; do
            if declare -f is_tool_ignored >/dev/null 2>&1 && is_tool_ignored "$tool_name" 2>/dev/null; then
                echo -e "${YELLOW}   Suppressing findings from tool: $tool_name${NC}"
                SUPPRESSED_TOOLS_JQ="${SUPPRESSED_TOOLS_JQ} and ((.tool // \"\" | ascii_downcase) | startswith(\"${tool_name}\") | not)"
            fi
        done

        FILTERED_SUMMARY="${FINDINGS_SUMMARY%.json}-filtered.json"
        if [[ -n "$SUPPRESSED_TOOLS_JQ" ]]; then
            FILTER_EXPR="select(true ${SUPPRESSED_TOOLS_JQ})"
            JQ_FILTER=".critical_findings = [.critical_findings[] | ${FILTER_EXPR}] |
              .high_findings     = [.high_findings[]     | ${FILTER_EXPR}] |
              .medium_findings   = [.medium_findings[]   | ${FILTER_EXPR}] |
              .low_findings      = [.low_findings[]      | ${FILTER_EXPR}] |
              .summary.total_critical = ([.critical_findings[] | ${FILTER_EXPR}] | length) |
              .summary.total_high     = ([.high_findings[]     | ${FILTER_EXPR}] | length) |
              .summary.total_medium   = ([.medium_findings[]   | ${FILTER_EXPR}] | length) |
              .summary.total_low      = ([.low_findings[]      | ${FILTER_EXPR}] | length)"
            jq "$JQ_FILTER" "$FINDINGS_SUMMARY" > "$FILTERED_SUMMARY" \
                && echo -e "${GREEN}✅ Filtered findings written to: $FILTERED_SUMMARY${NC}" \
                || echo -e "${YELLOW}⚠️  Could not write filtered findings${NC}"
        else
            cp "$FINDINGS_SUMMARY" "$FILTERED_SUMMARY" \
                && echo -e "${GREEN}✅ No active suppressions — copied summary to: $FILTERED_SUMMARY${NC}" \
                || echo -e "${YELLOW}⚠️  Could not copy findings summary${NC}"
        fi
    fi
fi

# ── Step 3: Enrich findings with NVD + CISA KEV data ─────────────────────────
echo ""
echo -e "${BLUE}🔍 Enriching findings with NVD + CISA KEV data...${NC}"
if [[ -f "$SCRIPT_DIR/enrich-findings.sh" ]]; then
    "$SCRIPT_DIR/enrich-findings.sh" --scan-dir "$SCAN_DIR" || true
else
    echo -e "${YELLOW}⚠️  enrich-findings.sh not found, skipping enrichment${NC}"
fi

# ── Step 3.5: Enrich with international CVE feeds ────────────────────────────
echo ""
echo -e "${BLUE}🌐 Enriching with international CVE feeds (OSV, GHSA, JVN, etc.)...${NC}"
if [[ -f "$SCRIPT_DIR/enrich-findings-multi-feed.sh" ]]; then
    "$SCRIPT_DIR/enrich-findings-multi-feed.sh" --scan-dir "$SCAN_DIR" || true
else
    echo -e "${YELLOW}⚠️  enrich-findings-multi-feed.sh not found, skipping multi-feed enrichment${NC}"
fi

# ── Step 4: Consolidate + generate dashboard (reads findings summary + suppressed-findings.md) ─
# Run the unified report consolidation
if [[ -f "$SCRIPT_DIR/consolidate-security-reports.sh" ]]; then
    SCAN_DIR="$SCAN_DIR" SCAN_ID="$SCAN_ID" "$SCRIPT_DIR/consolidate-security-reports.sh"
    consolidation_result=$?
    
    if [[ $consolidation_result -eq 0 ]]; then
        echo -e "${GREEN}✅ Security reports consolidated successfully${NC}"

        # ── Generate interactive dashboard + root-level shortcut ───────────────
        if [[ -f "$SCRIPT_DIR/generate-security-dashboard.sh" ]]; then
            echo ""
            echo -e "${BLUE}📊 Generating interactive security dashboard...${NC}"
            SCAN_DIR="$SCAN_DIR" "$SCRIPT_DIR/generate-security-dashboard.sh" 2>/dev/null || \
                echo -e "${YELLOW}⚠️  Interactive dashboard generation had issues${NC}"
        fi

        # Fallback: create root symlink if neither generator ran
        if [[ ! -f "$SCAN_DIR/security-dashboard.html" ]] && \
           [[ -f "$SCAN_DIR/consolidated-reports/dashboards/security-dashboard.html" ]]; then
            ln -sf "consolidated-reports/dashboards/security-dashboard.html" \
                "$SCAN_DIR/security-dashboard.html" 2>/dev/null || \
            cp "$SCAN_DIR/consolidated-reports/dashboards/security-dashboard.html" \
                "$SCAN_DIR/security-dashboard.html" 2>/dev/null || true
        fi
        
        # Display scan directory information
        echo ""
        echo -e "${BLUE}📊 Scan Results Location:${NC}"
        echo -e "${CYAN}📁 Scan Directory: $SCAN_DIR${NC}"
        echo -e "${CYAN}📊 Consolidated Reports: $SCAN_DIR/consolidated-reports/${NC}"
        echo -e "${CYAN}🔍 View all scan artifacts: ls -la $SCAN_DIR/*/"${NC}
        
        echo ""
        echo -e "${BLUE}🔧 Quick Access:${NC}"
        echo -e "${YELLOW}cd $SCAN_DIR${NC}"
        if [[ -f "$SCAN_DIR/security-dashboard.html" ]]; then
            echo -e "${YELLOW}open $SCAN_DIR/security-dashboard.html${NC}"
        elif [[ -f "$SCAN_DIR/consolidated-reports/dashboards/security-dashboard.html" ]]; then
            echo -e "${YELLOW}open $SCAN_DIR/consolidated-reports/dashboards/security-dashboard.html${NC}"
        fi
    else
        echo -e "${YELLOW}⚠️  Report consolidation had issues${NC}"
        analysis_success=false
    fi

    # ── Step 5: Generate Scan Manifest for Integrity Verification ─────────────
    echo ""
    echo -e "${BLUE}🔐 Generating scan manifest for integrity verification...${NC}"
    if [[ -f "$SCRIPT_DIR/generate-scan-manifest.sh" ]]; then
        "$SCRIPT_DIR/generate-scan-manifest.sh" "$SCAN_DIR" "$TARGET_DIR"
        manifest_result=$?
        
        if [[ $manifest_result -eq 0 ]]; then
            echo -e "${GREEN}✅ Scan manifest generated successfully${NC}"
            if [[ -f "$SCAN_DIR/scan-manifest.json" ]]; then
                echo -e "${CYAN}📋 Manifest: $SCAN_DIR/scan-manifest.json${NC}"
                echo -e "${CYAN}🔍 Verify: ./scripts/shell/verify-scan-manifest.sh $SCAN_DIR${NC}"
            fi
        else
            echo -e "${YELLOW}⚠️  Manifest generation had issues${NC}"
        fi
    else
        echo -e "${YELLOW}⚠️  Manifest generation script not found${NC}"
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

RUN_END_EPOCH=$(date +%s)
RUN_ELAPSED_SECONDS=$((RUN_END_EPOCH - RUN_START_EPOCH))
printf -v RUN_ELAPSED_HUMAN '%02dh:%02dm:%02ds' $((RUN_ELAPSED_SECONDS/3600)) $(((RUN_ELAPSED_SECONDS%3600)/60)) $((RUN_ELAPSED_SECONDS%60))

# Send webhook notification: scan complete
if [[ "$analysis_success" == "true" ]]; then
    send_webhook "scan_complete" "Security scan completed successfully for $APP_NAME" "success" ""
else
    send_webhook "scan_complete" "Security scan completed with warnings for $APP_NAME" "warning" ""
fi

echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}🎯 Target Security Scan Finished Successfully!${NC}"
echo -e "${CYAN}Target: $TARGET_DIR${NC}"
echo -e "${CYAN}Scan ID: $SCAN_ID${NC}"
echo -e "${CYAN}Scan Directory: $SCAN_DIR${NC}"
echo -e "${CYAN}Elapsed time: $RUN_ELAPSED_HUMAN${NC}"
echo -e "${CYAN}All scan artifacts stored in: $SCAN_DIR${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Automatically open the dashboard (prefer root-level shortcut)
if [[ -f "$SCAN_DIR/security-dashboard.html" ]]; then
    DASHBOARD_HTML="$SCAN_DIR/security-dashboard.html"
else
    DASHBOARD_HTML="$SCAN_DIR/consolidated-reports/dashboards/security-dashboard.html"
fi
if [[ -f "$DASHBOARD_HTML" ]]; then
    echo -e "${GREEN}🌐 Opening security dashboard...${NC}"
    
    # Convert WSL path to Windows path if needed
    if grep -qi microsoft /proc/version 2>/dev/null; then
        # Running in WSL - convert path and use Windows command
        WINDOWS_PATH=$(wslpath -w "$DASHBOARD_HTML" 2>/dev/null || echo "$DASHBOARD_HTML")
        cmd.exe /c start "" "$WINDOWS_PATH" 2>/dev/null
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        xdg-open "$DASHBOARD_HTML" 2>/dev/null || echo -e "${YELLOW}Please open: $DASHBOARD_HTML${NC}"
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        open "$DASHBOARD_HTML"
    elif [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "cygwin" ]]; then
        start "$DASHBOARD_HTML"
    else
        echo -e "${YELLOW}Please open: $DASHBOARD_HTML${NC}"
    fi
else
    echo -e "${YELLOW}⚠️  Dashboard not found at: $DASHBOARD_HTML${NC}"
fi

# Cleanup cloned repository if applicable
if [[ "$CLONED_REPO" == "true" ]] && [[ -n "$CLONE_DIR" ]]; then
    echo ""
    echo -e "${CYAN}🧹 Cleaning up cloned repository...${NC}"
    rm -rf "$CLONE_DIR"
    echo -e "${GREEN}✅ Temporary clone removed: $CLONE_DIR${NC}"
fi