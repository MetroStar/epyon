#!/bin/bash

# ══════════════════════════════════════════════════════════════════════════════
# SHELL COMPATIBILITY AUTO-DETECTION
# ══════════════════════════════════════════════════════════════════════════════
# Epyon requires bash 4+ for array operations, parameter expansion, and process
# substitution. This section detects the current shell and re-executes in bash
# if needed, providing cross-platform compatibility (macOS, Linux, Windows/Git Bash).
#
# Supported environments:
#   - Linux (bash)
#   - macOS (zsh/bash — auto-switches to bash 4+)
#   - Windows (Git Bash, WSL, Cygwin)
#
# If this script was invoked with bash 3.x (e.g., macOS default), it will
# automatically re-execute itself using bash 4+ from Homebrew or other locations.
# If bash 4+ is not available, it will print installation instructions and exit.
# ══════════════════════════════════════════════════════════════════════════════

# Check bash version FIRST and re-exec with newer bash if needed
BASH_VERSION_MAJOR="${BASH_VERSINFO[0]:-0}"
if [ "$BASH_VERSION_MAJOR" -lt 4 ]; then
    # Detect OS for better error messages
    OS_TYPE="$(uname -s 2>/dev/null || echo "Unknown")"
    
    # Try to find bash 4+ and re-execute
    for bash_path in \
        /opt/homebrew/bin/bash \
        /usr/local/bin/bash \
        /home/linuxbrew/.linuxbrew/bin/bash \
        /usr/bin/bash \
        bash; do
        if command -v "$bash_path" >/dev/null 2>&1 && [ "$bash_path" != "/bin/bash" ]; then
            # Check version before re-executing
            FOUND_VERSION=$("$bash_path" --version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+' | head -1)
            FOUND_MAJOR=$(echo "$FOUND_VERSION" | cut -d. -f1)
            
            # Only use bash 4.0+
            if [ -n "$FOUND_MAJOR" ] && [ "$FOUND_MAJOR" -ge 4 ]; then
                # Found suitable bash — re-execute this script
                exec "$bash_path" "$0" "$@"
            fi
        fi
    done
    
    # No bash 4+ found — provide helpful error message
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "❌ ERROR: Epyon requires bash 4.0 or later"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "Current bash version: ${BASH_VERSION}"
    echo "Required: 4.0 or later"
    echo ""
    echo "macOS users: System bash is 3.2 — install bash 4+ via Homebrew:"
    echo "  brew install bash"
    echo "  /opt/homebrew/bin/bash ./epyon.sh <target>"
    echo ""
    echo "Or add Homebrew bash to your PATH:"
    echo "  export PATH=\"/opt/homebrew/bin:\$PATH\""
    echo ""
    exit 1
fi

# Check if we're running in a non-bash shell (e.g., zsh)
if [ -z "${BASH_VERSION:-}" ]; then
    # Not running in bash — try to find and re-exec with bash
    
    # Detect OS for better error messages
    OS_TYPE="$(uname -s 2>/dev/null || echo "Unknown")"
    
    # Try common bash locations (prefer newer versions first)
    # Order: Homebrew (macOS), Linuxbrew, standard paths
    for bash_path in \
        /opt/homebrew/bin/bash \
        /usr/local/bin/bash \
        /home/linuxbrew/.linuxbrew/bin/bash \
        /usr/bin/bash \
        /bin/bash \
        bash; do
        if command -v "$bash_path" >/dev/null 2>&1; then
            # Found bash — re-execute this script
            exec "$bash_path" "$0" "$@"
        fi
    done
    
    # Bash not found — provide helpful error message
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "❌ ERROR: Epyon requires bash but it was not found on your system."
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "Current shell: ${SHELL:-unknown}"
    echo "Detected OS: $OS_TYPE"
    echo ""
    echo "Installation instructions:"
    echo ""
    case "$OS_TYPE" in
        Darwin*)
            echo "  macOS (Homebrew):"
            echo "    brew install bash"
            echo ""
            echo "  Or use the system bash:"
            echo "    bash ./epyon.sh <target>"
            ;;
        Linux*)
            echo "  Debian/Ubuntu:"
            echo "    sudo apt-get update && sudo apt-get install -y bash"
            echo ""
            echo "  Red Hat/CentOS/Fedora:"
            echo "    sudo yum install -y bash"
            echo ""
            echo "  Alpine:"
            echo "    apk add --no-cache bash"
            ;;
        MINGW*|MSYS*|CYGWIN*)
            echo "  Windows (Git Bash):"
            echo "    Git Bash includes bash by default."
            echo "    Ensure you're running this script from Git Bash, not PowerShell/CMD."
            echo ""
            echo "  Windows (WSL):"
            echo "    Bash is included in WSL by default."
            ;;
        *)
            echo "  Please install bash 4.0 or later for your platform."
            ;;
    esac
    echo ""
    echo "Workaround (if bash is installed but not in PATH):"
    echo "  bash ./epyon.sh <target>"
    echo ""
    exit 1
fi

# Verify bash version (require 4.0+ for associative arrays)
BASH_VERSION_MAJOR="${BASH_VERSINFO[0]:-0}"
if [ "$BASH_VERSION_MAJOR" -lt 4 ]; then
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "❌ ERROR: Epyon requires bash 4.0 or later"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "Current bash version: ${BASH_VERSION}"
    echo "Required: 4.0 or later"
    echo ""
    echo "macOS users: System bash is 3.2 — install bash 4+ via Homebrew:"
    echo "  brew install bash"
    echo "  /usr/local/bin/bash ./epyon.sh <target>"
    echo ""
    exit 1
fi

# ══════════════════════════════════════════════════════════════════════════════
# Epyon — Fifteen-Layer Security Scanning Platform
# ══════════════════════════════════════════════════════════════════════════════
# Entry point: shows usage overview or dispatches to the main scanner.
#
# Usage:
#   ./epyon.sh                        # Show this help
#   ./epyon.sh <TARGET> [SCAN_TYPE]   # Run a scan (delegates to run-target-security-scan.sh)
#   ./epyon.sh --help                 # Show full scanner help

set -euo pipefail

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
WHITE='\033[1;37m'
BOLD='\033[1m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERSION_FILE="${SCRIPT_DIR}/VERSION"
VERSION="$(cat "$VERSION_FILE" 2>/dev/null || echo "unknown")"
SCANNER="${SCRIPT_DIR}/scripts/shell/run-target-security-scan.sh"

# If any args are passed, forward directly to the scanner (including --help)
if [[ $# -gt 0 ]]; then
    exec "$SCANNER" "$@"
fi

# ── No args: show overview ─────────────────────────────────────────────────────

echo ""
echo -e "${WHITE}${BOLD}  Epyon Security Scanner${NC}  ${CYAN}v${VERSION}${NC}"
echo -e "  ${BLUE}Fifteen-layer automated security scanning platform${NC}"
echo ""
echo -e "${BOLD}Quick Start${NC}"
echo -e "  ${GREEN}./epyon.sh /path/to/project${NC}              Full scan (all 15 layers)"
echo -e "  ${GREEN}./epyon.sh /path/to/project quick${NC}        Quick scan (SBOM, secrets, CVEs)"
echo -e "  ${GREEN}./epyon.sh https://github.com/org/repo.git${NC}  Scan a remote Git repo"
echo ""
echo -e "${BOLD}Scan Types${NC}"
echo -e "  ${CYAN}quick${NC}      SBOM, TruffleHog, Helm, Trivy, Grype, Xeol, API Discovery"
echo -e "  ${CYAN}full${NC}       All 15 layers including SonarQube, ClamAV, Checkov, Garak (default)"
echo -e "  ${CYAN}images${NC}     Container-focused: TruffleHog, Grype, Trivy, Xeol"
echo -e "  ${CYAN}analysis${NC}   SonarQube, Checkov, API Discovery, Network Discovery"
echo -e "  ${CYAN}stig${NC}       DISA STIG compliance assessment (Layer 13)"
echo ""
echo -e "${BOLD}Security Layers${NC}"
echo -e "  1  SBOM Generation (Syft)          9  EOL Detection (Xeol)"
echo -e "  2  Secret Detection (TruffleHog)   10 Container Analysis (Anchore)"
echo -e "  3  Code Quality (SonarQube)        11 API Discovery"
echo -e "  4  Malware Detection (ClamAV)      12 LLM Security Probing (Garak)"
echo -e "  5  Helm Chart Build                13 Network Discovery"
echo -e "  6  IaC Security (Checkov)          14 Pickle/Serialization Safety"
echo -e "  7  Container Security (Trivy)      15 Model Card Compliance"
echo -e "  8  Vulnerability Scanning (Grype)"
echo ""
echo -e "${BOLD}Common Options${NC}"
echo -e "  ${YELLOW}--skip-tools sonar,garak${NC}         Skip specific layers"
echo -e "  ${YELLOW}--subdir apps/api <GIT_URL>${NC}      Scan a subdirectory of a repo"
echo -e "  ${YELLOW}--non-interactive${NC}                Disable prompts (CI/scripted use)"
echo -e "  ${YELLOW}--no-garak${NC}                       Skip Garak LLM probing"
echo -e "  ${YELLOW}--list-modes${NC}                     Print all scan types and exit"
echo ""
echo -e "${BOLD}More Detail${NC}"
echo -e "  ${GREEN}./epyon.sh --help${NC}                Full option reference"
echo -e "  ${GREEN}./epyon.sh --list-modes${NC}          Scan type descriptions"
echo -e "  ${GREEN}cat README.md${NC}                    Project documentation"
echo ""
echo -e "${BOLD}Utility Scripts${NC}"
echo -e "  ${CYAN}scripts/shell/run-stig-scan.sh${NC}              STIG compliance only"
echo -e "  ${CYAN}scripts/shell/generate-interactive-dashboard.sh${NC}  Rebuild dashboard"
echo -e "  ${CYAN}scripts/shell/open-latest-dashboard.sh${NC}      Open latest results"
echo -e "  ${CYAN}scripts/shell/enrich-findings.sh${NC}             CISA KEV + NVD enrichment"
echo -e "  ${CYAN}scripts/shell/cleanup-scripts.sh${NC}            Remove old scan directories"
echo -e "  ${CYAN}run-tests.sh${NC}                                Run the test suite"
echo ""
