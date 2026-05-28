#!/bin/bash

# Epyon — Fifteen-Layer Security Scanning Platform
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
