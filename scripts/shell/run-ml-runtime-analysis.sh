#!/bin/bash
# Layer 20 — ML Runtime Behavioral Analysis
# Executes ML models in sandboxed environments and monitors runtime behavior.
#
# WARNING: This layer executes potentially malicious code in a sandbox.
# Only run on models you need to analyze. Requires Docker/Podman.
#
# This scan is OPTIONAL and OPT-IN only. Set RUN_ML_RUNTIME=true to enable.
#
# Environment Variables:
#   TARGET_DIR       - Target directory containing models (required)
#   SCAN_DIR         - Output directory for scan results (required)
#   APP_NAME         - Application name (required)
#   ML_RUNTIME_TIMEOUT - Timeout per model in seconds (default: 60)
#   ML_RUNTIME_SANDBOX - Sandbox runtime: docker or podman (default: auto-detect)
#   SKIP_ML_RUNTIME  - Set to true to skip this scan
#   RUN_ML_RUNTIME   - Must be true to enable this scan (opt-in)

set -euo pipefail

# ═══════════════════════════════════════════════════════════════════════════
# Configuration
# ═══════════════════════════════════════════════════════════════════════════

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_SCRIPT="$SCRIPT_DIR/run-ml-runtime-analysis.py"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# ═══════════════════════════════════════════════════════════════════════════
# Functions
# ═══════════════════════════════════════════════════════════════════════════

show_help() {
    cat << EOF
Layer 20 — ML Runtime Behavioral Analysis

Executes ML models in sandboxed environments and monitors runtime behavior.

WARNING: This layer executes potentially malicious code in a sandbox.
Only run on models you need to analyze. Requires Docker/Podman.

This scan is OPTIONAL and OPT-IN only. Set RUN_ML_RUNTIME=true to enable.

Usage:
    TARGET_DIR=/path/to/models SCAN_DIR=/path/to/output APP_NAME=myapp RUN_ML_RUNTIME=true $0

Environment Variables:
    TARGET_DIR       - Target directory containing models (required)
    SCAN_DIR         - Output directory for scan results (required)
    APP_NAME         - Application name (required)
    ML_RUNTIME_TIMEOUT - Timeout per model in seconds (default: 60)
    ML_RUNTIME_SANDBOX - Sandbox runtime: docker or podman (default: auto-detect)
    SKIP_ML_RUNTIME  - Set to true to skip this scan
    RUN_ML_RUNTIME   - Must be true to enable this scan (opt-in)

Examples:
    # Basic scan
    TARGET_DIR=./models SCAN_DIR=./scans/app1 APP_NAME=app1 RUN_ML_RUNTIME=true ./run-ml-runtime-analysis.sh

    # With custom timeout
    TARGET_DIR=./models SCAN_DIR=./scans/app1 APP_NAME=app1 RUN_ML_RUNTIME=true ML_RUNTIME_TIMEOUT=120 ./run-ml-runtime-analysis.sh
EOF
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*" >&2
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

log_info() {
    echo -e "${BLUE}[INFO]${NC} $*"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $*"
}

# ═══════════════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════════════

# Handle help flag
if [[ "${1:-}" == "--help" ]] || [[ "${1:-}" == "-h" ]]; then
    show_help
    exit 0
fi

# Check if scan is skipped
if [[ "${SKIP_ML_RUNTIME:-false}" == "true" ]]; then
    log_info "ML Runtime Analysis scan skipped (SKIP_ML_RUNTIME=true)"
    exit 0
fi

# Check opt-in (this scan is OPTIONAL)
if [[ "${RUN_ML_RUNTIME:-false}" != "true" ]]; then
    log_info "ML Runtime Analysis scan disabled (opt-in required: set RUN_ML_RUNTIME=true)"
    log_info "This scan executes models in a sandbox and requires Docker/Podman"
    exit 0
fi

# Validate required environment variables
if [[ -z "${TARGET_DIR:-}" ]]; then
    log_error "TARGET_DIR environment variable is required"
    show_help
    exit 1
fi

if [[ -z "${SCAN_DIR:-}" ]]; then
    log_error "SCAN_DIR environment variable is required"
    show_help
    exit 1
fi

if [[ -z "${APP_NAME:-}" ]]; then
    log_error "APP_NAME environment variable is required"
    show_help
    exit 1
fi

# Validate target directory exists
if [[ ! -d "$TARGET_DIR" ]]; then
    log_error "Target directory does not exist: $TARGET_DIR"
    exit 1
fi

# Create output directory
OUTPUT_DIR="$SCAN_DIR/ml-runtime"
mkdir -p "$OUTPUT_DIR"

# Configuration
TIMEOUT="${ML_RUNTIME_TIMEOUT:-60}"
SANDBOX="${ML_RUNTIME_SANDBOX:-docker}"

log_info "═══════════════════════════════════════════════════════════════"
log_info "Layer 20 — ML Runtime Behavioral Analysis"
log_info "═══════════════════════════════════════════════════════════════"
log_info "Target: $TARGET_DIR"
log_info "Output: $OUTPUT_DIR"
log_info "App: $APP_NAME"
log_info "Timeout: ${TIMEOUT}s per model"
log_info "Sandbox: $SANDBOX"
log_info ""
log_warn "⚠️  WARNING: This scan executes models in a sandbox"
log_warn "⚠️  Only run on models you need to analyze"
log_info ""

# Check prerequisites
log_info "Checking prerequisites..."

# Check for Docker or Podman
HAS_DOCKER=false
HAS_PODMAN=false

if command -v docker &> /dev/null; then
    HAS_DOCKER=true
    log_info "✓ Docker available"
fi

if command -v podman &> /dev/null; then
    HAS_PODMAN=true
    log_info "✓ Podman available"
fi

if [[ "$HAS_DOCKER" == "false" ]] && [[ "$HAS_PODMAN" == "false" ]]; then
    log_error "Docker or Podman is required for runtime analysis"
    log_error "Install Docker: https://docs.docker.com/get-docker/"
    log_error "Or Podman: https://podman.io/getting-started/installation"
    exit 1
fi

# Auto-detect sandbox if set to docker but docker not available
if [[ "$SANDBOX" == "docker" ]] && [[ "$HAS_DOCKER" == "false" ]] && [[ "$HAS_PODMAN" == "true" ]]; then
    log_info "Auto-detected Podman (Docker not available)"
    SANDBOX="podman"
fi

# Check Python
if ! command -v python3 &> /dev/null; then
    log_error "python3 is required"
    exit 1
fi
log_info "✓ Python 3 available"

# Check scanner script exists
if [[ ! -f "$PYTHON_SCRIPT" ]]; then
    log_error "Python scanner script not found: $PYTHON_SCRIPT"
    exit 1
fi
log_info "✓ Scanner script found"

log_info ""
log_info "Starting runtime behavioral analysis..."

# Run Python scanner
python3 "$PYTHON_SCRIPT" \
    --target "$TARGET_DIR" \
    --scan-dir "$OUTPUT_DIR" \
    --app-name "$APP_NAME" \
    --timeout "$TIMEOUT" \
    --sandbox "$SANDBOX"

SCAN_EXIT_CODE=$?

# Parse results
RESULTS_FILE="$OUTPUT_DIR/ml-runtime-analysis-results.json"

if [[ ! -f "$RESULTS_FILE" ]]; then
    log_error "Results file not found: $RESULTS_FILE"
    exit 1
fi

# Check for errors
STATUS=$(python3 -c "import json; print(json.load(open('$RESULTS_FILE'))['status'])" 2>/dev/null || echo "unknown")

if [[ "$STATUS" == "error" ]]; then
    ERROR_MSG=$(python3 -c "import json; print(json.load(open('$RESULTS_FILE')).get('error', 'Unknown error'))" 2>/dev/null || echo "Unknown error")
    log_error "Scan failed: $ERROR_MSG"
    exit 1
fi

# Extract statistics
MODELS_ANALYZED=$(python3 -c "import json; print(json.load(open('$RESULTS_FILE'))['statistics']['models_analyzed'])" 2>/dev/null || echo "0")
SUSPICIOUS_BEHAVIOR=$(python3 -c "import json; print(json.load(open('$RESULTS_FILE'))['statistics']['suspicious_behavior_detected'])" 2>/dev/null || echo "0")
CRITICAL_FINDINGS=$(python3 -c "import json; print(json.load(open('$RESULTS_FILE'))['summary']['critical_findings'])" 2>/dev/null || echo "0")
HIGH_FINDINGS=$(python3 -c "import json; print(json.load(open('$RESULTS_FILE'))['summary']['high_findings'])" 2>/dev/null || echo "0")
MEDIUM_FINDINGS=$(python3 -c "import json; print(json.load(open('$RESULTS_FILE'))['summary']['medium_findings'])" 2>/dev/null || echo "0")
LOW_FINDINGS=$(python3 -c "import json; print(json.load(open('$RESULTS_FILE'))['summary']['low_findings'])" 2>/dev/null || echo "0")

log_info ""
log_info "═══════════════════════════════════════════════════════════════"
log_info "Scan Summary"
log_info "═══════════════════════════════════════════════════════════════"
log_info "Models analyzed: $MODELS_ANALYZED"
log_info "Suspicious behavior detected: $SUSPICIOUS_BEHAVIOR"
log_info "Critical findings: $CRITICAL_FINDINGS"
log_info "High findings: $HIGH_FINDINGS"
log_info "Medium findings: $MEDIUM_FINDINGS"
log_info "Low findings: $LOW_FINDINGS"
log_info ""
log_info "Results: $RESULTS_FILE"

# Exit with appropriate code
if [[ "$CRITICAL_FINDINGS" -gt 0 ]] || [[ "$HIGH_FINDINGS" -gt 0 ]]; then
    log_error "🚨 ALERT: Malicious runtime behavior detected!"
    log_error "Critical: $CRITICAL_FINDINGS, High: $HIGH_FINDINGS"
    exit 1
else
    log_success "✅ No critical runtime issues detected"
    exit 0
fi
