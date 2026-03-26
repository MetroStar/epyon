#!/usr/bin/env bash
# run-athena-sbom.sh
# Layer 1b – Python-focused SBOM generation via Athena (MetroStar).
# Athena produces CycloneDX 1.5 JSON with pkg:pypi PURLs, SHA-256 wheel hashes,
# and license SPDX identifiers.  Output is merged into the main SBOM directory
# by consolidate-security-reports.sh.
#
# Required env vars:
#   SCAN_DIR   – absolute path to the scan output directory
#   TARGET_DIR – absolute path to the repository being scanned
#
# Optional env vars:
#   SKIP_ATHENA          – set to "true" to bypass this layer entirely
#   ATHENA_REPO          – path/URL to Athena source (default: MetroStar/athena repo)
#   ATHENA_INSTALL_DIR   – where to clone/find Athena source (default: /tmp/athena-src)
# ---------------------------------------------------------------------------
set -euo pipefail

SCAN_DIR="${SCAN_DIR:?SCAN_DIR must be set}"
TARGET_DIR="${TARGET_DIR:?TARGET_DIR must be set}"
SKIP_ATHENA="${SKIP_ATHENA:-false}"
ATHENA_REPO="${ATHENA_REPO:-https://github.com/MetroStar/athena.git}"
ATHENA_INSTALL_DIR="${ATHENA_INSTALL_DIR:-/tmp/athena-src}"

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'

log()  { echo -e "${CYAN}[Athena SBOM]${NC} $*"; }
warn() { echo -e "${YELLOW}[Athena SBOM]${NC} $*"; }
err()  { echo -e "${RED}[Athena SBOM]${NC} $*" >&2; }

# ---------------------------------------------------------------------------
# Skip guard
# ---------------------------------------------------------------------------
if [[ "${SKIP_ATHENA}" == "true" ]]; then
  log "Skipping Athena SBOM layer (SKIP_ATHENA=true)"
  exit 0
fi

# ---------------------------------------------------------------------------
# Pre-flight: only run when TARGET_DIR has Python dependency artifacts
# ---------------------------------------------------------------------------
has_python_artifacts() {
  local dir="$1"
  # Look for pyproject.toml, requirements*.txt, requirements*.lock, Pipfile.lock, poetry.lock
  if find "$dir" -maxdepth 3 \
       \( -name "pyproject.toml" \
       -o -name "requirements*.txt" \
       -o -name "requirements*.lock" \
       -o -name "Pipfile.lock" \
       -o -name "poetry.lock" \) \
       -print -quit 2>/dev/null | grep -q .; then
    return 0
  fi
  return 1
}

if ! has_python_artifacts "$TARGET_DIR"; then
  log "No Python dependency artifacts found in $TARGET_DIR – skipping Athena SBOM"
  exit 0
fi

# ---------------------------------------------------------------------------
# Install / locate Athena
# ---------------------------------------------------------------------------
SBOM_DIR="${SCAN_DIR}/sbom"
mkdir -p "$SBOM_DIR"

SCAN_ID=$(basename "$SCAN_DIR")
OUTPUT_FILE="${SBOM_DIR}/athena-sbom-${SCAN_ID}.cyclonedx.json"
LICENSE_FILE="${SBOM_DIR}/athena-licenses.json"

# Detect which pip/python to use
PYTHON_BIN="${PYTHON_BIN:-$(command -v python3 2>/dev/null || command -v python 2>/dev/null || echo "")}"
if [[ -z "$PYTHON_BIN" ]]; then
  warn "python3/python not found – skipping Athena SBOM"
  exit 0
fi

PIP_BIN="${PIP_BIN:-$(command -v pip3 2>/dev/null || command -v pip 2>/dev/null || echo "")}"
if [[ -z "$PIP_BIN" ]]; then
  warn "pip3/pip not found – skipping Athena SBOM"
  exit 0
fi

install_athena() {
  if "$PYTHON_BIN" -c "import athena.deps.sbom" 2>/dev/null; then
    log "Athena already installed"
    return 0
  fi

  # Try local clone first if ATHENA_INSTALL_DIR already has it
  if [[ -d "${ATHENA_INSTALL_DIR}/pyproject.toml" ]] || [[ -f "${ATHENA_INSTALL_DIR}/pyproject.toml" ]]; then
    log "Installing Athena from ${ATHENA_INSTALL_DIR}"
    "$PIP_BIN" install -q -e "${ATHENA_INSTALL_DIR}[sbom]"
    return $?
  fi

  # Clone if not present
  if [[ ! -d "$ATHENA_INSTALL_DIR" ]]; then
    log "Cloning Athena from ${ATHENA_REPO}"
    if ! git clone --depth 1 "$ATHENA_REPO" "$ATHENA_INSTALL_DIR" 2>&1; then
      warn "Failed to clone Athena – skipping"
      return 1
    fi
  fi

  log "Installing Athena[sbom] into current Python environment"
  "$PIP_BIN" install -q -e "${ATHENA_INSTALL_DIR}[sbom]"
}

if ! install_athena; then
  warn "Athena installation failed – skipping SBOM layer"
  exit 0
fi

# ---------------------------------------------------------------------------
# Run Athena SBOM generation
# ---------------------------------------------------------------------------
log "Generating Python SBOM for ${TARGET_DIR} → ${OUTPUT_FILE}"

"$PYTHON_BIN" - <<PYEOF
import sys, json, pathlib

root = pathlib.Path("${TARGET_DIR}")
output = pathlib.Path("${OUTPUT_FILE}")
license_out = pathlib.Path("${LICENSE_FILE}")

try:
    from athena.deps.sbom import write_sbom
    write_sbom(str(root), str(output))
    print(f"[Athena SBOM] SBOM written to {output}")
except Exception as exc:
    print(f"[Athena SBOM] write_sbom() failed: {exc}", file=sys.stderr)
    raise

# License compliance output (best-effort – not all Athena versions have this)
try:
    from athena.deps.licenses import get_license_data
    license_data = get_license_data(str(root))
    license_out.write_text(json.dumps(license_data, indent=2))
    print(f"[Athena SBOM] License data written to {license_out}")
except Exception as exc:
    print(f"[Athena SBOM] License data generation skipped: {exc}", file=sys.stderr)
PYEOF

RC=$?

if [[ $RC -ne 0 ]]; then
  err "Athena SBOM generation exited with code $RC"
  exit $RC
fi

# Validate output
if [[ ! -f "$OUTPUT_FILE" ]]; then
  err "Expected output file not found: $OUTPUT_FILE"
  exit 1
fi

COMP_COUNT=$(jq '.components | length' "$OUTPUT_FILE" 2>/dev/null || echo "?")
log "Athena SBOM complete: ${COMP_COUNT} Python components cataloged"
