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
  # Look for pyproject.toml, requirements*.txt, requirements*.lock, Pipfile.lock, poetry.lock,
  # setup.py / setup.cfg, conda env files, or pre-installed dist-info / site-packages directories
  if find "$dir" -maxdepth 4 \
       \( -name "pyproject.toml" \
       -o -name "requirements*.txt" \
       -o -name "requirements*.lock" \
       -o -name "Pipfile.lock" \
       -o -name "poetry.lock" \
       -o -name "setup.py" \
       -o -name "setup.cfg" \
       -o -name "environment.yml" \
       -o -name "conda.yml" \
       -type d -name "*.dist-info" \
       -o -type d -name "site-packages" \) \
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

# Detect which pip/python to use — prefer newer Python (3.11+) for tomllib support
PYTHON_BIN="${PYTHON_BIN:-}"
if [[ -z "$PYTHON_BIN" ]]; then
  for candidate in python3.13 python3.12 python3.11 python3.10 python3 python; do
    _p=$(command -v "$candidate" 2>/dev/null) || continue
    # Skip macOS system Python (3.9 and older have no tomllib, no writable site-packages)
    _ver=$("$_p" -c 'import sys; print(sys.version_info[:2])' 2>/dev/null)
    [[ "$_ver" == "(3.9,"* || "$_ver" == "(3.8,"* || "$_ver" == "(3.7,"* ]] && continue
    PYTHON_BIN="$_p"
    break
  done
fi
# Fall back to whatever python3 is available even if old
if [[ -z "$PYTHON_BIN" ]]; then
  PYTHON_BIN=$(command -v python3 2>/dev/null || command -v python 2>/dev/null || echo "")
fi

if [[ -z "$PYTHON_BIN" ]]; then
  warn "python3/python not found – skipping Athena SBOM"
  exit 0
fi

log "Using Python: $PYTHON_BIN ($("$PYTHON_BIN" --version 2>&1))"

# Use a dedicated venv for Athena to avoid permission conflicts with system Python
ATHENA_VENV="${ATHENA_INSTALL_DIR}/.venv"
VENV_PYTHON="${ATHENA_VENV}/bin/python"
VENV_PIP="${ATHENA_VENV}/bin/pip"

install_athena() {
  # Create venv if it doesn't exist yet
  if [[ ! -x "$VENV_PYTHON" ]]; then
    log "Creating Athena venv at ${ATHENA_VENV}"
    "$PYTHON_BIN" -m venv "$ATHENA_VENV" || { warn "venv creation failed"; return 1; }
  fi

  # Check if already installed in venv
  if "$VENV_PYTHON" -c "import athena.deps.sbom" 2>/dev/null; then
    log "Athena already installed in venv"
    return 0
  fi

  # Clone source if not present and ATHENA_INSTALL_DIR doesn't have pyproject.toml
  if [[ ! -f "${ATHENA_INSTALL_DIR}/pyproject.toml" ]]; then
    if [[ ! -d "$ATHENA_INSTALL_DIR" ]]; then
      log "Cloning Athena from ${ATHENA_REPO}"
      if ! git clone --depth 1 "$ATHENA_REPO" "$ATHENA_INSTALL_DIR" 2>&1; then
        warn "Failed to clone Athena – skipping"
        return 1
      fi
    fi
  fi

  log "Installing Athena[sbom] into venv"
  "$VENV_PIP" install -q --upgrade pip
  # Install with [sbom] extra; fall back to base install if the extra doesn't exist
  "$VENV_PIP" install -q -e "${ATHENA_INSTALL_DIR}[sbom]" 2>/dev/null || \
    "$VENV_PIP" install -q -e "${ATHENA_INSTALL_DIR}"
}

if ! install_athena; then
  warn "Athena installation failed – skipping SBOM layer"
  exit 0
fi

# ---------------------------------------------------------------------------
# Run Athena SBOM generation
# ---------------------------------------------------------------------------
log "Generating Python SBOM for ${TARGET_DIR} → ${OUTPUT_FILE}"

"$VENV_PYTHON" - <<PYEOF
import sys, json, pathlib, subprocess

root = pathlib.Path("${TARGET_DIR}").resolve()
output_file = pathlib.Path("${OUTPUT_FILE}")
license_out = pathlib.Path("${LICENSE_FILE}")
tmp_dir = output_file.parent / "_athena_tmp"

try:
    from athena.deps.sbom import generate_sbom
    from athena.deps.inventory import inventory

    # Detect git SHA for metadata (best-effort)
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, timeout=5
        )
        git_sha = result.stdout.strip() or "dev"
    except Exception:
        git_sha = "dev"

    deps = inventory(root)
    sbom_json = generate_sbom(root, deps=deps, git_sha=git_sha)

    # Write to our explicit output path (not the auto-named one)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text(
        json.dumps(json.loads(sbom_json), indent=2) + "\n"
    )
    print(f"[Athena SBOM] SBOM written to {output_file} ({len(deps)} components)")

except Exception as exc:
    print(f"[Athena SBOM] SBOM generation failed: {exc}", file=sys.stderr)
    import traceback; traceback.print_exc()
    raise

# License compliance (best-effort)
try:
    from athena.deps.licenses import check_licenses

    # Load policy from pyproject.toml if present, else use permissive defaults
    license_config: dict = {}
    pyproject_path = root / "pyproject.toml"
    if pyproject_path.exists():
        import tomllib
        with open(pyproject_path, "rb") as f:
            pdata = tomllib.load(f)
        license_config = pdata.get("tool", {}).get("athena", {}).get("licenses", {})

    from athena.deps.inventory import inventory as inv2
    all_deps = inv2(root)
    license_results = check_licenses(all_deps, license_config, root)

    # Serialize to JSON
    license_data = [
        {
            "name": r.dep_name,
            "license": r.spdx,
            "source_field": r.source_field,
            "allowed": r.compatible,
            "denied": not r.compatible,
            "review_note": r.review_note,
        }
        for r in license_results
    ]
    license_out.write_text(json.dumps(license_data, indent=2) + "\n")
    print(f"[Athena SBOM] License data written to {license_out} ({len(license_data)} packages)")

except Exception as exc:
    print(f"[Athena SBOM] License compliance skipped: {exc}", file=sys.stderr)
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
