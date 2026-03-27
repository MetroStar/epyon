#!/usr/bin/env bash
# generate-sbom-lineage.sh
# Generates a dependency lineage JSON showing which package pulled in which,
# using pipdeptree (Python) and/or npm ls (Node.js).
# Enriches the CycloneDX SBOM by adding a `dependencies` array (CycloneDX 1.4+ spec).
#
# Required env vars:
#   SCAN_DIR   – absolute path to scan output directory
#   TARGET_DIR – absolute path to the repository being scanned
#
# Output:
#   $SCAN_DIR/sbom/dependency-lineage.json  – raw dependency tree per ecosystem
#   $SCAN_DIR/sbom/sbom-*.cyclonedx.json    – enriched in-place with dependencies[]
# ---------------------------------------------------------------------------
set -euo pipefail

SCAN_DIR="${SCAN_DIR:?SCAN_DIR must be set}"
TARGET_DIR="${TARGET_DIR:?TARGET_DIR must be set}"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'
CYAN='\033[0;36m'; NC='\033[0m'

log()  { echo -e "${CYAN}[Lineage]${NC} $*"; }
warn() { echo -e "${YELLOW}[Lineage]${NC} $*"; }
err()  { echo -e "${RED}[Lineage]${NC} $*" >&2; }

SBOM_DIR="$SCAN_DIR/sbom"
mkdir -p "$SBOM_DIR"
OUTPUT_JSON="$SBOM_DIR/dependency-lineage.json"

PYTHON_TREE="{}"
NODE_TREE="{}"

# ---------------------------------------------------------------------------
# Python lineage via pipdeptree
# ---------------------------------------------------------------------------
build_python_lineage() {
  local dir="$1"

  # Find Python interpreter (prefer venv in target, then system)
  local pybin=""
  for candidate in "$dir/.venv/bin/python3" "$dir/venv/bin/python3" \
                   "$dir/.venv/bin/python" \
                   "$(command -v python3 2>/dev/null)" \
                   "$(command -v python 2>/dev/null)"; do
    [[ -x "$candidate" ]] && { pybin="$candidate"; break; }
  done

  if [[ -z "$pybin" ]]; then
    warn "No Python found for lineage – skipping Python dependency tree"
    return
  fi

  # Install pipdeptree into a temp venv to avoid polluting target env
  local tmp_venv="/tmp/epyon-pipdeptree-venv"
  if [[ ! -x "$tmp_venv/bin/pipdeptree" ]]; then
    log "Installing pipdeptree..."
    "$pybin" -m venv "$tmp_venv" 2>/dev/null || { warn "venv creation failed"; return; }
    "$tmp_venv/bin/pip" install -q --upgrade pip pipdeptree 2>/dev/null || { warn "pipdeptree install failed"; return; }
  fi

  log "Building Python dependency tree..."
  # Run pipdeptree against the target's site-packages if using its venv,
  # otherwise against the current environment
  local pip_flags=""
  [[ -x "$dir/.venv/bin/python3" || -x "$dir/venv/bin/python3" ]] && \
    pip_flags="--python-interpreter $pybin"

  PYTHON_TREE=$("$tmp_venv/bin/pipdeptree" $pip_flags --json-tree 2>/dev/null) || PYTHON_TREE="[]"
  if [[ "$PYTHON_TREE" == "[]" || -z "$PYTHON_TREE" ]]; then
    warn "pipdeptree returned empty tree"
    PYTHON_TREE="[]"
    return
  fi

  log "Python lineage: $(echo "$PYTHON_TREE" | jq 'length' 2>/dev/null || echo "?") top-level packages"
}

# ---------------------------------------------------------------------------
# Node.js lineage via npm ls --json
# ---------------------------------------------------------------------------
build_node_lineage() {
  local dir="$1"

  if [[ ! -f "$dir/package.json" ]]; then
    return
  fi

  if ! command -v npm >/dev/null 2>&1; then
    warn "npm not available – skipping Node.js lineage"
    return
  fi

  log "Building Node.js dependency tree..."
  pushd "$dir" > /dev/null
  NODE_TREE=$(npm ls --json --all 2>/dev/null) || NODE_TREE="{}"
  popd > /dev/null
  log "Node.js lineage collected"
}

build_python_lineage "$TARGET_DIR"
build_node_lineage "$TARGET_DIR"

# ---------------------------------------------------------------------------
# Write combined lineage JSON
# ---------------------------------------------------------------------------
jq -n \
  --argjson python "$PYTHON_TREE" \
  --argjson node "$NODE_TREE" \
  '{
    python: $python,
    node:   $node
  }' > "$OUTPUT_JSON"

log "Dependency lineage written to $OUTPUT_JSON"

# ---------------------------------------------------------------------------
# Enrich CycloneDX SBOM with dependencies[] array (CycloneDX 1.4+ spec)
# Format: [{ref: "pkg:pypi/flask@3.0.0", dependsOn: ["pkg:pypi/werkzeug@3.0.0", ...]}]
# ---------------------------------------------------------------------------
CYCLONEDX_FILE=$(find "$SBOM_DIR" -maxdepth 1 -name "*.cyclonedx.json" 2>/dev/null | head -1)
if [[ ! -f "$CYCLONEDX_FILE" ]]; then
  warn "No CycloneDX JSON found – skipping SBOM enrichment"
  exit 0
fi

log "Enriching $(basename "$CYCLONEDX_FILE") with dependencies[]..."

# Flatten pipdeptree JSON into CycloneDX dependencies format
# pipdeptree --json-tree produces: [{package_name, installed_version, dependencies: [...]}]
if [[ "$PYTHON_TREE" != "{}" && "$PYTHON_TREE" != "[]" ]]; then
  DEPS_ARRAY=$(echo "$PYTHON_TREE" | jq -c '
    # Recursive flattener: extract ref + dependsOn for every package in the tree
    def flatten_pkg:
      . as $p |
      {
        ref: ("pkg:pypi/" + ($p.package_name | ascii_downcase) + "@" + $p.installed_version),
        dependsOn: [($p.dependencies // [])[] | "pkg:pypi/" + (.package_name | ascii_downcase) + "@" + .installed_version]
      },
      (($p.dependencies // [])[] | flatten_pkg);

    [.[] | flatten_pkg] | unique_by(.ref)
  ' 2>/dev/null) || DEPS_ARRAY="[]"

  if [[ "$DEPS_ARRAY" != "[]" && -n "$DEPS_ARRAY" ]]; then
    ENRICHED=$(jq \
      --argjson deps "$DEPS_ARRAY" \
      '.dependencies = $deps' \
      "$CYCLONEDX_FILE" 2>/dev/null)
    if [[ -n "$ENRICHED" ]]; then
      echo "$ENRICHED" > "$CYCLONEDX_FILE"
      log "Added $(echo "$DEPS_ARRAY" | jq 'length') dependency entries to CycloneDX SBOM"
    fi
  fi
fi
