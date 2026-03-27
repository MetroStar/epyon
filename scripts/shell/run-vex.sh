#!/usr/bin/env bash
# run-vex.sh
# VEX (Vulnerability Exploitability eXchange) document management for Epyon.
# 
# VEX allows teams to formally state that a CVE in a dependency is NOT exploitable
# in their specific context (e.g. the vulnerable code path is never called).
# Grype can consume VEX documents to suppress findings with documented justification,
# which is more auditable than the generic .epyon-ignore.yml.
#
# Usage modes:
#   create  – scaffold a new VEX document for a specific CVE
#   apply   – apply all VEX documents to a Grype results file (re-runs with --vex)
#   list    – list all VEX statements in the repo
#
# VEX documents live in: .epyon/vex/<CVE-ID>.vex.json
# They follow the OpenVEX 0.2.0 spec (https://github.com/openvex/spec)
#
# Required env vars:
#   SCAN_DIR   – absolute path to scan output directory  (for apply mode)
#   TARGET_DIR – absolute path to the scanned repository (for apply mode)
# ---------------------------------------------------------------------------
set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'
CYAN='\033[0;36m'; WHITE='\033[1;37m'; NC='\033[0m'

log()  { echo -e "${CYAN}[VEX]${NC} $*"; }
warn() { echo -e "${YELLOW}[VEX]${NC} $*"; }
err()  { echo -e "${RED}[VEX]${NC} $*" >&2; }

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

VEX_STATUS_OPTIONS="not_affected|affected|fixed|under_investigation"

show_help() {
  echo -e "${WHITE}run-vex.sh — VEX document management${NC}"
  echo ""
  echo "Usage:"
  echo "  $0 create <CVE-ID> <package> <version> <justification> [<detail>]"
  echo "  $0 apply"
  echo "  $0 list"
  echo ""
  echo "Justifications (OpenVEX spec):"
  echo "  component_not_present       Package is in SBOM but not actually shipped"
  echo "  vulnerable_code_not_present Vulnerable function/class removed or not compiled"
  echo "  vulnerable_code_not_in_execute_path  Vulnerable code exists but is never reached"
  echo "  inline_mitigations_already_exist     Compensating control makes exploitation infeasible"
  echo "  requires_configuration       Only exploitable with non-default config we don't use"
  echo ""
  echo "Environment (for 'apply'):"
  echo "  SCAN_DIR   – scan output directory"
  echo "  TARGET_DIR – scanned repository root (VEX docs in TARGET_DIR/.epyon/vex/)"
  echo ""
  exit 0
}

MODE="${1:-apply}"

# ---------------------------------------------------------------------------
# CREATE mode — scaffold a new VEX statement
# ---------------------------------------------------------------------------
if [[ "$MODE" == "create" ]]; then
  CVE_ID="${2:?Usage: $0 create <CVE-ID> <package> <version> <justification> [<detail>]}"
  PKG_NAME="${3:?Missing package name}"
  PKG_VERSION="${4:?Missing package version}"
  JUSTIFICATION="${5:?Missing justification — see --help for options}"
  DETAIL="${6:-No additional detail provided.}"
  TARGET_DIR="${TARGET_DIR:-$(pwd)}"

  VEX_DIR="$TARGET_DIR/.epyon/vex"
  mkdir -p "$VEX_DIR"
  VEX_FILE="$VEX_DIR/${CVE_ID}.vex.json"

  if [[ -f "$VEX_FILE" ]]; then
    warn "VEX file already exists: $VEX_FILE"
    warn "Edit it manually to add another statement."
    exit 0
  fi

  TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  AUTHOR="${GIT_AUTHOR_NAME:-$(git config user.name 2>/dev/null || echo "epyon")}"
  PRODUCT_ID="pkg:generic/${PKG_NAME}@${PKG_VERSION}"

  jq -n \
    --arg id "$CVE_ID" \
    --arg ts "$TIMESTAMP" \
    --arg author "$AUTHOR" \
    --arg pkg "$PKG_NAME" \
    --arg ver "$PKG_VERSION" \
    --arg purl "$PRODUCT_ID" \
    --arg justification "$JUSTIFICATION" \
    --arg detail "$DETAIL" \
    '{
      "@context": "https://openvex.dev/ns/v0.2.0",
      "@id": ("https://openvex.dev/docs/example/" + $id),
      "author": $author,
      "timestamp": $ts,
      "last_updated": $ts,
      "version": 1,
      "statements": [
        {
          "vulnerability": { "name": $id },
          "products": [{ "@id": $purl, "identifiers": { "purl": $purl } }],
          "status": "not_affected",
          "justification": $justification,
          "impact_statement": $detail
        }
      ]
    }' > "$VEX_FILE"

  log "Created VEX statement: $VEX_FILE"
  echo -e "${GREEN}✅ VEX statement created for $CVE_ID in $PKG_NAME@$PKG_VERSION${NC}"
  echo "   Edit $VEX_FILE to add more context or adjust the justification."
  exit 0
fi

# ---------------------------------------------------------------------------
# LIST mode — show all VEX statements
# ---------------------------------------------------------------------------
if [[ "$MODE" == "list" ]]; then
  TARGET_DIR="${TARGET_DIR:-$(pwd)}"
  VEX_DIR="$TARGET_DIR/.epyon/vex"
  if [[ ! -d "$VEX_DIR" ]] || [[ -z "$(ls "$VEX_DIR"/*.vex.json 2>/dev/null)" ]]; then
    log "No VEX statements found in $VEX_DIR"
    exit 0
  fi

  echo -e "${WHITE}VEX Statements${NC}"
  echo "=============="
  for f in "$VEX_DIR"/*.vex.json; do
    jq -r '
      .statements[]? |
      "CVE: \(.vulnerability.name)  |  Status: \(.status)  |  Justification: \(.justification // "N/A")  |  Detail: \(.impact_statement // "")"
    ' "$f" 2>/dev/null
  done
  exit 0
fi

# ---------------------------------------------------------------------------
# APPLY mode — re-run Grype with VEX documents to suppress findings
# ---------------------------------------------------------------------------
SCAN_DIR="${SCAN_DIR:?SCAN_DIR must be set for apply mode}"
TARGET_DIR="${TARGET_DIR:?TARGET_DIR must be set for apply mode}"

VEX_DIR="$TARGET_DIR/.epyon/vex"
GRYPE_SBOM_FILE=$(find "$SCAN_DIR/grype" -name "grype-sbom-results.json" 2>/dev/null | head -1)
SBOM_FILE="$SCAN_DIR/sbom/filesystem.json"
VEX_OUTPUT="$SCAN_DIR/grype/vex-applied-results.json"
VEX_SUMMARY="$SCAN_DIR/grype/vex-summary.json"

if [[ ! -d "$VEX_DIR" ]] || [[ -z "$(ls "$VEX_DIR"/*.vex.json 2>/dev/null)" ]]; then
  log "No VEX documents found in $VEX_DIR – nothing to apply"
  exit 0
fi

VEX_COUNT=$(ls "$VEX_DIR"/*.vex.json 2>/dev/null | wc -l | tr -d ' ')
log "Applying $VEX_COUNT VEX document(s) to Grype results..."

if [[ ! -f "$GRYPE_SBOM_FILE" ]]; then
  warn "No Grype SBOM results found at $SCAN_DIR/grype/grype-sbom-results.json – skipping VEX apply"
  exit 0
fi

# Build --vex flags list
VEX_FLAGS=()
for vex_file in "$VEX_DIR"/*.vex.json; do
  VEX_FLAGS+=("--vex" "$vex_file")
done

# Re-run Grype with VEX suppression using the original SBOM
if command -v grype >/dev/null 2>&1; then
  GRYPE_CMD="grype"
elif [[ -n "${CONTAINER_CLI:-}" ]]; then
  # Build a docker-compatible flag list — mount each VEX file
  warn "Container-based VEX apply not yet supported – using raw Grype JSON filtering instead"
  GRYPE_CMD=""
else
  warn "grype binary not found – applying VEX via JSON post-processing"
  GRYPE_CMD=""
fi

if [[ -n "$GRYPE_CMD" && -f "$SBOM_FILE" ]]; then
  log "Re-running grype with VEX suppression..."
  "$GRYPE_CMD" "sbom:$SBOM_FILE" -o json "${VEX_FLAGS[@]}" > "$VEX_OUTPUT" 2>/dev/null || {
    warn "Grype VEX re-run failed – falling back to JSON filtering"
    GRYPE_CMD=""
  }
fi

# JSON post-processing fallback: filter out matches whose CVE IDs appear in VEX "not_affected" statements
if [[ -z "$GRYPE_CMD" || ! -f "$VEX_OUTPUT" ]]; then
  log "Applying VEX suppression via JSON post-processing..."
  # Collect all "not_affected" CVE IDs from VEX docs
  NOT_AFFECTED_IDS=$(for vex_file in "$VEX_DIR"/*.vex.json; do
    jq -r '.statements[]? | select(.status == "not_affected") | .vulnerability.name' "$vex_file" 2>/dev/null
  done | sort -u | jq -Rs 'split("\n") | map(select(length>0))')

  BEFORE=$(jq '.matches | length' "$GRYPE_SBOM_FILE" 2>/dev/null || echo "0")
  jq --argjson suppress "$NOT_AFFECTED_IDS" '
    .matches |= map(select(.vulnerability.id as $id | $suppress | index($id) == null))
  ' "$GRYPE_SBOM_FILE" > "$VEX_OUTPUT" 2>/dev/null
  AFTER=$(jq '.matches | length' "$VEX_OUTPUT" 2>/dev/null || echo "0")
  SUPPRESSED=$((BEFORE - AFTER))
  log "VEX post-processing: suppressed $SUPPRESSED findings ($BEFORE → $AFTER)"
fi

# Write VEX summary
VEX_STATEMENTS=$(for vex_file in "$VEX_DIR"/*.vex.json; do
  jq -r '.statements[]? | {cve: .vulnerability.name, status, justification, detail: .impact_statement}' "$vex_file" 2>/dev/null
done | jq -s '.')

jq -n \
  --argjson statements "$VEX_STATEMENTS" \
  --argjson count "$VEX_COUNT" \
  '{
    vex_documents: $count,
    statements: $statements
  }' > "$VEX_SUMMARY"

BEFORE_TOTAL=$(jq '.matches | length' "$GRYPE_SBOM_FILE" 2>/dev/null || echo "0")
AFTER_TOTAL=$(jq '.matches | length' "$VEX_OUTPUT" 2>/dev/null || echo "0")
SUPPRESSED_TOTAL=$((BEFORE_TOTAL - AFTER_TOTAL))

log "VEX applied: $VEX_COUNT documents, $SUPPRESSED_TOTAL findings suppressed ($BEFORE_TOTAL → $AFTER_TOTAL)"
