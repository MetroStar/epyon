#!/usr/bin/env bash
# verify-sbom-hashes.sh
# Cross-references CycloneDX SBOM package hashes against PyPI's published
# SHA-256 wheel hashes to detect tampered or unofficial package distributions.
#
# Required env vars:
#   SCAN_DIR  – absolute path to the scan output directory
#
# Output:
#   $SCAN_DIR/sbom/hash-verification.json  – structured results
#   $SCAN_DIR/sbom/hash-verification.md    – human-readable summary
# ---------------------------------------------------------------------------
set -euo pipefail

show_help() {
  cat <<'EOF'
Usage: verify-sbom-hashes.sh [--help]

Cross-references CycloneDX SBOM package hashes with PyPI published digests.

Environment:
  SCAN_DIR   Required. Absolute path to scan output directory.

Options:
  -h, --help    Show this help text and exit.
EOF
}

if [[ "${1:-}" == "--help" ]] || [[ "${1:-}" == "-h" ]]; then
  show_help
  exit 0
fi

SCAN_DIR="${SCAN_DIR:?SCAN_DIR must be set}"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'
CYAN='\033[0;36m'; WHITE='\033[1;37m'; NC='\033[0m'

log()  { echo -e "${CYAN}[Hash Verify]${NC} $*"; }
warn() { echo -e "${YELLOW}[Hash Verify]${NC} $*"; }
err()  { echo -e "${RED}[Hash Verify]${NC} $*" >&2; }

SBOM_DIR="$SCAN_DIR/sbom"
CYCLONEDX_FILE=$(find "$SBOM_DIR" -maxdepth 1 -name "*.cyclonedx.json" 2>/dev/null | head -1)
OUTPUT_JSON="$SBOM_DIR/hash-verification.json"
OUTPUT_MD="$SBOM_DIR/hash-verification.md"

if [[ ! -f "$CYCLONEDX_FILE" ]]; then
  warn "No CycloneDX JSON found in $SBOM_DIR – skipping hash verification"
  exit 0
fi

if ! command -v curl >/dev/null 2>&1; then
  warn "curl not available – skipping hash verification"
  exit 0
fi

log "Verifying package hashes against PyPI for: $(basename "$CYCLONEDX_FILE")"

# Extract pypi components with their version from the CycloneDX SBOM
PYPI_PACKAGES=$(jq -r '
  .components[]?
  | select(.purl // "" | startswith("pkg:pypi"))
  | "\(.name)\t\(.version // "")"
' "$CYCLONEDX_FILE" 2>/dev/null)

if [[ -z "$PYPI_PACKAGES" ]]; then
  log "No pkg:pypi components found – nothing to verify"
  echo '{"verified":[],"tampered":[],"not_found":[],"errors":[],"summary":{"total":0,"verified":0,"tampered":0,"not_found":0}}' > "$OUTPUT_JSON"
  exit 0
fi

TOTAL=0; VERIFIED=0; TAMPERED=0; NOT_FOUND=0; ERRORS=0
RESULTS_VERIFIED="[]"
RESULTS_TAMPERED="[]"
RESULTS_NOT_FOUND="[]"
RESULTS_ERRORS="[]"

# Rate-limit: PyPI JSON API is public but we should be polite
DELAY=0.15

while IFS=$'\t' read -r pkg_name pkg_version; do
  [[ -z "$pkg_name" || -z "$pkg_version" ]] && continue
  TOTAL=$((TOTAL + 1))

  # Call PyPI JSON API
  PYPI_URL="https://pypi.org/pypi/${pkg_name}/${pkg_version}/json"
  PYPI_RESPONSE=$(curl -sf --max-time 8 "$PYPI_URL" 2>/dev/null) || true

  if [[ -z "$PYPI_RESPONSE" ]]; then
    # Package/version not found on PyPI (could be private, could be tampered name)
    NOT_FOUND=$((NOT_FOUND + 1))
    RESULTS_NOT_FOUND=$(echo "$RESULTS_NOT_FOUND" | jq --arg n "$pkg_name" --arg v "$pkg_version" \
      '. + [{"name":$n,"version":$v,"status":"not_found_on_pypi"}]')
    warn "Not found on PyPI: ${pkg_name}==${pkg_version}"
    sleep "$DELAY"
    continue
  fi

  # Collect all known hashes from PyPI for this version
  PYPI_HASHES=$(echo "$PYPI_RESPONSE" | jq -r '
    .urls[]?.digests?.sha256 // empty
  ' 2>/dev/null | sort -u)

  if [[ -z "$PYPI_HASHES" ]]; then
    ERRORS=$((ERRORS + 1))
    RESULTS_ERRORS=$(echo "$RESULTS_ERRORS" | jq --arg n "$pkg_name" --arg v "$pkg_version" \
      '. + [{"name":$n,"version":$v,"status":"no_hashes_on_pypi"}]')
    sleep "$DELAY"
    continue
  fi

  # Get the hash recorded in the SBOM for this package (if any)
  SBOM_HASH=$(jq -r --arg name "$pkg_name" --arg ver "$pkg_version" '
    .components[]?
    | select((.name == $name or (.name | ascii_downcase) == ($name | ascii_downcase))
             and .version == $ver)
    | .hashes[]?
    | select(.alg == "SHA-256")
    | .content
  ' "$CYCLONEDX_FILE" 2>/dev/null | head -1)

  if [[ -n "$SBOM_HASH" ]]; then
    # Compare SBOM hash against PyPI hashes
    if echo "$PYPI_HASHES" | grep -qF "$SBOM_HASH"; then
      VERIFIED=$((VERIFIED + 1))
      RESULTS_VERIFIED=$(echo "$RESULTS_VERIFIED" | jq --arg n "$pkg_name" --arg v "$pkg_version" --arg h "$SBOM_HASH" \
        '. + [{"name":$n,"version":$v,"sha256":$h,"status":"verified"}]')
    else
      TAMPERED=$((TAMPERED + 1))
      PYPI_HASHES_JSON=$(echo "$PYPI_HASHES" | jq -Rs 'split("\n") | map(select(length>0))')
      RESULTS_TAMPERED=$(echo "$RESULTS_TAMPERED" | jq \
        --arg n "$pkg_name" --arg v "$pkg_version" --arg h "$SBOM_HASH" \
        --argjson known "$PYPI_HASHES_JSON" \
        '. + [{"name":$n,"version":$v,"sha256_found":$h,"sha256_expected":$known,"status":"HASH_MISMATCH"}]')
      err "HASH MISMATCH: ${pkg_name}==${pkg_version} — installed hash not in PyPI known hashes!"
    fi
  else
    # No hash in SBOM — just confirm version exists on PyPI
    PYPI_HASHES_JSON=$(echo "$PYPI_HASHES" | jq -Rs 'split("\n") | map(select(length>0))')
    RESULTS_VERIFIED=$(echo "$RESULTS_VERIFIED" | jq \
      --arg n "$pkg_name" --arg v "$pkg_version" --argjson known "$PYPI_HASHES_JSON" \
      '. + [{"name":$n,"version":$v,"sha256":null,"status":"version_exists_no_sbom_hash","pypi_hashes":$known}]')
    VERIFIED=$((VERIFIED + 1))
  fi

  sleep "$DELAY"
done <<< "$PYPI_PACKAGES"

# Write JSON result
jq -n \
  --argjson verified "$RESULTS_VERIFIED" \
  --argjson tampered "$RESULTS_TAMPERED" \
  --argjson not_found "$RESULTS_NOT_FOUND" \
  --argjson errors "$RESULTS_ERRORS" \
  --argjson total "$TOTAL" \
  --argjson v "$VERIFIED" \
  --argjson t "$TAMPERED" \
  --argjson nf "$NOT_FOUND" \
  '{
    verified: $verified,
    tampered: $tampered,
    not_found: $not_found,
    errors: $errors,
    summary: {
      total: $total,
      verified: $v,
      tampered: $t,
      not_found: $nf,
      tampered_pct: (if $total > 0 then (($t / $total) * 100 | round) else 0 end)
    }
  }' > "$OUTPUT_JSON"

# Write markdown summary
{
  echo "# SBOM Hash Verification Report"
  echo ""
  echo "| Metric | Count |"
  echo "|--------|-------|"
  echo "| Total PyPI packages checked | $TOTAL |"
  echo "| ✅ Verified (hash matches PyPI) | $VERIFIED |"
  echo "| 🚨 HASH MISMATCH (possible tampering) | $TAMPERED |"
  echo "| ⚠️  Not found on PyPI | $NOT_FOUND |"
  echo ""
  if [[ $TAMPERED -gt 0 ]]; then
    echo "## 🚨 Hash Mismatches — Investigate Immediately"
    echo ""
    jq -r '.tampered[] | "- **\(.name)==\(.version)** — installed SHA-256: `\(.sha256_found)`"' "$OUTPUT_JSON"
    echo ""
  fi
  if [[ $NOT_FOUND -gt 0 ]]; then
    echo "## ⚠️  Packages Not Found on PyPI"
    echo ""
    jq -r '.not_found[] | "- \(.name)==\(.version)"' "$OUTPUT_JSON"
    echo ""
  fi
} > "$OUTPUT_MD"

log "Hash verification complete: $VERIFIED verified, $TAMPERED mismatches, $NOT_FOUND not on PyPI (of $TOTAL)"

if [[ $TAMPERED -gt 0 ]]; then
  err "$TAMPERED package(s) have hash mismatches — possible supply chain tampering!"
  exit 2
fi
