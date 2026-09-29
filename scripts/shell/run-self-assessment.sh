#!/bin/bash
# Self-Assessment: run a real Epyon scan against the deliberately vulnerable
# fixture at tests/fixtures/self-assessment/ and verify every layer that can
# be deterministically tested actually detected its planted issue.
#
# This catches "silently broken scanner" bugs (bad mounts, config drift, tool
# version bumps that changed CLI output, empty-target false-clean results)
# that a normal scan of a real, unlabeled target can't reveal on its own.
#
# Usage:
#   scripts/shell/run-self-assessment.sh [--output PATH] [--keep-scan] [--layers 1,2,7,8]
#
# --layers restricts the run to only the given manifest layer numbers (as
# they appear in tests/fixtures/self-assessment/expected-findings.json,
# e.g. "8.5" for the pip-audit layer). Any layer NOT in the list is skipped
# in the underlying scan (via --skip-tools) and reported with status
# "skipped" instead of pass/fail/not_validated. Omit --layers to run
# everything, matching prior behavior.
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
FIXTURE_DIR="$REPO_ROOT/tests/fixtures/self-assessment"
MANIFEST="$FIXTURE_DIR/expected-findings.json"
OUTPUT_FILE="$REPO_ROOT/web/data/self-assessment-latest.json"
KEEP_SCAN=false
LAYERS_FILTER=""

# Maps each togglable manifest layer number to the --skip-tools token that
# disables its underlying scan step in run-target-security-scan.sh. Layer 3
# (SonarQube) and Layer 20 (ML Runtime, opt-in only) are intentionally
# excluded — they're never run by this harness regardless of --layers.
declare -A LAYER_TOOL_TOKEN=(
    [1]=sbom [2]=trufflehog [4]=clamav [5]=helm [6]=checkov [7]=trivy
    [8]=grype [9]=xeol [10]=anchore [11]=api [13]=stig [14]=picklescan
    [15]=modelcard [16]=network [18]=model-provenance [19]=inference-security
)

while [[ $# -gt 0 ]]; do
    case "$1" in
        --output) OUTPUT_FILE="$2"; shift 2 ;;
        --keep-scan) KEEP_SCAN=true; shift ;;
        --layers) LAYERS_FILTER="$2"; shift 2 ;;
        *) echo -e "${RED}Unknown option: $1${NC}"; exit 1 ;;
    esac
done

if [[ ! -d "$FIXTURE_DIR" ]]; then
    echo -e "${RED}❌ Fixture directory not found: $FIXTURE_DIR${NC}"
    exit 1
fi

# Build the --skip-tools list for run-target-security-scan.sh from the
# (inverse of the) --layers selection, and decide whether to run the direct
# pip-audit step (Layer 8.5, not wired into run-target-security-scan.sh).
RUN_PIP_AUDIT=true
EXTRA_SKIP_TOOLS=""
if [[ -n "$LAYERS_FILTER" ]]; then
    IFS=',' read -r -a SELECTED_LAYERS <<< "$LAYERS_FILTER"
    declare -A SELECTED_SET=()
    for l in "${SELECTED_LAYERS[@]}"; do
        SELECTED_SET["$(echo "$l" | tr -d '[:space:]')"]=1
    done
    if [[ -z "${SELECTED_SET[8.5]:-}" ]]; then
        RUN_PIP_AUDIT=false
    fi
    for layer_num in "${!LAYER_TOOL_TOKEN[@]}"; do
        if [[ -z "${SELECTED_SET[$layer_num]:-}" ]]; then
            EXTRA_SKIP_TOOLS="${EXTRA_SKIP_TOOLS}${LAYER_TOOL_TOKEN[$layer_num]},"
        fi
    done
    echo -e "${GREEN}▶ Restricting self-assessment to layers: $LAYERS_FILTER${NC}"
fi


# ── Generate the EICAR malware test signature at scan-time only. It is
# intentionally NOT committed to source control — real antivirus engines
# (including on dev workstations and CI runners) quarantine/delete it
# on-sight, and some git hosts also flag it. See tests/fixtures/self-
# assessment/README for details.
EICAR_DIR="$FIXTURE_DIR/malware"
EICAR_FILE="$EICAR_DIR/eicar.txt"
cleanup() {
    rm -f "$EICAR_FILE" 2>/dev/null || true
    rmdir "$EICAR_DIR" 2>/dev/null || true
}
trap cleanup EXIT
mkdir -p "$EICAR_DIR"
printf 'X5O!P%%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > "$EICAR_FILE" 2>/dev/null || true

# Verify the file actually survived the write. Endpoint AV/EDR (Windows
# Defender, macOS XProtect, corporate agents) commonly deletes the EICAR
# string the instant it's written to disk — this is *correct, desired*
# host-level behavior, but it means the file never reaches Epyon's own
# ClamAV layer, so Layer 4 can't be validated on such a machine. Detect
# this and downgrade to a soft skip instead of a false "scanner is broken"
# failure. Run inside CI (no desktop AV) for a true end-to-end check.
EICAR_PERSISTED=false
if [[ -f "$EICAR_FILE" ]] && grep -q 'EICAR-STANDARD-ANTIVIRUS-TEST-FILE' "$EICAR_FILE" 2>/dev/null; then
    EICAR_PERSISTED=true
else
    echo -e "${YELLOW}⚠️  EICAR test file was removed immediately by local antivirus/EDR before the scan could run — this is expected, correct AV behavior. Layer 4 (Malware Detection) can't be validated on this machine and will be reported as environment-limited, not failed. Run this in CI (no desktop AV) for a true end-to-end check.${NC}"
fi

echo -e "${GREEN}▶ Running self-assessment scan against $FIXTURE_DIR${NC}"

# Defensively clear any stale /tmp/epyon-env from a previous scan. That file
# is meant to carry webhook/job config across CI steps for a single job, but
# on a shared host (or a long-lived container running multiple scans) a
# leftover copy gets silently `source`d by run-target-security-scan.sh and
# can override TARGET_NAME/SCAN_ID/SKIP_* for an unrelated later scan. We
# don't touch it if it looks like it belongs to a scan that's currently
# in-flight (best-effort: only remove if no matching scan dir is still open).
if [[ -f /tmp/epyon-env ]]; then
    echo -e "${YELLOW}⚠️  Found stale /tmp/epyon-env from a previous scan — removing to avoid leaking its TARGET_NAME/SCAN_ID/SKIP_* into this run.${NC}"
    rm -f /tmp/epyon-env
fi
unset TARGET_NAME SCAN_ID SCAN_DIR 2>/dev/null || true

# Snapshot existing scan dirs so we can identify the new one unambiguously,
# regardless of what TARGET_NAME the scanner resolves to.
SCANS_ROOT="$REPO_ROOT/scans"
mkdir -p "$SCANS_ROOT"
BEFORE_LIST=$(mktemp)
find "$SCANS_ROOT" -maxdepth 1 -mindepth 1 -type d > "$BEFORE_LIST" 2>/dev/null || true

"$SCRIPT_DIR/run-target-security-scan.sh" \
    --target "$FIXTURE_DIR" \
    --scan-type full \
    --non-interactive \
    --skip-tools "sonar,garak,${EXTRA_SKIP_TOOLS}"

AFTER_LIST=$(mktemp)
find "$SCANS_ROOT" -maxdepth 1 -mindepth 1 -type d > "$AFTER_LIST" 2>/dev/null || true
NEW_SCAN_DIR=$(comm -13 <(sort "$BEFORE_LIST") <(sort "$AFTER_LIST") | head -1)
rm -f "$BEFORE_LIST" "$AFTER_LIST"

if [[ -z "$NEW_SCAN_DIR" || ! -d "$NEW_SCAN_DIR" ]]; then
    echo -e "${RED}❌ Could not identify the resulting scan directory under $SCANS_ROOT${NC}"
    exit 1
fi

# Layer 8.5 (pip-audit) is only wired into the CI orchestrator
# (run-epyon-scan-ci.sh), not run-target-security-scan.sh — invoke it
# directly here so the self-assessment covers it too.
if [[ "$RUN_PIP_AUDIT" == "true" ]]; then
    echo -e "${GREEN}▶ Running pip-audit directly (Layer 8.5 — not part of run-target-security-scan.sh)${NC}"
    chmod +x "$SCRIPT_DIR/run-pip-audit-scan.sh" 2>/dev/null || true
    TARGET_DIR="$FIXTURE_DIR" SCAN_DIR="$NEW_SCAN_DIR" "$SCRIPT_DIR/run-pip-audit-scan.sh" || \
        echo -e "${YELLOW}⚠️  pip-audit scan step exited non-zero — treated as a soft failure for Layer 8.5${NC}"
else
    echo -e "${YELLOW}⚠️  Skipping Layer 8.5 (pip-audit) — not selected${NC}"
fi

echo -e "${GREEN}▶ Comparing results in $NEW_SCAN_DIR against $MANIFEST${NC}"
COMPARE_EXIT=0
COMPARE_ARGS=(--scan-dir "$NEW_SCAN_DIR" --manifest "$MANIFEST" --output "$OUTPUT_FILE")
if [[ "$EICAR_PERSISTED" != "true" ]]; then
    COMPARE_ARGS+=(--environment-limited-layer 4)
fi
if [[ -n "$LAYERS_FILTER" ]]; then
    COMPARE_ARGS+=(--only-layers "$LAYERS_FILTER")
fi
python3 "$SCRIPT_DIR/compare-self-assessment.py" "${COMPARE_ARGS[@]}" || COMPARE_EXIT=$?

echo -e "${GREEN}▶ Results written to $OUTPUT_FILE${NC}"

if [[ "$KEEP_SCAN" != "true" ]]; then
    rm -rf "$NEW_SCAN_DIR"
    echo -e "${YELLOW}▶ Removed scan directory (pass --keep-scan to retain it for debugging)${NC}"
fi

exit $COMPARE_EXIT
