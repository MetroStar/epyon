#!/bin/bash

# Validate the artifacts that make a scan reviewable and auditable.
# Usage: validate-scan-output.sh SCAN_DIR [--require-build] [--require-ssp]

set -euo pipefail

SCAN_DIR="${1:-}"
REQUIRE_BUILD=false
REQUIRE_SSP=false

if [[ -z "$SCAN_DIR" || ! -d "$SCAN_DIR" ]]; then
    echo "Usage: $0 SCAN_DIR [--require-build] [--require-ssp]" >&2
    exit 2
fi
shift
while [[ $# -gt 0 ]]; do
    case "$1" in
        --require-build) REQUIRE_BUILD=true ;;
        --require-ssp) REQUIRE_SSP=true ;;
        *) echo "Unknown option: $1" >&2; exit 2 ;;
    esac
    shift
done

failures=0
require_file() {
    local relative_path="$1"
    if [[ ! -s "$SCAN_DIR/$relative_path" ]]; then
        echo "MISSING: $relative_path" >&2
        failures=$((failures + 1))
    fi
}

require_dir() {
    local relative_path="$1"
    if [[ ! -d "$SCAN_DIR/$relative_path" ]]; then
        echo "MISSING: $relative_path/" >&2
        failures=$((failures + 1))
    fi
}

require_file "security-findings-summary.json"
require_file "scan-manifest.json"
require_file "suppressed-findings.md"
require_dir "sbom"

if [[ ! -s "$SCAN_DIR/security-dashboard.html" && \
      ! -s "$SCAN_DIR/consolidated-reports/dashboards/security-dashboard.html" ]]; then
    echo "MISSING: security dashboard HTML" >&2
    failures=$((failures + 1))
fi

if command -v jq >/dev/null 2>&1 && [[ -s "$SCAN_DIR/security-findings-summary.json" ]]; then
    if ! jq -e 'type == "object"' "$SCAN_DIR/security-findings-summary.json" >/dev/null 2>&1; then
        echo "INVALID: security-findings-summary.json" >&2
        failures=$((failures + 1))
    fi
fi

if command -v jq >/dev/null 2>&1 && [[ -s "$SCAN_DIR/scan-manifest.json" ]]; then
    if ! jq -e 'type == "object"' "$SCAN_DIR/scan-manifest.json" >/dev/null 2>&1; then
        echo "INVALID: scan-manifest.json" >&2
        failures=$((failures + 1))
    fi
fi

if [[ "$REQUIRE_BUILD" == "true" ]]; then
    require_dir "build"
    require_file "build/image-digest.txt"
    require_file "build/oci-manifest.json"
    require_file "build/build.log"
    require_file "provenance.jsonl"
    require_file "image.sig"
fi

if [[ "$REQUIRE_SSP" == "true" ]]; then
    ssp_count=0
    for evidence_file in "$SCAN_DIR"/ssp-ato-evidence-*; do
        if [[ -s "$evidence_file" ]]; then
            ssp_count=$((ssp_count + 1))
        fi
    done
    if [[ "$ssp_count" -eq 0 ]]; then
        echo "MISSING: ssp-ato-evidence-*" >&2
        failures=$((failures + 1))
    fi
fi

if [[ "$failures" -gt 0 ]]; then
    echo "Scan output validation failed: $failures issue(s)" >&2
    exit 1
fi

echo "Scan output validation passed: $SCAN_DIR"
