#!/bin/bash
# Check scan coverage - verify all expected tool layers ran

SCAN_DIR="$1"
if [[ -z "$SCAN_DIR" ]]; then
    echo "Usage: $0 <scan_directory>"
    exit 1
fi

if [[ ! -d "$SCAN_DIR" ]]; then
    echo "Error: Scan directory not found: $SCAN_DIR"
    exit 1
fi

echo "=== Scan Coverage Report ==="
echo "Scan: $(basename $SCAN_DIR)"
echo ""

# Read scan metadata
if [[ -f "$SCAN_DIR/scan-metadata.json" ]]; then
    SCAN_TYPE=$(python3 -c "import json, sys; print(json.load(open('$SCAN_DIR/scan-metadata.json')).get('scan_type', 'unknown'))" 2>/dev/null || echo "unknown")
    echo "Scan Type: $SCAN_TYPE"
else
    SCAN_TYPE="unknown"
    echo "Scan Type: unknown (no metadata)"
fi
echo ""

# Define expected layers for each scan type
declare -A EXPECTED_LAYERS
case "$SCAN_TYPE" in
    quick)
        EXPECTED_LAYERS=(
            ["sbom"]="Layer 1: SBOM Generation"
            ["trufflehog"]="Layer 2: Secret Detection"
            ["trivy"]="Layer 7: Container Security"
            ["grype"]="Layer 8: Vulnerability Scanning"
            ["pip-audit"]="Layer 8.5: Direct Dependency Scan"
            ["safety"]="Layer 8.6: Python Safety Check"
        )
        ;;
    full|nightly)
        EXPECTED_LAYERS=(
            ["sbom"]="Layer 1: SBOM Generation"
            ["trufflehog"]="Layer 2: Secret Detection"
            ["sonar"]="Layer 3: Code Quality"
            ["clamav"]="Layer 4: Malware Detection"
            ["helm"]="Layer 5: Helm Chart Build"
            ["checkov"]="Layer 6: IaC Security"
            ["trivy"]="Layer 7: Container Security"
            ["grype"]="Layer 8: Vulnerability Scanning"
            ["pip-audit"]="Layer 8.5: Direct Dependency Scan"
            ["safety"]="Layer 8.6: Python Safety Check"
            ["xeol"]="Layer 9: EOL Detection"
            ["anchore"]="Layer 10: Container Analysis"
            ["api"]="Layer 11: API Discovery"
            ["picklescan"]="Layer 14: Model File Analysis"
            ["modelcard"]="Layer 15: Model Card Compliance"
            ["network"]="Layer 16: Network Discovery"
            ["model-provenance"]="Layer 18: Model Provenance"
            ["inference-security"]="Layer 19: Inference Security"
        )
        ;;
    *)
        echo "Unknown scan type: $SCAN_TYPE"
        echo "Skipping expected layer check"
        echo ""
        ;;
esac

# Check for each expected layer
echo "=== Expected Layers ==="
MISSING_COUNT=0
PRESENT_COUNT=0
for dir in "${!EXPECTED_LAYERS[@]}"; do
    name="${EXPECTED_LAYERS[$dir]}"
    if [[ -d "$SCAN_DIR/$dir" ]]; then
        echo "✓ $name ($dir/)"
        ((PRESENT_COUNT++))
    else
        echo "✗ $name ($dir/) - MISSING"
        ((MISSING_COUNT++))
    fi
done
echo ""

# List all actual directories
echo "=== Actual Tool Directories ==="
ls -d "$SCAN_DIR"/*/ 2>/dev/null | while read dir; do
    echo "  • $(basename $dir)"
done
echo ""

# Summary
echo "=== Summary ==="
echo "Expected layers: $((PRESENT_COUNT + MISSING_COUNT))"
echo "Present: $PRESENT_COUNT"
echo "Missing: $MISSING_COUNT"
echo ""

# Check layer timing
if [[ -f "$SCAN_DIR/layer-timing.json" ]]; then
    echo "=== Layer Timing ==="
    cat "$SCAN_DIR/layer-timing.json"
    echo ""
fi

# Check for no-op results
echo "=== No-Op Check (tools that ran but found nothing) ==="
for dir in "$SCAN_DIR"/*/; do
    dirname=$(basename "$dir")
    # Check for status.json or results files
    if [[ -f "$dir/status.json" ]]; then
        STATUS=$(python3 -c "import json; d=json.load(open('$dir/status.json')); print(d.get('status', 'unknown'), '-', d.get('reason', ''))" 2>/dev/null || echo "error reading status")
        if echo "$STATUS" | grep -qiE "no.*found|skip|empty"; then
            echo "  ⚠ $dirname: $STATUS"
        fi
    fi
done
echo ""

echo "=== Coverage Report Complete ==="
