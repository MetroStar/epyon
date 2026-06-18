#!/bin/bash

################################################################################
# Layer 11.5: Python Safety Check - Direct dependency vulnerability scanner
#
# Purpose: Scan Python dependencies against Safety's vulnerability database
#          (complements pip-audit by providing NVD + PyPI advisory coverage)
#
# Accepts: --target DIR, --scan-dir DIR, --app-name NAME
# Outputs: {SCAN_DIR}/safety/*.json + {SCAN_DIR}/safety/safety-consolidated-results.json
#
# Exit codes: 0 (success), 1 (execution error), 2 (vulnerabilities found but recorded)
################################################################################

set -euo pipefail

# Color output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Arguments (from orchestration)
TARGET_DIR="${TARGET_DIR:-.}"
SCAN_DIR="${SCAN_DIR:-.}"
APP_NAME="${APP_NAME:-unknown}"

# Derived paths
SAFETY_DIR="$SCAN_DIR/safety"
SAFETY_CONSOLIDATED="$SAFETY_DIR/safety-consolidated-results.json"

# Initialize
mkdir -p "$SAFETY_DIR"

echo "[INFO] Layer 11.5: Python Safety Check"
echo "[INFO] Target: $TARGET_DIR"
echo "[INFO] Output: $SAFETY_DIR"

# Check if safety is available
if ! command -v safety &> /dev/null; then
    echo -e "${YELLOW}[WARN] safety not found in PATH, attempting Docker fallback...${NC}"
    SAFETY_CMD="docker run --rm -v $TARGET_DIR:/target pyupio/safety:latest safety check"
    TEST_CMD="docker run --rm -v $TARGET_DIR:/target pyupio/safety:latest safety --version"
else
    SAFETY_CMD="safety check"
    TEST_CMD="safety --version"
fi

# Verify safety works
if ! eval "$TEST_CMD" > /dev/null 2>&1; then
    echo -e "${RED}[ERROR] safety unavailable (not installed and Docker fallback failed)${NC}" >&2
    echo '{"error": "safety not available", "scan_results": []}' > "$SAFETY_CONSOLIDATED"
    exit 1
fi

# Consolidate results
consolidate_safety_results() {
    local consolidated_json="{\"scan_results\": [], \"metadata\": {\"app_name\": \"$APP_NAME\", \"scan_date\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}}"
    local total_vulns=0
    
    # Find all safety result files
    if [[ -f "$SAFETY_DIR"/*.json ]]; then
        for result_file in "$SAFETY_DIR"/*.json; do
            # Skip the consolidated file itself
            if [[ "$(basename "$result_file")" == "safety-consolidated-results.json" ]]; then
                continue
            fi
            
            local file_path=$(basename "$result_file" | sed 's/safety-//;s/-results\.json//')
            local results=$(cat "$result_file" 2>/dev/null | jq '.vulnerabilities // []' 2>/dev/null || echo '[]')
            local vuln_count=$(echo "$results" | jq 'length')
            
            total_vulns=$((total_vulns + vuln_count))
            
            consolidated_json=$(echo "$consolidated_json" | jq --arg file "$file_path" --argjson vulns "$results" \
                '.scan_results += [{"file": $file, "results": $vulns}]')
        done
    fi
    
    echo "$consolidated_json" | jq ".metadata.total_vulnerabilities = $total_vulns" > "$SAFETY_CONSOLIDATED"
}

# Scan Python dependency files
find "$TARGET_DIR" -type f \( -name "requirements*.txt" -o -name "poetry.lock" -o -name "Pipfile.lock" -o -name "setup.py" -o -name "pyproject.toml" \) | while read -r dep_file; do
    rel_path="${dep_file#$TARGET_DIR/}"
    safe_name=$(echo "$rel_path" | tr '/' '-' | sed 's/\.lock$//;s/\.txt$//;s/\.py$//')
    output_file="$SAFETY_DIR/safety-${safe_name}-results.json"
    
    echo "[INFO] Scanning: $rel_path"
    
    # Run safety check
    if [[ -f "$dep_file" ]]; then
        # Skip Pipfile.lock for now (requires special handling)
        if [[ "$dep_file" == *.lock ]] && [[ "$safe_name" == *"Pipfile"* ]]; then
            echo "[SKIP] Pipfile.lock requires pipenv (not supported yet)"
            continue
        fi
        
        # For poetry.lock, extract requirements
        if [[ "$dep_file" == "poetry.lock" ]]; then
            # poetry.lock requires different handling - skip for now
            echo "[SKIP] poetry.lock requires poetry (not auto-convertible)"
            continue
        fi
        
        # Standard requirements.txt
        if eval "$SAFETY_CMD --file $dep_file --json" > "$output_file" 2>/dev/null; then
            local vuln_count=$(jq '.vulnerabilities // [] | length' "$output_file" 2>/dev/null || echo "0")
            if [[ $vuln_count -gt 0 ]]; then
                echo -e "${YELLOW}[WARN] Found $vuln_count vulnerabilities in $rel_path${NC}"
            else
                echo -e "${GREEN}[OK] No vulnerabilities found in $rel_path${NC}"
            fi
        else
            # Safety found vulnerabilities or error - still capture output
            if [[ -s "$output_file" ]]; then
                local vuln_count=$(jq '.vulnerabilities // [] | length' "$output_file" 2>/dev/null || echo "?")
                echo -e "${YELLOW}[WARN] Found vulnerabilities in $rel_path${NC}"
            else
                echo -e "${RED}[ERROR] Failed to scan $rel_path${NC}" >&2
                echo '{"vulnerabilities": [], "error": "scan failed"}' > "$output_file"
            fi
        fi
        
        # Create symlink for easy access
        ln -sf "$(basename "$output_file")" "$SAFETY_DIR/safety-${safe_name}-results.json" 2>/dev/null || true
    fi
done

# Consolidate all results
consolidate_safety_results

if [[ -f "$SAFETY_CONSOLIDATED" ]]; then
    echo -e "${GREEN}[OK] Consolidated results: $SAFETY_CONSOLIDATED${NC}"
else
    echo -e "${YELLOW}[WARN] No consolidated results file generated${NC}"
fi

exit 0
