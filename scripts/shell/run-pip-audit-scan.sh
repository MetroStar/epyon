#!/bin/bash

# pip-audit Direct Dependency Vulnerability Scanner
# Scans Python dependency files directly (requirements.txt, poetry.lock, etc.)
# Catches CVEs missed by SBOM-based scanners (Syft/Grype)

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

# Help function
show_help() {
    cat <<EOF
${WHITE}pip-audit Direct Dependency Vulnerability Scanner${NC}

Usage: $0 [OPTIONS] [TARGET_DIRECTORY]
       $0 --target <TARGET>

Scans Python dependency files directly using pip-audit.
Catches CVEs missed by SBOM-based scanners like Syft/Grype.

Options:
  -h, --help          Show this help message and exit
  -t, --target PATH   Target directory to scan
  --list-modes        List available scan modes and exit

Environment Variables:
  TARGET_DIR          Alternative way to specify target directory
  SCAN_ID             Override auto-generated scan ID
  SCAN_DIR            Override output directory for scan results

Output:
  Results are saved to: scans/{SCAN_ID}/pip-audit/
  - pip-audit-{filename}-results.json    Audit results per dependency file
  - pip-audit-consolidated-results.json  Consolidated findings
  - pip-audit-scan.log                   Scan process log

Dependency Files Scanned:
  - requirements.txt
  - requirements-lock.txt
  - requirements-*.txt (all variants)
  - poetry.lock
  - Pipfile.lock
    - pyproject.toml
  - setup.py (if pip-audit supports)

Examples:
  $0                                      # Scan current directory
  $0 /path/to/project                     # Scan specific directory
  $0 --target /path/to/project            # Using flag syntax

Notes:
  - pip-audit must be installed: pip install pip-audit
  - Scans Python dependency files directly (not SBOM-based)
  - More complete than Grype/Syft for newly published CVEs
  - Complements Grype layer for comprehensive coverage

EOF
    exit 0
}

require_option_value() {
    local opt_name="$1"
    local opt_value="$2"
    if [[ -z "$opt_value" ]] || [[ "$opt_value" == -* ]]; then
        echo -e "${RED}❌ Error: ${opt_name} requires a value${NC}"
        echo -e "${YELLOW}Run with --help for usage examples.${NC}"
        exit 1
    fi
}

# Parse arguments
TARGET_ARG=""
POSITIONAL_ARGS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)
            show_help
            ;;
        --list-modes)
            echo "pip-audit scans all Python dependency files automatically (no mode selection needed)"
            exit 0
            ;;
        -t|--target)
            require_option_value "$1" "${2:-}"
            TARGET_ARG="$2"
            shift 2
            ;;
        -*)
            echo -e "${RED}❌ Error: Unknown option: $1${NC}"
            echo "Run with --help for usage examples."
            exit 1
            ;;
        *)
            POSITIONAL_ARGS+=("$1")
            shift
            ;;
    esac
done

# Handle positional arguments
for positional in "${POSITIONAL_ARGS[@]}"; do
    if [[ -z "$TARGET_ARG" ]]; then
        TARGET_ARG="$positional"
    else
        echo -e "${RED}❌ Error: Unexpected extra argument: $positional${NC}"
        echo -e "${YELLOW}Run with --help for usage examples.${NC}"
        exit 1
    fi
done

# Determine target directory
if [[ -n "$TARGET_ARG" ]]; then
    REPO_PATH="$TARGET_ARG"
elif [[ -n "${TARGET_DIR:-}" ]]; then
    REPO_PATH="$TARGET_DIR"
else
    REPO_PATH="$(pwd)"
fi

REPO_PATH=$(realpath "${REPO_PATH}" 2>/dev/null) || { echo "ERROR: Target path does not exist or is invalid: ${REPO_PATH}" >&2; exit 1; }

# Generate or use existing SCAN_ID
if [[ -n "${SCAN_ID:-}" ]]; then
    TARGET_NAME=$(echo "$SCAN_ID" | cut -d'_' -f1)
    USERNAME=$(echo "$SCAN_ID" | cut -d'_' -f2)
    TIMESTAMP=$(echo "$SCAN_ID" | cut -d'_' -f3-)
else
    TARGET_NAME=$(basename "$REPO_PATH")
    USERNAME=$(whoami)
    TIMESTAMP=$(date '+%Y-%m-%d_%H-%M-%S')
    SCAN_ID="${TARGET_NAME}_${USERNAME}_${TIMESTAMP}"
fi

# Determine output directory
if [[ -n "${SCAN_DIR:-}" ]]; then
    OUTPUT_DIR="${SCAN_DIR}/pip-audit"
else
    OUTPUT_DIR="scans/${SCAN_ID}/pip-audit"
fi

SCAN_LOG="$OUTPUT_DIR/${SCAN_ID}_pip-audit-scan.log"

# Check if pip-audit is installed
if ! command -v pip-audit >/dev/null 2>&1; then
    echo -e "${RED}❌ Error: pip-audit is not installed${NC}"
    echo -e "${YELLOW}Install it with: pip install pip-audit${NC}"
    exit 1
fi

PIP_AUDIT_VERSION=$(pip-audit --version 2>/dev/null || echo "unknown")

# Header
echo -e "${WHITE}============================================${NC}"
echo -e "${WHITE}pip-audit Dependency Vulnerability Scanner${NC}"
echo -e "${WHITE}============================================${NC}"
echo "Repository: $REPO_PATH"
echo "Output Directory: $OUTPUT_DIR"
echo "pip-audit Version: $PIP_AUDIT_VERSION"
echo "Advisory Service: OSV"
echo "Timestamp: $TIMESTAMP"
echo

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Initialize scan log
{
    echo "pip-audit dependency scan started: $TIMESTAMP"
    echo "Target: $REPO_PATH"
    echo "Version: $PIP_AUDIT_VERSION"
    echo "---"
} > "$SCAN_LOG"

# Find all Python dependency files
echo -e "${CYAN}🔍 Scanning for Python dependency files...${NC}"

declare -a DEPENDENCY_FILES
FOUND_COUNT=0

# Search for requirements files
while IFS= read -r -d '' file; do
    DEPENDENCY_FILES+=("$file")
    FOUND_COUNT=$((FOUND_COUNT + 1))
done < <(find "$REPO_PATH" \
    -type f \
    \( -name "requirements*.txt" -o -name "poetry.lock" -o -name "Pipfile.lock" -o -name "pyproject.toml" \) \
    -not -path "*/\.*" \
    -not -path "*/.git/*" \
    -not -path "*/node_modules/*" \
    -not -path "*/__pycache__/*" \
    -print0)

if [ $FOUND_COUNT -eq 0 ]; then
    echo -e "${YELLOW}⚠️  No Python dependency files found${NC}"
    echo "Looking for: requirements.txt, requirements-*.txt, poetry.lock, Pipfile.lock, pyproject.toml"
    echo "{\"scan_results\": [], \"message\": \"No dependency files found\"}" > "$OUTPUT_DIR/${SCAN_ID}_pip-audit-consolidated-results.json"
    exit 0
fi

echo -e "${GREEN}✅ Found $FOUND_COUNT dependency file(s)${NC}"
for file in "${DEPENDENCY_FILES[@]}"; do
    echo "   📄 ${file#$REPO_PATH/}"
done
echo

# Consolidated results
CONSOLIDATED_FINDINGS=()
TOTAL_VULNERABILITIES=0

# Scan each dependency file
echo -e "${CYAN}🛡️  Scanning dependency files...${NC}"
echo

for dep_file in "${DEPENDENCY_FILES[@]}"; do
    # Create a friendly name for the file
    file_basename=$(basename "$dep_file")
    output_file="$OUTPUT_DIR/${SCAN_ID}_pip-audit-${file_basename%.*}-results.json"
    
    echo -e "${BLUE}📋 Scanning: ${dep_file#$REPO_PATH/}${NC}"
    
    # Build pip-audit command based on dependency file type
    dep_basename=$(basename "$dep_file")
    dep_dir=$(dirname "$dep_file")
    if [[ "$dep_basename" == requirements*.txt ]]; then
        PIP_AUDIT_CMD=(pip-audit -r "$dep_file" --format json -s osv)
    elif [[ "$dep_basename" == "poetry.lock" || "$dep_basename" == "Pipfile.lock" ]]; then
        PIP_AUDIT_CMD=(pip-audit -r "$dep_file" --locked --format json -s osv)
    elif [[ "$dep_basename" == "pyproject.toml" ]]; then
        # Project mode can resolve transitive dependencies from pyproject context.
        PIP_AUDIT_CMD=(pip-audit "$dep_dir" --format json -s osv)
    else
        PIP_AUDIT_CMD=(pip-audit -r "$dep_file" --format json -s osv)
    fi

    # Run pip-audit with JSON output (non-zero exit can still include findings JSON)
    if "${PIP_AUDIT_CMD[@]}" 2>>"$SCAN_LOG" > "$output_file"; then
        # Extract vulnerability count
        if command -v jq >/dev/null 2>&1; then
            VULN_COUNT=$(jq '.vulnerabilities | length' "$output_file" 2>/dev/null || echo 0)
            if [ "$VULN_COUNT" -gt 0 ]; then
                echo -e "${RED}   ❌ Found $VULN_COUNT vulnerability(ies)${NC}"
                TOTAL_VULNERABILITIES=$((TOTAL_VULNERABILITIES + VULN_COUNT))
                
                # Extract vulnerabilities for consolidated output
                jq '.vulnerabilities[]' "$output_file" 2>/dev/null | while read -r vuln; do
                    CONSOLIDATED_FINDINGS+=("$vuln")
                done
            else
                echo -e "${GREEN}   ✅ No vulnerabilities found${NC}"
            fi
        else
            echo -e "${GREEN}   ✅ Scan completed${NC}"
        fi
        
        # Create symlink for easy access
        ln -sf "$(basename "$output_file")" "$OUTPUT_DIR/pip-audit-${file_basename%.*}-results.json" 2>/dev/null || true
        
    else
        exit_code=$?
        if [ -s "$output_file" ] && jq -e '.vulnerabilities' "$output_file" >/dev/null 2>&1; then
            VULN_COUNT=$(jq '.vulnerabilities | length' "$output_file" 2>/dev/null || echo 0)
            if [ "$VULN_COUNT" -gt 0 ]; then
                echo -e "${RED}   ❌ Found $VULN_COUNT vulnerability(ies)${NC}"
                TOTAL_VULNERABILITIES=$((TOTAL_VULNERABILITIES + VULN_COUNT))
            else
                echo -e "${YELLOW}   ⚠️  Scan exited non-zero ($exit_code) with no findings${NC}"
            fi
        else
            echo -e "${YELLOW}   ⚠️  Scan failed (exit code: $exit_code)${NC}"
            echo '{"vulnerabilities": [], "error": "scan failed"}' > "$output_file"
        fi
    fi
done

# Optional: resolved environment audit for transitive dependencies.
# This aligns closer to Athena-style checks that inspect installed dependency graphs.
ENV_OUTPUT_FILE="$OUTPUT_DIR/${SCAN_ID}_pip-audit-environment-results.json"
if [[ -f "$REPO_PATH/pyproject.toml" ]]; then
    echo
    echo -e "${CYAN}🧪 Running resolved dependency audit (environment mode)...${NC}"
    AUDIT_VENV="$OUTPUT_DIR/.pip-audit-venv"
    rm -rf "$AUDIT_VENV"

    if python3 -m venv "$AUDIT_VENV" 2>>"$SCAN_LOG"; then
        if "$AUDIT_VENV/bin/python" -m pip install --upgrade pip >>"$SCAN_LOG" 2>&1 && \
           "$AUDIT_VENV/bin/python" -m pip install pip-audit >>"$SCAN_LOG" 2>&1; then
            # Try dev extras first; fallback to core install.
            if "$AUDIT_VENV/bin/python" -m pip install "$REPO_PATH[dev]" >>"$SCAN_LOG" 2>&1 || \
               "$AUDIT_VENV/bin/python" -m pip install "$REPO_PATH" >>"$SCAN_LOG" 2>&1; then
                if "$AUDIT_VENV/bin/pip-audit" -l --format json -s osv > "$ENV_OUTPUT_FILE" 2>>"$SCAN_LOG"; then
                    ENV_VULN_COUNT=$(jq '.vulnerabilities | length' "$ENV_OUTPUT_FILE" 2>/dev/null || echo 0)
                    if [ "$ENV_VULN_COUNT" -gt 0 ]; then
                        echo -e "${RED}   ❌ Environment audit found $ENV_VULN_COUNT vulnerability(ies)${NC}"
                        TOTAL_VULNERABILITIES=$((TOTAL_VULNERABILITIES + ENV_VULN_COUNT))
                    else
                        echo -e "${GREEN}   ✅ Environment audit found no vulnerabilities${NC}"
                    fi
                else
                    if [ -s "$ENV_OUTPUT_FILE" ] && jq -e '.vulnerabilities' "$ENV_OUTPUT_FILE" >/dev/null 2>&1; then
                        ENV_VULN_COUNT=$(jq '.vulnerabilities | length' "$ENV_OUTPUT_FILE" 2>/dev/null || echo 0)
                        if [ "$ENV_VULN_COUNT" -gt 0 ]; then
                            echo -e "${RED}   ❌ Environment audit found $ENV_VULN_COUNT vulnerability(ies)${NC}"
                            TOTAL_VULNERABILITIES=$((TOTAL_VULNERABILITIES + ENV_VULN_COUNT))
                        fi
                    else
                        echo '{"vulnerabilities": [], "error": "environment audit failed"}' > "$ENV_OUTPUT_FILE"
                        echo -e "${YELLOW}   ⚠️  Environment audit failed; see $SCAN_LOG${NC}"
                    fi
                fi
            else
                echo -e "${YELLOW}   ⚠️  Could not install project into audit venv; skipping environment audit${NC}"
            fi
        fi
    fi

    rm -rf "$AUDIT_VENV" 2>/dev/null || true
fi

echo
echo -e "${CYAN}📊 pip-audit Summary${NC}"
echo "=================================="

if [ $TOTAL_VULNERABILITIES -eq 0 ]; then
    echo -e "${GREEN}✅ No vulnerabilities detected in Python dependencies${NC}"
else
    echo -e "${RED}⚠️  Found $TOTAL_VULNERABILITIES total vulnerability(ies)${NC}"
fi

# Generate consolidated results
CONSOLIDATED_OUTPUT="$OUTPUT_DIR/${SCAN_ID}_pip-audit-consolidated-results.json"
{
    echo "{"
    echo "  \"scan_id\": \"$SCAN_ID\","
    echo "  \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\","
    echo "  \"target\": \"$REPO_PATH\","
    echo "  \"total_vulnerabilities\": $TOTAL_VULNERABILITIES,"
    echo "  \"dependency_files_scanned\": $FOUND_COUNT,"
    echo "  \"scan_results\": ["
    
    first=true
    for file in "${DEPENDENCY_FILES[@]}"; do
        file_basename=$(basename "$file")
        output_file="$OUTPUT_DIR/${SCAN_ID}_pip-audit-${file_basename%.*}-results.json"
        if [ -s "$output_file" ]; then
            if [ "$first" = true ]; then
                first=false
            else
                echo ","
            fi
            echo "    {"
            echo "      \"file\": \"${file#$REPO_PATH/}\","
            echo "      \"results\": $(jq '.vulnerabilities' "$output_file" 2>/dev/null || echo '[]')"
            echo -n "    }"
        fi
    done

    if [ -s "$ENV_OUTPUT_FILE" ]; then
        if [ "$first" = true ]; then
            first=false
        else
            echo ","
        fi
        echo "    {"
        echo "      \"file\": \"__resolved_environment__\"," 
        echo "      \"results\": $(jq '.vulnerabilities' "$ENV_OUTPUT_FILE" 2>/dev/null || echo '[]')"
        echo -n "    }"
    fi
    
    echo ""
    echo "  ]"
    echo "}"
} > "$CONSOLIDATED_OUTPUT"

# Create symlink for easy access
ln -sf "$(basename "$CONSOLIDATED_OUTPUT")" "$OUTPUT_DIR/pip-audit-consolidated-results.json" 2>/dev/null || true

echo -e "${GREEN}✅ Scan completed: $CONSOLIDATED_OUTPUT${NC}"

# ═══════════════════════════════════════════════════════════════════════════
# ML-Aware Analysis Enhancement
# ═══════════════════════════════════════════════════════════════════════════

echo
echo -e "${CYAN}🤖 Running ML-aware dependency analysis...${NC}"

ML_ANALYZER="$(dirname "${BASH_SOURCE[0]}")/analyze-ml-dependencies.py"
ML_ENHANCED_OUTPUT="$OUTPUT_DIR/${SCAN_ID}_pip-audit-ml-enhanced-results.json"

if [ -f "$ML_ANALYZER" ]; then
    if python3 "$ML_ANALYZER" "$CONSOLIDATED_OUTPUT" "$ML_ENHANCED_OUTPUT" 2>&1 | tee -a "$SCAN_LOG"; then
        echo -e "${GREEN}✅ ML-aware analysis completed${NC}"
        
        # Create symlink for easy access
        ln -sf "$(basename "$ML_ENHANCED_OUTPUT")" "$OUTPUT_DIR/pip-audit-ml-enhanced-results.json" 2>/dev/null || true
        
        # Extract ML-specific counts
        if command -v jq >/dev/null 2>&1 && [ -f "$ML_ENHANCED_OUTPUT" ]; then
            ML_PACKAGES=$(jq -r '.ml_packages_detected // 0' "$ML_ENHANCED_OUTPUT" 2>/dev/null || echo 0)
            ML_VULNS=$(jq -r '.ml_vulnerabilities_count // 0' "$ML_ENHANCED_OUTPUT" 2>/dev/null || echo 0)
            TYPOSQUAT_WARNS=$(jq -r '.typosquat_warnings_count // 0' "$ML_ENHANCED_OUTPUT" 2>/dev/null || echo 0)
            
            echo
            echo -e "${CYAN}🔬 ML-Specific Findings${NC}"
            echo "=================================="
            echo "ML/AI packages detected: $ML_PACKAGES"
            echo "ML vulnerabilities: $ML_VULNS"
            
            if [ "$TYPOSQUAT_WARNS" -gt 0 ]; then
                echo -e "${RED}⚠️  Typosquat warnings: $TYPOSQUAT_WARNS${NC}"
                echo
                echo -e "${RED}🚨 CRITICAL: Potential typosquatting attack detected!${NC}"
                echo -e "${YELLOW}Review the ML-enhanced results file for details.${NC}"
            fi
        fi
    else
        ML_ANALYZER_EXIT=$?
        if [ $ML_ANALYZER_EXIT -eq 2 ]; then
            echo -e "${RED}🚨 CRITICAL: Typosquatting attack detected in dependencies!${NC}"
            echo -e "${RED}Review: $ML_ENHANCED_OUTPUT${NC}"
            echo
            exit 2
        elif [ $ML_ANALYZER_EXIT -eq 1 ]; then
            echo -e "${YELLOW}⚠️  High-severity vulnerabilities found in ML packages${NC}"
            # Don't fail the build, just warn (pip-audit already reported vulns)
        else
            echo -e "${YELLOW}⚠️  ML analysis completed with warnings${NC}"
        fi
    fi
else
    echo -e "${YELLOW}⚠️  ML analyzer not found: $ML_ANALYZER${NC}"
    echo "   Skipping ML-specific analysis (basic pip-audit results still available)"
fi

echo

exit 0
