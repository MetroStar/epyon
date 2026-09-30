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
if [[ ${#POSITIONAL_ARGS[@]} -gt 0 ]]; then
    for positional in "${POSITIONAL_ARGS[@]}"; do
        if [[ -z "$TARGET_ARG" ]]; then
            TARGET_ARG="$positional"
        else
            echo -e "${RED}❌ Error: Unexpected extra argument: $positional${NC}"
            echo -e "${YELLOW}Run with --help for usage examples.${NC}"
            exit 1
        fi
    done
fi

# Determine target directory
if [[ -n "$TARGET_ARG" ]]; then
    REPO_PATH="$TARGET_ARG"
elif [[ -n "${TARGET_DIR:-}" ]]; then
    REPO_PATH="$TARGET_DIR"
else
    REPO_PATH="$(pwd)"
fi

REPO_PATH=$(realpath "${REPO_PATH}" 2>/dev/null) || { echo "ERROR: Target path does not exist or is invalid: ${REPO_PATH}" >&2; exit 1; }

# Source scan-directory-template.sh (for get_epyon_ignore_exclude_paths only —
# this script doesn't use init_scan_environment) so dependency-file discovery
# below can honor `type: path` rules in the target's .epyon-ignore.yml.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "$SCRIPT_DIR/scan-directory-template.sh" ]]; then
    # shellcheck source=/dev/null
    source "$SCRIPT_DIR/scan-directory-template.sh"
fi

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

# Build -not -path excludes from any `type: path` rules in the target's
# .epyon-ignore.yml (e.g. Epyon's own self-assessment fixture) so a normal
# scan never picks up deliberately-suppressed dependency files.
IGNORE_FIND_EXCLUDES=()
if declare -f get_epyon_ignore_exclude_paths >/dev/null 2>&1; then
    while IFS= read -r _pat; do
        [[ -n "$_pat" ]] && IGNORE_FIND_EXCLUDES+=(-not -path "$REPO_PATH/${_pat%/\*\*}/*" -not -path "$REPO_PATH/${_pat%/\*\*}")
    done < <(get_epyon_ignore_exclude_paths "$REPO_PATH")
fi

# Search for requirements files.
#
# NOTE: requirements-conda-env.txt / requirements-pyproject.txt are excluded
# by exact basename. Layer 1 (SBOM/Syft) writes throwaway files with these
# exact names directly into the target repo (next to environment.yml /
# pyproject.toml, respectively) so Syft's python-package-cataloger can pick up
# conda/pyproject deps, then deletes them once its own scan finishes. Since
# every layer runs in parallel, this scan's `find` could catch one of those
# files while it briefly exists, but the actual `pip-audit -r ...` invocation
# for it may not happen until minutes later in this script's own per-file
# loop below -- by which point Layer 1 has already deleted it, causing a hard
# "file not found" failure that looks like a real scan error. pyproject.toml
# itself is scanned directly a few lines below (project mode), so excluding
# its synthetic duplicate loses no coverage. Conda coverage is regenerated
# independently, in this layer's own output directory, right after this block.
while IFS= read -r -d '' file; do
    DEPENDENCY_FILES+=("$file")
    FOUND_COUNT=$((FOUND_COUNT + 1))
done < <(find "$REPO_PATH" \
    -type f \
    \( -name "requirements*.txt" -o -name "poetry.lock" -o -name "Pipfile.lock" -o -name "pyproject.toml" \) \
    -not -name "requirements-conda-env.txt" \
    -not -name "requirements-pyproject.txt" \
    -not -path "*/\.*" \
    -not -path "*/.git/*" \
    -not -path "*/node_modules/*" \
    -not -path "*/__pycache__/*" \
    "${IGNORE_FIND_EXCLUDES[@]+"${IGNORE_FIND_EXCLUDES[@]}"}" \
    -print0)

# Independently audit conda environment.yml/environment.yaml files. This
# generates our own synthetic requirements file in THIS layer's own output
# directory (never in the target repo), so there's no cross-layer race with
# Layer 1's SBOM preprocessing -- see the note above.
CONDA_ENV_IDX=0
while IFS= read -r -d '' envfile; do
    CONDA_ENV_IDX=$((CONDA_ENV_IDX + 1))
    conda_req="$OUTPUT_DIR/conda-env-requirements-${CONDA_ENV_IDX}.txt"
    python3 - "$envfile" "$conda_req" <<'PYEOF' 2>/dev/null
import sys, re
try:
    import yaml
except ImportError:
    sys.exit(0)
src, dst = sys.argv[1], sys.argv[2]
with open(src) as f:
    data = yaml.safe_load(f)
deps = data.get("dependencies") or []

def normalize_spec(spec):
    """Convert any version spec to an exact == pin so pip-audit can resolve it."""
    spec = spec.strip()
    name_part = re.split(r'[=<>!;\[]', spec)[0].strip()
    if not name_part:
        return None
    if '==' in spec:
        return spec
    m = re.search(r'[><=!]+\s*([\d][^\s,;]*)', spec)
    if m:
        return f"{name_part}=={m.group(1)}"
    # Unpinned conda deps have no resolvable version for pip-audit; skip rather
    # than guessing a fake 0.0.0 that would just report false vulnerabilities.
    return None

lines = []
for dep in deps:
    if isinstance(dep, str):
        if dep.startswith("python") or dep.startswith("_") or dep.strip() == "pip":
            continue
        spec = re.sub(r'(?<![=<>!])=(?!=)', '==', dep)
        result = normalize_spec(spec)
        if result:
            lines.append(result)
    elif isinstance(dep, dict) and "pip" in dep:
        for pip_dep in (dep["pip"] or []):
            if isinstance(pip_dep, str):
                result = normalize_spec(pip_dep)
                if result:
                    lines.append(result)
if lines:
    with open(dst, "w") as f:
        f.write("\n".join(lines) + "\n")
PYEOF
    if [[ -s "$conda_req" ]]; then
        DEPENDENCY_FILES+=("$conda_req")
        FOUND_COUNT=$((FOUND_COUNT + 1))
        echo "Pre-processed conda env for pip-audit: $envfile -> $conda_req" >> "$SCAN_LOG"
    else
        rm -f "$conda_req"
    fi
done < <(find "$REPO_PATH" \( -name "environment.yml" -o -name "environment.yaml" \) -not -path "*/.git/*" -print0 2>/dev/null)

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

# pip-audit's JSON output schema is {"dependencies": [{"name", "version",
# "vulns": [...]}]}, not the flat {"vulnerabilities": [...]} this script
# previously assumed. That mismatch meant every real finding was silently
# discarded and replaced with a fake "scan failed" placeholder (jq -e
# '.vulnerabilities' always failed since that key never exists). This
# filter flattens the real schema into a single array, tagging each vuln
# with its package name/version for context.
VULN_FILTER='[.dependencies[]? // empty | . as $d | ($d.vulns // [])[] | . + {package: $d.name, installed_version: $d.version}]'

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

    # Run pip-audit with JSON output. pip-audit exits non-zero whenever it
    # finds vulnerabilities (by design, for CI gating) even though stdout
    # still contains the full, valid JSON results — so a non-zero exit
    # code alone must NOT be treated as a failed scan.
    if "${PIP_AUDIT_CMD[@]}" 2>>"$SCAN_LOG" > "$output_file"; then
        # Extract vulnerability count
        if command -v jq >/dev/null 2>&1; then
            VULN_COUNT=$(jq "$VULN_FILTER | length" "$output_file" 2>/dev/null || echo 0)
            if [ "$VULN_COUNT" -gt 0 ]; then
                echo -e "${RED}   ❌ Found $VULN_COUNT vulnerability(ies)${NC}"
                TOTAL_VULNERABILITIES=$((TOTAL_VULNERABILITIES + VULN_COUNT))
                
                # Extract vulnerabilities for consolidated output
                jq -c "$VULN_FILTER[]" "$output_file" 2>/dev/null | while read -r vuln; do
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
        # Non-zero exit can still mean "scan succeeded, vulnerabilities
        # found" — only treat as a real failure if the output isn't valid
        # pip-audit JSON at all (missing the "dependencies" key).
        if [ -s "$output_file" ] && jq -e '.dependencies' "$output_file" >/dev/null 2>&1; then
            VULN_COUNT=$(jq "$VULN_FILTER | length" "$output_file" 2>/dev/null || echo 0)
            if [ "$VULN_COUNT" -gt 0 ]; then
                echo -e "${RED}   ❌ Found $VULN_COUNT vulnerability(ies)${NC}"
                TOTAL_VULNERABILITIES=$((TOTAL_VULNERABILITIES + VULN_COUNT))
            else
                echo -e "${YELLOW}   ⚠️  Scan exited non-zero ($exit_code) with no findings${NC}"
            fi
        else
            echo -e "${YELLOW}   ⚠️  Scan failed (exit code: $exit_code)${NC}"
            echo '{"dependencies": [], "error": "scan failed"}' > "$output_file"
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
                    ENV_VULN_COUNT=$(jq "$VULN_FILTER | length" "$ENV_OUTPUT_FILE" 2>/dev/null || echo 0)
                    if [ "$ENV_VULN_COUNT" -gt 0 ]; then
                        echo -e "${RED}   ❌ Environment audit found $ENV_VULN_COUNT vulnerability(ies)${NC}"
                        TOTAL_VULNERABILITIES=$((TOTAL_VULNERABILITIES + ENV_VULN_COUNT))
                    else
                        echo -e "${GREEN}   ✅ Environment audit found no vulnerabilities${NC}"
                    fi
                else
                    if [ -s "$ENV_OUTPUT_FILE" ] && jq -e '.dependencies' "$ENV_OUTPUT_FILE" >/dev/null 2>&1; then
                        ENV_VULN_COUNT=$(jq "$VULN_FILTER | length" "$ENV_OUTPUT_FILE" 2>/dev/null || echo 0)
                        if [ "$ENV_VULN_COUNT" -gt 0 ]; then
                            echo -e "${RED}   ❌ Environment audit found $ENV_VULN_COUNT vulnerability(ies)${NC}"
                            TOTAL_VULNERABILITIES=$((TOTAL_VULNERABILITIES + ENV_VULN_COUNT))
                        fi
                    else
                        echo '{"dependencies": [], "error": "environment audit failed"}' > "$ENV_OUTPUT_FILE"
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
            echo "      \"results\": $(jq "$VULN_FILTER" "$output_file" 2>/dev/null || echo '[]')"
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
        echo "      \"results\": $(jq "$VULN_FILTER" "$ENV_OUTPUT_FILE" 2>/dev/null || echo '[]')"
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
