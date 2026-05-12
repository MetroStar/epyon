#!/bin/bash

# SBOM (Software Bill of Materials) Generation Script
# Generates comprehensive software inventory using Syft from Anchore

# Colors for help output
WHITE='\033[1;37m'
NC='\033[0m'

# Help function
show_help() {
    echo -e "${WHITE}SBOM (Software Bill of Materials) Generator${NC}"
    echo ""
    echo "Usage: $0 [OPTIONS] [TARGET_DIRECTORY]"
    echo ""
    echo "Generates comprehensive software inventory using Syft from Anchore."
    echo "Creates a complete list of all packages, libraries, and dependencies."
    echo ""
    echo "Arguments:"
    echo "  TARGET_DIRECTORY    Path to directory to scan (default: current directory)"
    echo ""
    echo "Options:"
    echo "  -h, --help          Show this help message and exit"
    echo ""
    echo "Environment Variables:"
    echo "  TARGET_DIR          Alternative way to specify target directory"
    echo "  SCAN_ID             Override auto-generated scan ID"
    echo "  SCAN_DIR            Override output directory for scan results"
    echo ""
    echo "Output:"
    echo "  Results are saved to: scans/{SCAN_ID}/sbom/"
    echo "  - sbom-results.json             Full SBOM in SPDX JSON format"
    echo "  - sbom-cyclonedx.json           CycloneDX format"
    echo "  - sbom-summary.json             Package summary statistics"
    echo "  - sbom-scan.log                 Scan process log"
    echo ""
    echo "Package Types Detected:"
    echo "  - npm (Node.js packages)"
    echo "  - pip/poetry (Python packages, requirements.txt, requirements.lock, poetry.lock, Pipfile)"
    echo "  - gem (Ruby packages)"
    echo "  - maven/gradle (Java packages)"
    echo "  - go modules"
    echo "  - Rust crates"
    echo "  - OS packages (deb, rpm, apk)"
    echo ""
    echo "Examples:"
    echo "  $0                              # Generate SBOM for current directory"
    echo "  $0 /path/to/project             # Generate SBOM for specific directory"
    echo "  TARGET_DIR=/app $0              # Generate via environment variable"
    echo ""
    echo "Notes:"
    echo "  - Requires Docker to be installed and running"
    echo "  - Uses anchore/syft:latest Docker image"
    echo "  - Generates multiple output formats for compatibility"
    exit 0
}

# Parse arguments
for arg in "$@"; do
    case $arg in
        -h|--help)
            show_help
            ;;
    esac
done

# Support target directory scanning - priority: command line arg, TARGET_DIR env var, current directory
REPO_PATH="${1:-${TARGET_DIR:-$(pwd)}}"
REPO_PATH=$(realpath "${REPO_PATH}" 2>/dev/null) || { echo "ERROR: Target path does not exist or is invalid: ${REPO_PATH}" >&2; exit 1; }

# Initialize scan environment using scan directory approach
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source the scan directory template
source "$SCRIPT_DIR/scan-directory-template.sh"

# Initialize scan environment for SBOM
init_scan_environment "sbom"

# Set REPO_ROOT for compatibility
REPO_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"

# Extract scan information
if [[ -n "$SCAN_ID" ]]; then
    TARGET_NAME=$(echo "$SCAN_ID" | cut -d'_' -f1)
    USERNAME=$(echo "$SCAN_ID" | cut -d'_' -f2)
    TIMESTAMP=$(echo "$SCAN_ID" | cut -d'_' -f3-)
else
    # Fallback for standalone execution
    TARGET_NAME=$(basename "$REPO_PATH")
    USERNAME=$(whoami)
    TIMESTAMP=$(date '+%Y-%m-%d_%H-%M-%S')
    SCAN_ID="${TARGET_NAME}_${USERNAME}_${TIMESTAMP}"
fi

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

echo -e "${WHITE}============================================${NC}"
echo -e "${WHITE}SBOM Generation with Syft${NC}"
echo -e "${WHITE}============================================${NC}"
echo "Target: $REPO_PATH"
echo "Output Directory: $OUTPUT_DIR"
echo "Scan ID: $SCAN_ID"
echo "Started: $(date)"
echo

# Display dependency manifest count for transparency
if [ -d "$REPO_PATH" ]; then
    echo -e "${CYAN}📊 SBOM Source Analysis:${NC}"
    echo -e "   📁 Target Directory: $REPO_PATH"
    # Count package manifests
    PACKAGE_JSON=$(find "$REPO_PATH" -name "package.json" -not -path "*/node_modules/*" 2>/dev/null | wc -l | tr -d ' ')
    REQUIREMENTS=$(find "$REPO_PATH" \( -name "requirements*.txt" -o -name "requirements*.lock" -o -name "Pipfile*" -o -name "pyproject.toml" -o -name "poetry.lock" \) 2>/dev/null | wc -l | tr -d ' ')
    CONDA_ENV=$(find "$REPO_PATH" \( -name "environment.yml" -o -name "environment.yaml" \) -not -path "*/.git/*" 2>/dev/null | wc -l | tr -d ' ')
    GO_MOD=$(find "$REPO_PATH" -name "go.mod" 2>/dev/null | wc -l | tr -d ' ')
    POM_XML=$(find "$REPO_PATH" -name "pom.xml" 2>/dev/null | wc -l | tr -d ' ')
    GEMFILE=$(find "$REPO_PATH" -name "Gemfile" 2>/dev/null | wc -l | tr -d ' ')
    CARGO=$(find "$REPO_PATH" -name "Cargo.toml" 2>/dev/null | wc -l | tr -d ' ')
    echo -e "   📦 Node.js (package.json): $PACKAGE_JSON"
    echo -e "   🐍 Python (requirements/Pipfile/poetry.lock): $REQUIREMENTS"
    echo -e "   🐍 Conda (environment.yml): $CONDA_ENV"
    echo -e "   🐹 Go (go.mod): $GO_MOD"
    echo -e "   ☕ Java (pom.xml): $POM_XML"
    echo -e "   💎 Ruby (Gemfile): $GEMFILE"
    echo -e "   🦀 Rust (Cargo.toml): $CARGO"
    echo
fi

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Initialize scan log
echo "SBOM generation started: $TIMESTAMP" > "$SCAN_LOG"
echo "Target: $REPO_PATH" >> "$SCAN_LOG"
echo "Syft version check:" >> "$SCAN_LOG"

# Function to detect project metadata
detect_project_info() {
    local target_path="$1"
    local project_name=""
    local project_version=""
    
    # Try to extract project info from various manifest files
    if [[ -f "$target_path/package.json" ]]; then
        project_name=$(jq -r '.name // empty' "$target_path/package.json" 2>/dev/null)
        project_version=$(jq -r '.version // empty' "$target_path/package.json" 2>/dev/null)
    elif [[ -f "$target_path/pyproject.toml" ]]; then
        # Python pyproject.toml
        project_name=$(grep -E '^name\s*=' "$target_path/pyproject.toml" 2>/dev/null | sed 's/.*=\s*"\([^"]*\)".*/\1/')
        project_version=$(grep -E '^version\s*=' "$target_path/pyproject.toml" 2>/dev/null | sed 's/.*=\s*"\([^"]*\)".*/\1/')
    elif [[ -f "$target_path/setup.py" ]]; then
        # Python setup.py (basic extraction)
        project_name=$(grep -E 'name\s*=' "$target_path/setup.py" 2>/dev/null | head -1 | sed 's/.*name\s*=\s*['\''\"]\([^'\''\"]*\)['\''\"]/\1/')
        project_version=$(grep -E 'version\s*=' "$target_path/setup.py" 2>/dev/null | head -1 | sed 's/.*version\s*=\s*['\''\"]\([^'\''\"]*\)['\''\"]/\1/')
    elif [[ -f "$target_path/go.mod" ]]; then
        # Go module
        project_name=$(head -1 "$target_path/go.mod" 2>/dev/null | awk '{print $2}')
        # Go doesn't typically have versions in go.mod for the main module
    elif [[ -f "$target_path/pom.xml" ]]; then
        # Maven project
        project_name=$(grep -E '<artifactId>' "$target_path/pom.xml" 2>/dev/null | head -1 | sed 's/.*<artifactId>\([^<]*\)<\/artifactId>.*/\1/')
        project_version=$(grep -E '<version>' "$target_path/pom.xml" 2>/dev/null | head -1 | sed 's/.*<version>\([^<]*\)<\/version>.*/\1/')
    elif [[ -f "$target_path/Cargo.toml" ]]; then
        # Rust project
        project_name=$(grep -E '^name\s*=' "$target_path/Cargo.toml" 2>/dev/null | sed 's/.*=\s*"\([^"]*\)".*/\1/')
        project_version=$(grep -E '^version\s*=' "$target_path/Cargo.toml" 2>/dev/null | sed 's/.*=\s*"\([^"]*\)".*/\1/')
    fi
    
    # Fallback to directory name if no project name found
    if [[ -z "$project_name" ]]; then
        project_name=$(basename "$target_path")
    fi
    
    # Set default version if none found
    if [[ -z "$project_version" ]]; then
        project_version="unknown"
    fi
    
    echo "${project_name}:${project_version}"
}

# Function to generate SBOM for a target
generate_sbom() {
    local scan_type="$1"
    local target="$2"
    local output_file="$OUTPUT_DIR/${scan_type}.json"
    
    echo -e "${CYAN}🔍 Generating SBOM for ${scan_type}: ${target}${NC}"
    echo "Generating SBOM for ${scan_type}: ${target}" >> "$SCAN_LOG"
    
    # Detect project information to reduce warnings
    local project_info=$(detect_project_info "$target")
    local project_name=$(echo "$project_info" | cut -d: -f1)
    local project_version=$(echo "$project_info" | cut -d: -f2)
    
    echo -e "${BLUE}📋 Project: ${project_name} (${project_version})${NC}"
    echo "Project: ${project_name} (${project_version})" >> "$SCAN_LOG"
    
    # Use .cyclonedx.json extension so the dashboard glob (*.cyclonedx.json) picks it up
    local cyclonedx_file="$OUTPUT_DIR/${scan_type}.cyclonedx.json"

    if command -v syft >/dev/null 2>&1; then
        # Use local Syft installation — output syft-json AND cyclonedx-json in one pass
        echo -e "${GREEN}✅ Using local Syft installation${NC}"
        syft version >> "$SCAN_LOG" 2>&1

        # Use dir: prefix and explicitly enable the lock-file cataloger so
        # package-lock.json / yarn.lock / pnpm-lock.yaml are fully expanded.
        # Without +javascript-lock-cataloger Syft reads only package.json
        # direct deps and misses the full transitive dependency tree.
        # Exclude node_modules/.venv/vendor dirs — those are the resolved
        # artifacts; scanning them makes the SBOM take 100x longer and inflates
        # the count with duplicates of what the lock file already covers.
        if syft scan "dir:${target}" \
            --select-catalogers "+javascript-lock-cataloger" \
            --select-catalogers "+conda-meta-cataloger" \
            --exclude "./node_modules" \
            --exclude "./.venv" \
            --exclude "./vendor" \
            --exclude "./.git" \
            -o "syft-json=${output_file}" \
            -o "cyclonedx-json=${cyclonedx_file}" \
            2>>"$SCAN_LOG"; then
            echo -e "${GREEN}✅ SBOM generated successfully: $(basename "$output_file")${NC}"
            echo -e "${GREEN}✅ CycloneDX SBOM: $(basename "$cyclonedx_file")${NC}"
            echo "SBOM generated successfully: $output_file" >> "$SCAN_LOG"
        else
            echo -e "${RED}❌ Failed to generate SBOM for $scan_type${NC}"
            echo "Failed to generate SBOM for $scan_type" >> "$SCAN_LOG"
            echo '{"artifacts": [], "artifactRelationships": [], "source": {"type": "directory", "target": "'$target'"}, "distro": {}, "descriptor": {"name": "syft", "version": "error"}}' > "$output_file"
        fi
    elif command -v docker >/dev/null 2>&1; then
        # Use Docker version of Syft
        echo -e "${YELLOW}⚠️  Local Syft not found, using Docker version${NC}"
        echo "Using Docker version of Syft" >> "$SCAN_LOG"

        if docker run --rm -v "$target":/workspace:ro \
            anchore/syft:latest \
            scan "dir:/workspace" \
            --select-catalogers "+javascript-lock-cataloger" \
            --select-catalogers "+conda-meta-cataloger" \
            --exclude "./node_modules" \
            --exclude "./.venv" \
            --exclude "./vendor" \
            --exclude "./.git" \
            -o "syft-json=/dev/stdout" \
            2>>"$SCAN_LOG" > "$output_file"; then
            echo -e "${GREEN}✅ SBOM generated successfully: $(basename "$output_file")${NC}"
            echo "SBOM generated successfully: $output_file" >> "$SCAN_LOG"
            # Convert to CycloneDX after Docker run
            if syft convert "$output_file" -o "cyclonedx-json=${cyclonedx_file}" 2>>"$SCAN_LOG"; then
                echo -e "${GREEN}✅ CycloneDX SBOM: $(basename "$cyclonedx_file")${NC}"
            fi
        else
            echo -e "${RED}❌ Failed to generate SBOM for $scan_type using Docker${NC}"
            echo "Failed to generate SBOM for $scan_type using Docker" >> "$SCAN_LOG"
            echo '{"artifacts": [], "artifactRelationships": [], "source": {"type": "directory", "target": "'$target'"}, "distro": {}, "descriptor": {"name": "syft", "version": "docker-error"}}' > "$output_file"
        fi
    else
        echo -e "${RED}❌ Neither Syft nor Docker available for SBOM generation${NC}"
        echo "Neither Syft nor Docker available for SBOM generation" >> "$SCAN_LOG"
        echo '{"artifacts": [], "artifactRelationships": [], "source": {"type": "directory", "target": "'$target'"}, "distro": {}, "descriptor": {"name": "syft", "version": "unavailable"}}' > "$output_file"
        return 1
    fi
    
    # Display SBOM summary
    if [[ -f "$output_file" ]] && [[ -s "$output_file" ]]; then
        local artifact_count=$(jq -r '.artifacts | length' "$output_file" 2>/dev/null || echo "0")
        echo -e "${BLUE}📊 SBOM Summary: $artifact_count artifacts cataloged${NC}"
        echo "SBOM Summary: $artifact_count artifacts cataloged" >> "$SCAN_LOG"
        
        # Show top package types
        echo -e "${CYAN}📦 Package Types:${NC}"
        jq -r '.artifacts[].type' "$output_file" 2>/dev/null | sort | uniq -c | sort -nr | head -5 | while read count type; do
            echo -e "  ${type}: ${count}"
        done
    fi
    
    echo "" >> "$SCAN_LOG"
}

# Generate different types of SBOMs based on target content
echo -e "${PURPLE}🔍 Analyzing target for SBOM generation...${NC}"

# Detect project types for logging purposes
DETECTED_TYPES=""
if [[ -f "$REPO_PATH/package.json" ]]; then
    DETECTED_TYPES="${DETECTED_TYPES}Node.js, "
fi
if [[ -f "$REPO_PATH/requirements.txt" ]] || [[ -f "$REPO_PATH/requirements.lock" ]] || [[ -f "$REPO_PATH/pyproject.toml" ]] || [[ -f "$REPO_PATH/poetry.lock" ]] || [[ -f "$REPO_PATH/Pipfile" ]] || [[ -f "$REPO_PATH/Pipfile.lock" ]] || [[ -f "$REPO_PATH/setup.py" ]]; then
    DETECTED_TYPES="${DETECTED_TYPES}Python, "
fi
CONDA_ENV_COUNT=$(find "$REPO_PATH" \( -name "environment.yml" -o -name "environment.yaml" \) -not -path "*/.git/*" 2>/dev/null | wc -l | tr -d ' ')
if [[ "$CONDA_ENV_COUNT" -gt 0 ]]; then
    DETECTED_TYPES="${DETECTED_TYPES}Conda, "
fi
if [[ -f "$REPO_PATH/go.mod" ]]; then
    DETECTED_TYPES="${DETECTED_TYPES}Go, "
fi
if [[ -f "$REPO_PATH/pom.xml" ]] || [[ -f "$REPO_PATH/build.gradle" ]]; then
    DETECTED_TYPES="${DETECTED_TYPES}Java, "
fi
if [[ -f "$REPO_PATH/Cargo.toml" ]]; then
    DETECTED_TYPES="${DETECTED_TYPES}Rust, "
fi
if [[ -f "$REPO_PATH/Dockerfile" ]]; then
    DETECTED_TYPES="${DETECTED_TYPES}Docker, "
fi

# Remove trailing comma and space
DETECTED_TYPES="${DETECTED_TYPES%, }"
if [[ -n "$DETECTED_TYPES" ]]; then
    echo -e "${CYAN}📦 Detected Project Types: ${DETECTED_TYPES}${NC}"
else
    echo -e "${CYAN}📦 No specific project type detected - scanning filesystem${NC}"
fi

# Pre-process conda environment.yml files into requirements-conda-env.txt files
# so that Syft's python-package-cataloger picks up conda dependencies.
# Syft has no native environment.yml cataloger; conda-meta-cataloger only works
# on installed environments, not declaration files.
CONDA_TMP_FILES=()
while IFS= read -r -d '' envfile; do
    dir="$(dirname "$envfile")"
    tmp_req="$dir/requirements-conda-env.txt"
    # Skip if we'd overwrite an existing file
    if [[ -f "$tmp_req" ]]; then
        continue
    fi
    # Extract conda dependency lines (not sub-lists, not pip: marker, not comments)
    # Syft's python-package-cataloger ONLY catalogs packages that have an exact ==
    # version pin in requirements files. All specs are therefore normalised to ==:
    #   numpy=1.21.0  (conda exact)   → numpy==1.21.0
    #   torch>=2.6.0  (pip minimum)   → torch==2.6.0  (version extracted)
    #   alembic       (unpinned)      → alembic==0.0.0
    python3 - "$envfile" "$tmp_req" <<'PYEOF' 2>/dev/null
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
    """Convert any version spec to an exact == pin so Syft catalogs the package."""
    spec = spec.strip()
    # Strip extras like pyjwt[crypto] → pyjwt, keep for matching only
    name_part = re.split(r'[=<>!;\[]', spec)[0].strip()
    if not name_part:
        return None
    # Already has exact pin
    if '==' in spec:
        return spec
    # Has >= or > — extract first version number and make it exact
    m = re.search(r'[><=!]+\s*([\d][^\s,;]*)', spec)
    if m:
        return f"{name_part}=={m.group(1)}"
    # No version at all
    return f"{name_part}==0.0.0"

lines = []
for dep in deps:
    if isinstance(dep, str):
        # Skip python itself, pip itself, and conda-only meta-packages
        if dep.startswith("python") or dep.startswith("_") or dep.strip() == "pip":
            continue
        # conda exact pin uses single = — normalise then convert to ==
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
    if [[ -f "$tmp_req" ]]; then
        CONDA_TMP_FILES+=("$tmp_req")
        count=$(wc -l < "$tmp_req" | tr -d ' ')
        echo -e "${CYAN}📦 Pre-processed conda env: $(basename "$envfile") → $(basename "$tmp_req") ($count deps)${NC}"
        echo "Pre-processed conda env: $envfile -> $tmp_req ($count deps)" >> "$SCAN_LOG"
    fi
done < <(find "$REPO_PATH" \( -name "environment.yml" -o -name "environment.yaml" \) -not -path "*/.git/*" -print0 2>/dev/null)

if [[ ${#CONDA_TMP_FILES[@]} -gt 0 ]]; then
    DETECTED_TYPES="${DETECTED_TYPES:+${DETECTED_TYPES}, }Conda"
fi

# Pre-process pyproject.toml files into requirements-pyproject.txt files.
# Syft 1.x does not extract packages from [project.dependencies] in pyproject.toml
# when scanning a directory — only installed site-packages are catalogued.
# Extracting to requirements format ensures python-package-cataloger picks them up.
PYPROJECT_TMP_FILES=()
while IFS= read -r -d '' pyproj; do
    dir="$(dirname "$pyproj")"
    tmp_req="$dir/requirements-pyproject.txt"
    if [[ -f "$tmp_req" ]]; then
        continue
    fi
    python3 - "$pyproj" "$tmp_req" <<'PYEOF' 2>/dev/null
import sys, re

src, dst = sys.argv[1], sys.argv[2]

# Try tomllib (Python 3.11+) first, then tomli, then fall back to regex
tomllib = None
try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib
    except ImportError:
        pass

lines = []

if tomllib:
    try:
        with open(src, 'rb') as f:
            data = tomllib.load(f)
        project = data.get('project', {})
        for dep in project.get('dependencies', []):
            if isinstance(dep, str):
                lines.append(dep.strip())
        for group_deps in project.get('optional-dependencies', {}).values():
            for dep in group_deps:
                if isinstance(dep, str):
                    lines.append(dep.strip())
    except Exception:
        pass
else:
    # Regex fallback for Python < 3.11 without tomli
    with open(src, 'r', encoding='utf-8') as f:
        content = f.read()
    # Find [project] section and extract dependency strings
    # Only look inside [project] or [project.optional-dependencies.*] tables
    in_section = False
    depth = 0
    for line in content.split('\n'):
        stripped = line.strip()
        if re.match(r'^\[project(?:\.[a-z0-9_-]*)?\]', stripped, re.I):
            in_section = True
            depth = 0
            continue
        elif re.match(r'^\[', stripped):
            in_section = False
            depth = 0
            continue
        if not in_section:
            continue
        depth += stripped.count('[') - stripped.count(']')
        for m in re.finditer(r'"([^"]+)"', stripped):
            val = m.group(1).strip()
            # pip-style spec: name followed by comparator or extras bracket
            if val and re.match(r'^[a-zA-Z0-9_\-]+[^"]*$', val) and not val.startswith('#'):
                lines.append(val)

# Deduplicate preserving order, skip blank
seen = set()
result = []
for l in lines:
    if l and l not in seen:
        seen.add(l)
        result.append(l)

if result:
    with open(dst, 'w') as f:
        f.write('\n'.join(result) + '\n')
PYEOF
    if [[ -f "$tmp_req" ]]; then
        PYPROJECT_TMP_FILES+=("$tmp_req")
        count=$(wc -l < "$tmp_req" | tr -d ' ')
        echo -e "${CYAN}📦 Pre-processed pyproject.toml: $(basename "$pyproj") → $(basename "$tmp_req") ($count deps)${NC}"
        echo "Pre-processed pyproject.toml: $pyproj -> $tmp_req ($count deps)" >> "$SCAN_LOG"
    fi
done < <(find "$REPO_PATH" -name "pyproject.toml" -not -path "*/.git/*" -not -path "*/node_modules/*" -print0 2>/dev/null)

# Generate ONE comprehensive SBOM for the entire filesystem
# Syft automatically detects all package types in a single scan
generate_sbom "filesystem" "$REPO_PATH"

# Clean up all temporary requirements files
for tmp_req in "${CONDA_TMP_FILES[@]}" "${PYPROJECT_TMP_FILES[@]}"; do
    rm -f "$tmp_req"
done

# Note: We no longer generate separate language-specific SBOMs
# The filesystem SBOM captures ALL packages from ALL detected ecosystems
# This prevents duplication in the dashboard and reports

# Generate combined SBOM report
echo -e "${CYAN}📋 Generating SBOM summary report...${NC}"
SUMMARY_FILE="$OUTPUT_DIR/sbom-summary.json"

# Create summary JSON
cat > "$SUMMARY_FILE" << EOF
{
  "scan_info": {
    "scan_id": "$SCAN_ID",
    "target": "$REPO_PATH",
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "tool": "syft",
    "scan_type": "sbom_generation"
  },
  "sbom_files": [
$(find "$OUTPUT_DIR" -name "*.json" | grep -v summary | while read file; do
    type=$(basename "$file" .json)
    artifact_count=$(jq -r '.artifacts | length' "$file" 2>/dev/null || echo "0")
    echo "    {\"type\": \"$type\", \"file\": \"$(basename "$file")\", \"artifacts\": $artifact_count},"
done | sed '$ s/,$//')
  ],
  "total_artifacts": $(find "$OUTPUT_DIR" -name "*.json" | grep -v summary | xargs jq -r '.artifacts | length' 2>/dev/null | tr '\n' '+' | sed 's/+$//' | sed 's/^$/0/' | bc 2>/dev/null || echo "0"),
  "metadata": {
    "generator": "comprehensive-security-architecture",
    "version": "1.0.0"
  }
}
EOF

echo ""
echo -e "${WHITE}============================================${NC}"
echo -e "${WHITE}SBOM Generation Summary${NC}"
echo -e "${WHITE}============================================${NC}"

# Count total SBOMs generated
SBOM_COUNT=$(find "$OUTPUT_DIR" -name "*.json" | grep -v summary | wc -l)
echo -e "${GREEN}✅ Generated $SBOM_COUNT SBOM files${NC}"

echo -e "${CYAN}📁 SBOM Files Created:${NC}"
find "$OUTPUT_DIR" -name "*.json" | grep -v summary | while read file; do
    size=$(du -h "$file" | cut -f1)
    artifacts=$(jq -r '.artifacts | length' "$file" 2>/dev/null || echo "0")
    echo -e "  📄 $(basename "$file") (${size}, ${artifacts} artifacts)"
done

echo ""
finalize_scan_results "sbom"
echo "Completed: $(date)"
echo ""

exit 0