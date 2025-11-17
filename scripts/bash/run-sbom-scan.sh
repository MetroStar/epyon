#!/bin/bash

# SBOM (Software Bill of Materials) Generation Script
# Generates comprehensive software inventory using Syft from Anchore

# Support target directory scanning - priority: command line arg, TARGET_DIR env var, current directory
REPO_PATH="${1:-${TARGET_DIR:-$(pwd)}}"
# Set REPO_ROOT for report generation
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
TARGET_NAME=$(basename "$REPO_PATH")
USERNAME=$(whoami)
TIMESTAMP=$(date '+%Y-%m-%d_%H-%M-%S')
SCAN_ID="${TARGET_NAME}_${USERNAME}_${TIMESTAMP}"
OUTPUT_DIR="$REPO_ROOT/reports/sbom-reports"
SCAN_LOG="$OUTPUT_DIR/${SCAN_ID}_sbom-scan.log"

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

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Initialize scan log
echo "SBOM generation started: $TIMESTAMP" > "$SCAN_LOG"
echo "Target: $REPO_PATH" >> "$SCAN_LOG"
echo "Syft version check:" >> "$SCAN_LOG"

# Function to generate SBOM for a target
generate_sbom() {
    local scan_type="$1"
    local target="$2"
    local output_file="$OUTPUT_DIR/${SCAN_ID}_sbom-${scan_type}.json"
    local current_sbom="$OUTPUT_DIR/sbom-${scan_type}.json"
    
    echo -e "${CYAN}🔍 Generating SBOM for ${scan_type}: ${target}${NC}"
    echo "Generating SBOM for ${scan_type}: ${target}" >> "$SCAN_LOG"
    
    if command -v syft >/dev/null 2>&1; then
        # Use local Syft installation
        echo -e "${GREEN}✅ Using local Syft installation${NC}"
        syft version >> "$SCAN_LOG" 2>&1
        
        if syft "$target" -o json > "$output_file" 2>>"$SCAN_LOG"; then
            echo -e "${GREEN}✅ SBOM generated successfully: $(basename "$output_file")${NC}"
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
        
        if docker run --rm -v "$REPO_PATH":/workspace \
            anchore/syft:latest \
            /workspace -o json > "$output_file" 2>>"$SCAN_LOG"; then
            echo -e "${GREEN}✅ SBOM generated successfully: $(basename "$output_file")${NC}"
            echo "SBOM generated successfully: $output_file" >> "$SCAN_LOG"
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
    
    # Create symlink to current SBOM
    cd "$OUTPUT_DIR"
    ln -sf "$(basename "$output_file")" "$current_sbom"
    
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

# Filesystem SBOM (always generated)
generate_sbom "filesystem" "$REPO_PATH"

# Language-specific SBOMs
if [[ -f "$REPO_PATH/package.json" ]]; then
    echo -e "${PURPLE}📦 Node.js project detected${NC}"
    generate_sbom "nodejs" "$REPO_PATH"
fi

if [[ -f "$REPO_PATH/requirements.txt" ]] || [[ -f "$REPO_PATH/pyproject.toml" ]] || [[ -f "$REPO_PATH/setup.py" ]]; then
    echo -e "${PURPLE}🐍 Python project detected${NC}"
    generate_sbom "python" "$REPO_PATH"
fi

if [[ -f "$REPO_PATH/go.mod" ]]; then
    echo -e "${PURPLE}🐹 Go project detected${NC}"
    generate_sbom "golang" "$REPO_PATH"
fi

if [[ -f "$REPO_PATH/pom.xml" ]] || [[ -f "$REPO_PATH/build.gradle" ]]; then
    echo -e "${PURPLE}☕ Java project detected${NC}"
    generate_sbom "java" "$REPO_PATH"
fi

if [[ -f "$REPO_PATH/Cargo.toml" ]]; then
    echo -e "${PURPLE}🦀 Rust project detected${NC}"
    generate_sbom "rust" "$REPO_PATH"
fi

# Container image SBOMs (if Dockerfile exists)
if [[ -f "$REPO_PATH/Dockerfile" ]]; then
    echo -e "${PURPLE}🐳 Docker project detected${NC}"
    # Note: This would need the image to be built first
    echo -e "${YELLOW}ℹ️  Container image SBOM generation requires built images${NC}"
    echo "Container image SBOM generation requires built images" >> "$SCAN_LOG"
fi

# Generate combined SBOM report
echo -e "${CYAN}📋 Generating SBOM summary report...${NC}"
SUMMARY_FILE="$OUTPUT_DIR/${SCAN_ID}_sbom-summary.json"

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
$(find "$OUTPUT_DIR" -name "${SCAN_ID}_sbom-*.json" | grep -v summary | while read file; do
    type=$(basename "$file" | sed "s/${SCAN_ID}_sbom-//; s/.json//")
    artifact_count=$(jq -r '.artifacts | length' "$file" 2>/dev/null || echo "0")
    echo "    {\"type\": \"$type\", \"file\": \"$(basename "$file")\", \"artifacts\": $artifact_count},"
done | sed '$ s/,$//')
  ],
  "total_artifacts": $(find "$OUTPUT_DIR" -name "${SCAN_ID}_sbom-*.json" | grep -v summary | xargs jq -r '.artifacts | length' 2>/dev/null | tr '\n' '+' | sed 's/+$//' | bc 2>/dev/null || echo "0"),
  "metadata": {
    "generator": "comprehensive-security-architecture",
    "version": "1.0.0"
  }
}
EOF

# Create symlinks for latest results
cd "$OUTPUT_DIR"
ln -sf "${SCAN_ID}_sbom-summary.json" "sbom-summary.json"
ln -sf "${SCAN_ID}_sbom-scan.log" "sbom-scan.log"

echo ""
echo -e "${WHITE}============================================${NC}"
echo -e "${WHITE}SBOM Generation Summary${NC}"
echo -e "${WHITE}============================================${NC}"

# Count total SBOMs generated
SBOM_COUNT=$(find "$OUTPUT_DIR" -name "${SCAN_ID}_sbom-*.json" | grep -v summary | wc -l)
echo -e "${GREEN}✅ Generated $SBOM_COUNT SBOM files${NC}"

echo -e "${CYAN}📁 SBOM Files Created:${NC}"
find "$OUTPUT_DIR" -name "${SCAN_ID}_sbom-*.json" | while read file; do
    size=$(du -h "$file" | cut -f1)
    artifacts=$(jq -r '.artifacts | length' "$file" 2>/dev/null || echo "0")
    echo -e "  📄 $(basename "$file") (${size}, ${artifacts} artifacts)"
done

echo ""
echo -e "${CYAN}📊 Reports Directory: ${OUTPUT_DIR}${NC}"
echo -e "${CYAN}🔗 Latest Results: sbom-summary.json, sbom-scan.log${NC}"
echo "Completed: $(date)"
echo ""

exit 0