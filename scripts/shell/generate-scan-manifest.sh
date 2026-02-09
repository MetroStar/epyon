#!/bin/bash

# Generate Scan Manifest for Integrity Verification
# Creates a cryptographic manifest with file hashes and scan metadata

# Don't exit on error - we want to continue even if some files fail
set -uo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"

# Detect hash command (cross-platform support)
if command -v sha256sum &> /dev/null; then
    HASH_CMD="sha256sum"
elif command -v shasum &> /dev/null; then
    HASH_CMD="shasum -a 256"
else
    echo -e "${RED}❌ Error: No SHA-256 command available (sha256sum or shasum)${NC}"
    exit 1
fi

# Usage
show_usage() {
    echo "Usage: $0 <scan_directory> [target_directory]"
    echo ""
    echo "Arguments:"
    echo "  scan_directory    Absolute path to scan output directory"
    echo "  target_directory  Optional: Absolute path to scanned target directory"
    echo ""
    echo "Example:"
    echo "  $0 /path/to/scans/app_user_2026-02-06 /path/to/target"
    exit 1
}

# Validate arguments
if [[ $# -lt 1 ]]; then
    show_usage
fi

SCAN_DIR="$1"
TARGET_DIR="${2:-}"

if [[ ! -d "$SCAN_DIR" ]]; then
    echo -e "${RED}❌ Error: Scan directory does not exist: $SCAN_DIR${NC}"
    exit 1
fi

echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}  Generating Scan Manifest${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Extract scan ID from directory name
SCAN_ID=$(basename "$SCAN_DIR")
MANIFEST_FILE="$SCAN_DIR/scan-manifest.json"

# Get Epyon version (from git or default)
EPYON_VERSION="2.5.0"
if [[ -d "$REPO_ROOT/.git" ]]; then
    EPYON_VERSION=$(cd "$REPO_ROOT" && git describe --tags --always 2>/dev/null || echo "2.5.0")
fi

# Collect scan metadata
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
USERNAME="${GITHUB_ACTOR:-$(whoami)}"
HOSTNAME=$(hostname)

echo -e "${BLUE}📋 Collecting scan metadata...${NC}"
echo "   Scan ID: $SCAN_ID"
echo "   User: $USERNAME"
echo "   Host: $HOSTNAME"
echo "   Epyon Version: $EPYON_VERSION"
echo ""

# Get target repository information
REPO_URL=""
COMMIT_SHA=""
BRANCH=""
SUBDIR=""

if [[ -n "$TARGET_DIR" ]] && [[ -d "$TARGET_DIR/.git" ]]; then
    echo -e "${BLUE}📦 Extracting target repository information...${NC}"
    cd "$TARGET_DIR"
    REPO_URL=$(git config --get remote.origin.url 2>/dev/null || echo "")
    COMMIT_SHA=$(git rev-parse HEAD 2>/dev/null || echo "")
    BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "")
    cd - > /dev/null
    echo "   Repository: ${REPO_URL:-N/A}"
    echo "   Commit: ${COMMIT_SHA:-N/A}"
    echo "   Branch: ${BRANCH:-N/A}"
    echo ""
fi

# Check if subdirectory was scanned (from scan metadata if available)
if [[ -f "$SCAN_DIR/scan-metadata.json" ]]; then
    SUBDIR=$(jq -r '.target.subdirectory // ""' "$SCAN_DIR/scan-metadata.json" 2>/dev/null || echo "")
fi

# Collect tool versions
echo -e "${BLUE}🔧 Detecting tool versions...${NC}"

TOOL_VERSIONS_JSON="{"

# Try to get versions from scan results or Docker (simplified, no Perl regex)
if command -v docker &> /dev/null; then
    TRIVY_VER=$(docker run --rm aquasec/trivy:latest --version 2>/dev/null | grep "Version:" | head -1 | awk '{print $2}' || echo "unknown")
    GRYPE_VER=$(docker run --rm anchore/grype:latest version 2>/dev/null | grep "Version:" | head -1 | awk '{print $2}' || echo "unknown")
    SYFT_VER=$(docker run --rm anchore/syft:latest version 2>/dev/null | grep "Version:" | head -1 | awk '{print $2}' || echo "unknown")
    TRUFFLEHOG_VER=$(docker run --rm trufflesecurity/trufflehog:latest --version 2>/dev/null | head -1 | awk '{print $2}' || echo "unknown")
    CHECKOV_VER=$(docker run --rm bridgecrew/checkov:latest --version 2>/dev/null | head -1 | tr -d '\n\r' || echo "unknown")
    
    echo "   trivy: $TRIVY_VER"
    echo "   grype: $GRYPE_VER"
    echo "   syft: $SYFT_VER"
    echo "   trufflehog: $TRUFFLEHOG_VER"
    echo "   checkov: $CHECKOV_VER"
    
    TOOL_VERSIONS_JSON+='"trivy":"'$TRIVY_VER'","grype":"'$GRYPE_VER'","syft":"'$SYFT_VER'","trufflehog":"'$TRUFFLEHOG_VER'","checkov":"'$CHECKOV_VER'"'
fi

TOOL_VERSIONS_JSON+="}"
echo ""

# Generate file hashes
echo -e "${BLUE}🔐 Generating file hashes (SHA-256)...${NC}"
echo -e "${BLUE}   Scanning directory: $SCAN_DIR${NC}"
FILE_HASHES_JSON="{"
FILE_COUNT=0
SKIP_COUNT=0

# Find all JSON, HTML, CSV, and Markdown report files
while IFS= read -r -d '' file; do
    if [[ -f "$file" ]]; then
        relative_path="${file#$SCAN_DIR/}"
        
        # Skip the manifest files themselves to avoid circular reference
        if [[ "$relative_path" == "scan-manifest.json" ]] || [[ "$relative_path" == "manifest-summary.txt" ]]; then
            continue
        fi
        
        # Generate hash with error handling
        if ! hash=$($HASH_CMD "$file" 2>/dev/null | awk '{print $1}'); then
            echo "   ⚠️  Failed to hash: $relative_path (skipping)"
            ((SKIP_COUNT++))
            continue
        fi
        
        # Skip if hash is empty
        if [[ -z "$hash" ]]; then
            echo "   ⚠️  Empty hash for: $relative_path (skipping)"
            ((SKIP_COUNT++))
            continue
        fi
        
        # Add comma if not first entry
        if [[ $FILE_COUNT -gt 0 ]]; then
            FILE_HASHES_JSON+=","
        fi
        
        # Escape path for JSON
        escaped_path=$(echo "$relative_path" | sed 's/\\/\\\\/g' | sed 's/"/\\"/g')
        FILE_HASHES_JSON+='"'$escaped_path'":"sha256:'$hash'"'
        
        echo "   ✓ $relative_path"
        ((FILE_COUNT++))
    fi
done < <(find "$SCAN_DIR" -type f \( -name "*.json" -o -name "*.html" -o -name "*.csv" -o -name "*.md" -o -name "*.log" \) -print0 2>/dev/null)

FILE_HASHES_JSON+="}"

echo ""
if [[ $SKIP_COUNT -gt 0 ]]; then
    echo -e "${YELLOW}⚠️  Skipped $SKIP_COUNT files due to errors${NC}"
fi
echo -e "${BLUE}📊 Found $FILE_COUNT files to include in manifest${NC}"
echo ""

# Build JSON manifest using jq for proper JSON formatting
echo -e "${BLUE}📝 Building manifest...${NC}"

# Create temp JSON files
echo "$TOOL_VERSIONS_JSON" > /tmp/epyon-tools.json
echo "$FILE_HASHES_JSON" > /tmp/epyon-hashes.json

# Build complete manifest using jq to ensure proper JSON escaping
# First validate the temp JSON files
if ! jq empty /tmp/epyon-tools.json 2>/dev/null; then
    echo -e "${RED}❌ Invalid JSON in tools data${NC}"
    cat /tmp/epyon-tools.json
    exit 1
fi

if ! jq empty /tmp/epyon-hashes.json 2>/dev/null; then
    echo -e "${RED}❌ Invalid JSON in file hashes${NC}"
    cat /tmp/epyon-hashes.json
    exit 1
fi

# Build the manifest
jq -n \
  --arg ver "1.0" \
  --arg timestamp "$TIMESTAMP" \
  --arg scan_id "$SCAN_ID" \
  --arg username "$USERNAME" \
  --arg hostname "$HOSTNAME" \
  --arg epyon_ver "$EPYON_VERSION" \
  --arg repo "${REPO_URL:-}" \
  --arg commit "${COMMIT_SHA:-}" \
  --arg branch "${BRANCH:-}" \
  --arg subdir "${SUBDIR:-}" \
  --slurpfile tools /tmp/epyon-tools.json \
  --slurpfile hashes /tmp/epyon-hashes.json \
  '{
    manifest_version: $ver,
    generated_at: $timestamp,
    scan_metadata: {
      scan_id: $scan_id,
      timestamp: $timestamp,
      username: $username,
      hostname: $hostname,
      epyon_version: $epyon_ver
    },
    target: {
      repository: (if $repo == "" then null else $repo end),
      commit_sha: (if $commit == "" then null else $commit end),
      branch: (if $branch == "" then null else $branch end),
      subdirectory: (if $subdir == "" then null else $subdir end)
    },
    tools: $tools[0],
    file_hashes: $hashes[0]
  }' > "$MANIFEST_FILE"

# Calculate manifest hash itself using canonical JSON (no extra whitespace)
# Use compact output to ensure consistent formatting across platforms
MANIFEST_HASH=$(jq -c '.' "$MANIFEST_FILE" | $HASH_CMD | awk '{print $1}')

# Update manifest with its own hash (use -S for sorted keys and compact output)
jq -S --arg hash "sha256:$MANIFEST_HASH" '. + {manifest_hash: $hash}' "$MANIFEST_FILE" > "$MANIFEST_FILE.tmp"
mv "$MANIFEST_FILE.tmp" "$MANIFEST_FILE"

echo -e "${GREEN}✅ Manifest generated successfully${NC}"
echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}  Manifest Summary${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "📄 Manifest File: $MANIFEST_FILE"
echo "📋 Files Tracked: $FILE_COUNT"
echo "🔐 Manifest Hash: sha256:$MANIFEST_HASH"
echo ""
echo "🔍 Verification:"
echo "   Run: ./scripts/shell/verify-scan-manifest.sh $SCAN_DIR"
echo ""

# Cleanup temp files
rm -f /tmp/epyon-tools.json /tmp/epyon-hashes.json

# Create a human-readable summary
SUMMARY_FILE="$SCAN_DIR/manifest-summary.txt"
cat > "$SUMMARY_FILE" <<EOF
EPYON SCAN MANIFEST SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Generated: $TIMESTAMP
Manifest Hash: sha256:$MANIFEST_HASH

SCAN INFORMATION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Scan ID:        $SCAN_ID
Username:       $USERNAME
Hostname:       $HOSTNAME
Epyon Version:  $EPYON_VERSION

TARGET INFORMATION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Repository:     ${REPO_URL:-N/A}
Commit SHA:     ${COMMIT_SHA:-N/A}
Branch:         ${BRANCH:-N/A}
Subdirectory:   ${SUBDIR:-N/A}

INTEGRITY VERIFICATION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
This manifest contains SHA-256 hashes of all scan report files.
To verify integrity, run:

  ./scripts/shell/verify-scan-manifest.sh $SCAN_DIR

TRACKED FILES: $FILE_COUNT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
EOF

# List files by reading from manifest JSON
if command -v jq &> /dev/null; then
    jq -r '.file_hashes | keys[]' "$MANIFEST_FILE" | sort | while read -r file; do
        echo "  ✓ $file" >> "$SUMMARY_FILE"
    done
fi

cat >> "$SUMMARY_FILE" <<EOF

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

For full manifest details, see: scan-manifest.json
EOF

echo -e "${GREEN}📋 Human-readable summary: $SUMMARY_FILE${NC}"
echo ""
