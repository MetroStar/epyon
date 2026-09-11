#!/bin/bash
set -euo pipefail

# SLSA Provenance Attestation Generator
# Generates an in-toto SLSA v1.0 provenance predicate (provenance.jsonl)

# Colors for output
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
PURPLE='\033[0;35m'
NC='\033[0m'

show_help() {
    echo "Usage: $0 [OPTIONS]"
    echo "  -s, --scan-dir PATH   Output scan directory"
    echo "  -t, --target PATH     Target directory"
    echo "  -n, --image-name NAME Image name"
    echo "  -g, --image-tag TAG   Image tag"
    exit 0
}

SCAN_DIR="${SCAN_DIR:-}"
TARGET_DIR="${TARGET_DIR:-.}"
IMAGE_NAME="${IMAGE_NAME:-}"
IMAGE_TAG="${IMAGE_TAG:-}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)
            show_help
            ;;
        -s|--scan-dir)
            SCAN_DIR="$2"
            shift 2
            ;;
        -t|--target)
            TARGET_DIR="$2"
            shift 2
            ;;
        -n|--image-name)
            IMAGE_NAME="$2"
            shift 2
            ;;
        -g|--image-tag)
            IMAGE_TAG="$2"
            shift 2
            ;;
        *)
            shift
            ;;
    esac
done

if [[ -z "$SCAN_DIR" || ! -d "$SCAN_DIR" ]]; then
    echo -e "${YELLOW}⚠️  SCAN_DIR not set or doesn't exist. Skipping SLSA provenance generation.${NC}"
    exit 0
fi

BUILD_DIR="$SCAN_DIR/build"
DIGEST_FILE="$BUILD_DIR/image-digest.txt"

IMAGE_DIGEST=""
if [[ -f "$DIGEST_FILE" ]]; then
    IMAGE_DIGEST="$(cat "$DIGEST_FILE" | tr -d '\n' | xargs)"
fi

if [[ -z "$IMAGE_DIGEST" ]]; then
    IMAGE_DIGEST="sha256:0000000000000000000000000000000000000000000000000000000000000000"
fi

# Clean digest hash without sha256: prefix for struct
DIGEST_HASH="${IMAGE_DIGEST#sha256:}"

COMMIT_SHA="unknown"
REPO_URL="local"
BRANCH="main"

if command -v git &>/dev/null && git -C "$TARGET_DIR" rev-parse HEAD &>/dev/null; then
    COMMIT_SHA="$(git -C "$TARGET_DIR" rev-parse HEAD)"
    BRANCH="$(git -C "$TARGET_DIR" rev-parse --abbrev-ref HEAD 2>/dev/null || echo "main")"
    REPO_URL="$(git -C "$TARGET_DIR" config --get remote.origin.url 2>/dev/null || echo "local")"
fi

SUBJ_NAME="${IMAGE_NAME:-epyon-built-image}:${IMAGE_TAG:-latest}"
TIMESTAMP="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
SCAN_ID="$(basename "$SCAN_DIR")"

echo -e "${PURPLE}============================================${NC}"
echo -e "${PURPLE}📜 Generating SLSA v1.0 Provenance Attestation${NC}"
echo -e "${PURPLE}============================================${NC}"

PROVENANCE_FILE="$SCAN_DIR/provenance.jsonl"
PROVENANCE_JSON="$SCAN_DIR/provenance.json"

python3 -c "
import json

statement = {
    \"_type\": \"https://in-toto.io/Statement/v0.1\",
    \"subject\": [
        {
            \"name\": \"$SUBJ_NAME\",
            \"digest\": {
                \"sha256\": \"$DIGEST_HASH\"
            }
        }
    ],
    \"predicateType\": \"https://slsa.dev/provenance/v1\",
    \"predicate\": {
        \"buildDefinition\": {
            \"buildType\": \"https://github.com/epyon-security/epyon-build-runner@v1\",
            \"externalParameters\": {
                \"repository\": \"$REPO_URL\",
                \"ref\": \"$BRANCH\"
            },
            \"internalParameters\": {
                \"commit_sha\": \"$COMMIT_SHA\"
            },
            \"resolvedDependencies\": []
        },
        \"runDetails\": {
            \"builder\": {
                \"id\": \"epyon-security-scanner\"
            },
            \"metadata\": {
                \"invocationId\": \"$SCAN_ID\",
                \"startedOn\": \"$TIMESTAMP\",
                \"finishedOn\": \"$TIMESTAMP\"
            }
        }
    }
}

with open('$PROVENANCE_JSON', 'w') as f:
    json.dump(statement, f, indent=2)

with open('$PROVENANCE_FILE', 'w') as f:
    f.write(json.dumps(statement) + '\n')
"

echo -e "${GREEN}✅ Wrote SLSA Provenance: $PROVENANCE_FILE${NC}"
