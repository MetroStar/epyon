#!/bin/bash
set -euo pipefail

# Cosign Image Signature Generator
# Cryptographically signs container image or creates signature metadata record

# Colors for output
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
PURPLE='\033[0;35m'
NC='\033[0m'

show_help() {
    echo "Usage: $0 [OPTIONS]"
    echo "  -s, --scan-dir PATH   Output scan directory"
    echo "  -n, --image-name NAME Image name"
    echo "  -g, --image-tag TAG   Image tag"
    echo "  -k, --key PATH        Cosign private key path or env var"
    exit 0
}

SCAN_DIR="${SCAN_DIR:-}"
IMAGE_NAME="${IMAGE_NAME:-}"
IMAGE_TAG="${IMAGE_TAG:-}"
COSIGN_KEY="${COSIGN_KEY:-}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)
            show_help
            ;;
        -s|--scan-dir)
            SCAN_DIR="$2"
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
        -k|--key)
            COSIGN_KEY="$2"
            shift 2
            ;;
        *)
            shift
            ;;
    esac
done

if [[ -z "$SCAN_DIR" || ! -d "$SCAN_DIR" ]]; then
    echo -e "${YELLOW}⚠️  SCAN_DIR not set or doesn't exist. Skipping image signing.${NC}"
    exit 0
fi

SIG_FILE="$SCAN_DIR/image.sig"
TIMESTAMP="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
BUILD_DIR="$SCAN_DIR/build"
DIGEST_FILE="$BUILD_DIR/image-digest.txt"

IMAGE_DIGEST=""
if [[ -f "$DIGEST_FILE" ]]; then
    IMAGE_DIGEST="$(cat "$DIGEST_FILE" | tr -d '\n' | xargs)"
fi

echo -e "${PURPLE}============================================${NC}"
echo -e "${PURPLE}🔏 Cryptographic Image Signature Processing${NC}"
echo -e "${PURPLE}============================================${NC}"

HAS_COSIGN=false
if command -v cosign &>/dev/null; then
    HAS_COSIGN=true
fi

# Check if Cosign is configured
if [[ "$HAS_COSIGN" == "true" && -n "$COSIGN_KEY" && -n "$IMAGE_DIGEST" ]]; then
    echo -e "${CYAN}Signing image digest $IMAGE_DIGEST with Cosign...${NC}"
    if cosign sign-blob --key "$COSIGN_KEY" "$DIGEST_FILE" --output-signature "$SCAN_DIR/digest.sig" 2>/dev/null; then
        cat << EOF > "$SIG_FILE"
{
  "status": "signed",
  "tool": "cosign",
  "digest": "$IMAGE_DIGEST",
  "signature_file": "digest.sig",
  "timestamp": "$TIMESTAMP"
}
EOF
        echo -e "${GREEN}✅ Cryptographic signature created: $SCAN_DIR/digest.sig${NC}"
        exit 0
    fi
fi

# Fallback signature metadata record if key/tool not present
cat << EOF > "$SIG_FILE"
{
  "status": "unsigned",
  "reason": "Cosign key or tool not configured",
  "tool": "cosign",
  "digest": "${IMAGE_DIGEST:-none}",
  "timestamp": "$TIMESTAMP"
}
EOF

echo -e "${YELLOW}ℹ️  Image signature record created ($SIG_FILE) — status: unsigned${NC}"
