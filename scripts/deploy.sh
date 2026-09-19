#!/usr/bin/env bash
# Epyon Web UI Deployment Script
# Deploys the Epyon dashboard/API to a local Docker engine or a remote host
# over SSH. Modeled after MetroStar/SRTM-MS's scripts/deploy.sh.
# Usage: ./scripts/deploy.sh

set -euo pipefail

echo "🚀 Epyon Web UI Deployment"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# ── Project root ───────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_ROOT"
echo "📁 Project root: $PROJECT_ROOT"

APP_NAME="epyon-web"
PORT="8057"

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 1 — GATHER ALL OPTIONS UPFRONT
# ══════════════════════════════════════════════════════════════════════════════
echo ""
echo "── Deployment options ──────────────────────────────"

# 1. Deploy mode
read -r -p "Deployment mode ('ssh' or 'local') [local]: " deployMode
deployMode="${deployMode:-local}"

# ── Resolve env source (never .env itself, to avoid clobbering secrets) ───────
envSource=""
for f in ".env.production" ".env.local" ".env"; do
  if [[ -f "$f" ]]; then envSource="$f"; break; fi
done

if [[ "$deployMode" == "local" ]]; then
  echo ""
  echo "⚙️  Local deployment — running docker compose up -d --build..."

  if [[ -n "$envSource" && "$envSource" != ".env" ]]; then
    echo "📋 Copying $envSource to .env for Docker Compose..."
    cp "$envSource" .env
  elif [[ -z "$envSource" ]]; then
    echo "⚠️  No .env file found — container may fail to start due to missing secrets."
    echo "    Copy .env.local.example to .env.local and set required values."
  fi

  docker compose down 2>/dev/null || true
  docker compose up -d --build

  echo "✅ Local deployment complete — http://localhost:$PORT"
  exit 0
fi

if [[ "$deployMode" != "ssh" ]]; then
  echo "❌ Unknown deployment mode: $deployMode"
  exit 1
fi

# ── SSH mode ──────────────────────────────────────────────────────────────────

# 2. Server connection
read -r -p "SSH server IP or hostname: " SERVER_IP
read -r -p "SSH username: " SERVER_USER

# 3. SSH key
KEY_PATH="$HOME/.ssh/id_rsa"
generateKey=false
copyKey=false
if [[ ! -f "$KEY_PATH" ]]; then
  read -r -p "No SSH key found at $KEY_PATH — generate one now? (y/N): " ans
  if [[ "$ans" == "y" || "$ans" == "Y" ]]; then generateKey=true; copyKey=true; fi
else
  read -r -p "Copy SSH public key to ${SERVER_USER}@${SERVER_IP}? (Y/n): " ans
  ans="${ans:-y}"
  if [[ "$ans" == "y" || "$ans" == "Y" ]]; then copyKey=true; fi
fi

# ── Plan summary + confirmation ────────────────────────────────────────────────
echo ""
echo "── Plan ────────────────────────────────────────────"
echo "  Target    : ${SERVER_USER}@${SERVER_IP}:${PORT}"
if $generateKey; then
  echo "  SSH key   : generate + copy"
elif $copyKey; then
  echo "  SSH key   : copy existing"
else
  echo "  SSH key   : skip"
fi
if [[ -n "$envSource" ]]; then
  echo "  Env file  : $envSource"
else
  echo "  Env file  : none found"
fi
echo ""
read -r -p "Proceed? (Y/n): " confirm
if [[ "$confirm" == "n" || "$confirm" == "N" ]]; then echo "Aborted."; exit 0; fi

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 2 — EXECUTION  (no more interactive prompts below this line)
# ══════════════════════════════════════════════════════════════════════════════
echo ""
echo "── Executing ───────────────────────────────────────"

SSH_OPTS=(-o StrictHostKeyChecking=accept-new -o BatchMode=no)
if [[ -f "$KEY_PATH" ]]; then SSH_OPTS+=(-i "$KEY_PATH"); fi

REMOTE_PATH="/home/$SERVER_USER/$APP_NAME"

# ── SSH key setup ──────────────────────────────────────────────────────────────
if $generateKey; then
  echo "🔑 Generating SSH key pair..."
  ssh-keygen -t rsa -b 4096 -f "$KEY_PATH" -N ""
fi

if $copyKey && [[ -f "${KEY_PATH}.pub" ]]; then
  echo "🔑 Copying public key to server (one password prompt)..."
  pubKey="$(cat "${KEY_PATH}.pub")"
  if ssh -o StrictHostKeyChecking=accept-new "${SERVER_USER}@${SERVER_IP}" \
      "mkdir -p ~/.ssh && chmod 700 ~/.ssh && echo '${pubKey}' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"; then
    echo "✅ Key installed."
  else
    echo "⚠️  Key copy failed — continuing with password auth."
  fi
fi

# ── Verify SSH connection ──────────────────────────────────────────────────────
echo "🔗 Verifying SSH connection..."
if ! ssh "${SSH_OPTS[@]}" "${SERVER_USER}@${SERVER_IP}" "echo 'Connection established'"; then
  echo "❌ Could not connect to ${SERVER_USER}@${SERVER_IP}"
  exit 1
fi

cleanup() { rm -f "$PROJECT_ROOT/${APP_NAME}.tar"; }
trap cleanup EXIT

# ── Docker build + save ────────────────────────────────────────────────────────
echo "📦 Building Docker image for AMD64 (x86_64) server..."
docker build --no-cache --platform linux/amd64 -f Dockerfile -t "${APP_NAME}:latest" .

echo "💾 Saving Docker image..."
docker save "${APP_NAME}:latest" -o "${APP_NAME}.tar"

# ── Copy files to server ──────────────────────────────────────────────────────
echo "📤 Copying files to ${SERVER_IP}..."
ssh "${SSH_OPTS[@]}" "${SERVER_USER}@${SERVER_IP}" "mkdir -p '${REMOTE_PATH}/scans' '${REMOTE_PATH}/configuration' '${REMOTE_PATH}/web/data'"
scp "${SSH_OPTS[@]}" "${APP_NAME}.tar"    "${SERVER_USER}@${SERVER_IP}:/tmp/"
scp "${SSH_OPTS[@]}" "docker-compose.yml" "${SERVER_USER}@${SERVER_IP}:/tmp/"

if [[ -f ".epyon-ignore.yml" ]]; then
  scp "${SSH_OPTS[@]}" ".epyon-ignore.yml" "${SERVER_USER}@${SERVER_IP}:/tmp/.epyon-ignore.yml"
fi

if [[ -n "$envSource" ]]; then
  echo "📋 Copying $envSource as .env..."
  scp "${SSH_OPTS[@]}" "$envSource" "${SERVER_USER}@${SERVER_IP}:/tmp/.env"
else
  echo "⚠️  No env file found — secrets (Jira, GitHub, OpenAI) may be missing on server."
fi

# ── Swap to new image — minimal downtime ─────────────────────────────────────
echo "🚀 Swapping to new image on server..."
ssh "${SSH_OPTS[@]}" "${SERVER_USER}@${SERVER_IP}" bash -s <<SWAP
set -e
mkdir -p "${REMOTE_PATH}"
cd "${REMOTE_PATH}"
cp /tmp/docker-compose.yml .
[ -f /tmp/.epyon-ignore.yml ] && cp /tmp/.epyon-ignore.yml . && rm -f /tmp/.epyon-ignore.yml
[ -f /tmp/.env ] && cp /tmp/.env . && rm -f /tmp/.env
touch .epyon-ignore.yml 2>/dev/null || true
docker load < /tmp/${APP_NAME}.tar
rm -f /tmp/${APP_NAME}.tar /tmp/docker-compose.yml
docker compose down 2>/dev/null || true
docker compose up -d --remove-orphans
echo "✅ Epyon Web UI updated!"
docker ps | grep ${APP_NAME}
SWAP

echo ""
echo "✅ Deployment complete — app is live!"
echo "🌐 http://${SERVER_IP}:${PORT}"
