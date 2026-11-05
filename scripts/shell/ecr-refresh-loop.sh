#!/bin/bash
# Keeps the container's Docker login to private Amazon ECR registries fresh.
# ECR tokens expire after 12 hours, so this logs in at startup and then every
# ECR_REFRESH_HOURS (default 6). Idle unless ECR_REGISTRY is set. Never fails.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=ecr-login.sh
source "$SCRIPT_DIR/ecr-login.sh"

[[ -z "${ECR_REGISTRY:-}" ]] && exit 0

interval=$(( ${ECR_REFRESH_HOURS:-6} * 3600 ))
while true; do
    epyon_ecr_login || true
    sleep "$interval"
done
