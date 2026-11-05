#!/bin/bash
# Best-effort login to private Amazon ECR registries so local scans can pull
# base images the same way the CI workflow does. Never fails the scan.
#
# Registries come from ECR_REGISTRY (comma/space separated) and from any ECR
# host referenced in the files passed as arguments (e.g. a Dockerfile).
# Credentials: ECR_SCAN_AWS_ACCESS_KEY_ID / ECR_SCAN_AWS_SECRET_ACCESS_KEY (same
# names as the CI repo secrets) when set, otherwise the AWS CLI's own credential
# chain. SKIP_ECR_LOGIN=true disables it.
#
# Usage: source this file, then call: epyon_ecr_login <file> [<file>...]

_epyon_aws_ecr_password() {
    if [[ -n "${ECR_SCAN_AWS_ACCESS_KEY_ID:-}" && -n "${ECR_SCAN_AWS_SECRET_ACCESS_KEY:-}" ]]; then
        AWS_ACCESS_KEY_ID="$ECR_SCAN_AWS_ACCESS_KEY_ID" \
        AWS_SECRET_ACCESS_KEY="$ECR_SCAN_AWS_SECRET_ACCESS_KEY" \
        AWS_SESSION_TOKEN="" AWS_PROFILE="" \
            aws ecr get-login-password --region "$1"
    else
        aws ecr get-login-password --region "$1"
    fi
}

epyon_ecr_login() {
    [[ "${SKIP_ECR_LOGIN:-false}" == "true" ]] && return 0

    local pattern='[0-9]{12}\.dkr\.ecr(-fips)?\.[a-z0-9-]+\.amazonaws\.com(\.cn)?'
    local registries="" f host
    for host in $(echo "${ECR_REGISTRY:-}" | tr ',' ' '); do
        registries+="$host"$'\n'
    done
    for f in "$@"; do
        [[ -f "$f" ]] || continue
        registries+="$(grep -Eo "$pattern" "$f" 2>/dev/null || true)"$'\n'
    done
    registries="$(printf '%s' "$registries" | sed '/^$/d' | sort -u)"
    [[ -z "$registries" ]] && return 0

    if ! command -v aws &>/dev/null; then
        echo "⚠️  ECR registry referenced but the AWS CLI is not installed; skipping ECR login (pulls may return 401)."
        return 0
    fi

    local region
    while IFS= read -r host; do
        [[ -z "$host" ]] && continue
        region="${ECR_REGION:-$(echo "$host" | sed -E 's/^[0-9]+\.dkr\.ecr(-fips)?\.([a-z0-9-]+)\.amazonaws\.com.*/\2/')}"
        if _epyon_aws_ecr_password "$region" 2>/dev/null \
            | "${RUNTIME:-docker}" login --username AWS --password-stdin "$host" >/dev/null 2>&1; then
            echo "✅ Logged in to ECR: $host"
        else
            echo "⚠️  ECR login to $host failed (check 'aws sts get-caller-identity' / AWS_PROFILE); pulls may return 401."
        fi
    done <<< "$registries"
    return 0
}
