#!/usr/bin/env bats
# Regression test: the deployed web app image (Dockerfile) must install
# pip-audit. scripts/shell/run-pip-audit-scan.sh (Layer 8.5 — Direct
# Dependency Scanning) shells out to the `pip-audit` binary directly, unlike
# every other scan layer which runs as its own Docker container — so if this
# image doesn't install it, any scan or self-assessment run triggered from
# the web UI silently reports zero findings for Layer 8.5 instead of a clear
# error.

setup() {
    REPO_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
    DOCKERFILE="$REPO_ROOT/Dockerfile"
}

@test "Dockerfile installs pip-audit for Layer 8.5" {
    grep -q 'pip install --no-cache-dir -r /app/web/api/requirements.txt pip-audit semgrep awscli' "$DOCKERFILE"
    grep -q 'python3 -m pip check' "$DOCKERFILE"
}

@test "Dockerfile still installs web/api/requirements.txt" {
    grep -q "pip install --no-cache-dir -r /app/web/api/requirements.txt" "$DOCKERFILE"
}

@test "Dockerfile uses patched Wolfi packages and npm without Debian's dependency tree" {
    grep -q '^FROM cgr.dev/chainguard/wolfi-base:latest$' "$DOCKERFILE"
    grep -q 'python-3.12 py3.12-pip nodejs-24 docker-cli' "$DOCKERFILE"
    grep -q 'python3 -m venv --system-site-packages --without-pip /opt/venv' "$DOCKERFILE"
    grep -q 'npm/bin/npm-cli.js /usr/local/bin/npm' "$DOCKERFILE"
    grep -q 'npm/bin/npx-cli.js /usr/local/bin/npx' "$DOCKERFILE"
    grep -q '^ARG NPM_VERSION=12.2.2$' "$DOCKERFILE"
    grep -q 'npm-${NPM_VERSION}.tgz' "$DOCKERFILE"
    grep -q 'node --version && npm --version && npx --version' "$DOCKERFILE"
    ! grep -Eq '^[[:space:]]+(nodejs|npm)[[:space:]]*\\?$' "$DOCKERFILE"
}

@test "Dockerfile rebuilds CLIs with patched Go dependencies and no daemon module" {
    grep -q '^FROM golang:1.27.3-alpine AS cli-builder$' "$DOCKERFILE"
    grep -q 'go get golang.org/x/net@v0.62.0 github.com/moby/go-archive@v0.3.0' "$DOCKERFILE"
    grep -q 'go mod edit -droprequire=github.com/docker/docker' "$DOCKERFILE"
    grep -q 'go test -p 2 ./store ./internal/namesgenerator' "$DOCKERFILE"
    grep -q 'COPY --from=cli-builder /src/buildx/internal/namesgenerator/LICENSE' "$DOCKERFILE"
    grep -q 'docker --version && docker buildx version && helm version --short' "$DOCKERFILE"
}
