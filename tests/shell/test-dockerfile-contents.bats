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
    grep -q "pip install --no-cache-dir pip-audit" "$DOCKERFILE"
}

@test "Dockerfile still installs web/api/requirements.txt" {
    grep -q "pip install --no-cache-dir -r /app/web/api/requirements.txt" "$DOCKERFILE"
}
