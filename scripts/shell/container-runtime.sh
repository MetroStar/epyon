#!/usr/bin/env bash
# Container runtime detection utility
# Exports: CONTAINER_CLI (docker|podman|nerdctl|""), CONTAINER_IS_PODMAN (true|false)
# Note: Do not use 'set -e' here as this file is meant to be sourced

# Prefer Docker CLI, fall back to podman, then nerdctl
if command -v docker &>/dev/null; then
    CONTAINER_CLI=docker
elif command -v podman &>/dev/null; then
    CONTAINER_CLI=podman
elif command -v nerdctl &>/dev/null; then
    CONTAINER_CLI=nerdctl
else
    CONTAINER_CLI=""
fi

export CONTAINER_CLI

CONTAINER_IS_PODMAN=false
if [ "$CONTAINER_CLI" = "podman" ]; then
    CONTAINER_IS_PODMAN=true
fi
export CONTAINER_IS_PODMAN

# Check if the selected runtime is responsive
container_info() {
    if [ -z "$CONTAINER_CLI" ]; then
        return 1
    fi
    # Some CLIs support `info`, others may require different flags, but try generic info
    if $CONTAINER_CLI info &>/dev/null; then
        return 0
    fi
    return 1
}
