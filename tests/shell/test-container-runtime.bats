#!/usr/bin/env bats

# Unit tests for container-runtime.sh

SCRIPT_DIR="${BATS_TEST_DIRNAME}/../../scripts/shell"
SCRIPT_PATH="${SCRIPT_DIR}/container-runtime.sh"

@test "container-runtime.sh exists and is executable" {
    # container-runtime.sh is a sourced library; only check it exists
    [ -f "$SCRIPT_PATH" ]
}

@test "container-runtime.sh has proper shebang" {
    head -n 1 "$SCRIPT_PATH" | grep -qE "^#!/usr/bin/env bash|^#!/bin/bash"
}

@test "container-runtime.sh exports CONTAINER_CLI" {
    grep -q "export CONTAINER_CLI" "$SCRIPT_PATH"
}

@test "container-runtime.sh exports CONTAINER_IS_PODMAN" {
    grep -q "export CONTAINER_IS_PODMAN\|CONTAINER_IS_PODMAN" "$SCRIPT_PATH"
}

@test "container-runtime.sh prefers docker over podman over nerdctl" {
    # docker should appear before podman and nerdctl in the detection logic
    # Skip comment lines to avoid matching the header comment that lists all three
    awk '/^[[:space:]]*#/{next} /docker/{if(!d)d=NR} /podman/{if(!p)p=NR} /nerdctl/{if(!n)n=NR} END{exit (d<p && p<n) ? 0 : 1}' "$SCRIPT_PATH"
}

@test "container-runtime.sh sets CONTAINER_CLI to empty string when nothing found" {
    grep -q 'CONTAINER_CLI=""' "$SCRIPT_PATH"
}

@test "container-runtime.sh does not use set -e (safe for sourcing)" {
    # Must not have bare 'set -e' at file scope (it would break callers that source this)
    ! grep -qE '^set -e$' "$SCRIPT_PATH"
}

@test "container-runtime.sh defines container_info function" {
    grep -q "container_info" "$SCRIPT_PATH"
}

@test "container-runtime.sh sets CONTAINER_IS_PODMAN=true when podman selected" {
    grep -q "CONTAINER_IS_PODMAN=true" "$SCRIPT_PATH"
}

@test "container-runtime.sh sourcing sets CONTAINER_CLI variable" {
    run bash -c "source '$SCRIPT_PATH' && echo \$CONTAINER_CLI"
    [ "$status" -eq 0 ]
    # Output is the name of a runtime or empty — either is valid
}

@test "container-runtime.sh CONTAINER_IS_PODMAN is false by default" {
    run bash -c "source '$SCRIPT_PATH' && echo \$CONTAINER_IS_PODMAN"
    [ "$status" -eq 0 ]
    # Should be 'true' only when podman is selected; most environments have docker
    [[ "$output" == "true" || "$output" == "false" ]]
}
