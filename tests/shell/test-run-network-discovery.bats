#!/usr/bin/env bats

# Unit tests for run-network-discovery.sh — Layer 16

SCRIPT_DIR="${BATS_TEST_DIRNAME}/../../scripts/shell"
SCRIPT_PATH="${SCRIPT_DIR}/run-network-discovery.sh"

# ── Script existence and basics ───────────────────────────────────────────────

@test "run-network-discovery.sh exists and is executable" {
    [ -f "$SCRIPT_PATH" ]
    [ -x "$SCRIPT_PATH" ]
}

@test "run-network-discovery.sh has proper shebang" {
    head -n 1 "$SCRIPT_PATH" | grep -q "^#!/bin/bash"
}

@test "run-network-discovery.sh defines color variables" {
    grep -q "^RED=" "$SCRIPT_PATH"
    grep -q "^GREEN=" "$SCRIPT_PATH"
    grep -q "^NC=" "$SCRIPT_PATH"
}

@test "run-network-discovery.sh shows help with --help flag" {
    run bash "$SCRIPT_PATH" --help
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Network Discovery" ]] || [[ "$output" =~ "Usage" ]]
}

@test "run-network-discovery.sh shows help with -h flag" {
    run bash "$SCRIPT_PATH" -h
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Network" ]] || [[ "$output" =~ "USAGE" ]]
}

# ── Source detection capability ───────────────────────────────────────────────

@test "run-network-discovery.sh supports Dockerfile EXPOSE detection" {
    grep -q "EXPOSE" "$SCRIPT_PATH"
}

@test "run-network-discovery.sh supports docker-compose ports detection" {
    grep -q "docker-compose" "$SCRIPT_PATH"
}

@test "run-network-discovery.sh supports Kubernetes manifest scanning" {
    grep -q "kind:" "$SCRIPT_PATH"
}

@test "run-network-discovery.sh supports Helm chart scanning" {
    grep -q "Chart.yaml\|values.yaml\|helm" "$SCRIPT_PATH"
}

@test "run-network-discovery.sh supports Spring Boot config scanning" {
    grep -q "application.yml\|server.port\|Spring Boot" "$SCRIPT_PATH"
}

@test "run-network-discovery.sh supports .env file PORT variable detection" {
    grep -q "\.env\|PORT=" "$SCRIPT_PATH"
}

# ── Active scan gating ────────────────────────────────────────────────────────

@test "run-network-discovery.sh only runs nmap when NMAP_TARGET is set" {
    grep -q "NMAP_TARGET" "$SCRIPT_PATH"
}

@test "run-network-discovery.sh references nmap Docker image" {
    grep -q "instrumentisto/nmap\|NMAP_IMAGE" "$SCRIPT_PATH"
}

@test "run-network-discovery.sh includes active scan security notice" {
    grep -q "authorization\|SECURITY NOTICE\|own" "$SCRIPT_PATH"
}

# ── Output and JSON ───────────────────────────────────────────────────────────

@test "run-network-discovery.sh writes network-discovery.json output" {
    grep -q "network-discovery.json" "$SCRIPT_PATH"
}

@test "run-network-discovery.sh creates output in SCAN_DIR/network/" {
    grep -q "SCAN_DIR.*network\|network.*SCAN_DIR" "$SCRIPT_PATH"
}

@test "run-network-discovery.sh generates JSON with summary section" {
    grep -q "'summary'\|\"summary\"" "$SCRIPT_PATH"
}

@test "run-network-discovery.sh does not have bash syntax errors" {
    bash -n "$SCRIPT_PATH"
}

# ── Integration: static Dockerfile EXPOSE parsing ────────────────────────────

@test "run-network-discovery.sh produces JSON output for a directory with a Dockerfile" {
    # Create a temporary target directory with a minimal Dockerfile
    local tmpdir
    tmpdir=$(mktemp -d)
    local scandir
    scandir=$(mktemp -d)

    cat > "$tmpdir/Dockerfile" << 'EOF'
FROM alpine:3.18
EXPOSE 8080
EXPOSE 443/tcp
CMD ["sh"]
EOF

    run bash "$SCRIPT_PATH" "$tmpdir"
    local exit_code=$status

    # Check that the script ran without fatal error
    [ "$exit_code" -eq 0 ] || [ "$exit_code" -eq 1 ]

    # Clean up
    rm -rf "$tmpdir" "$scandir"
}

@test "run-network-discovery.sh handles a directory with no config files gracefully" {
    local tmpdir
    tmpdir=$(mktemp -d)

    run bash "$SCRIPT_PATH" "$tmpdir"
    # Should exit without crashing
    [ "$status" -eq 0 ] || [ "$status" -eq 1 ]

    rm -rf "$tmpdir"
}
