#!/usr/bin/env bats

# Unit tests for run-api-discovery.sh

SCRIPT_DIR="${BATS_TEST_DIRNAME}/../../scripts/shell"
SCRIPT_PATH="${SCRIPT_DIR}/run-api-discovery.sh"

@test "run-api-discovery.sh exists and is executable" {
    [ -f "$SCRIPT_PATH" ]
    [ -x "$SCRIPT_PATH" ]
}

@test "run-api-discovery.sh shows help with --help flag" {
    run bash "$SCRIPT_PATH" --help
    [ "$status" -eq 0 ]
    [[ "$output" =~ "API Discovery" ]] || [[ "$output" =~ "Usage" ]]
}

@test "run-api-discovery.sh shows help with -h flag" {
    run bash "$SCRIPT_PATH" -h
    [ "$status" -eq 0 ]
    [[ "$output" =~ "API" ]]
}

@test "run-api-discovery.sh defines required functions" {
    # API discovery has its own structure
    grep -q "function" "$SCRIPT_PATH" || grep -q "()" "$SCRIPT_PATH"
}

@test "run-api-discovery.sh has proper shebang" {
    head -n 1 "$SCRIPT_PATH" | grep -q "^#!/bin/bash"
}

@test "run-api-discovery.sh defines color variables" {
    grep -q "^RED=" "$SCRIPT_PATH"
    grep -q "^GREEN=" "$SCRIPT_PATH"
    grep -q "^NC=" "$SCRIPT_PATH"
}

@test "run-api-discovery.sh contains API discovery logic" {
    grep -q "discover" "$SCRIPT_PATH" || grep -q "API" "$SCRIPT_PATH"
}

@test "run-api-discovery.sh supports OpenAPI/Swagger detection" {
    grep -q "openapi\|swagger" "$SCRIPT_PATH"
}

@test "run-api-discovery.sh supports Express.js detection" {
    grep -q "express" "$SCRIPT_PATH"
}

@test "run-api-discovery.sh supports Flask detection" {
    grep -q "Flask\|@app.route" "$SCRIPT_PATH"
}

@test "run-api-discovery.sh supports Django detection" {
    grep -q "django\|urlpatterns" "$SCRIPT_PATH"
}

@test "run-api-discovery.sh supports Next.js App Router detection" {
    grep -q "route\\.js\|route\\.ts" "$SCRIPT_PATH"
}

@test "run-api-discovery.sh detects authentication patterns" {
    grep -q "NextAuth\|JWT\|Bearer" "$SCRIPT_PATH"
}

@test "run-api-discovery.sh extracts HTTP methods" {
    grep -q "GET\|POST\|PUT\|DELETE" "$SCRIPT_PATH"
}

@test "run-api-discovery.sh creates JSON output" {
    grep -q "jq\|json" "$SCRIPT_PATH"
}

@test "run-api-discovery.sh does not have duplicate fi statements" {
    # Check that there are no consecutive 'fi' statements that would cause syntax errors
    # This validates the bug fix for duplicate fi on line 369
    run bash -c "grep -n '^fi$' '$SCRIPT_PATH' | awk '{print \$1}' | sed 's/:.*//'"
    # Count fi statements
    fi_count=$(echo "$output" | wc -l)
    # Verify no duplicate consecutive fi (basic check - script should parse)
    bash -n "$SCRIPT_PATH"
}

@test "run-api-discovery.sh handles Next.js App Router structure" {
    # Verify the Next.js detection logic is properly structured
    grep -q "route\.js" "$SCRIPT_PATH" || grep -q "route\.ts" "$SCRIPT_PATH"
}

@test "run-api-discovery.sh checks for required tools (jq)" {
    grep -q "command -v jq" "$SCRIPT_PATH"
}

@test "run-api-discovery.sh creates API discovery report" {
    grep -q "api-discovery\\.json\|api_discovery" "$SCRIPT_PATH"
}

@test "run-api-discovery.sh handles authentication middleware detection" {
    # Verify authentication patterns are extracted
    grep -q "auth.*middleware\|authenticate" "$SCRIPT_PATH"
}
