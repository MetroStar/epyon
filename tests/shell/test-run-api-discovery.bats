#!/usr/bin/env bats

# Unit tests for run-api-discovery.sh

SCRIPT_DIR="${BATS_TEST_DIRNAME}/../../scripts/shell"
SCRIPT_PATH="${SCRIPT_DIR}/run-api-discovery.sh"

setup() {
    TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/quartz-api-discovery.XXXXXX")"
}

teardown() {
    [[ "$TEST_ROOT" == "${TMPDIR:-/tmp}"/quartz-api-discovery.* ]] && rm -rf -- "$TEST_ROOT"
}

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

@test "run-api-discovery.sh reports exact OpenAPI and Python counts without Node routes" {
    local target="${TEST_ROOT}/source"
    local scan="${TEST_ROOT}/scan"
    mkdir -p "$target" "$scan"
    printf '%s\n' '{"openapi":"3.1.0","info":{"title":"Example API","version":"0.1.0"},"paths":{}}' > "$target/openapi.json"
    printf '%s\n' 'from fastapi import FastAPI' 'app = FastAPI()' '@app.get("/health")' 'def health():' '    return {"ok": True}' > "$target/app.py"

    run env TARGET_DIR="$target" SCAN_DIR="$scan" bash "$SCRIPT_PATH"
    [ "$status" -eq 0 ]
    [[ "$output" != *"integer expression expected"* ]]
    [[ "$output" != *"syntax error"* ]]
    run jq -e '.summary.total_specs_found == 1 and .summary.python_routes == 1 and .summary.nodejs_routes == 0 and .summary.total_endpoints_discovered == 2 and (.discovery_methods.openapi_specs | length) == 1 and (.discovery_methods.code_routes.python | length) == 1' "$scan/api/api-discovery.json"
    [ "$status" -eq 0 ]
}

@test "run-api-discovery.sh reports zero for an empty Next pages API directory" {
    local target="${TEST_ROOT}/source"
    local scan="${TEST_ROOT}/scan"
    mkdir -p "$target/pages/api" "$scan"

    run env TARGET_DIR="$target" SCAN_DIR="$scan" bash "$SCRIPT_PATH"
    [ "$status" -eq 0 ]
    [[ "$output" != *"integer expression expected"* ]]
    run jq -e '.summary.total_specs_found == 0 and .summary.total_routes_found == 0 and .summary.total_endpoints_discovered == 0' "$scan/api/api-discovery.json"
    [ "$status" -eq 0 ]
}

@test "run-api-discovery.sh retains discovered Express routes" {
    local target="${TEST_ROOT}/source"
    local scan="${TEST_ROOT}/scan"
    mkdir -p "$target" "$scan"
    printf '%s\n' 'const app = require("express")();' "app.get('/health', (_req, res) => res.json({ok: true}));" > "$target/app.js"

    run env TARGET_DIR="$target" SCAN_DIR="$scan" bash "$SCRIPT_PATH"
    [ "$status" -eq 0 ]
    [[ "$output" != *"integer expression expected"* ]]
    run jq -e '.summary.nodejs_routes == 1 and (.discovery_methods.code_routes.nodejs | length) == 1 and .discovery_methods.code_routes.nodejs[0].path == "/health"' "$scan/api/api-discovery.json"
    [ "$status" -eq 0 ]
}
