#!/usr/bin/env bats

# Unit tests for parse-epyon-ignore.sh

SCRIPT_DIR="${BATS_TEST_DIRNAME}/../../scripts/shell"
SCRIPT_PATH="${SCRIPT_DIR}/parse-epyon-ignore.sh"

@test "parse-epyon-ignore.sh exists and is executable" {
    [ -f "$SCRIPT_PATH" ]
    [ -x "$SCRIPT_PATH" ]
}

@test "parse-epyon-ignore.sh has proper shebang" {
    head -n 1 "$SCRIPT_PATH" | grep -q "^#!/bin/bash"
}

@test "parse-epyon-ignore.sh defines parse_ignore_rules function" {
    grep -q "parse_ignore_rules" "$SCRIPT_PATH"
}

@test "parse-epyon-ignore.sh writes to IGNORE_CACHE" {
    grep -q "IGNORE_CACHE" "$SCRIPT_PATH"
}

@test "parse-epyon-ignore.sh uses python3 to parse YAML" {
    grep -q "python3" "$SCRIPT_PATH"
}

@test "parse-epyon-ignore.sh creates empty cache when no ignore file present" {
    local CACHE
    CACHE=$(mktemp)
    rm -f "$CACHE"

    run bash -c "
        IGNORE_CACHE='$CACHE'
        source '$SCRIPT_PATH'
        parse_ignore_rules '/nonexistent/.epyon-ignore.yml'
    "
    [ "$status" -eq 0 ]
    [ -f "$CACHE" ]
    run jq -e '.ignores | length == 0' "$CACHE"
    [ "$status" -eq 0 ]
    rm -f "$CACHE"
}

@test "parse-epyon-ignore.sh parses valid ignore file into cache" {
    command -v python3 &>/dev/null || skip "python3 not available"
    python3 -c "import yaml" 2>/dev/null || skip "PyYAML not installed"

    local IGNORE_FILE
    IGNORE_FILE=$(mktemp).yml
    cat > "$IGNORE_FILE" << 'EOF'
ignores:
  - type: cve
    value: CVE-2024-1234
    reason: "test suppression"
    approved_by: "security-team"
  - type: tool
    value: ClamAV
    reason: "not applicable"
    approved_by: "ops"
EOF

    local CACHE
    CACHE=$(mktemp)

    run bash -c "
        IGNORE_CACHE='$CACHE'
        source '$SCRIPT_PATH'
        parse_ignore_rules '$IGNORE_FILE'
    "
    [ "$status" -eq 0 ]
    [ -f "$CACHE" ]

    run jq -e '.ignores | length == 2' "$CACHE"
    [ "$status" -eq 0 ]

    run jq -e '[.ignores[].value] | contains(["CVE-2024-1234"])' "$CACHE"
    [ "$status" -eq 0 ]

    rm -f "$IGNORE_FILE" "$CACHE"
}

@test "parse-epyon-ignore.sh handles expired ignore entries" {
    command -v python3 &>/dev/null || skip "python3 not available"
    python3 -c "import yaml" 2>/dev/null || skip "PyYAML not installed"

    local IGNORE_FILE
    IGNORE_FILE=$(mktemp).yml
    cat > "$IGNORE_FILE" << 'EOF'
ignores:
  - type: cve
    value: CVE-2020-0001
    reason: "old entry"
    approved_by: "ops"
    expires: "2020-01-01"
EOF

    local CACHE
    CACHE=$(mktemp)

    run bash -c "
        IGNORE_CACHE='$CACHE'
        source '$SCRIPT_PATH'
        parse_ignore_rules '$IGNORE_FILE'
    "
    [ "$status" -eq 0 ]
    [ -f "$CACHE" ]

    # Expired entries should not appear in the active cache
    run jq -e '[.ignores[] | select(.expired != true)] | length == 0' "$CACHE"
    [ "$status" -eq 0 ]

    rm -f "$IGNORE_FILE" "$CACHE"
}

@test "parse-epyon-ignore.sh auto-repairs a mis-indented entry under ignores:" {
    command -v python3 &>/dev/null || skip "python3 not available"
    python3 -c "import yaml" 2>/dev/null || skip "PyYAML not installed"

    # Reproduces a real-world mistake: a new entry pasted at 0-space
    # indentation while its siblings are indented 2 spaces. This is invalid
    # YAML (a block sequence requires one consistent indentation level) and
    # previously caused the *entire* ignores list to silently fail to load
    # (0 rules), not just the new entry.
    local IGNORE_FILE
    IGNORE_FILE=$(mktemp).yml
    cat > "$IGNORE_FILE" << 'EOF'
version: "1.0"

ignores:
  - type: cve
    value: "CKV_GHA_7"
    reason: "pre-existing, correctly indented"
    approved_by: "rlnelson"

- type: cve
  value: "GHSA-98qh-xjc8-98pq"
  reason: "newly pasted at the wrong indentation"
  approved_by: "rlnelson"
EOF

    local CACHE
    CACHE=$(mktemp)

    run bash -c "
        IGNORE_CACHE='$CACHE'
        source '$SCRIPT_PATH'
        parse_ignore_rules '$IGNORE_FILE'
    "
    [ "$status" -eq 0 ]
    [ -f "$CACHE" ]

    # Both the pre-existing and the mis-indented entry must still load.
    run jq -e '.ignores | length == 2' "$CACHE"
    [ "$status" -eq 0 ]

    run jq -e '[.ignores[].value] | contains(["GHSA-98qh-xjc8-98pq", "CKV_GHA_7"])' "$CACHE"
    [ "$status" -eq 0 ]

    # A warning must still be surfaced so the file itself gets fixed.
    run jq -e '.warnings | length > 0' "$CACHE"
    [ "$status" -eq 0 ]

    rm -f "$IGNORE_FILE" "$CACHE"
}

@test "parse-epyon-ignore.sh does not alter a correctly-indented file" {
    command -v python3 &>/dev/null || skip "python3 not available"
    python3 -c "import yaml" 2>/dev/null || skip "PyYAML not installed"

    local IGNORE_FILE
    IGNORE_FILE=$(mktemp).yml
    cat > "$IGNORE_FILE" << 'EOF'
ignores:
  - type: cve
    value: CVE-2024-1234
    reason: "consistent indentation"
    approved_by: "security-team"
EOF

    local CACHE
    CACHE=$(mktemp)

    run bash -c "
        IGNORE_CACHE='$CACHE'
        source '$SCRIPT_PATH'
        parse_ignore_rules '$IGNORE_FILE'
    "
    [ "$status" -eq 0 ]

    run jq -e '.warnings | length == 0' "$CACHE"
    [ "$status" -eq 0 ]

    rm -f "$IGNORE_FILE" "$CACHE"
}

@test "parse-epyon-ignore.sh handles empty YAML file gracefully" {
    local IGNORE_FILE
    IGNORE_FILE=$(mktemp).yml
    echo "" > "$IGNORE_FILE"

    local CACHE
    CACHE=$(mktemp)

    run bash -c "
        IGNORE_CACHE='$CACHE'
        source '$SCRIPT_PATH'
        parse_ignore_rules '$IGNORE_FILE'
    "
    [ "$status" -eq 0 ]
    [ -f "$CACHE" ]

    run jq -e '.ignores | length == 0' "$CACHE"
    [ "$status" -eq 0 ]

    rm -f "$IGNORE_FILE" "$CACHE"
}
