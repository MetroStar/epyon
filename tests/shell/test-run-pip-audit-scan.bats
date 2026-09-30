#!/usr/bin/env bats

# Unit tests for run-pip-audit-scan.sh

SCRIPT_DIR="${BATS_TEST_DIRNAME}/../../scripts/shell"
SCRIPT_PATH="${SCRIPT_DIR}/run-pip-audit-scan.sh"

@test "run-pip-audit-scan.sh exists and is executable" {
    [ -f "$SCRIPT_PATH" ]
    [ -x "$SCRIPT_PATH" ]
}

@test "run-pip-audit-scan.sh has proper shebang" {
    head -n 1 "$SCRIPT_PATH" | grep -q "^#!/bin/bash"
}

@test "run-pip-audit-scan.sh excludes Layer 1's synthetic requirements-pyproject.txt/requirements-conda-env.txt from discovery" {
    # Layer 1 (SBOM/Syft) writes throwaway files with these exact names
    # directly into the target repo, then deletes them once its own scan
    # finishes. Since layers run in parallel, this scan must never treat a
    # leftover copy of one of them as a real project file -- doing so causes
    # a "file not found" race if Layer 1 deletes it before this script's own
    # per-file loop gets around to actually invoking pip-audit on it.
    grep -q -- '-not -name "requirements-conda-env.txt"' "$SCRIPT_PATH"
    grep -q -- '-not -name "requirements-pyproject.txt"' "$SCRIPT_PATH"
}

@test "run-pip-audit-scan.sh independently discovers and audits conda environment.yml/yaml files" {
    # Conda coverage must not depend on Layer 1's leftover synthetic file --
    # this script generates its own, in its own output directory.
    grep -q 'environment.yml' "$SCRIPT_PATH"
    grep -q 'environment.yaml' "$SCRIPT_PATH"
    grep -q 'conda-env-requirements-' "$SCRIPT_PATH"
}

@test "run-pip-audit-scan.sh conda requirements file is written to OUTPUT_DIR, never into the target repo" {
    grep -q 'conda_req="\$OUTPUT_DIR/conda-env-requirements-' "$SCRIPT_PATH"
}

@test "run-pip-audit-scan.sh functional: audits conda deps independently and skips Layer 1's leftover pyproject duplicate" {
    if ! command -v pip-audit >/dev/null 2>&1; then
        skip "pip-audit not installed in this environment"
    fi
    if ! python3 -c "import yaml" >/dev/null 2>&1; then
        skip "pyyaml not installed in this environment"
    fi

    local target_dir
    target_dir=$(mktemp -d)
    local scan_dir
    scan_dir=$(mktemp -d)
    mkdir -p "$target_dir/api"

    cat > "$target_dir/api/environment.yaml" << 'EOF'
name: test-env
dependencies:
  - python=3.11
  - numpy=1.24.0
  - pip:
    - pyjwt==2.4.0
EOF
    cat > "$target_dir/api/pyproject.toml" << 'EOF'
[project]
name = "testproj"
dependencies = ["flask==2.0.0"]
EOF
    # Simulate a leftover Layer 1 (SBOM) synthetic file that should be
    # excluded from discovery rather than raced against.
    echo "pyjwt==2.4.0" > "$target_dir/api/requirements-pyproject.txt"

    run env TARGET_DIR="$target_dir" SCAN_DIR="$scan_dir" "$SCRIPT_PATH" --target "$target_dir"
    [ "$status" -eq 0 ]

    # The leftover synthetic file must never appear as a discovered/scanned
    # dependency file.
    ! grep -q "requirements-pyproject.txt" <<< "$output" || {
        echo "requirements-pyproject.txt (Layer 1 leftover) should not be discovered" >&2
        false
    }

    # Conda deps must be audited via a self-generated file in this layer's
    # own output directory.
    [ -f "$scan_dir/pip-audit/conda-env-requirements-1.txt" ]
    grep -q "numpy==1.24.0" "$scan_dir/pip-audit/conda-env-requirements-1.txt"
    grep -q "pyjwt==2.4.0" "$scan_dir/pip-audit/conda-env-requirements-1.txt"
    # conda meta-packages (python) must be excluded.
    ! grep -q "^python" "$scan_dir/pip-audit/conda-env-requirements-1.txt"

    rm -rf "$target_dir" "$scan_dir"
}
