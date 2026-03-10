# Shell Script Unit Tests

This directory contains unit tests for all shell scripts in the `scripts/shell` directory.

## Overview

The test suite uses [bats-core](https://github.com/bats-core/bats-core) (Bash Automated Testing System) to validate the functionality and structure of security scanning scripts.

## Test Coverage

Unit tests are provided for the following scripts:

1. **run-trivy-scan.sh** - Container and filesystem vulnerability scanning
2. **run-grype-scan.sh** - Multi-target vulnerability scanning
3. **run-checkov-scan.sh** - Infrastructure-as-Code security scanning
4. **run-clamav-scan.sh** - Antivirus and malware scanning
5. **run-trufflehog-scan.sh** - Secret detection scanning
6. **run-xeol-scan.sh** - End-of-Life software detection
7. **run-garak-scan.sh** - LLM red-team probing and safety scanning
8. **run-sbom-scan.sh** - Software Bill of Materials generation
9. **run-helm-build.sh** - Helm chart building and validation
10. **run-anchore-scan.sh** - Anchore security analysis (placeholder)
11. **run-sonar-analysis.sh** - SonarQube code quality analysis
12. **run-target-security-scan.sh** - Main orchestrator script
13. **scan-directory-template.sh** - Shared template functions

## Prerequisites

### Installing bats-core

The test framework requires bats-core to be installed. Install it using one of these methods:

#### Ubuntu/Debian
```bash
sudo apt-get install bats
```

#### macOS (Homebrew)
```bash
brew install bats-core
```

#### From Source
```bash
git clone https://github.com/bats-core/bats-core.git
cd bats-core
sudo ./install.sh /usr/local
```

Verify installation:
```bash
bats --version
```

## Running Tests

### Run All Tests

Execute all unit tests with a single command:

```bash
cd tests/shell
./run-tests.sh
```

### Run Individual Test Files

Test a specific script:

```bash
cd tests/shell
bats test-run-trivy-scan.bats
bats test-run-grype-scan.bats
```

### Run Specific Tests

You can also filter tests using pattern matching:

```bash
bats test-run-*.bats
```

## Test Structure

Each test file follows this structure:

```bash
#!/usr/bin/env bats

# Unit tests for <script-name>.sh

SCRIPT_DIR="/path/to/scripts/shell"
SCRIPT_PATH="${SCRIPT_DIR}/<script-name>.sh"

@test "test description" {
    # Test assertions
    [ -f "$SCRIPT_PATH" ]
    grep -q "pattern" "$SCRIPT_PATH"
}
```

## What Tests Validate

The unit tests verify:

1. **File Existence & Permissions**
   - Script files exist
   - Scripts are executable

2. **Script Structure**
   - Proper shebang (`#!/bin/bash`)
   - Required functions are defined
   - Color variables are defined

3. **Dependencies**
   - Scripts source required templates
   - Scripts call initialization functions

4. **Docker Integration**
   - Scripts use Docker for security scanning
   - Scripts check for Docker availability

5. **Help Documentation**
   - Help flags (`-h`, `--help`) work correctly
   - Help text is informative

6. **Tool-Specific Features**
   - Correct Docker images are used
   - Proper scan modes are supported
   - Environment variables are handled

## Test Results

Example output:

```
=========================================
Shell Script Unit Test Runner
=========================================

✅ bats is installed: Bats 1.13.0

Found 12 test files

Running all unit tests...

1..107
ok 1 run-anchore-scan.sh exists and is executable
ok 2 run-anchore-scan.sh has proper shebang
...
ok 107 scan-directory-template.sh count_scannable_files excludes .git

=========================================
✅ All tests passed!
=========================================
```

## Adding New Tests

To add tests for a new script:

1. Create a new test file: `test-<script-name>.bats`
2. Copy the template from an existing test file
3. Update the `SCRIPT_PATH` variable
4. Add relevant test cases
5. Run tests to verify

Example test case:

```bash
@test "script-name.sh has proper shebang" {
    head -n 1 "$SCRIPT_PATH" | grep -q "^#!/bin/bash"
}

@test "script-name.sh defines required functions" {
    grep -q "function_name()" "$SCRIPT_PATH"
}
```

## Continuous Integration

These tests can be integrated into CI/CD pipelines:

```yaml
# Example GitHub Actions workflow
- name: Run Shell Script Tests
  run: |
    cd tests/shell
    ./run-tests.sh
```

## Troubleshooting

### bats not found
Install bats-core as described in Prerequisites section.

### Permission denied
Make test runner executable:
```bash
chmod +x tests/shell/run-tests.sh
```

### Tests failing
Check if the script being tested has changed. Update test expectations to match current script behavior.

## Test Statistics

- **Total Tests**: 107
- **Test Files**: 12
- **Scripts Covered**: 12
- **Success Rate**: 100%

## Contributing

When modifying shell scripts in `scripts/shell/`:

1. Update or add corresponding tests
2. Run the test suite to verify changes
3. Ensure all tests pass before committing
4. Update test documentation as needed

## References

- [bats-core Documentation](https://bats-core.readthedocs.io/)
- [Bash Testing Best Practices](https://github.com/bats-core/bats-core#writing-tests)
- [Shell Script Testing Guide](https://www.shellcheck.net/)
