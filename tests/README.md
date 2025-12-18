# BATS Testing Guide

This project uses [BATS (Bash Automated Testing System)](https://github.com/bats-core/bats-core) for testing shell scripts.

## Quick Start

Run all tests:
```bash
./run-tests.sh
```

Run a specific test:
```bash
./run-tests.sh test-run-trivy-scan.bats
# or
./run-tests.sh run-trivy-scan
```

## Installation

The `run-tests.sh` script will automatically install BATS locally if not found. It will:
1. Check for system-wide BATS installation
2. Check for local BATS in `.bats/` directory
3. Clone and install BATS locally if needed

### Manual Installation (Optional)

**Via Homebrew** (requires admin):
```bash
brew install bats-core
```

**Manual Clone**:
```bash
git clone https://github.com/bats-core/bats-core.git .bats/bats-core
cd .bats/bats-core
./install.sh ..
```

## Test Structure

Tests are located in `tests/shell/`:
- `test-run-trivy-scan.bats` - Tests for Trivy scanner
- `test-run-grype-scan.bats` - Tests for Grype scanner
- `test-run-trufflehog-scan.bats` - Tests for TruffleHog scanner
- `test-run-clamav-scan.bats` - Tests for ClamAV scanner
- `test-run-checkov-scan.bats` - Tests for Checkov scanner
- `test-run-xeol-scan.bats` - Tests for Xeol scanner
- `test-run-sonar-analysis.bats` - Tests for SonarQube scanner
- `test-run-sbom-scan.bats` - Tests for SBOM generation
- `test-run-helm-build.bats` - Tests for Helm builds
- `test-run-anchore-scan.bats` - Tests for Anchore scanner
- `test-run-target-security-scan.bats` - Tests for orchestrator
- `test-scan-directory-template.bats` - Tests for shared utilities

## Writing Tests

BATS test syntax:
```bash
#!/usr/bin/env bats

@test "description of test" {
    # Test commands
    run command arg1 arg2
    [ "$status" -eq 0 ]
    [[ "$output" =~ "expected string" ]]
}
```

Common assertions:
- `[ "$status" -eq 0 ]` - Command succeeded
- `[ "$status" -ne 0 ]` - Command failed
- `[[ "$output" =~ "pattern" ]]` - Output matches pattern
- `[ -f "file.txt" ]` - File exists
- `[ -x "script.sh" ]` - File is executable

## Test Categories

Tests check for:
1. **Existence** - Script files exist and are executable
2. **Help Functions** - Scripts show help with `--help` or `-h`
3. **Dependencies** - Scripts source required templates
4. **Functionality** - Core features work as expected

## Continuous Integration

Tests can be integrated into CI/CD pipelines:
```yaml
# GitHub Actions example
- name: Run BATS tests
  run: ./run-tests.sh
```

## Troubleshooting

**BATS not found:**
```bash
./run-tests.sh
# This will auto-install BATS locally
```

**Permission denied:**
```bash
chmod +x run-tests.sh
chmod +x scripts/shell/*.sh
```

**Test failures:**
- Check script syntax: `bash -n scripts/shell/script-name.sh`
- Run script directly: `bash scripts/shell/script-name.sh --help`
- Check for missing dependencies
