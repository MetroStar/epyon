# Grype Scan Troubleshooting Guide

## Issue: Grype Scans Not Showing Up

### Symptoms

- Layer timing shows Grype executed (e.g., 36-226 seconds)
- No `grype/` directory in scan output
- No error messages visible to user
- Other tools (Trivy, SBOM, etc.) work correctly

### Root Causes

#### 1. Silent Failure Suppression

**Location**: [scripts/shell/run-epyon-scan-ci.sh](../scripts/shell/run-epyon-scan-ci.sh) lines 925-926

**Problem**: Commands use `|| true` which suppresses all errors:

```bash
SCAN_DIR="$SCAN_DIR" TARGET_DIR="$TARGET_DIR" ./scripts/shell/run-grype-scan.sh sbom || true
SCAN_DIR="$SCAN_DIR" TARGET_DIR="$TARGET_DIR" ./scripts/shell/run-grype-scan.sh images || true
```

**Impact**: If Grype fails for any reason, the orchestrator continues without reporting the failure.

**Fix Applied**: Added explicit error handling and validation:
- Check exit codes
- Verify output directory creation  
- Log detailed debug information
- Surface failures in parallel logs

#### 2. Missing Prerequisites

**Location**: [scripts/shell/run-grype-scan.sh](../scripts/shell/run-grype-scan.sh) lines 210-225

**Problem**: Script requires either:
- Local Grype binary (`grype` command)
- Container runtime (Docker/Podman)

If neither is available, the script fails but the error is hidden by `|| true`.

**Fix Applied**: Added prerequisite validation:
```bash
if [ -z "${CONTAINER_CLI:-}" ]; then
    echo "ERROR: Neither local Grype nor container runtime available"
    exit 1
fi

if ! command -v "${CONTAINER_CLI}" >/dev/null 2>&1; then
    echo "ERROR: Container CLI $CONTAINER_CLI not found"
    exit 1
fi
```

#### 3. SBOM Dependency

**Dependency**: Grype SBOM mode requires Layer 1 to complete successfully

**Problem**: If SBOM generation fails silently, Grype has nothing to scan.

**Mitigation**: CI script already waits for Layer 1, but if SBOM file doesn't exist, Grype now logs a clear error.

### How to Diagnose

#### 1. Check Hidden Logs

Parallel execution logs are in a hidden directory:

```bash
# View Grype logs
cat scans/YOUR_SCAN/.parallel-logs/layer-08-grype.log

# List all parallel logs
ls -la scans/YOUR_SCAN/.parallel-logs/
```

#### 2. Verify Prerequisites

```bash
# Check for local Grype
command -v grype && grype version

# Check for Docker
command -v docker && docker ps

# Check for Podman
command -v podman && podman ps
```

#### 3. Manual Test

Run Grype script directly to see full output:

```bash
export SCAN_DIR="scans/test_scan"
export TARGET_DIR="/path/to/target/repo"
export SCAN_ID="test_$(date +%Y-%m-%d_%H-%M-%S)"

./scripts/shell/run-grype-scan.sh sbom
```

### Fix Summary

**Changes Made**:

1. **[run-epyon-scan-ci.sh](../scripts/shell/run-epyon-scan-ci.sh)** (Lines 922-950):
   - Removed `|| true` from Grype commands
   - Added explicit exit code checking
   - Added output directory validation
   - Enhanced debug logging

2. **[run-grype-scan.sh](../scripts/shell/run-grype-scan.sh)** (Lines 195-250):
   - Added prerequisite validation
   - Added early exit on missing dependencies
   - Enhanced logging with OUTPUT_DIR and SCAN_MODE
   - Clear error messages for missing tools

### Testing

After applying fixes, Grype failures will be visible in:

1. **CI logs**: Search for `[grype-error]` prefix
2. **Parallel logs**: `scans/{scan_id}/.parallel-logs/layer-08-grype.log`
3. **Scan logs**: `scans/{scan_id}/grype/scan.log` (if directory was created)

### Expected Behavior

**Success**:
- `grype/` directory created
- `grype-sbom-results.json` and `grype-images-results.json` present
- Log shows: `[grype-debug] Output directory exists`

**Failure** (now visible):
```
[grype-error] SBOM scan failed with exit code 1
[grype-error] CRITICAL: grype directory was not created
[grype-error] This indicates Grype failed before init_scan_environment completed
```

### Next Steps

1. **Monitor**: Check `.parallel-logs` in upcoming scans
2. **Report**: If errors persist, file issue with:
   - Full contents of `layer-08-grype.log`
   - `scan-metadata.json` (scan mode, version)
   - Container runtime info (`docker version` or `podman version`)
3. **Workaround**: Install local Grype to bypass container dependency:
   ```bash
   # macOS
   brew install grype
   
   # Linux
   curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
   ```

### Related Documentation

- [SCAN_MATRIX.md](SCAN_MATRIX.md) - Which modes run Grype
- [SCAN_DIRECTORY_ARCHITECTURE.md](SCAN_DIRECTORY_ARCHITECTURE.md) - Output structure
- [ML_SECURITY_GUIDE.md](ML_SECURITY_GUIDE.md) - Container requirements for ML layers

### Date

**Issue Identified**: 2026-08-21  
**Fixes Applied**: 2026-08-21  
**Status**: Ready for testing in next CI run
