# Scan Manifest and Integrity Verification Guide

## Overview

Epyon automatically generates a **cryptographic manifest** for each scan to ensure integrity, authenticity, and non-repudiation of security assessment results. This Tier 1 integrity system provides tamper detection without requiring complex GPG key management.

## What is a Scan Manifest?

A scan manifest is a JSON file (`scan-manifest.json`) that contains:

- **Scan Metadata**: Scan ID, timestamp, username, hostname, Epyon version
- **Target Information**: Repository URL, commit SHA, branch, subdirectory (if applicable)
- **Tool Versions**: Versions of all security tools used (Trivy, Grype, Syft, TruffleHog, Checkov)
- **File Hashes**: SHA-256 cryptographic hashes of all report files
- **Manifest Hash**: Self-integrity verification hash

## Benefits

### 1. **Tamper Detection**
Detect if any scan report has been modified after generation

### 2. **Attribution**
Track who performed the scan and on which system

### 3. **Reproducibility**
Record exact tool versions and git commit for reproducible results

### 4. **STIG Compliance**
Provides evidence for multiple STIG controls:
- AU-10: Non-repudiation
- SI-7: Software integrity monitoring
- AC-16: Security attributes

### 5. **Chain of Custody**
Maintain audit trail for security assessments

## Automatic Generation

Manifests are **automatically generated** at the end of every scan. No additional steps required.

### Local Scans

```bash
# Run any scan locally
./scripts/shell/run-target-security-scan.sh <target> <scan_type>

# Manifest is automatically created
# scans/<scan_id>/scan-manifest.json
# scans/<scan_id>/manifest-summary.txt
```

### GitHub Actions Workflows

Manifests are automatically generated in both public and private repository scans via GitHub Actions:

- **Public Repo Scans**: `scan-public-repo.yml` workflow
- **Private Repo Scans**: `scan-private-repo.yml` workflow

The manifest is included in the downloaded scan artifacts along with all reports.

## Manifest Contents

### Example Structure

```json
{
  "manifest_version": "1.0",
  "generated_at": "2026-02-06T21:20:16Z",
  "scan_metadata": {
    "scan_id": "myapp_rnelson_2026-02-06_09-48-27",
    "timestamp": "2026-02-06T21:20:16Z",
    "username": "rnelson",
    "hostname": "ITLP01183.local",
    "epyon_version": "16a19f6"
  },
  "target": {
    "repository": "https://github.com/example/repo.git",
    "commit_sha": "abc123def456",
    "branch": "main",
    "subdirectory": "apps/api"
  },
  "tools": {
    "trivy": "0.67.2",
    "grype": "0.103.0",
    "syft": "1.37.0",
    "trufflehog": "3.91.0",
    "checkov": "3.2.500"
  },
  "file_hashes": {
    "scan-metadata.json": "sha256:96e6ceaa...",
    "security-findings-summary.json": "sha256:e6c639dd...",
    "consolidated-reports/index.html": "sha256:31eff361...",
    ...
  },
  "manifest_hash": "sha256:ce85e718b3a34051451fc6ce1e5d658a641400322d67e92c2ea1454302e33fec"
}
```

### Field Descriptions

| Field | Description | Example |
|-------|-------------|---------|
| `manifest_version` | Format version of the manifest | `"1.0"` |
| `generated_at` | ISO 8601 timestamp (UTC) | `"2026-02-06T21:20:16Z"` |
| `scan_id` | Unique scan identifier | `"myapp_rnelson_2026-02-06_09-48-27"` |
| `username` | User who ran the scan | `"rnelson"` |
| `hostname` | System where scan was executed | `"ITLP01183.local"` |
| `epyon_version` | Git commit SHA of Epyon | `"16a19f6"` |
| `repository` | Git repository URL (if applicable) | `"https://github.com/example/repo.git"` |
| `commit_sha` | Exact git commit scanned | `"abc123def456"` |
| `branch` | Git branch scanned | `"main"` |
| `subdirectory` | Subdirectory path (monorepo) | `"apps/api"` |
| `tools` | Tool versions used | `{"trivy": "0.67.2", ...}` |
| `file_hashes` | SHA-256 of each report file | `{"file.json": "sha256:..."}` |
| `manifest_hash` | Self-integrity hash | `"sha256:ce85e718..."` |

## Verifying Scan Integrity

### Basic Verification

```bash
# Verify a specific scan
./scripts/shell/verify-scan-manifest.sh scans/<scan_id>

# Example
./scripts/shell/verify-scan-manifest.sh scans/myapp_rnelson_2026-02-06_09-48-27
```

### Verification Output

#### ✅ Success (All Files Verified)

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Verifying Scan Manifest
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📋 Manifest Information
   Scan ID: myapp_rnelson_2026-02-06_09-48-27
   Generated: 2026-02-06T21:20:16Z
   User: rnelson
   Manifest Version: 1.0

🔐 Verifying manifest integrity...
   ✓ Manifest file integrity verified

🔍 Verifying file hashes...
   ✓ scan-metadata.json
   ✓ security-findings-summary.json
   ✓ consolidated-reports/index.html
   ... (39 files total)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Verification Summary
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📊 Results:
   Verified: 39

✅ All files verified successfully - Scan integrity intact

Exit Code: 0
```

#### ❌ Failure (Tampering Detected)

```
🔍 Verifying file hashes...
   ✓ scan-metadata.json
   ✗ security-findings-summary.json
     Expected: sha256:e6c639ddcbab9aee19f70f7c597b7b274b141c4faeb0ebb410ad9c06e8c7c81e
     Actual:   sha256:d6e43e54eb0606bd404e7920dbe8e94a03104d1a8b705f152ebdc9949a30603f
   ✓ consolidated-reports/index.html
   ...

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Verification Summary
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📊 Results:
   Verified: 38
   Failed: 1

❌ Verification FAILED - Files have been modified!

Exit Code: 1
```

#### ⚠️ Missing Files

```
🔍 Verifying file hashes...
   ✓ scan-metadata.json
   ⚠ security-findings-summary.json - FILE MISSING
   ✓ consolidated-reports/index.html
   ...

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Verification Summary
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📊 Results:
   Verified: 38
   Missing: 1

⚠️  Verification incomplete - Some files are missing

Exit Code: 2
```

### Exit Codes

| Code | Meaning | CI/CD Action |
|------|---------|--------------|
| `0` | All files verified successfully | ✅ Pass |
| `1` | File tampering detected (hash mismatch) | ❌ Fail |
| `2` | Files missing from scan directory | ⚠️ Warning |

## Integration with CI/CD

### GitHub Actions Example

```yaml
name: Security Scan with Verification

on:
  push:
    branches: [main]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Run Epyon Security Scan
        run: |
          ./scripts/shell/run-target-security-scan.sh . quick
      
      - name: Verify Scan Integrity
        run: |
          SCAN_DIR=$(ls -td scans/* | head -1)
          ./scripts/shell/verify-scan-manifest.sh "$SCAN_DIR"
      
      - name: Upload Scan with Manifest
        uses: actions/upload-artifact@v4
        with:
          name: security-scan-results
          path: |
            scans/
            !scans/**/.tmp-*
```

### GitLab CI Example

```yaml
security-scan:
  stage: security
  script:
    - ./scripts/shell/run-target-security-scan.sh . quick
    - SCAN_DIR=$(ls -td scans/* | head -1)
    - ./scripts/shell/verify-scan-manifest.sh "$SCAN_DIR"
  artifacts:
    paths:
      - scans/
    when: always
```

## STIG Evidence Collection

### AU-10: Non-Repudiation

**Control**: Protect against an individual falsely denying having performed actions.

**Evidence**: 
```bash
# Extract attribution information
jq '.scan_metadata' scans/<scan_id>/scan-manifest.json
```

**Output**:
```json
{
  "scan_id": "myapp_rnelson_2026-02-06_09-48-27",
  "timestamp": "2026-02-06T21:20:16Z",
  "username": "rnelson",
  "hostname": "ITLP01183.local",
  "epyon_version": "16a19f6"
}
```

### SI-7: Software, Firmware, and Information Integrity

**Control**: Detect unauthorized changes to software, firmware, and information.

**Evidence**:
```bash
# Verify integrity of all scans
for scan in scans/*/; do
  echo "Checking: $scan"
  ./scripts/shell/verify-scan-manifest.sh "$scan" || echo "FAILED: $scan"
done
```

### AC-16: Security and Privacy Attributes

**Control**: Associate security and privacy attributes with information.

**Evidence**:
```bash
# Extract security context
jq '{
  scan_id: .scan_metadata.scan_id,
  timestamp: .generated_at,
  tools: .tools,
  target: .target
}' scans/<scan_id>/scan-manifest.json
```

## Manual Manifest Generation

While manifests are generated automatically, you can manually regenerate:

```bash
# Regenerate manifest for a specific scan
./scripts/shell/generate-scan-manifest.sh scans/<scan_id>

# Example
./scripts/shell/generate-scan-manifest.sh scans/myapp_rnelson_2026-02-06_09-48-27
```

**Use Cases**:
- Manifest was deleted
- Need to update manifest after adding files
- Testing manifest generation

## Human-Readable Summary

Each scan includes `manifest-summary.txt` with human-readable information:

```bash
cat scans/<scan_id>/manifest-summary.txt
```

**Contents**:
- Scan metadata (ID, user, host, timestamp)
- Target information (repo, commit, branch)
- Tool versions
- List of all tracked files
- Verification command

## Architecture Details

### Hash Algorithm

**SHA-256** is used for all cryptographic hashing:
- Industry standard
- FIPS 140-2 approved
- Collision-resistant
- Widely supported

### Tracked Files

Manifests include hashes for:
- `*.json` - All JSON reports
- `*.html` - All HTML reports
- `*.csv` - All CSV exports
- `*.md` - All Markdown reports
- `*.log` - All scan logs

**Excluded**:
- `scan-manifest.json` (self-reference)
- `manifest-summary.txt` (human-readable copy)

### Tool Version Detection

Tool versions are detected by running Docker containers:

```bash
docker run --rm aquasec/trivy:latest --version | grep "Version:" | awk '{print $2}'
docker run --rm anchore/grype:latest version | grep "Version:" | awk '{print $2}'
docker run --rm anchore/syft:latest version | grep "Version:" | awk '{print $2}'
docker run --rm trufflesecurity/trufflehog:latest --version | awk '{print $2}'
docker run --rm bridgecrew/checkov:latest --version | head -1
```

Versions are captured at manifest generation time (not scan time).

## Troubleshooting

### Manifest Generation Fails

**Error**: `jq: command not found`

**Solution**: Install `jq`
```bash
# macOS
brew install jq

# Ubuntu/Debian
sudo apt-get install jq

# RHEL/CentOS
sudo yum install jq
```

### Verification Fails with "Missing Files"

**Cause**: Files were deleted or moved after scan

**Solution**: 
1. Check if files exist: `ls -la scans/<scan_id>/`
2. If intentionally removed, regenerate manifest:
   ```bash
   ./scripts/shell/generate-scan-manifest.sh scans/<scan_id>
   ```

### Tool Versions Show "unknown"

**Cause**: Docker not available or network issues

**Impact**: Manifest still generates, versions marked as "unknown"

**Solution**:
1. Ensure Docker is running: `docker ps`
2. Test Docker connectivity: `docker run --rm hello-world`
3. Check network access for Docker Hub

### Hash Mismatch on Verified Files

**Cause**: Files modified after manifest generation

**Actions**:
1. **Investigate**: Who modified the files?
2. **Audit**: Check git history: `git log -- scans/<scan_id>`
3. **Decide**: 
   - If legitimate change: Regenerate manifest
   - If unauthorized: Report security incident

## Best Practices

### 1. **Always Verify Before Sharing**

```bash
# Verify integrity before uploading
./scripts/shell/verify-scan-manifest.sh scans/<scan_id>

# If verified, safe to share
tar -czf scan-results.tar.gz scans/<scan_id>/
```

### 2. **Store Manifests Separately**

For high-security environments, store manifests in separate system:

```bash
# After scan, copy manifest to secure storage
SCAN_ID=$(ls -t scans/ | head -1)
scp "scans/$SCAN_ID/scan-manifest.json" secure-server:/manifests/

# Later, retrieve and verify
scp secure-server:/manifests/scan-manifest.json scans/$SCAN_ID/
./scripts/shell/verify-scan-manifest.sh "scans/$SCAN_ID"
```

### 3. **Archive with Manifest**

When archiving scans, always include manifest:

```bash
# Good: Includes manifest
tar -czf myapp-scan.tar.gz scans/myapp_*/

# Verify after extraction
tar -xzf myapp-scan.tar.gz
./scripts/shell/verify-scan-manifest.sh scans/myapp_*/
```

### 4. **Automate Verification in CI/CD**

Add verification as a pipeline step:

```yaml
- name: Verify Scan Integrity
  run: |
    SCAN_DIR=$(ls -td scans/* | head -1)
    if ! ./scripts/shell/verify-scan-manifest.sh "$SCAN_DIR"; then
      echo "::error::Scan integrity verification failed"
      exit 1
    fi
```

### 5. **Document Chain of Custody**

For compliance, maintain audit trail:

```bash
# Create audit log
cat > scan-audit.txt <<EOF
Scan Performed: $(date -u +"%Y-%m-%dT%H:%M:%SZ")
Performed By: $(whoami)
System: $(hostname)
Manifest Hash: $(jq -r .manifest_hash scans/<scan_id>/scan-manifest.json)
Verified By: $(whoami)
Verified At: $(date -u +"%Y-%m-%dT%H:%M:%SZ")
EOF
```

## Future Enhancements (Tier 2)

Potential future additions:

### GPG Signing
- Sign manifests with GPG keys
- Cryptographic proof of authorship
- Non-repudiation with private keys

### Timestamp Authority
- RFC 3161 timestamping
- Tamper-proof timestamps
- Legal-grade evidence

### Remote Verification
- API endpoint for manifest verification
- Centralized integrity checking
- Real-time validation

### Blockchain Anchoring
- Immutable audit trail
- Distributed trust model
- Permanent record

## Related Documentation

- [STIG Compliance Guide](STIG_COMPLIANCE_GUIDE.md) - STIG controls and evidence collection
- [Security Architecture](COMPREHENSIVE_SECURITY_ARCHITECTURE.md) - Overall security design
- [Scan Directory Architecture](SCAN_DIRECTORY_ARCHITECTURE.md) - Scan structure and outputs

## Summary

Epyon's scan manifest system provides:

✅ **Automatic** - Generated for every scan  
✅ **Tamper Detection** - SHA-256 cryptographic hashing  
✅ **Attribution** - User, host, timestamp tracking  
✅ **Reproducibility** - Tool versions and git commits  
✅ **STIG Compliance** - AU-10, SI-7, AC-16 evidence  
✅ **Chain of Custody** - Audit trail for assessments  
✅ **CI/CD Ready** - Exit codes for pipeline integration  
✅ **Zero-Config** - No keys or certificates required  

**No additional setup needed** - manifests are automatically created and ready to verify!
