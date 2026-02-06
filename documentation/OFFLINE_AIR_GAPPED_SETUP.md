# Offline & Air-Gapped Setup Guide

## Overview

This document outlines the requirements and implementation steps for running Epyon in offline or air-gapped environments where internet connectivity is restricted or unavailable.

## Current Limitations

Epyon currently requires internet connectivity for:
- Downloading Docker images for security scanning tools
- Updating vulnerability databases (Grype, Trivy, Xeol)
- GitHub Actions workflow execution
- External repository scanning
- Docker registry access

## Future Enhancement: Air-Gapped Mode

### Phase 1: Docker Images

**Required Images:**
```bash
# Security Scanning Tools
anchore/grype:latest
aquasec/trivy:latest
trufflesecurity/trufflehog:latest
anchore/syft:latest
bridgecrew/checkov:latest
anchore/xeol:latest
sonarsource/sonar-scanner-cli:latest
clamav/clamav:latest

# Base Images for Scanning
dhi/caddy:latest
alpine:latest
ubuntu:latest
```

**Implementation:**
- Create `scripts/shell/export-offline-images.sh` to save all Docker images to tar files
- Create `scripts/shell/import-offline-images.sh` to load images on air-gapped system
- Add manifest file listing all required images with versions and checksums

### Phase 2: Vulnerability Databases

**Grype Database:**
- Location: `~/.cache/grype/db/`
- Size: ~500MB (compressed)
- Update frequency: Daily
- Export command: `grype db update && tar -czf grype-db.tar.gz ~/.cache/grype/db/`

**Trivy Database:**
- Location: `~/.cache/trivy/db/`
- Size: ~200MB (compressed)
- Update frequency: Daily
- Export command: `trivy image --download-db-only && tar -czf trivy-db.tar.gz ~/.cache/trivy/db/`

**Xeol Database:**
- Location: `~/.cache/xeol/db/`
- Size: ~50MB (compressed)
- Update frequency: Weekly
- Export command: `xeol db update && tar -czf xeol-db.tar.gz ~/.cache/xeol/db/`

**ClamAV Database:**
- Location: `/var/lib/clamav/`
- Size: ~200MB
- Update frequency: Multiple times daily
- Export command: `freshclam && tar -czf clamav-db.tar.gz /var/lib/clamav/`

**Implementation:**
- Create `scripts/shell/export-vulnerability-databases.sh` to package all databases
- Create `scripts/shell/import-vulnerability-databases.sh` to restore on offline system
- Add database version manifest with timestamps and checksums
- Implement database age checks with warnings for stale data

### Phase 3: Configuration Changes

**Environment Variables to Add:**
```bash
# Offline Mode Flag
EPYON_OFFLINE_MODE=true

# Disable Auto-Updates
GRYPE_DB_AUTO_UPDATE=false
TRIVY_SKIP_DB_UPDATE=true
XEOL_DB_AUTO_UPDATE=false
CHECKOV_SKIP_DOWNLOAD=true

# Custom Database Paths
GRYPE_DB_CACHE_DIR=/path/to/offline/grype/db
TRIVY_CACHE_DIR=/path/to/offline/trivy/db
XEOL_DB_CACHE_DIR=/path/to/offline/xeol/db
```

**Script Modifications Needed:**
- Add offline mode detection to all scanner scripts
- Skip update checks when `EPYON_OFFLINE_MODE=true`
- Use local databases exclusively
- Add pre-flight checks to verify database availability
- Provide clear error messages when databases are missing or stale

### Phase 4: Air-Gapped Package

**Create Portable Bundle:**
```
epyon-offline-bundle/
├── docker-images/
│   ├── grype.tar
│   ├── trivy.tar
│   ├── trufflehog.tar
│   ├── syft.tar
│   ├── checkov.tar
│   ├── xeol.tar
│   ├── sonar-scanner.tar
│   └── clamav.tar
├── vulnerability-databases/
│   ├── grype-db.tar.gz
│   ├── trivy-db.tar.gz
│   ├── xeol-db.tar.gz
│   └── clamav-db.tar.gz
├── scripts/
│   ├── setup-offline-environment.sh
│   ├── import-all.sh
│   └── verify-installation.sh
├── manifests/
│   ├── images.manifest
│   ├── databases.manifest
│   └── checksums.sha256
└── README-OFFLINE.md
```

### Phase 5: Tools That Work Offline (No Changes Needed)

**Fully Functional Offline:**
- ✅ TruffleHog (filesystem scanning)
- ✅ Checkov (with `--skip-download` flag)
- ✅ SBOM Generation (Syft - scans local files)
- ✅ Git History Scanning (local repositories)
- ✅ Security Dashboard Generation

**Requires Local Setup:**
- ⚠️ SonarQube (requires local SonarQube server)
- ⚠️ ClamAV (requires virus database)

### Phase 6: Features That Won't Work Offline

**Permanently Disabled in Offline Mode:**
- ❌ GitHub Actions workflows (requires GitHub infrastructure)
- ❌ External repository scanning (`git clone` from internet)
- ❌ Docker registry scanning (requires registry network access)
- ❌ Automatic vulnerability database updates
- ❌ External API documentation fetching
- ❌ Cloud provider integrations (AWS, Azure, GCP)

**Workarounds:**
- Use local git clones for repository scanning
- Pre-download external repositories before air-gapping
- Use local Docker registry (Harbor, GitLab Registry)
- Schedule periodic database updates via approved transfer mechanisms

## Implementation Plan

### Step 1: Create Export Scripts (1-2 days)
- `scripts/shell/export-offline-images.sh`
- `scripts/shell/export-vulnerability-databases.sh`
- `scripts/shell/create-offline-bundle.sh`

### Step 2: Create Import Scripts (1-2 days)
- `scripts/shell/import-offline-images.sh`
- `scripts/shell/import-vulnerability-databases.sh`
- `scripts/shell/setup-offline-environment.sh`

### Step 3: Modify Scanner Scripts (2-3 days)
- Add offline mode detection to:
  - `run-grype-scan.sh`
  - `run-trivy-scan.sh`
  - `run-xeol-scan.sh`
  - `run-clamav-scan.sh`
  - `run-sonarqube-analysis.sh`

### Step 4: Add Verification & Monitoring (1 day)
- Database age checks
- Missing database warnings
- Offline mode status indicators
- Pre-flight validation

### Step 5: Documentation (1 day)
- Complete offline setup guide
- Transfer procedures
- Troubleshooting guide
- Database update procedures

### Step 6: Testing (2-3 days)
- Test complete offline bundle creation
- Verify all scanners work without internet
- Test database age warnings
- Validate error handling

**Total Estimated Time:** 8-12 days

## Database Freshness Considerations

**Recommended Maximum Ages:**
- Grype DB: 7 days (critical vulnerabilities discovered frequently)
- Trivy DB: 7 days (same as Grype)
- Xeol DB: 30 days (EOL dates change infrequently)
- ClamAV DB: 3 days (new malware variants daily)

**Implementation:**
- Add database timestamp checks
- Display warnings when databases are stale
- Include database ages in scan reports
- Provide clear guidance on update procedures

## Security Considerations

**Offline Bundle Security:**
- Sign all bundles with GPG keys
- Generate SHA256 checksums for all components
- Include manifest with versions and build dates
- Document chain of custody for database transfers

**Database Integrity:**
- Verify checksums on import
- Validate database compatibility with tool versions
- Test databases before distribution
- Maintain audit log of database updates

## Transfer Mechanisms

**Approved Transfer Methods (varies by organization):**
- Physical media (USB drives, external HDDs)
- Secure file transfer protocols (SFTP with bastion hosts)
- Cross-domain solutions (CDSs)
- One-way data diodes
- Approved cloud storage with encryption

**Bundle Size Estimates:**
- Docker Images: ~5-8 GB
- Vulnerability Databases: ~1 GB
- Total Bundle: ~6-9 GB (compressed)

## Future Enhancements

1. **Automated Bundle Creation**
   - Scheduled exports (weekly/monthly)
   - Version tracking
   - Incremental updates

2. **Database Diff Updates**
   - Only transfer changed data
   - Reduce transfer size
   - Faster updates

3. **Local Registry Support**
   - Pre-configure for Harbor/GitLab Registry
   - Automatic registry detection
   - Mirror mode for hybrid environments

4. **Offline Dashboard**
   - Pre-generate static HTML
   - No external dependencies
   - Embed all assets

5. **Compliance Reporting**
   - Database age compliance checks
   - Transfer audit trails
   - Offline approval workflows

## Priority Level

**Priority:** Medium-High

**Justification:**
- Many government and defense contractors require air-gapped scanning
- Financial institutions often have isolated networks
- Healthcare organizations have strict data isolation requirements
- Adds significant value for enterprise adoption

## Success Metrics

- [ ] Complete offline bundle can be created in < 30 minutes
- [ ] All scanners function correctly without internet
- [ ] Database imports complete successfully on fresh system
- [ ] Clear error messages when databases are stale
- [ ] Documentation covers all transfer scenarios
- [ ] Bundle size is optimized (< 10 GB)

## Related Documents

- [DEPLOYMENT_SUMMARY_NOV_3_2025.md](DEPLOYMENT_SUMMARY_NOV_3_2025.md)
- [PORTABLE_SCANNER_GUIDE.md](PORTABLE_SCANNER_GUIDE.md)
- [DOCKER_RUNTIME_AGNOSTIC_IMPLEMENTATION.md](DOCKER_RUNTIME_AGNOSTIC_IMPLEMENTATION.md)

## Questions to Resolve

1. Should we support multiple database versions simultaneously?
2. How do we handle tool version mismatches with database versions?
3. Should offline mode be auto-detected or explicitly enabled?
4. Do we need a local web UI for offline bundle management?
5. Should we provide database signing/verification tools?

## Notes

- Consider creating a separate "Epyon Offline Edition" distribution
- May require different licensing considerations
- Could partner with vulnerability database providers for offline licenses
- Investigate using SQLite for local vulnerability database storage
- Consider implementing local vulnerability feed aggregation
