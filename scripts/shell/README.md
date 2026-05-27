# Bash Scripts

Shell scripts for Linux, macOS, WSL, and Git Bash.

## 📋 Available Scripts (47 total)

### Security Scanners
- `run-clamav-scan.sh` - ClamAV antivirus scanning
- `run-trufflehog-scan.sh` - TruffleHog secret detection
- `run-trivy-scan.sh` - Trivy container vulnerability scanning
- `run-grype-scan.sh` - Grype vulnerability detection with SBOM
- `run-xeol-scan.sh` - Xeol end-of-life software detection
- `run-checkov-scan.sh` - Checkov Infrastructure-as-Code security
- `run-garak-scan.sh` - Garak LLM red-team security probing
- `run-sonar-analysis.sh` - SonarQube code quality analysis
- `run-helm-build.sh` - Helm chart building and validation
- `run-picklescan.sh` - Python pickle file security scanning
- `run-anchore-scan.sh` - Anchore container security analysis
- `run-api-discovery.sh` - API endpoint discovery
- `run-network-discovery.sh` - Network discovery scanning
- `run-athena-sbom.sh` - Athena SBOM generation
- `run-modelcard-check.sh` - ML model card validation
- `run-vex.sh` - Vulnerability Exploitability eXchange
- `run-baseline-scan.sh` - Baseline security scanning
- `run-complete-sbom-scan.sh` - Complete SBOM generation
- `run-sbom-scan.sh` - Standard SBOM generation
- `run-stig-scan.sh` - STIG compliance assessment
- `run-epyon-scan-ci.sh` - CI orchestrator for all security layers

### Dashboard & Reporting
- `generate-security-dashboard.sh` - Generate interactive security dashboard
- `generate-interactive-dashboard.sh` - Generate enhanced interactive dashboard
- `generate-remediation-suggestions.sh` - Generate actionable fix recommendations
- `consolidate-security-reports.sh` - Consolidate all reports
- `embed-dashboard-data.sh` - Embed data in dashboards
- `embed-metrics-in-dashboard.sh` - Embed metrics in dashboards
- `get-scan-metrics.sh` - Cross-scan metrics aggregator

### Orchestration & Workflow
- `run-target-security-scan.sh` - Target-aware security scan orchestration
- `scan-directory-template.sh` - Shared scan directory functions

### Export & Integration
- `export-api-discovery.sh` - Export API discovery results
- `export-sbom.sh` - Export SBOM data
- `create-jira-tickets.sh` - Create Jira tickets from findings

### Validation & Verification
- `check-severity-gate.sh` - Severity threshold gate checking
- `check-sonar-config.sh` - SonarQube configuration validation
- `check-docker-runtime.sh` - Docker runtime detection
- `verify-sbom-hashes.sh` - SBOM hash verification
- `verify-scan-manifest.sh` - Scan manifest verification
- `generate-scan-manifest.sh` - Generate scan manifest
- `generate-scan-findings-summary.sh` - Generate findings summary

### SBOM & Analysis
- `generate-sbom-lineage.sh` - Generate dependency lineage
- `enrich-findings.sh` - Enrich security findings
- `filter-ignored-findings.sh` - Filter ignored findings
- `parse-epyon-ignore.sh` - Parse .epyon-ignore.yml

### Utilities
- `open-latest-dashboard.sh` - Open most recent dashboard
- `container-runtime.sh` - Container runtime utilities
- `update-base-images.sh` - Update approved base images

## 🚀 Usage

### Basic Usage
```bash
# Make script executable (if needed)
chmod +x script-name.sh

# Run script
./script-name.sh
```

### Common Workflows

**Quick Security Scan**
```bash
./run-trufflehog-scan.sh
./run-clamav-scan.sh
./generate-security-dashboard.sh
./open-latest-dashboard.sh
```

**Complete Security Scan**
```bash
./run-target-security-scan.sh /path/to/project full
```

**CI/CD Scan**
```bash
./run-epyon-scan-ci.sh
```

**Dashboard Generation**
```bash
./generate-security-dashboard.sh
./generate-interactive-dashboard.sh
./open-latest-dashboard.sh
```

**Metrics & Analysis**
```bash
./get-scan-metrics.sh --from-github
./generate-remediation-suggestions.sh
```

## 📦 Prerequisites

- Bash shell
- Docker (for most security scanners)
- Optional: Helm, AWS CLI, Node.js (depending on scripts used)

## 📁 Output Locations

Results are saved to scan directories:
- `../../scans/{SCAN_ID}/` - Individual scan results
  - `trivy/` - Trivy scan results
  - `grype/` - Grype scan results
  - `trufflehog/` - TruffleHog scan results
  - `clamav/` - ClamAV scan results
  - `checkov/` - Checkov scan results
  - `sonar/` - SonarQube analysis
  - `sbom/` - SBOM files
  - `consolidated-reports/` - Consolidated reports and dashboards
  - `security-dashboard.html` - Main security dashboard

## 💡 Tips

1. **Check Docker is running**:
   ```bash
   docker ps
   ```

2. **View script help**:
   ```bash
   ./script-name.sh --help
   ```

3. **Run in background**:
   ```bash
   ./script-name.sh &
   ```

4. **View logs**:
   ```bash
   tail -f ../scanner-reports/scan.log
   ```

## 🔗 Related

- PowerShell versions available in `../powershell/` directory
- See main `../README.md` for overall structure
