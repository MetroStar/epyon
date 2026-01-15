# Bash Scripts

Shell scripts for Linux, macOS, WSL, and Git Bash.

## 📋 Available Scripts (32 total)

### Security Scanners
- `run-clamav-scan.sh` - ClamAV antivirus scanning
- `run-trufflehog-scan.sh` - TruffleHog secret detection
- `run-trivy-scan.sh` - Trivy container vulnerability scanning
- `run-grype-scan.sh` - Grype vulnerability detection with SBOM
- `run-xeol-scan.sh` - Xeol end-of-life software detection
- `run-checkov-scan.sh` - Checkov Infrastructure-as-Code security
- `run-sonar-analysis.sh` - SonarQube code quality analysis
- `run-helm-build.sh` - Helm chart building and validation

### Analysis Tools
- `analyze-clamav-results.sh` - Analyze ClamAV scan results
- `analyze-trufflehog-results.sh` - Analyze TruffleHog results
- `analyze-trivy-results.sh` - Analyze Trivy results
- `analyze-grype-results.sh` - Analyze Grype results
- `analyze-xeol-results.sh` - Analyze Xeol results
- `analyze-checkov-results.sh` - Analyze Checkov results
- `analyze-helm-results.sh` - Analyze Helm results
- **`generate-remediation-suggestions.sh`** - **NEW!** Generate actionable fix recommendations

### Orchestration Scripts
- `run-complete-security-scan.sh` - Run all security scans
- `run-target-security-scan.sh` - Run targeted security scans
- `consolidate-security-reports.sh` - Consolidate all reports into dashboard
- `portable-app-scanner.sh` - Portable application scanner
- `nodejs-security-scanner.sh` - Node.js specific security scanner
- `real-nodejs-scanner.sh` - Real Node.js scanner
- `real-nodejs-scanner-fixed.sh` - Fixed Node.js scanner

### Management & Utilities
- `manage-dashboard-data.sh` - Interactive dashboard data management
- `open-dashboard.sh` - Open security dashboard in browser
- `open-compliance-dashboard.sh` - Open compliance dashboard for audit tracking
- `force-refresh-dashboard.sh` - Force refresh dashboard with cache busting
- `create-stub-dependencies.sh` - Create stub Helm dependencies
- `resolve-helm-dependencies.sh` - Resolve Helm chart dependencies
- `aws-ecr-helm-auth.sh` - AWS ECR authentication for Helm
- `aws-ecr-helm-auth-guide.sh` - AWS ECR authentication guide

### Audit & Compliance
- `audit-logger.sh` - Centralized audit logging system
- `compliance-logger.sh` - Generate compliance dashboard and CSV reports

### Demo & Testing
- `demo-portable-scanner.sh` - Demonstrate portable scanner
- `test-desktop-default.sh` - Test desktop default behavior

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
./analyze-clamav-results.sh
./open-dashboard.sh
```

**Complete Security Scan**
```bash
./run-complete-security-scan.sh
```

**Targeted Scan**
```bash
./run-target-security-scan.sh
```

**Dashboard Management**
```bash
./manage-dashboard-data.sh
./open-dashboard.sh              # Open main security dashboard
./open-compliance-dashboard.sh   # Open compliance audit dashboard
```

**Audit & Compliance**
```bash
./audit-logger.sh               # Manual audit logging
./compliance-logger.sh          # Generate compliance dashboard
./open-compliance-dashboard.sh  # View compliance dashboard
```

## 📦 Prerequisites

- Bash shell
- Docker (for most security scanners)
- Optional: Helm, AWS CLI, Node.js (depending on scripts used)

## 📁 Output Locations

Results are saved to parent directory:
- `../clamav-reports/`
- `../trufflehog-reports/`
- `../trivy-reports/`
- `../grype-reports/`
- `../xeol-reports/`
- `../checkov-reports/`
- `../reports/security-reports/`

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
