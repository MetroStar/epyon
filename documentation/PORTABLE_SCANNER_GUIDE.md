# 🛡️ Portable Application Security Scanner

## Overview

The **Portable Application Security Scanner** is a standalone security analysis tool that can be pointed at any application directory to perform comprehensive security scanning. It automatically detects application types and runs appropriate security tools using Docker containers.

## 🎯 Key Features

### ✅ **Universal Application Support**
- **Auto-Detection**: Automatically identifies Node.js, Python, Java, Go, Rust, Docker, and Kubernetes applications
- **Generic Support**: Works with any application type, even if not specifically detected
- **Multi-Language**: Supports scanning of polyglot applications with multiple technologies

### ✅ **Comprehensive Security Analysis**
- **Secret Detection**: TruffleHog-powered credential and API key detection
- **Malware Scanning**: ClamAV antivirus protection with latest virus definitions
- **Vulnerability Assessment**: Trivy and Grype for CVE detection and risk analysis
- **Infrastructure Security**: Checkov for Infrastructure-as-Code security validation
- **EOL Detection**: Xeol for identifying end-of-life software components
- **Code Quality**: Language-specific code quality and security analysis

### ✅ **Flexible Scan Types**
- **Full Scan** - Complete security analysis with all tools
- **Quick Scan** - Fast essential security checks (secrets, malware, vulnerabilities)
- **Targeted Scans** - Focus on specific security aspects:
  - `secrets-only` - Just secret detection
  - `vulns-only` - Only vulnerability scanning
  - `container-only` - Docker and container security
  - `iac-only` - Infrastructure-as-Code security
  - `code-only` - Code quality and static analysis

### ✅ **Docker-Based Architecture**
- **No Local Dependencies**: All security tools run in Docker containers
- **Consistent Results**: Same security analysis regardless of host system
- **Cross-Platform**: Works on macOS, Linux, and Windows
- **Always Updated**: Uses latest security tool versions from Docker Hub

## 🚀 Installation and Setup

### Prerequisites
- Docker installed and running
- `jq` command-line JSON processor
- Bash shell (version 4.0+)

### Quick Setup
```bash
# Download the portable scanner
curl -O https://your-repo/portable-app-scanner.sh

# Make it executable
chmod +x portable-app-scanner.sh

# Run help to verify installation
./portable-app-scanner.sh --help
```

## 📋 Usage Guide

### Basic Usage
```bash
# Scan any application directory
./portable-app-scanner.sh /path/to/your/application

# Quick security check
./portable-app-scanner.sh /path/to/your/app quick

# Secrets-only scan
./portable-app-scanner.sh /path/to/your/app secrets-only
```

### Advanced Usage
```bash
# Custom output directory
./portable-app-scanner.sh /path/to/app full --output-dir /custom/output

# Verbose output for debugging
./portable-app-scanner.sh /path/to/app quick --verbose

# Skip Docker scans (for environments without Docker)
./portable-app-scanner.sh /path/to/app code-only --no-docker
```

### Scan Type Reference

| Scan Type | Tools Used | Use Case |
|-----------|------------|----------|
| `full` | All security tools | Comprehensive security audit |
| `quick` | TruffleHog, ClamAV, Grype | Fast essential security check |
| `secrets-only` | TruffleHog | Find hardcoded credentials/API keys |
| `vulns-only` | Trivy, Grype, Xeol | Vulnerability and EOL assessment |
| `container-only` | Trivy, Grype | Docker/container security |
| `iac-only` | Checkov | Kubernetes/Terraform security |
| `code-only` | Language-specific tools | Code quality and static analysis |

## 📊 Output Structure

### Directory Organization
```
security-scan-results-TIMESTAMP/
├── reports/
│   └── SECURITY_SCAN_SUMMARY.md      # Human-readable summary
├── raw-data/
│   ├── trufflehog-results.json       # Secret detection results
│   ├── clamav-results.txt            # Malware scan results
│   ├── trivy-filesystem-results.json # Vulnerability scan results
│   ├── grype-results.json            # Advanced vulnerability data
│   ├── sbom.json                     # Software Bill of Materials
│   ├── checkov-results.json          # IaC security results
│   └── xeol-results.json             # EOL software results
├── logs/
│   └── [tool-name].log               # Scan execution logs
└── QUICK_REFERENCE.md                # Commands for result analysis
```

### Report Features
- **Executive Summary**: High-level security status overview
- **Detailed Findings**: Tool-specific security analysis results
- **Risk Assessment**: Prioritized list of security issues to address
- **Action Items**: Specific next steps and remediation guidance
- **File References**: Direct paths to detailed scan data

## 🔍 Application Type Detection

The scanner automatically detects application types and adjusts scanning accordingly:

### Node.js Applications
**Detected by**: `package.json`
**Additional Scans**: 
- NPM audit for known vulnerabilities
- ESLint security rules (if configured)
- Test coverage analysis (if test framework detected)

### Python Applications  
**Detected by**: `requirements.txt`, `setup.py`, `pyproject.toml`
**Additional Scans**:
- Bandit security linter for Python-specific vulnerabilities
- Dependency vulnerability analysis

### Java Applications
**Detected by**: `pom.xml`, `build.gradle`
**Additional Scans**:
- Maven/Gradle dependency security analysis
- Java-specific vulnerability patterns

### Docker Applications
**Detected by**: `Dockerfile`, `docker-compose.yml`
**Additional Scans**:
- Container image security analysis
- Dockerfile best practices validation
- Base image vulnerability assessment

### Kubernetes Applications
**Detected by**: `chart/` directory, `*.yaml` files with K8s resources
**Additional Scans**:
- Kubernetes security policy validation
- Resource configuration security analysis
- Network policy and RBAC reviews

### Go Applications
**Detected by**: `go.mod`
**Additional Scans**:
- Go module vulnerability analysis
- Go-specific security patterns

### Rust Applications
**Detected by**: `Cargo.toml`
**Additional Scans**:
- Cargo audit for known vulnerabilities
- Rust-specific security analysis

## 🎯 Real-World Usage Examples

### Example 1: Scanning a Web Application
```bash
# Full security audit of a React/Node.js application
./portable-app-scanner.sh /home/developer/my-web-app full

# Results will include:
# - Frontend dependency vulnerabilities
# - Backend API security analysis  
# - Docker container security (if Dockerfile present)
# - Infrastructure security (if K8s manifests present)
```

### Example 2: CI/CD Integration
```bash
#!/bin/bash
# ci-security-check.sh

APP_DIR="/workspace/application"
RESULTS_DIR="/workspace/security-results"

# Run quick security scan in CI pipeline
./portable-app-scanner.sh "$APP_DIR" quick --output-dir "$RESULTS_DIR"

# Check for critical security issues
if grep -q "🚨\|MALWARE DETECTED\|VULNERABILITIES FOUND" "$RESULTS_DIR/reports/SECURITY_SCAN_SUMMARY.md"; then
    echo "❌ Critical security issues found - failing build"
    exit 1
else
    echo "✅ Security scan passed"
fi
```

### Example 3: Multi-Application Scanning
```bash
#!/bin/bash
# scan-all-applications.sh

APPS_DIR="/home/developer/projects"

for app in "$APPS_DIR"/*; do
    if [ -d "$app" ]; then
        echo "Scanning: $(basename "$app")"
        ./portable-app-scanner.sh "$app" quick --output-dir "/tmp/scans/$(basename "$app")"
    fi
done
```

### Example 4: Development Workflow Integration
```bash
# Add to your .bashrc or .zshrc
alias security-scan='~/tools/portable-app-scanner.sh'

# Quick security check during development
security-scan . quick

# Full audit before production deployment  
security-scan . full --output-dir ./security-audit
```

## 🔧 Customization and Extension

### Custom Exclusions
The scanner automatically creates exclusion files for common false positives, but you can customize them:

```bash
# Edit TruffleHog exclusions after first run
nano [output-dir]/trufflehog-exclusions.txt
```

### Adding New Security Tools
The modular design allows easy addition of new security tools:

1. Add new function for the tool (e.g., `run_new_tool_scan()`)
2. Add tool to appropriate scan types in the `main()` function
3. Update report generation to include new tool results

### Environment-Specific Configuration
Create environment-specific configurations:

```bash
# Development environment (faster, less thorough)
./portable-app-scanner.sh /path/to/app quick

# Staging environment (comprehensive analysis)  
./portable-app-scanner.sh /path/to/app full

# Production environment (focused on critical issues)
./portable-app-scanner.sh /path/to/app vulns-only
```

## 🚀 Performance Optimization

### Scan Speed Optimization
- **Use `quick` scan** for daily development checks
- **Use `secrets-only`** for rapid credential validation
- **Use `vulns-only`** for dependency update validation

### Resource Management
- Scanner automatically manages Docker container lifecycle
- Temporary files cleaned up after each scan
- Configurable output retention policies

### Network Optimization
- Docker images cached locally after first download
- Vulnerability databases cached and reused
- Minimal network usage after initial setup

## 🛡️ Security Considerations

### Scanner Security
- **No Credential Storage**: Scanner never stores or transmits credentials
- **Local Execution**: All analysis performed locally
- **Read-Only Access**: Scanner only reads target application files
- **Isolated Execution**: Docker containers provide security isolation

### Result Privacy
- **Local Storage**: All results stored locally on your system
- **No External Transmission**: No data sent to external services
- **Configurable Retention**: You control how long results are kept
- **Secure Cleanup**: Sensitive results can be securely deleted

## 📈 Integration Strategies

### Development Workflow
```bash
# Pre-commit hook example
#!/bin/bash
# .git/hooks/pre-commit

# Run quick security scan before each commit
./tools/portable-app-scanner.sh . secrets-only --output-dir /tmp/pre-commit-scan

if [ $? -ne 0 ]; then
    echo "❌ Security scan failed - commit blocked"
    exit 1
fi
```

### CI/CD Pipeline Integration
```yaml
# GitHub Actions example
- name: Security Scan
  run: |
    chmod +x ./tools/portable-app-scanner.sh
    ./tools/portable-app-scanner.sh . full --output-dir ./security-results
    
- name: Upload Security Results
  uses: actions/upload-artifact@v3
  with:
    name: security-scan-results
    path: ./security-results/
```

### Automated Monitoring
```bash
#!/bin/bash
# weekly-security-scan.sh (cron job)

APPS_ROOT="/home/apps"
RESULTS_ROOT="/var/security-scans"
DATE=$(date +%Y%m%d)

for app in "$APPS_ROOT"/*; do
    if [ -d "$app" ]; then
        app_name=$(basename "$app")
        ./portable-app-scanner.sh "$app" full --output-dir "$RESULTS_ROOT/$app_name-$DATE"
        
        # Send email if critical issues found
        if grep -q "🚨" "$RESULTS_ROOT/$app_name-$DATE/reports/SECURITY_SCAN_SUMMARY.md"; then
            mail -s "Security Alert: $app_name" security-team@company.com < "$RESULTS_ROOT/$app_name-$DATE/reports/SECURITY_SCAN_SUMMARY.md"
        fi
    fi
done
```

## 🏆 Best Practices

### Regular Scanning Schedule
- **Daily**: `quick` scan during active development
- **Weekly**: `full` scan for comprehensive security review
- **Before Releases**: `full` scan with detailed review of all findings
- **After Dependencies Updates**: `vulns-only` scan to verify security improvements

### Result Management
- **Archive Important Scans**: Keep security audit results for compliance
- **Track Trends**: Monitor security posture improvements over time
- **Share Results**: Include security summaries in team reviews
- **Prioritize Fixes**: Address high-severity findings first

### Team Workflow Integration
- **Security Champions**: Train team members on scanner usage
- **Shared Standards**: Establish security scanning standards across projects
- **Knowledge Sharing**: Document and share security findings and fixes
- **Continuous Improvement**: Regularly review and update scanning practices

---

## 📞 Support and Troubleshooting

### Common Issues
- **Docker not running**: Ensure Docker daemon is started
- **Permission errors**: Check file/directory permissions on target
- **Network issues**: Verify Docker can pull images from registries
- **Out of space**: Ensure sufficient disk space for scan results

### Getting Help
- Check scan logs in `[output-dir]/logs/` for detailed error information
- Use `--verbose` flag for additional debugging output
- Review Docker container status if scans fail unexpectedly

### Contributing
The portable scanner is designed for easy extension and customization. Contributions welcome for:
- Additional security tool integrations
- New application type detection
- Enhanced reporting features
- Performance optimizations

---

**Status**: ✅ Production Ready  
**Version**: 1.0  
**Last Updated**: November 3, 2025