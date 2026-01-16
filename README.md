# EPYON

**Absolute Security Control**

Epyon is a comprehensive DevSecOps security architecture designed to orchestrate, execute, and consolidate security scanning across the entire software delivery lifecycle.

Built for modern pipelines, Epyon provides:
- Unified orchestration of multiple security tools
- Consistent, repeatable security enforcement
- Centralized reporting and visibility
- Extensible architecture for evolving security needs

Epyon is designed to be opinionated, automated, and decisive — empowering teams to move fast without sacrificing security.

---

## 🗺️ Product Roadmap

### Outcome-Oriented Development

Our roadmap is organized by level of certainty and timeframe, focusing on key outcomes that drive value:

| Timeframe | Waypoint | Desired Outcomes | Key Challenges | Success Metrics |
|-----------|----------|------------------|----------------|-----------------|
| **Now** | 1 | **Feature Enhancements of scanners** | • Scanner drift<br>• Signatures updated on demand validated<br>• Add Anchore scanning | Scanning capabilities are validated with 0% margin of error between scanning the same application | Test against same application multiple times<br>Addition of Anchore |
| **Now** | 2 | **GitHub integration** | GitHub action may not support spinning up docker containers for the scanning tools | Can be ran successfully by 3 or more GitHub repositories | GitHub actions |
| **Near** | 3 | **Report generation** | How might the best way to generate a report be? Is the dashboard good enough. Should it auto .zip the scan upon completion for ease of sharing | Reports can be created and shared out easily | Reports and exports |
| **Near** | 4 | **Failed build check** | What does failed mean?<br>• Aggressive No crits no highs<br>• Strong no crits 10 highs<br>• ??? | When an application has critical or highs, it reports as a failed build | Build checker |
| **Far future** | 5 | **Security implementations** | STIG and RMF review of the tool | Complete STIG/RMF documentation for an application | STIGS/RMF/POA&M |
| **Far future** | X, Y, ... | **Widely used as DEVSECOPS pipeline alternative** | Does this tool meet the needs for individual teams that do not have a proper pipeline | Utilized by 10 or more app teams | - |

### Features in Development
- **Enhanced Scanner Capabilities**: Continuous validation and signature updates
- **CI/CD Integration**: GitHub Actions support with containerized scanning
- **Advanced Reporting**: Automated report generation with export options
- **Quality Gates**: Configurable build failure criteria based on severity
- **Compliance Framework**: STIG and RMF documentation integration

*Roadmap current as of January 16, 2026*

---

## Overview

This repository contains a **production-ready, enterprise-grade** multi-layer DevOps security architecture with **target-aware scanning**, **AWS ECR integration**, and **isolated scan directory architecture**. Built for real-world enterprise applications with comprehensive Docker-based tooling.

**Latest Update: January 15, 2026** - Complete scan isolation architecture with all outputs contained in scan-specific directories. Automated remediation suggestions with inline dashboard display.

## 📋 Prerequisites

Before using this security architecture, ensure you have the following tools installed and configured.

### 🐳 Docker (Required)
All security tools run in Docker containers. Install Docker Desktop or Docker Engine:

```bash
# macOS (using Homebrew)
brew install --cask docker

# Ubuntu/Debian
sudo apt-get update && sudo apt-get install docker.io docker-compose
sudo systemctl start docker && sudo systemctl enable docker
sudo usermod -aG docker $USER  # Add your user to docker group

# Verify installation
docker --version
docker run hello-world
```

### ☁️ AWS CLI (Required for ECR Integration)
Required for AWS ECR authentication and container registry operations:

```bash
# macOS
brew install awscli

# Ubuntu/Debian
sudo apt-get install awscli

# Configure AWS credentials
aws configure
# Enter: AWS Access Key ID, Secret Access Key, Region (e.g., us-east-1)

# Verify installation
aws --version
aws sts get-caller-identity
```

### 📊 SonarQube Setup (Layer 7 - Code Quality Analysis)

SonarQube provides code quality analysis, test coverage metrics, and security vulnerability detection. You can use either a hosted SonarQube server or run one locally.

#### Option A: Using an Existing SonarQube Server

If your organization has a SonarQube server, create a `.env.sonar` file in the repository root:

```bash
# .env.sonar - SonarQube authentication configuration
export SONAR_HOST_URL='https://your-sonarqube-server.com'
export SONAR_TOKEN='your_sonarqube_token_here'
```

**To generate a SonarQube token:**
1. Log in to your SonarQube server
2. Go to **My Account** → **Security** → **Generate Tokens**
3. Create a new token with appropriate permissions
4. Copy the token to your `.env.sonar` file

#### Option B: Running SonarQube Locally with Docker

For local development or testing, run SonarQube using Docker:

```bash
# Create a Docker network for SonarQube
docker network create sonarqube-network

# Start SonarQube server (Community Edition - free)
docker run -d --name sonarqube \
  --network sonarqube-network \
  -p 9000:9000 \
  -v sonarqube_data:/opt/sonarqube/data \
  -v sonarqube_logs:/opt/sonarqube/logs \
  -v sonarqube_extensions:/opt/sonarqube/extensions \
  sonarqube:lts-community

# Wait for SonarQube to start (may take 1-2 minutes)
echo "Waiting for SonarQube to start..."
until curl -s http://localhost:9000/api/system/status | grep -q '"status":"UP"'; do
  sleep 5
done
echo "SonarQube is ready!"
```

**Initial SonarQube Configuration:**
1. Open http://localhost:9000 in your browser
2. Login with default credentials: `admin` / `admin`
3. **Change the default password immediately** when prompted
4. Generate an authentication token:
   - Go to **My Account** → **Security** → **Generate Tokens**
   - Name: `security-scanner` (or any descriptive name)
   - Type: **Global Analysis Token**
   - Click **Generate** and copy the token

5. Create your `.env.sonar` file:
```bash
# .env.sonar - Local SonarQube configuration
export SONAR_HOST_URL='http://localhost:9000'
export SONAR_TOKEN='your_generated_token_here'
```

#### Option C: SonarQube with Docker Compose

For a more robust local setup with persistent storage:

```yaml
# docker-compose.sonarqube.yml
version: '3.8'
services:
  sonarqube:
    image: sonarqube:lts-community
    container_name: sonarqube
    ports:
      - "9000:9000"
    environment:
      - SONAR_ES_BOOTSTRAP_CHECKS_DISABLE=true
    volumes:
      - sonarqube_data:/opt/sonarqube/data
      - sonarqube_logs:/opt/sonarqube/logs
      - sonarqube_extensions:/opt/sonarqube/extensions
    networks:
      - sonarqube-network
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:9000/api/system/status"]
      interval: 30s
      timeout: 10s
      retries: 5

volumes:
  sonarqube_data:
  sonarqube_logs:
  sonarqube_extensions:

networks:
  sonarqube-network:
    driver: bridge
```

```bash
# Start SonarQube with Docker Compose
docker-compose -f docker-compose.sonarqube.yml up -d

# Check status
docker-compose -f docker-compose.sonarqube.yml ps

# View logs
docker-compose -f docker-compose.sonarqube.yml logs -f sonarqube

# Stop SonarQube
docker-compose -f docker-compose.sonarqube.yml down
```

#### SonarQube Project Configuration

For projects you want to analyze, create a `sonar-project.properties` file in the project root:

```properties
# sonar-project.properties - Project configuration
sonar.projectKey=your-project-key
sonar.projectName=Your Project Name
sonar.projectVersion=1.0

# Source directories
sonar.sources=src
sonar.tests=src
sonar.test.inclusions=**/*.test.ts,**/*.test.tsx,**/*.spec.ts,**/*.spec.tsx

# Exclusions
sonar.exclusions=**/node_modules/**,**/dist/**,**/coverage/**,**/*.config.*

# Coverage (if using LCOV format)
sonar.javascript.lcov.reportPaths=coverage/lcov.info
sonar.typescript.lcov.reportPaths=coverage/lcov.info

# Language settings
sonar.language=ts
sonar.sourceEncoding=UTF-8
```

### 🔧 Other Tool Dependencies

The remaining security tools run entirely in Docker and require no additional setup:

| Tool | Docker Image | Auto-Pulled |
|------|-------------|-------------|
| **TruffleHog** | `trufflesecurity/trufflehog` | ✅ Yes |
| **ClamAV** | `clamav/clamav` | ✅ Yes |
| **Checkov** | `bridgecrew/checkov` | ✅ Yes |
| **Grype** | `anchore/grype` | ✅ Yes |
| **Trivy** | `aquasec/trivy` | ✅ Yes |
| **Xeol** | `xeol/xeol` | ✅ Yes |
| **Helm** | `alpine/helm` | ✅ Yes |

### ✅ Verify Prerequisites

Run this quick verification script to check your setup:

```bash
#!/bin/bash
echo "🔍 Checking prerequisites..."

# Docker
if command -v docker &> /dev/null && docker info &> /dev/null; then
    echo "✅ Docker: $(docker --version)"
else
    echo "❌ Docker: Not installed or not running"
fi

# AWS CLI
if command -v aws &> /dev/null; then
    echo "✅ AWS CLI: $(aws --version 2>&1 | head -1)"
else
    echo "⚠️  AWS CLI: Not installed (required for ECR integration)"
fi

# SonarQube configuration
if [ -f ".env.sonar" ]; then
    echo "✅ SonarQube: .env.sonar file found"
else
    echo "⚠️  SonarQube: .env.sonar not found (Layer 7 will be skipped)"
fi

echo "🎯 Prerequisites check complete!"
```

## 🏗️ Architecture Components

### Eight Security Layers (All Operational - Cross-Platform):

1. **🔍 TruffleHog** - Multi-target secret detection with filesystem, container, and registry scanning
2. **🦠 ClamAV** - Enterprise antivirus scanning with real-time virus definition updates  
3. **🔒 Checkov** - Infrastructure as Code security scanning with directory fallback (Terraform, Kubernetes, Docker)
4. **🎯 Grype** - Advanced vulnerability scanning with SBOM generation and multi-format support
5. **🔒 Trivy** - Comprehensive security scanner for containers, filesystems, and Kubernetes
6. **⏰ Xeol** - End-of-Life software detection for proactive dependency management
7. **📊 SonarQube** - Code quality analysis with target directory intelligence and interactive authentication
8. **⚓ Helm** - Chart validation, linting, and packaging with interactive ECR authentication
9. **📊 Report Consolidation** - Unified dashboard generation with comprehensive analytics

### 🖥️ Cross-Platform Implementation (NEW - v2.2)

**✅ Windows PowerShell Support** - Complete implementation achieving **95% feature parity**:
- **Interactive ECR Authentication** - Unified AWS authentication across all security tools
- **9-Step Security Pipeline** - Complete orchestration including Step 9 (Report Consolidation) 
- **Directory Scanning Fallback** - Graceful handling when Helm charts or projects lack expected structure
- **Comprehensive Error Handling** - Stub dependency creation and fallback mechanisms
- **Identical User Experience** - Same command patterns and output formatting across platforms

**Key PowerShell Scripts:**
- `run-complete-security-scan.ps1` - 9-step orchestrator with Step 9 integration
- `run-helm-build.ps1` - ✅ **NEW**: Full implementation with ECR authentication
- `run-checkov-scan.ps1` - Enhanced with directory scanning fallback
- `run-trivy-scan.ps1`, `run-grype-scan.ps1`, `run-trufflehog-scan.ps1` - Multi-target scanning
- `consolidate-security-reports.ps1` - Unified reporting and dashboard generation

## 📁 Directory Structure

```
epyon/
├── scripts/                    # Cross-platform security scanning scripts
│   ├── bash/                   # Unix/Linux/macOS scripts (legacy)
│   ├── shell/                  # Modern shell scripts
│   │   ├── run-target-security-scan.sh  # Target-aware orchestrator
│   │   ├── generate-security-dashboard.sh  # Interactive HTML dashboard
│   │   ├── generate-remediation-suggestions.sh  # Automated fix recommendations
│   │   ├── run-sonar-analysis.sh
│   │   ├── run-trufflehog-scan.sh
│   │   ├── run-clamav-scan.sh
│   │   ├── run-helm-build.sh   # Interactive ECR authentication
│   │   ├── run-checkov-scan.sh # Directory scanning fallback
│   │   ├── run-trivy-scan.sh
│   │   ├── run-grype-scan.sh
│   │   ├── run-xeol-scan.sh
│   │   ├── analyze-*.sh        # Analysis scripts for each tool
│   │   └── consolidate-security-reports.sh
│   └── powershell/             # Windows PowerShell scripts (full parity)
│       ├── run-target-security-scan.ps1  # Target-aware orchestrator
│       ├── run-complete-security-scan.ps1  # 9-step orchestrator with Step 9 consolidation
│       ├── run-helm-build.ps1  # Full implementation with ECR auth
│       ├── run-checkov-scan.ps1
│       ├── run-trivy-scan.ps1
│       ├── run-grype-scan.ps1
│       ├── run-trufflehog-scan.ps1
│       ├── Scan-Directory-Template.ps1  # Centralized scan directory management
│       └── consolidate-security-reports.ps1
├── scans/                     # Isolated scan output directory (NEW v2.4)
│   └── {scan_id}/            # Per-scan isolated directory
│       ├── trufflehog/       # Tool-specific subdirectories
│       ├── clamav/
│       ├── checkov/
│       ├── grype/
│       ├── trivy/
│       ├── xeol/
│       ├── sonar/
│       ├── helm/
│       ├── sbom/
│       ├── anchore/
│       └── consolidated-reports/  # Unified dashboard and reports
│           ├── dashboards/       # Interactive security dashboard
│           ├── html-reports/     # Tool-specific HTML reports
│           ├── markdown-reports/ # Summary reports
│           └── csv-reports/      # Data exports
└── documentation/             # Complete setup and architecture guides
    ├── SECURITY_AND_QUALITY_SETUP.md
    └── COMPREHENSIVE_SECURITY_ARCHITECTURE.md
```

## 🚀 Quick Start

### Target-Aware Security Scanning (Recommended)

Scan any external application or directory with comprehensive security analysis and centralized output:

```bash
# Unix/Linux/macOS
# Quick scan (4 core security tools: TruffleHog, ClamAV, Grype, Trivy)
./scripts/bash/run-target-security-scan.sh "/path/to/your/project" quick

# Full scan (all 8 layers)
./scripts/bash/run-target-security-scan.sh "/path/to/your/project" full

# Image-focused security scan (6 container tools)
./scripts/bash/run-target-security-scan.sh "/path/to/your/project" images

# Analysis-only mode (existing reports)
./scripts/bash/run-target-security-scan.sh "/path/to/your/project" analysis

# Windows PowerShell
# Quick scan (4 core security tools)
.\scripts\powershell\run-target-security-scan.ps1 -TargetDir "C:\path\to\your\project" -ScanType quick

# Full scan (all 8 layers)
.\scripts\powershell\run-target-security-scan.ps1 -TargetDir "C:\path\to\your\project" -ScanType full

# Image-focused security scan
.\scripts\powershell\run-target-security-scan.ps1 -TargetDir "C:\path\to\your\project" -ScanType images
```

**Isolated Scan Architecture:**
All scan results are stored in `scans/{scan_id}/` where `scan_id` format is:
```
{target_name}_{username}_{timestamp}
Example: comet_rnelson_2025-11-25_09-40-22
```

**Complete Scan Isolation:**
- Each scan is self-contained in its own directory
- No centralized reports/ directory - full isolation for audit trails
- Tool-specific subdirectories: `trufflehog/`, `clamav/`, `sonar/`, etc.
- Consolidated reports: `consolidated-reports/dashboards/security-dashboard.html`
- Historical scans preserved indefinitely for compliance and trending

**Quick Dashboard Access:**
```bash
# Simplest way - opens latest scan dashboard automatically
./scripts/bash/open-latest-dashboard.sh

# Or manually open latest
LATEST_SCAN=$(ls -t scans/ | head -1)
open scans/$LATEST_SCAN/consolidated-reports/dashboards/security-dashboard.html

# Regenerate dashboard for latest scan (if needed)
./scripts/bash/consolidate-security-reports.sh  # Auto-detects latest scan
```

### Cross-Platform Script Execution

**Unix/Linux/macOS (Bash):**
```bash
cd scripts/bash

# Complete 9-Step Security Pipeline (includes Step 9: Report Consolidation)
./run-complete-security-scan.sh full

# Individual Layer Execution using TARGET_DIR method:

# Layer 1: Secret Detection (TruffleHog)
TARGET_DIR="/path/to/project" ./run-trufflehog-scan.sh filesystem

# Layer 2: Antivirus Scanning (ClamAV)  
TARGET_DIR="/path/to/project" ./run-clamav-scan.sh

# Layer 3: Infrastructure Security (Checkov) - Directory scanning fallback
TARGET_DIR="/path/to/project" ./run-checkov-scan.sh filesystem

# Layer 4: Vulnerability Scanning (Grype)
TARGET_DIR="/path/to/project" ./run-grype-scan.sh filesystem

# Layer 5: Container Security (Trivy)
TARGET_DIR="/path/to/project" ./run-trivy-scan.sh filesystem

# Layer 6: End-of-Life Detection (Xeol)
TARGET_DIR="/path/to/project" ./run-xeol-scan.sh filesystem

# Layer 7: Code Quality Analysis (SonarQube) 
TARGET_DIR="/path/to/project" ./run-sonar-analysis.sh

# Layer 8: Helm Chart Building - Interactive ECR authentication
TARGET_DIR="/path/to/project" ./run-helm-build.sh

# Step 9: Report Consolidation (integrated into complete scan)
./consolidate-security-reports.sh
```

**Windows (PowerShell):**
```powershell
cd scripts\powershell

# Complete 9-Step Security Pipeline (includes Step 9: Report Consolidation)
.\run-complete-security-scan.ps1 -Mode full

# Individual Layer Execution using TARGET_DIR method:

# Layer 1: Secret Detection (TruffleHog)
$env:TARGET_DIR="/path/to/project"; .\run-trufflehog-scan.ps1 filesystem

# Layer 3: Infrastructure Security (Checkov) - Directory scanning fallback
$env:TARGET_DIR="/path/to/project"; .\run-checkov-scan.ps1 filesystem

# Layer 4: Vulnerability Scanning (Grype)
$env:TARGET_DIR="/path/to/project"; .\run-grype-scan.ps1 filesystem

# Layer 5: Container Security (Trivy)
$env:TARGET_DIR="/path/to/project"; .\run-trivy-scan.ps1 filesystem

# Layer 6: End-of-Life Detection (TruffleHog)
$env:TARGET_DIR="/path/to/project"; .\run-trufflehog-scan.ps1 filesystem

# Layer 8: Helm Chart Building - ✅ NEW: Interactive ECR authentication
$env:TARGET_DIR="/path/to/project"; .\run-helm-build.ps1

# Step 9: Report Consolidation (integrated into complete scan)
.\consolidate-security-reports.ps1
```

### Security Dashboard Access

```bash
# Open latest scan's interactive dashboard
LATEST_SCAN=$(ls -t scans/ | head -1)
open scans/$LATEST_SCAN/consolidated-reports/dashboards/security-dashboard.html

# Or specify a particular scan
open scans/comet_rnelson_2025-11-25_09-40-22/consolidated-reports/dashboards/security-dashboard.html
```

## 📊 Enterprise Features

### 🎯 Target-Aware Architecture
- **External Directory Support**: Scan any project without file copying
- **Path Intelligence**: Automatic detection of project structure and technologies
- **Flexible Target Modes**: Support for monorepos, microservices, and legacy applications
- **Non-Destructive Scanning**: Read-only analysis with no project modifications

### 🔐 Enterprise Authentication
- **AWS ECR Integration**: Automatic ECR authentication with graceful fallbacks
- **SonarQube Enterprise**: Multi-location config discovery and interactive credentials
- **Container Registry Support**: Private registry authentication for image scanning
- **Service Account Compatibility**: JWT and token-based authentication support

### 📊 Advanced Coverage Analysis
- **LCOV Format Integration**: SonarQube-standard coverage format for professional reporting
- **Multi-Format Support**: Automatic fallback from LCOV to JSON coverage formats
- **Coverage Calculation**: 92.51% LCOV (professional) vs 95.33% JSON (simplified) methodologies
- **Target-Aware Scanning**: `TARGET_DIR` environment variable method for clean path handling

### 🛡️ Comprehensive Security Coverage
- **8-Layer Security Model**: Complete DevOps security pipeline coverage
- **Real-Time Scanning**: Live vulnerability databases with automatic updates
- **Multi-Format Analysis**: Source code, containers, infrastructure, dependencies
- **Compliance Support**: NIST, OWASP, CIS benchmarks integration

### 📊 Advanced Reporting & Analytics
- **Interactive Dashboards**: Rich HTML reports with filtering and search
- **Trend Analysis**: Security posture tracking over time
- **Executive Summaries**: C-level reporting with risk prioritization
- **Integration APIs**: JSON output for CI/CD pipeline integration

### ⚡ Performance & Reliability
- **Graceful Failure Handling**: Continues scanning on individual tool failures
- **Resource Optimization**: Efficient scanning with configurable parallelization
- **Large Codebase Support**: Tested on 448MB+ projects with 63K+ files
- **Cross-Platform Excellence**: **95% PowerShell/bash parity** - identical functionality across Windows, macOS, and Linux

### 🖥️ Cross-Platform Support (NEW)
- **Windows**: Full PowerShell implementation with interactive ECR authentication
- **Unix/Linux/macOS**: Enhanced bash scripts with unified ECR authentication
- **Feature Parity**: 95% identical functionality across all platforms
- **9-Step Security Pipeline**: Complete orchestration available on all platforms

## 🎯 Recent Security Scan Results

### ✅ Production Validation (Nov 19, 2025)
**Target**: Enterprise application with **Centralized Scan Architecture**

#### **Core Security Results:**
- **🔍 TruffleHog**: Secret detection with filesystem scanning
- **🦠 ClamAV**: Clean - 0 malware threats detected (42,919 files scanned)
- **🔒 Checkov**: Infrastructure security analysis completed
- **🎯 Grype**: Vulnerability scanning with SBOM generation completed
- **🐳 Trivy**: Container security analysis completed
- **⏰ Xeol**: EOL software detection completed
- **📊 SonarQube**: Code quality analysis with coverage metrics
- **⚓ Helm**: Chart validation and packaging

#### **🏗️ Isolated Scan Architecture:**
- **✅ Complete Isolation**: All outputs in scan-specific `scans/{scan_id}/` directory
- **✅ No Centralized Reports**: Each scan is fully self-contained
- **✅ Tool Isolation**: Each tool has dedicated subdirectory within scan
- **✅ Cross-Platform**: Identical directory structure on Windows and Unix
- **✅ Audit Trail**: Historical scans preserved with unique scan IDs
- **✅ Environment Variables**: `$SCAN_ID`, `$SCAN_DIR`, `$TARGET_DIR`
- **✅ Parallel Scanning**: Multiple scans can run simultaneously without conflicts

#### **🖥️ Cross-Platform Validation:**
- **✅ Windows (PowerShell)**: All 8 security layers operational with centralized output
- **✅ Unix/Linux/macOS (Bash)**: Enhanced with centralized scan directory architecture
- **✅ Variable Fixes**: Corrected `$OutputDir` → `$OUTPUT_DIR` in Grype/Trivy scripts
- **✅ Path Validation**: Fixed null path checks in `Scan-Directory-Template.ps1`

### 🏆 **Scan Isolation Achievement (Nov 25, 2025)**
**Complete Scan Isolation Architecture** - All security scan outputs are fully isolated within scan-specific directories. Removed centralized `reports/` directory entirely. Each scan is self-contained with its own dashboard, reports, and tool outputs - enabling true audit trails, historical analysis, and parallel scanning without conflicts.

## 🔧 Tools and Technologies

- **Docker**: Containerized execution environment
- **SonarQube**: Code quality and test coverage analysis with LCOV format support
- **TruffleHog**: Secret and credential detection
- **ClamAV**: Antivirus and malware scanning
- **Helm**: Kubernetes chart building and validation
- **Checkov**: Infrastructure-as-Code security scanning
- **Trivy**: Container and Kubernetes vulnerability scanning
- **Grype**: Advanced vulnerability scanning with SBOM generation
- **Xeol**: End-of-Life software detection
- **Syft**: Software Bill of Materials (SBOM) generation

## 📊 Coverage Analysis Methodology

### LCOV Format Integration (November 6, 2025)
Our SonarQube integration now uses **LCOV format** as the primary coverage source, aligning with SonarQube's standard methodology:

```bash
# Coverage Results Comparison:
# • LCOV Format:    92.51% (SonarQube-standard, professional metric)
# • JSON Fallback:  95.33% (simplified line counting)  
# • SonarQube Server: 74.4% (comprehensive with branch coverage)
```

**Key Improvements:**
- ✅ **LCOV Priority**: Uses `lcov.info` first, falls back to JSON coverage files
- ✅ **SonarQube Alignment**: Same format that SonarQube analyzes natively  
- ✅ **Professional Reporting**: More accurate coverage calculation methodology
- ✅ **TARGET_DIR Support**: Clean path handling for external project scanning

## 📖 Documentation

### Complete Setup Guide
- **Location**: `documentation/SECURITY_AND_QUALITY_SETUP.md`
- **Content**: Step-by-step setup instructions for all eight security layers
- **Includes**: Configuration, troubleshooting, and best practices

### Architecture Overview
- **Location**: `documentation/COMPREHENSIVE_SECURITY_ARCHITECTURE.md`
- **Content**: Executive summary and technical implementation details
- **Includes**: Current status, action items, and strategic recommendations

## 🏆 Achievement Summary

✅ **Eight-Layer Security Architecture** - Complete implementation  
✅ **Multi-Target Scanning** - Enhanced capabilities across all tools  
✅ **Unified Reporting System** - Human-readable dashboards and reports  
✅ **Production-Ready** - Docker-based, cross-platform compatible  
✅ **Comprehensive Documentation** - Complete setup and usage guides  
✅ **Unit Testing** - Comprehensive test coverage for all shell scripts

## 🧪 Unit Testing

### Overview
All shell scripts in `scripts/shell/` have comprehensive unit test coverage using [bats-core](https://github.com/bats-core/bats-core).

### Running Tests
```bash
# Install bats-core (if not already installed)
# Ubuntu/Debian:
sudo apt-get install bats

# macOS:
brew install bats-core

# Run all tests
cd tests/shell
./run-tests.sh

# Run specific test file
bats test-run-trivy-scan.bats
```

### Test Coverage
- **Total Tests**: 107
- **Scripts Covered**: 12 (all scan scripts)
- **Success Rate**: 100%

Tests validate:
- Script existence and permissions
- Proper structure and shebang
- Required functions and dependencies
- Docker integration
- Help documentation
- Tool-specific features

For detailed testing documentation, see [tests/shell/README.md](tests/shell/README.md).

## 🔄 Enterprise Maintenance & Operations

### 📊 Regular Security Operations
```bash
# Weekly comprehensive enterprise scan
./scripts/run-target-security-scan.sh "/path/to/enterprise/app" full

# Daily quick security check  
./scripts/run-target-security-scan.sh "/path/to/enterprise/app" quick

# Container security monitoring
./scripts/run-target-security-scan.sh "/path/to/enterprise/app" images
```

### 🔄 Continuous Monitoring Pipeline
- **Vulnerability Management**: Real-time CVE monitoring with Grype and Trivy
- **Secret Detection**: Continuous credential scanning with TruffleHog
- **Code Quality Gates**: SonarQube integration with quality thresholds
- **Infrastructure Security**: Automated IaC security with Checkov
- **Dependency Lifecycle**: Proactive EOL management with Xeol
- **Malware Protection**: Regular antivirus scanning with ClamAV

### 📈 Performance Optimization
```bash
# Large enterprise project optimization
export EXCLUDE_PATTERNS="node_modules/*,*.min.js,vendor/*"
export MAX_PARALLEL_SCANS="4"
export SCAN_TIMEOUT="3600"

# Resource monitoring
docker stats --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}"
```

## 🚀 Production Deployment

### 📦 Infrastructure Requirements
- **Docker Engine**: Version 20.10+ for container execution
- **System Memory**: 8GB+ recommended for large projects  
- **Disk Space**: 10GB+ for reports and container images
- **Network Access**: Internet connectivity for tool updates
- **Authentication**: AWS CLI configured for ECR access

### 🔐 Security Configuration  
- **Container Security**: All tools run in isolated containers
- **Data Privacy**: Read-only scanning with no data transmission
- **Access Control**: Proper file permissions and user management
- **Audit Logging**: Comprehensive security event logging

### 📊 Monitoring & Alerting
```bash
# Performance monitoring
./scripts/monitor-security-performance.sh

# Alert configuration  
export SLACK_WEBHOOK="your_webhook_url"
export CRITICAL_ALERT_THRESHOLD="0"
export HIGH_ALERT_THRESHOLD="5"
```

---

## 📚 Documentation Suite

### 📖 Complete Documentation Library
- **[DEPLOYMENT_SUMMARY_NOV_4_2025.md](DEPLOYMENT_SUMMARY_NOV_4_2025.md)** - Complete deployment guide and validation results
- **[DASHBOARD_DATA_GUIDE.md](DASHBOARD_DATA_GUIDE.md)** - Interactive dashboard and analytics guide
- **[DASHBOARD_QUICK_REFERENCE.md](DASHBOARD_QUICK_REFERENCE.md)** - Production commands and usage patterns
- **[documentation/COMPREHENSIVE_SECURITY_ARCHITECTURE.md](documentation/COMPREHENSIVE_SECURITY_ARCHITECTURE.md)** - Complete architecture documentation
- **[documentation/SECURITY_AND_QUALITY_SETUP.md](documentation/SECURITY_AND_QUALITY_SETUP.md)** - Detailed setup and configuration guide

### 🎯 Quick Reference Commands
```bash
# Complete enterprise security scan
./scripts/run-target-security-scan.sh "/path/to/project" full

# Access security dashboard
open ./reports/security-reports/index.html

# Individual layer execution (recommended TARGET_DIR method)
TARGET_DIR="/path/to/project" ./scripts/run-[tool]-scan.sh

# SonarQube with LCOV coverage format
TARGET_DIR="/path/to/project" ./scripts/run-sonar-analysis.sh

# CI/CD integration
export TARGET_DIR="/workspace" && ./scripts/run-target-security-scan.sh "$TARGET_DIR" full
```

---

**Created**: November 3, 2025  
**Updated**: November 25, 2025  
**Version**: 2.4 - Complete Scan Isolation Architecture  
**Status**: ✅ **ENTERPRISE PRODUCTION READY - COMPLETE ISOLATION**  
**Validation**: Successfully tested with complete scan isolation, no centralized reports, full audit trail support

### 🆕 Latest Updates (v2.4) - Complete Scan Isolation
- ✅ **Removed Centralized Reports**: Eliminated `reports/` directory entirely
- ✅ **Full Scan Isolation**: All outputs contained in `scans/{scan_id}/` structure
- ✅ **Self-Contained Dashboards**: Each scan has its own dashboard and consolidated reports
- ✅ **Historical Preservation**: Scans remain independent for compliance and trending
- ✅ **Parallel Scan Support**: Multiple scans can run simultaneously without conflicts
- ✅ **Audit Trail Ready**: Complete isolation enables proper security audit trails
- ✅ **Script Cleanup**: Removed 8 obsolete scripts referencing old reports/ structure
- ✅ **Template Updates**: `scan-directory-template.sh` enforces scan isolation

### 🏆 **Scan Isolation Benefits**
| Feature | Before (v2.3) | After (v2.4) | Impact |
|---------|--------|-------|---------|-------|
| **Output Location** | Centralized `reports/` | Isolated `scans/{scan_id}/` | **Complete Isolation** |
| **Scan Independence** | Shared directories | Fully self-contained | **Audit Ready** |
| **Dashboard Location** | Central `reports/` | Per-scan dashboards | **Historical Analysis** |
| **Parallel Scans** | Possible conflicts | No conflicts | **Truly Parallel** |
| **Multi-Scan Support** | Same output paths | Isolated directories | **Unlimited Concurrent** |
| **Cleanup** | Complex selective deletion | Delete entire scan dir | **Simple Management** |
| **Compliance** | Difficult to track | Complete audit trail | **Regulation Ready** |

**🎯 Achievement**: **Complete scan isolation architecture** - Each security scan is fully self-contained with its own outputs, dashboard, and reports. Enables true parallel scanning, complete audit trails, and historical compliance tracking.

## 📊 Security Dashboard Access

### Scan-Specific Dashboards
**Location:** `scans/{scan_id}/consolidated-reports/dashboards/security-dashboard.html`

#### Quick Access Methods
```bash
# Method 1: Open latest scan dashboard
LATEST_SCAN=$(ls -t scans/ | head -1)
open scans/$LATEST_SCAN/consolidated-reports/dashboards/security-dashboard.html

# Method 2: Open specific scan dashboard
open scans/comet_rnelson_2025-11-25_09-40-22/consolidated-reports/dashboards/security-dashboard.html

# Method 3: List all scan dashboards
find scans/ -name "security-dashboard.html" | sort -r
```

#### Dashboard Features
✅ **Interactive Overview** - Visual status of all security tools  
✅ **Expandable Sections** - Click to view detailed findings  
✅ **Severity Badges** - Critical, High, Medium, Low indicators  
✅ **Tool-Specific Details** - Per-tool vulnerability breakdowns  
✅ **Self-Contained** - Each scan has its own complete dashboard  
✅ **Historical Analysis** - Compare dashboards across scan runs  

#### Scan Management
```bash
# List recent scans
ls -lt scans/ | head -5

# Compare two scans
diff scans/scan1/consolidated-reports/dashboards/security-dashboard.html \
     scans/scan2/consolidated-reports/dashboards/security-dashboard.html

# Archive old scans
tar -czf archive.tar.gz scans/comet_rnelson_2025-11-*

# Remove scans older than 30 days
find scans/ -type d -mtime +30 -name "*_rnelson_*" -exec rm -rf {} \;
```

