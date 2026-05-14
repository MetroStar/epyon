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

## Overview

Epyon is a **production-ready, enterprise-grade** 15-layer DevSecOps security platform with a FastAPI-backed web UI, comprehensive test coverage, baseline scanning, automated comparison, and isolated scan directory architecture. Built for real-world applications with Docker-based tooling and 641 automated tests.

**Version: 3.2.0** · **Updated: May 14, 2026**

## 📋 Prerequisites

Before using this security architecture, ensure you have the following tools installed and configured.

### 🐳 Container Runtime (Required)
All security tools run in containers. **Epyon is container-engine-agnostic** and supports multiple runtimes:

**Supported Container Runtimes:**
- **Docker** (Docker Engine, Docker Desktop) - Most common
- **Podman** - Rootless alternative, no daemon required
- **nerdctl** - containerd CLI, Docker-compatible
- **Alternative distributions** - Colima, Rancher Desktop, OrbStack

Scripts automatically detect and use whichever runtime you have installed.

**Docker Engine (Recommended for Linux/CI):**
```bash
# Ubuntu/Debian
sudo apt-get update && sudo apt-get install docker.io docker-compose
sudo systemctl start docker && sudo systemctl enable docker
sudo usermod -aG docker $USER  # Add your user to docker group

# IMPORTANT: After adding to docker group, you must:
# - Log out and log back in, OR
# - Open a new terminal session, OR
# - Run: exec su -l $USER
```

**Podman (Docker Alternative - No Daemon Required):**
```bash
# Ubuntu/Debian
sudo apt-get update && sudo apt-get install podman

# Fedora/RHEL
sudo dnf install podman

# Verify
podman info
```

**Docker Desktop (GUI Option for macOS/Windows):**
```bash
# macOS
brew install --cask docker

# Or download from https://docker.com
```

**Docker Alternatives (macOS):**
```bash
# Colima (Lightweight, no GUI)
brew install colima docker docker-compose
colima start

# Rancher Desktop (GUI alternative to Docker Desktop)
brew install --cask rancher

# OrbStack (Fast, native macOS)
brew install --cask orbstack
```

**Verify Installation:**
```bash
# Method 1: Use the built-in runtime check (recommended)
./scripts/shell/check-docker-runtime.sh

# Method 2: Manual verification
docker --version      # or: podman --version
docker info          # Should show your runtime details
docker run hello-world

# If you see permission errors, see Troubleshooting section below
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

> **GitHub Actions**: When using `scan-private-repo.yml` or `scan-public-repo.yml`, the `SONAR_PROJECT_KEY` is automatically derived from `GITHUB_REPOSITORY` (e.g., `owner_repo`) if the `SONAR_PROJECT_KEY` Actions variable is not set. Subdirectory scans append a sanitized directory suffix (e.g., `owner_repo_apps_api`). A `sonar-project.properties` file in the target repo takes priority over auto-derivation.

### 🔧 Other Tool Dependencies

The remaining security tools run entirely in Docker and require no additional setup:

| Tool | Docker Image | Auto-Pulled |
|------|-------------|-------------|
| **TruffleHog** | `dhi.io/trufflehog` | ✅ Yes |
| **ClamAV** | `clamav/clamav` | ✅ Yes |
| **Checkov** | `bridgecrew/checkov` | ✅ Yes |
| **Grype** | `anchore/grype` | ✅ Yes |
| **Trivy** | `dhi/trivy` (with `aquasec/trivy` fallback) | ✅ Yes |
| **Xeol** | `xeol/xeol` | ✅ Yes |
| **Helm** | `alpine/helm` | ✅ Yes |

### ✅ Verify Prerequisites

#### Quick Docker Runtime Check

Use the built-in Docker runtime detection utility to verify your Docker setup:

```bash
# Check Docker runtime and compatibility
./scripts/shell/check-docker-runtime.sh
```

This utility will:
- ✅ Detect which Docker runtime you're using (Docker Desktop, Colima, Rancher Desktop, etc.)
- ✅ Show available Docker contexts and endpoints
- ✅ Test Docker functionality with image pull and container run
- ✅ Display all installed Docker runtimes on your system

#### Manual Verification Script

Alternatively, run this quick verification script to check your setup:

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

## 🖥️ Web Dashboard (GUI)

Epyon ships a FastAPI-backed single-page web UI for running scans, browsing results, viewing SBOMs, and managing suppressed findings.

### Setup (first time only)

Create a virtual environment (optional but recommended):

```bash
# From the repo root
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
```

> Dependencies are installed automatically when you run `start.sh`, so no manual `pip install` is needed.

### Start the server

```bash
# Option A — convenience script (recommended)
# Installs/updates dependencies automatically, then starts the server
cd web
./start.sh

# Option B — manual uvicorn
source .venv/bin/activate
cd web
pip install -q -r api/requirements.txt
python3 -m uvicorn api.main:app --host 127.0.0.1 --port 8000 --app-dir .

# Option C — hot-reload during development
pip install -q -r api/requirements.txt
python3 -m uvicorn api.main:app --host 127.0.0.1 --port 8000 --app-dir . --reload
```

Then open **http://127.0.0.1:8000** in your browser.

### Environment variables

| Variable | Default | Description |
|---|---|---|
| `HOST` | `127.0.0.1` | Bind address for `start.sh` |
| `PORT` | `8000` | Port for `start.sh` |
| `EPYON_SCANS_DIR` | `../scans` (relative to `web/`) | Directory where scan results are stored |
| `OPENAI_API_KEY` | *(optional)* | Enables AI-powered scan summaries |

> **Note:** The scans displayed in the UI are read from the `scans/` directory at the repo root by default. Point `EPYON_SCANS_DIR` to a different path if your results live elsewhere.

---

## 🤖 GitHub Actions Integration

**Use Epyon as a GitHub Action to automatically scan repositories!**

### 🎟️ Jira Ticket Creation

Epyon automatically creates Jira Cloud tickets for critical and high severity findings.

**Setup (one-time, in GitHub repo or org secrets):**

| Secret | Value |
|--------|-------|
| `JIRA_BASE_URL` | `https://yourcompany.atlassian.net` |
| `JIRA_USER_EMAIL` | Email tied to your Jira API token |
| `JIRA_API_TOKEN` | [Jira Cloud personal API token](https://id.atlassian.com/manage-profile/security/api-tokens) |
| `JIRA_PROJECT_KEY` | Project key in uppercase (e.g. `SAP`, `SEC`) |

**Behavior:**
- One ticket is created per severity group per repo: critical, high, medium, and low
- Each ticket contains an ADF table listing CVE/ID, package, version, and scanner tool for every finding
- Tickets are labeled `epyon`, `security`, `epyon-critical`/`epyon-high`/`epyon-medium`/`epyon-low`, and a repo slug
- **Deduplication**: if an unresolved ticket with matching labels already exists, creation is skipped and the existing ticket URL is logged
- Ticket creation is skipped entirely if `JIRA_*` secrets are not configured

### Quick Start - Scan Any Repository

1. **Go to your Epyon repository** on GitHub: `https://github.com/MetroStar/epyon`
2. **Click the "Actions" tab** at the top
3. **Select "Scan External Repository"** from the left sidebar
4. **Click "Run workflow"** (green button on the right)
5. **Enter the repository URL** you want to scan (e.g., `https://github.com/owner/repo.git`)
6. **Optional: Enter subdirectory path** to scan only part of a monorepo (e.g., `apps/api`)
7. **Select scan mode**:
   - **quick** - Fast scan (~2-5 minutes) ⚡
   - **full** - Complete analysis (~10-20 minutes) 🔍
   - **baseline** - Compare against previous scans 📊
8. **Click "Run workflow"** to start
9. **View results**:
   - Click on the workflow run
   - Click **"Summary"** in the left sidebar
   - Scroll down to **"Artifacts"** section
   - Download the ZIP file with all reports

### Automated Scan Mode Defaults

`scan-private-repo.yml` now uses fixed automated defaults:

- `pull_request` events run `quick` scans for fast feedback
- `push` events (including post-merge pushes to protected branches) run `full` scans
- `schedule` events run `full` scans
- Manual `workflow_dispatch` runs still let you choose `quick`, `full`, or `baseline`

This gives short PR turnaround with deeper security checks after merge.

### Garak (LLM) Workflow Inputs

The manual workflows expose Garak configuration fields directly in the Actions UI.

For `scan-private-repo.yml`, `scan-public-repo.yml`, and `baseline-scan.yml`:

- `garak_target_type` (dropdown): `openai`, `test`, `huggingface`, `ollama`, `litellm`
- `garak_target_name` (dropdown): includes `gpt-4o-mini`, `gpt-4.1-mini`, and test presets
- `garak_target_name_custom` (text): optional override for any custom model name
- `garak_probes` (dropdown): includes `promptinject`, `dan`, `encoding`, `xss`, `all`

Production defaults are set to:

- `garak_target_type: openai`
- `garak_target_name: gpt-4o-mini`
- `garak_probes: promptinject`

### Garak API Key Requirements

For production Garak runs against OpenAI models, configure this GitHub Actions secret:

- `OPENAI_API_KEY`

Optional (only if using Anthropic-backed targets):

- `ANTHROPIC_API_KEY`

Without required provider keys, the Garak step runs but will not produce real target results.

### Scan a Specific PR or Branch (Manual)

When running `scan-private-repo.yml` or `scan-public-repo.yml` manually (`workflow_dispatch`), you can target a specific PR or branch:

- **PR scan**: set `pr_number` (example: `123`)
- **Branch/tag/commit scan**: set `target_ref` (examples: `feature/my-branch`, `refs/heads/main`, commit SHA)
- If both are provided, `pr_number` takes precedence

> For `scan-public-repo.yml`, PR targeting (`pr_number`) is intended for GitHub-hosted repositories.

Examples:

```text
pr_number: 123
target_ref: (empty)
```

```text
pr_number: (empty)
target_ref: feature/security-hardening
```

### Scan Specific Directories (Monorepos)

Epyon supports scanning specific subdirectories within repositories:

**Examples:**
```yaml
# Scan only the API directory in a monorepo
Repository: https://github.com/MetroStar/sapphire.git
Subdirectory: apps/sapphire-splunk/sapphire-ai-api

# Scan specific microservice
Repository: https://github.com/company/monorepo.git
Subdirectory: services/auth-service

# Leave subdirectory empty to scan entire repository
Repository: https://github.com/company/app.git
Subdirectory: (empty)
```

**Benefits:**
- 🚀 **Faster**: Only downloads needed files (sparse-checkout)
- 💾 **Less storage**: Doesn't clone entire monorepo
- 🎯 **Focused results**: Security findings for specific component
- 📊 **Better reports**: Scan name uses subdirectory (e.g., `sapphire-ai-api_user_2026-02-06`)

### Scan Integrity and Verification

Every scan automatically generates a **cryptographic manifest** for tamper detection and audit trails:

**Automatic Features:**
- 🔐 **SHA-256 hashes** of all report files
- 👤 **Attribution**: User, hostname, timestamp
- 📌 **Reproducibility**: Tool versions, git commit SHA
- ✅ **Verification**: Detect if reports are modified
- 📋 **STIG compliance**: AU-10, SI-7, AC-16 evidence

**Verify scan integrity:**
```bash
# Verify a scan hasn't been tampered with
./scripts/shell/verify-scan-manifest.sh scans/<scan_id>

# View manifest summary
cat scans/<scan_id>/manifest-summary.txt
```

**Exit codes for CI/CD:**
- `0` - All files verified (✅ Pass)
- `1` - Tampering detected (❌ Fail)
- `2` - Files missing (⚠️ Warning)

See [Scan Manifest Guide](documentation/SCAN_MANIFEST_GUIDE.md) for complete details.

### Add to Your Own Repository

Want automatic scanning on every push and PR?

1. **Download the workflow file** to your repo:
   ```bash
   # In your repository directory
   mkdir -p .github/workflows
   curl -o .github/workflows/epyon-security-scan.yml \
     https://raw.githubusercontent.com/MetroStar/epyon/main/.github/workflows/scan-private-repo.yml
   ```

2. **Commit and push**:
   ```bash
   git add .github/workflows/epyon-security-scan.yml
   git commit -m "Add Epyon security scanning"
   git push
   ```

3. **That's it!** Epyon will now automatically:
   - ✅ Scan every push to `main` or `develop`
   - ✅ Scan all pull requests
   - ✅ Run daily security scans at 2 AM UTC
   - ✅ Comment on PRs with findings
   - ✅ Fail builds on critical vulnerabilities

**How it works:**
The workflow checks out both your repository and Epyon, then runs Epyon's scanners against your code. No need to install anything in your repo!

### What You Get

**📦 Artifacts (downloadable):**
- Interactive HTML dashboard
- Individual tool reports (HTML, Markdown, CSV)
- Raw JSON data
- Complete SBOM

**📊 In Pull Requests:**
- Automated security comments
- Severity summary
- Links to detailed reports

**⚡ Fast Feedback:**
- Quick mode: 2-5 minutes
- Full mode: 10-20 minutes
- Runs in parallel with your CI/CD

👉 **Full documentation**: [.github/README.md](.github/README.md)

## 🏗️ Architecture Components

### 🐳 Approved Base Images

Epyon uses **Docker Hardened Images (DHI)** as the default baseline for container security scans:

**Primary Baseline Image:** `dhi/caddy:latest`

**Why Docker Hardened Images?**
- 🔒 **Distroless**: Minimal attack surface with no package manager
- ✅ **Reduced CVEs**: Significantly fewer vulnerabilities than traditional base images
- 🛡️ **Security First**: Built with security as the primary design principle
- 📜 **FIPS Compliant**: Meets federal security standards
- 🔄 **Regular Updates**: Maintained with latest security patches

**Available DHI Images:**
- `dhi/caddy` - Web server and reverse proxy
- `dhi/node` - Node.js runtime
- `dhi/nginx` - High-performance web server
- `dhi/httpd` - Apache HTTP server
- `dhi/python` - Python runtime

**Configuration:** Baseline images are defined in [configuration/approved-base-images.conf](configuration/approved-base-images.conf)

**More Info:** [Docker Hardened Images Catalog](https://hub.docker.com/hardened-images/catalog)

---

### Current Security Layers (15 Operational):

1. **🔍 TruffleHog** - Multi-target secret detection with filesystem, container, and registry scanning
2. **🦠 ClamAV** - Enterprise antivirus scanning with real-time virus definition updates  
3. **🔒 Checkov** - Infrastructure as Code security scanning (Terraform, Kubernetes, Docker)
4. **🎯 Grype** - Advanced vulnerability scanning with SBOM generation and multi-format support
5. **🐳 Trivy** - Comprehensive security scanner for containers, filesystems, and Kubernetes
6. **⏰ Xeol** - End-of-Life software detection for proactive dependency management
7. **📊 SonarQube** - Code quality analysis with test coverage metrics
8. **⚓ Helm** - Kubernetes chart validation, linting, and packaging
9. **🔍 API Discovery** - Automatic API endpoint detection (OpenAPI, Express, Flask, Django, Next.js App Router)
10. **📦 SBOM Generation** - Complete Software Bill of Materials with Syft (CycloneDX + SPDX)
11. **🤖 Garak** - LLM vulnerability probing and red-team style safety testing
12. **🌐 API Security Testing** - OpenAPI/Swagger validation, REST/GraphQL endpoint security analysis, and authentication testing
13. **📋 STIG Assessment** - AI-powered DISA STIG control evaluation against source code (requires OpenAI API key)
14. **🥒 PickleScan** - ML model serialization safety scanning (`.pkl`, `.pt`, `.bin`, `.h5`, `.ckpt`, etc.)
15. **📄 Model Card Compliance** - HuggingFace model card validation against documentation standards

### Quality Assurance

**✅ Comprehensive Test Coverage:**
- **641 automated tests** across 44 test files (100% pass rate)
- **44 shell scripts** fully covered with unit tests
- **BATS** (Bash Automated Testing System) framework
- Validates scanner integration, orchestration, dashboards, exports, and utilities

**✅ Fixed Critical Bugs:**
- **CVE GHSA-5xr6-xhww-33m4**: Updated artifact download action (v3→v6)
- **API Discovery**: Fixed duplicate `fi` syntax error breaking Next.js detection
- **Checkov Parsing**: Fixed array format handling in dashboard generation

**✅ Baseline Scanning:**
- Scans DHI baseline images (`dhi/caddy:latest`)
- Automated comparison with previous scans
- Detects scanner drift and tool consistency issues
- Scheduled runs every 89 days to maintain artifact retention


## 📁 Directory Structure

```
epyon/
├── .github/workflows/          # GitHub Actions workflows
│   ├── baseline-scan.yml       # DHI baseline scanning (every 89 days)
│   ├── target-scan.yml         # Target repository scanning
│   └── scan-private-repo.yml   # Reusable workflow for any repository
├── scripts/shell/              # Shell scripts (Bash-compatible)
│   ├── run-target-security-scan.sh      # Main orchestrator
│   ├── run-baseline-scan.sh             # Baseline scanning with DHI
│   ├── run-api-discovery.sh             # API endpoint detection
│   ├── generate-security-dashboard.sh   # Interactive HTML dashboard
│   ├── generate-interactive-dashboard.sh # Enhanced dashboard with filtering
│   ├── generate-remediation-suggestions.sh # Automated fix recommendations
│   ├── consolidate-security-reports.sh  # Unified reporting
│   ├── run-sonar-analysis.sh
│   ├── run-trufflehog-scan.sh
│   ├── run-clamav-scan.sh
│   ├── run-helm-build.sh
│   ├── run-checkov-scan.sh
│   ├── run-garak-scan.sh
│   ├── run-trivy-scan.sh
│   ├── run-grype-scan.sh
│   ├── run-xeol-scan.sh
│   ├── run-sbom-scan.sh
│   ├── export-api-discovery.sh
│   ├── export-sbom.sh
│   ├── check-severity-gate.sh
│   ├── update-base-images.sh
│   └── cleanup-scripts.sh
├── tests/shell/                # Test suite (BATS)
│   ├── test-run-*.bats         # Scanner tests (11 files)
│   ├── test-generate-*.bats    # Dashboard/report tests (4 files)
│   ├── test-export-*.bats      # Export tests (2 files)
│   ├── test-check-*.bats       # Validation tests (2 files)
│   ├── test-consolidate-*.bats # Consolidation tests
│   └── run-tests.sh            # Test runner
├── configuration/
│   └── approved-base-images.conf # DHI baseline images
├── documentation/              # Essential documentation
│   ├── SECURITY_REVIEW_AND_TEST_COVERAGE.md # Security review (Feb 2026)
│   ├── SCAN_DIRECTORY_ARCHITECTURE.md       # Scan organization
│   ├── OFFLINE_AIR_GAPPED_SETUP.md         # Air-gapped deployment
│   └── README.md                            # Documentation index
├── scans/                      # Scan results (isolated directories)
│   └── {project}_{user}_{timestamp}/
│       ├── trivy/
│       ├── grype/
│       ├── checkov/
│       ├── trufflehog/
│       ├── clamav/
│       ├── xeol/
│       ├── garak/
│       ├── sbom/
│       ├── api-discovery/
│       └── consolidated-reports/
│           └── dashboards/
│               └── security-dashboard.html
└── baseline/                   # Baseline scan repository
    └── comet-starter/          # MetroStar baseline project
```
│           ├── html-reports/     # Tool-specific HTML reports
│           ├── markdown-reports/ # Summary reports
│           └── csv-reports/      # Data exports
└── documentation/             # Complete setup and architecture guides
    ├── SECURITY_AND_QUALITY_SETUP.md
    └── COMPREHENSIVE_SECURITY_ARCHITECTURE.md
```

## 🚀 Quick Start

### 1. Verify Container Runtime

Before running scans, verify your container runtime is properly configured:

```bash
# Check Docker/Podman/nerdctl detection and permissions
./scripts/shell/check-docker-runtime.sh

# If you see "Container runtime requires elevated permissions"
# Follow the instructions to activate your docker group membership
# (typically requires logging out and back in)

# Temporary workaround: run with sudo
sudo ./scripts/shell/check-docker-runtime.sh
```

**Supported Container Runtimes:**
- Docker (Docker Engine, Docker Desktop)
- Podman (rootless or rootful)
- nerdctl (containerd CLI)
- Alternative Docker distributions (Colima, Rancher Desktop, OrbStack)

All scripts automatically detect and use whichever runtime is available.

### 2. Target-Aware Security Scanning (Recommended)

Scan any external application or directory with comprehensive security analysis and centralized output:

```bash
# Unix/Linux/macOS
# Quick scan (4 core security tools: TruffleHog, ClamAV, Grype, Trivy)
./scripts/shell/run-target-security-scan.sh "/path/to/your/project" quick

# Full scan (all 12 layers)
./scripts/shell/run-target-security-scan.sh "/path/to/your/project" full

# Scan a Git repository directly
./scripts/shell/run-target-security-scan.sh "https://github.com/user/repo.git" full

# Image-focused security scan (6 container tools)
./scripts/shell/run-target-security-scan.sh "/path/to/your/project" images

# Analysis-only mode (existing reports)
./scripts/shell/run-target-security-scan.sh "/path/to/your/project" analysis

# Windows with WSL (Windows Subsystem for Linux)
# Ensure you're in the epyon repository directory
cd C:\path\to\epyon

# Quick scan - local directory
wsl ./scripts/shell/run-target-security-scan.sh "/mnt/c/path/to/your/project" quick

# Full scan - local directory (convert Windows paths to WSL format)
wsl ./scripts/shell/run-target-security-scan.sh "/mnt/c/Users/username/Desktop/project" full

# Full scan - Git repository
./scripts/shell/run-target-security-scan.sh "https://github.com/user/repo.git" full

# Image-focused security scan
./scripts/shell/run-target-security-scan.sh "/path/to/project" images

# Scan specific subdirectory within a Git repository (sparse-checkout)
./scripts/shell/run-target-security-scan.sh --subdir apps/api "https://github.com/user/repo.git" full
./scripts/shell/run-target-security-scan.sh --subdir apps/sapphire-splunk/sapphire-ai-api "https://github.com/MetroStar/sapphire.git"
```

**Windows Users - Path Conversion:**
When using WSL, Windows paths must be converted to WSL format:
- Windows: `C:\Users\username\project` → WSL: `/mnt/c/Users/username/project`
- Windows: `D:\repos\myapp` → WSL: `/mnt/d/repos/myapp`

**Windows Users - WSL Prerequisites:**
```bash
# 1. Enable WSL (if not already enabled)
wsl --install

# 2. Ensure Docker Desktop is running with WSL 2 backend
# Open Docker Desktop → Settings → Resources → WSL Integration
# Enable integration with your WSL distribution

# 3. Verify Docker is accessible from WSL
wsl docker --version
wsl docker ps

# 4. Fix line endings for shell scripts (one-time setup)
wsl bash -c "find ./scripts/shell -name '*.sh' -type f -exec sed -i 's/\r$//' {} \;"
wsl bash -c "chmod +x ./scripts/shell/*.sh"
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
./scripts/shell/open-latest-dashboard.sh

# Or manually open latest
LATEST_SCAN=$(ls -t scans/ | head -1)
open scans/$LATEST_SCAN/consolidated-reports/dashboards/security-dashboard.html

# Regenerate dashboard for latest scan (if needed)
./scripts/shell/consolidate-security-reports.sh  # Auto-detects latest scan
```

### Cross-Platform Script Execution

**Unix/Linux/macOS (Shell):**
```bash
cd /path/to/epyon

# Full scan - all 15 layers (recommended)
./scripts/shell/run-target-security-scan.sh "/path/to/project" full

# Individual Layer Execution using TARGET_DIR method:

# Layer 1: Secret Detection (TruffleHog)
TARGET_DIR="/path/to/project" ./scripts/shell/run-trufflehog-scan.sh filesystem

# Layer 2: Antivirus Scanning (ClamAV)  
TARGET_DIR="/path/to/project" ./scripts/shell/run-clamav-scan.sh

# Layer 3: Infrastructure Security (Checkov) - Directory scanning fallback
TARGET_DIR="/path/to/project" ./scripts/shell/run-checkov-scan.sh filesystem

# Layer 4: Vulnerability Scanning (Grype)
TARGET_DIR="/path/to/project" ./scripts/shell/run-grype-scan.sh filesystem

# Layer 5: Container Security (Trivy)
TARGET_DIR="/path/to/project" ./scripts/shell/run-trivy-scan.sh filesystem

# Layer 6: End-of-Life Detection (Xeol)
TARGET_DIR="/path/to/project" ./scripts/shell/run-xeol-scan.sh filesystem

# Layer 7: Code Quality Analysis (SonarQube) 
TARGET_DIR="/path/to/project" ./scripts/shell/run-sonar-analysis.sh

# Layer 8: Helm Chart Building - Interactive ECR authentication
TARGET_DIR="/path/to/project" ./scripts/shell/run-helm-build.sh

# Layer 9: Anchore Container Analysis
TARGET_DIR="/path/to/project" ./scripts/shell/run-anchore-scan.sh

# Layer 10: SBOM Generation (Syft - CycloneDX + Syft JSON)
TARGET_DIR="/path/to/project" ./scripts/shell/run-sbom-scan.sh

# Layer 11: LLM Vulnerability Probing (Garak)
TARGET_DIR="/path/to/project" ./scripts/shell/run-garak-scan.sh

# Layer 14: Pickle/Serialization Safety (HuggingFace mode)
TARGET_DIR="/path/to/model-repo" ./scripts/shell/run-picklescan.sh

# Layer 15: Model Card Compliance (HuggingFace mode)
TARGET_DIR="/path/to/model-repo" ./scripts/shell/run-modelcard-check.sh

# Report Consolidation (integrated into complete scan)
./scripts/shell/consolidate-security-reports.sh
```

> **Windows Users**: Use WSL (Windows Subsystem for Linux) with the bash commands above. See the WSL prerequisites section for setup instructions. Native PowerShell is not supported — all Epyon scripts are Bash-based.

### Baseline Scanning for Scanner Drift Detection

Epyon provides two approaches for baseline security scanning:

#### 1. GitHub Actions Baseline Workflow (Recommended for Teams)

**Create security baselines with git commit tracking** for comparing security posture over time:

**Setup:**
```bash
# Add baseline workflow to your repository
mkdir -p .github/workflows
curl -o .github/workflows/baseline-scan.yml \
  https://raw.githubusercontent.com/MetroStar/epyon/main/.github/workflows/baseline-scan.yml

git add .github/workflows/baseline-scan.yml
git commit -m "Add Epyon baseline security scanning"
git push
```

**Usage:**
1. Navigate to **Actions** → **Baseline Security Scan** in your repository
2. Click **Run workflow** (manual trigger only)
3. Download artifacts containing:
   - Git commit SHA for tracking
   - Baseline metadata JSON
   - Reduced scan reports (SBOM, Secrets, IaC, Trivy, Grype)
   - Interactive security dashboard

**Baseline Workflow Features:**
- 🎯 **Git SHA Capture**: Records exact commit for future comparison
- 📌 **Metadata Tracking**: Creates `baseline-metadata.json` with SHA and timestamp
- 🔄 **Scan Naming**: Directory named `baseline_{repo}_{sha}_{user}_{timestamp}`
- 📊 **Reduced Layers**: Runs 5 essential layers (excludes SonarQube, ClamAV, Helm, Xeol, Anchore, API)
- 💾 **90-Day Retention**: Artifacts stored for long-term baseline comparison
- 🔒 **Portable**: Works in any repository by checking out MetroStar/epyon

#### 2. Local Baseline Scanning (Recommended for Scanner Validation)

**For validating scanner consistency and detecting tool drift:**

```bash
# Run initial baseline scan (clones comet-starter if needed)
./scripts/shell/run-baseline-scan.sh

# Update repository and run new baseline scan
./scripts/shell/run-baseline-scan.sh --update-repo

# Mark the most recent scan as official baseline (with SHA256 hash)
./scripts/shell/run-baseline-scan.sh --set-baseline

# Mark a specific scan as official baseline
./scripts/shell/run-baseline-scan.sh --set-baseline comet-starter_rnelson_2026-01-22_08-41-30

# Compare latest scan with official baseline
./scripts/shell/run-baseline-scan.sh --compare

# List all baseline scans (★ marks official baseline)
./scripts/shell/run-baseline-scan.sh --list
```

**Local Baseline Features:**
- 🎯 **Consistent Reference**: Uses MetroStar/comet-starter as standard baseline application
- 🔐 **SHA256 Hashing**: Cryptographic hash of security findings for integrity verification
- 📌 **Official Baseline**: Mark and track a specific scan as the authoritative reference
- 📊 **Drift Detection**: Compare scans over time to detect tool inconsistencies
- ✅ **0% Error Margin**: Validate identical results when scanning the same codebase
- 📈 **Historical Tracking**: All baseline scans preserved with timestamps and commit info
- 🔍 **Visual Comparison**: Automatically opens dashboards side-by-side for analysis
- 🔒 **Integrity Verification**: Baseline reference file with hash prevents tampering

**Baseline Reference File** (`baseline/.baseline-reference`):
```bash
BASELINE_SCAN_ID="comet-starter_rnelson_2026-01-22_08-41-30"
BASELINE_SCAN_PATH="scans/comet-starter_rnelson_2026-01-22_08-41-30"
BASELINE_HASH="c5096e8ed66e4b612c4b5629ac9e6fec1a1db679f184d2d515a0240189b34629"
BASELINE_HASH_ALGORITHM="SHA256"
BASELINE_REPO_COMMIT="a46f32b"
BASELINE_SET_DATE="2026-01-22T14:47:55Z"
BASELINE_SET_BY="rnelson"
```

**Use Cases:**
- **GitHub Actions**: Compare security posture between releases, track vulnerability trends, establish benchmarks
- **Local Scanning**: Validate scanner updates, ensure tool signatures are current, detect configuration drift
- **Both**: Compliance audit trails, verify consistent results, support Waypoint 1 ("0% margin of error")

**Workflow Example:**
```bash
# 1. Run initial baseline and set it as official
./scripts/shell/run-baseline-scan.sh
./scripts/shell/run-baseline-scan.sh --set-baseline

# 2. After tool updates, run new scan and compare
./scripts/shell/run-baseline-scan.sh --update-repo
./scripts/shell/run-baseline-scan.sh --compare

# 3. If results are identical, no drift detected ✅
# 4. If results differ, investigate scanner drift ⚠️
```

### Security Dashboard Access

```bash
# Open latest scan's interactive dashboard
LATEST_SCAN=$(ls -t scans/ | head -1)
open scans/$LATEST_SCAN/consolidated-reports/dashboards/security-dashboard.html

# Or specify a particular scan
open scans/comet_rnelson_2025-11-25_09-40-22/consolidated-reports/dashboards/security-dashboard.html

# Open latest baseline scan dashboard
LATEST_BASELINE=$(ls -t scans/comet-starter_* | head -1)
open $LATEST_BASELINE/consolidated-reports/dashboards/security-dashboard.html

# Open official baseline dashboard (if set)
if [ -f baseline/.baseline-reference ]; then
    source baseline/.baseline-reference
    open "${BASELINE_DASHBOARD}"
fi
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
- **15-Layer Security Model**: Complete DevSecOps pipeline coverage
- **Real-Time Scanning**: Live vulnerability databases with automatic updates
- **Multi-Format Analysis**: Source code, containers, infrastructure, dependencies
- **Compliance Support**: NIST, OWASP, CIS benchmarks integration

### � Intelligent Severity Gates
- **Container Exclusion**: Container image vulnerabilities marked informational only (not included in build failures)
- **Filesystem Focus**: Build failures based on application code and filesystem vulnerabilities
- **Configurable Thresholds**: Default fails on Critical and High severity findings
- **Warning-Only Mode**: Optional mode to report vulnerabilities without failing builds
- **Granular Control**: Separate controls for critical vs high severity findings

**What's Excluded from Build Failures:**
- ❌ Container base image vulnerabilities (Grype image scans, Trivy base scans)
- ℹ️ These are still scanned and reported as "informational only"

**What Causes Build Failures:**
- ✅ Application code vulnerabilities (Grype SBOM scans)
- ✅ Filesystem vulnerabilities (Trivy filesystem scans)
- ✅ Exposed secrets (TruffleHog)
- ✅ IaC misconfigurations (Checkov)

**Rationale:** Container base image vulnerabilities are often outside developer control and require coordinated updates. By excluding them from build failures, teams can focus on vulnerabilities they can immediately remediate while still tracking container security separately.

### �📊 Advanced Reporting & Analytics
- **Interactive Dashboards**: Rich HTML reports with filtering and search
- **Trend Analysis**: Security posture tracking over time
- **Executive Summaries**: C-level reporting with risk prioritization
- **Integration APIs**: JSON output for CI/CD pipeline integration

### ⚡ Performance & Reliability
- **Graceful Failure Handling**: Continues scanning on individual tool failures
- **Resource Optimization**: Efficient scanning with configurable parallelization
- **Large Codebase Support**: Tested on 448MB+ projects with 63K+ files
- **Platform Support**: Unix/Linux/macOS with shell scripts

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
- **Anchore**: Container and software composition analysis

---

## 🐍 Python & AI Application Security

### Current Capabilities

Epyon provides **excellent security coverage for Python applications** with comprehensive scanning across traditional security domains:

#### ⭐⭐⭐⭐⭐ Python Security Coverage (5/5)

| Security Domain | Tools | Coverage |
|----------------|-------|----------|
| **Dependency Vulnerabilities** | Grype, Trivy | ✅ Excellent - Scans Python packages, requirements.txt, Pipfile, poetry.lock |
| **Code Quality** | SonarQube | ✅ Excellent - Python-specific rules, complexity analysis, code smells |
| **Secret Detection** | TruffleHog | ✅ Excellent - API keys, tokens, credentials in Python code |
| **End-of-Life Libraries** | Xeol | ✅ Excellent - Identifies deprecated Python packages |
| **Infrastructure Security** | Checkov | ✅ Excellent - Terraform, Kubernetes, Docker for Python deployments |
| **Container Security** | Trivy, Grype | ✅ Excellent - Python container images and base layers |

**What Works Great:**
- 🐍 **Python Package Scanning**: Automatic detection of `requirements.txt`, `Pipfile.lock`, `poetry.lock`, `setup.py`
- 🔒 **CVE Detection**: Real-time vulnerability databases for PyPI packages
- 📊 **Code Quality**: SonarQube's Python analyzer with comprehensive rule sets
- 🔑 **Secret Scanning**: Detection of hardcoded credentials, API keys, tokens
- 🐳 **Container Images**: Full scanning of Python base images (python:3.x, alpine, etc.)

#### ⭐⭐⭐⭐⭐ AI/ML Security Coverage (5/5)

**Current AI/ML Capabilities:**
- ✅ **Python ML Libraries**: Scans vulnerabilities in TensorFlow, PyTorch, scikit-learn, etc.
- ✅ **Dependency Security**: Detects CVEs in ML framework dependencies
- ✅ **Container Security**: Scans ML model serving containers (TensorFlow Serving, TorchServe)
- ✅ **Code Quality**: Analyzes ML training scripts and inference code
- ✅ **LLM Safety (Garak)**: Prompt injection, jailbreaking, and safety probe testing (Layer 11)
- ✅ **ML Model Scanning (PickleScan)**: Detects malicious opcodes in `.pkl`, `.pt`, `.bin`, `.h5`, `.ckpt`, and other serialization formats (Layer 14)
- ✅ **Model Card Compliance**: Validates HuggingFace model cards against documentation standards (Layer 15)
- ✅ **STIG Assessment**: AI-powered static code review against DISA STIG controls (Layer 13)

### Recommended Usage for Python/AI Projects

#### Standard Python Application
```bash
# Comprehensive Python security scan
./scripts/shell/run-target-security-scan.sh "/path/to/python-app" full

# Quick Python vulnerability check
./scripts/shell/run-target-security-scan.sh "/path/to/python-app" quick
```

#### Python ML/AI Application
```bash
# Full HuggingFace scan — standard layers + pickle safety + model card compliance
./scripts/shell/run-target-security-scan.sh "/path/to/ml-app" huggingface

# Standard full scan — Python deps, containers, code quality, secrets, STIG
./scripts/shell/run-target-security-scan.sh "/path/to/ml-app" full

# Container-focused
./scripts/shell/run-target-security-scan.sh "/path/to/ml-app" images
```

### Example Scan Output (Python Application)

```bash
✅ TruffleHog: 0 secrets detected (scanned Python source files)
✅ Grype: 12 vulnerabilities in Python packages (3 High, 9 Medium)
   - Django 3.2.0 → CVE-2023-12345 (High) - Upgrade to 3.2.5
   - requests 2.25.0 → CVE-2023-67890 (Medium) - Upgrade to 2.28.1
✅ SonarQube: 85.2% code coverage, 15 code smells (Python-specific rules)
✅ Trivy: Python:3.9-slim base image - 4 OS vulnerabilities
✅ Xeol: 2 EOL packages detected (Flask 1.1.x, Jinja2 2.x)
```

### Best Practices for Python/AI Security

1. **Regular Scanning**: Run `full` scans weekly for Python applications
2. **Container Hygiene**: Use minimal base images (python:3.x-slim, alpine)
3. **Dependency Pinning**: Lock versions in `requirements.txt` or `poetry.lock`
4. **Secret Management**: Never commit API keys - use environment variables
5. **ML Model Security**: Store trained models separately from code repositories
6. **LLM API Security**: Rotate API keys regularly, use scoped permissions
7. **Code Review**: Use SonarQube quality gates for Python code
8. **SBOM Compliance**: Export SBOM in standard formats for supply chain security

### 📦 SBOM Pipeline & Supply Chain Security

Epyon generates a CycloneDX SBOM at scan time and automatically enriches it with four layers of supply chain analysis.

#### SBOM Output

Each scan writes `scans/{scan_id}/sbom/sbom-{scan_id}.cyclonedx.json` — a standards-compliant CycloneDX JSON file compatible with Dependency-Track, Snyk, JFrog Xray, and OWASP OSS Index.

#### Supply Chain Enrichment Layers

| Layer | Script | What it does |
|-------|--------|-------------|
| **License Compliance** | `check-severity-gate.sh` | Fails build on copyleft licenses (GPL, AGPL, SSPL, EUPL, CDDL, MPL, LGPL) detected in CycloneDX SBOM |
| **Dependency Lineage** | `generate-sbom-lineage.sh` | Builds parent→child dependency tree via `pipdeptree` (Python) and `npm ls` (Node.js); enriches CycloneDX `dependencies[]` |
| **Hash Verification** | `verify-sbom-hashes.sh` | Cross-references SHA-256 of all `pkg:pypi` components against PyPI published digests; flags tampered packages |
| **VEX Suppressions** | `run-vex.sh` | Manage OpenVEX 0.2.0 justification documents; apply to Grype results to suppress accepted false positives |

#### VEX Workflow

```bash
# Create a justified suppression for a CVE
./scripts/shell/run-vex.sh create CVE-2024-1234 requests 2.31.0 vulnerable_code_not_in_execute_path

# List all VEX statements for a target
./scripts/shell/run-vex.sh list

# Apply VEX suppressions to Grype results
./scripts/shell/run-vex.sh apply
```

VEX documents are stored in `{target_dir}/.epyon/vex/` and applied automatically during `consolidate-security-reports.sh`.

#### Dashboard Integration

All enrichment data surfaces inline in the SBOM accordion on the security dashboard — no separate tabs needed. Each package row shows:
- License badge (green = allowed, red = copyleft denied, yellow = unknown)
- Dependency counts (↓ deps pulled in, ↑ packages that use it)
- Hash verification status (PyPI packages only)
- VEX suppression indicator (if any CVEs have been justified)

#### Integration Examples

**Dependency-Track (Vulnerability Analysis):**
```bash
curl -X POST https://dependency-track.example.com/api/v1/bom \
  -H "X-Api-Key: YOUR_API_KEY" \
  -F "project=PROJECT_UUID" \
  -F "bom=@scans/{scan_id}/sbom/sbom-{scan_id}.cyclonedx.json"
```

**Snyk Vulnerability Scanning:**
```bash
snyk test --file=scans/midas_user_2026-01-22/sbom/exports/sbom.cyclonedx.json
```

**JFrog Xray:**
```bash
# Import via Xray UI: Settings → SBOM → Upload
# Select: CycloneDX JSON or SPDX JSON
```

#### SBOM Features

- **✅ Comprehensive Package Detection**: All Python packages from requirements.txt, requirements.lock, poetry.lock, Pipfile.lock
- **✅ Multi-Ecosystem Support**: Python, Node.js, Go, Java, Ruby, Rust, OS packages
- **✅ Version Pinning**: Exact package versions for reproducible builds
- **✅ License Information**: Software license metadata included
- **✅ Dependency Relationships**: Package dependency tree mapping
- **✅ PURL Identifiers**: Package URL (PURL) for universal identification
- **✅ Compliance Ready**: NTIA Minimum Elements compliant

### 🌐 API Discovery Export & Integration

Epyon discovers and catalogs APIs in your applications, preparing comprehensive inventories for security scanning and integration.

#### Discovered API Types

| Discovery Method | Sources | Frameworks Supported |
|-----------------|---------|---------------------|
| **OpenAPI/Swagger Specs** | `openapi.json`, `swagger.yaml` | All OpenAPI 2.0/3.0 compliant |
| **Python Routes** | Flask, Django, FastAPI decorators | Flask, Django REST, FastAPI |
| **Node.js Routes** | Express, Next.js, Fastify routes | Express, Next.js, Fastify, Nest.js |
| **Java Routes** | Spring annotations | Spring Boot, JAX-RS |
| **GraphQL Schemas** | `schema.graphql`, `.gql` files | Apollo, GraphQL Yoga |

#### Export Commands

```bash
# Export latest scan API discovery
./scripts/shell/export-api-discovery.sh

# Export specific scan
./scripts/shell/export-api-discovery.sh midas_rnelson_2026-01-22_10-28-22

# Export and copy to Desktop for easy access
./scripts/shell/export-api-discovery.sh --desktop

# Export to custom directory
./scripts/shell/export-api-discovery.sh -o /tmp/api-exports

# View export options
./scripts/shell/export-api-discovery.sh --help
```

#### Export Location

API discovery exports are saved to:
- **Scan Directory**: `scans/{scan_id}/api/exports/api-discovery-{scan_id}.json`
- **Desktop Copy** (with `--desktop` flag): `~/Desktop/api-discovery/`

#### Integration Examples

**Postman Collection Import:**
```bash
# Open Postman → Import → Select api-discovery-{scan_id}.json
# Postman auto-detects endpoints and creates collection
```

**Swagger UI:**
```bash
# Extract OpenAPI specs from discovery
jq '.discovery_methods.openapi_specs[]' scans/midas_user_2026-01-22/api/exports/api-discovery-*.json

# Serve with Swagger UI
docker run -p 80:8080 -e SWAGGER_JSON=/api/openapi.json \
  -v $(pwd)/scans/midas_user_2026-01-22/api:/api \
  swaggerapi/swagger-ui
```

**API Security Testing:**
```bash
# Extract all endpoints for security scanning
jq -r '.discovery_methods.code_routes[][] | "\(.method) \(.endpoint)"' \
  scans/midas_user_2026-01-22/api/exports/api-discovery-*.json

# Feed to OWASP ZAP or Burp Suite for API testing
```

**Custom Integration:**
```bash
# Parse with jq for automation
jq '.summary' api-discovery-*.json
jq '.discovery_methods.code_routes.python[]' api-discovery-*.json
jq '.summary.frameworks_detected' api-discovery-*.json
```

#### API Discovery Features

- **✅ Code-Level Detection**: Analyzes source code for API route definitions
- **✅ Multi-Framework Support**: Python, Node.js, Java web frameworks
- **✅ OpenAPI Spec Discovery**: Finds and catalogs API specifications
- **✅ GraphQL Schema Detection**: Identifies GraphQL endpoints and schemas
- **✅ Method & Path Extraction**: HTTP methods (GET, POST, etc.) and URL paths
- **✅ Authentication Detection**: Identifies protected routes and auth requirements
- **✅ Framework Detection**: Automatically identifies API frameworks in use
- **✅ Export Ready**: JSON format for integration with security tools

#### Dashboard Integration

The security dashboard displays discovered APIs with:
- Total endpoints found badge
- Framework detection summary
- Route breakdown by language
- OpenAPI specification links
- One-click export functionality

### Limitations & Workarounds

**Current Limitation**: No adversarial robustness testing  
**Workaround**: Integrate IBM ART in ML training pipelines

---

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

### Complete Documentation Library
- **[documentation/README.md](documentation/README.md)** - Documentation index and navigation guide
- **[documentation/SCAN_DIRECTORY_ARCHITECTURE.md](documentation/SCAN_DIRECTORY_ARCHITECTURE.md)** - Scan output organization and isolation model
- **[documentation/SCAN_MANIFEST_GUIDE.md](documentation/SCAN_MANIFEST_GUIDE.md)** - Cryptographic manifest creation and verification
- **[documentation/DEPLOYMENT_SUMMARY_MANIFEST_SYSTEM.md](documentation/DEPLOYMENT_SUMMARY_MANIFEST_SYSTEM.md)** - Manifest system deployment and validation results
- **[documentation/IGNORE_RULES_GUIDE.md](documentation/IGNORE_RULES_GUIDE.md)** - `.epyon-ignore.yml` suppression configuration guide
- **[documentation/DEDUPLICATION_IMPLEMENTATION.md](documentation/DEDUPLICATION_IMPLEMENTATION.md)** - Finding deduplication logic and implementation details
- **[documentation/SECURITY_REVIEW_AND_TEST_COVERAGE.md](documentation/SECURITY_REVIEW_AND_TEST_COVERAGE.md)** - Security review and test coverage analysis
- **[documentation/STIG_COMPLIANCE_GUIDE.md](documentation/STIG_COMPLIANCE_GUIDE.md)** - STIG and RMF compliance documentation
- **[documentation/OFFLINE_AIR_GAPPED_SETUP.md](documentation/OFFLINE_AIR_GAPPED_SETUP.md)** - Air-gapped and offline deployment guide
- **[documentation/AI Integration Strategy for Epyon.md](documentation/AI%20Integration%20Strategy%20for%20Epyon.md)** - CIO roadmap for AI/ML integration opportunities

## 🏆 Achievement Summary

✅ **15-Layer Security Architecture** — TruffleHog, ClamAV, Checkov, Grype, Trivy, Xeol, SonarQube, Helm, API Discovery, SBOM, Garak, API Security Testing, STIG Assessment, PickleScan, Model Card Compliance  
✅ **Multi-Target Scanning** — Local directories, Git repositories, HuggingFace models, monorepo subdirectories  
✅ **FastAPI Web UI** — Run scans, browse results, view STIG findings, manage suppressions  
✅ **AI-Powered Analysis** — STIG control assessment and scan summaries via OpenAI  
✅ **Production-Ready** — Docker-based, container-runtime-agnostic, cross-platform  
✅ **641 Automated Tests** — BATS test suite covering all 44 scanner scripts

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
- **Total Tests**: 641
- **Scripts Covered**: 44 (all scan scripts)
- **Success Rate**: 100%

Tests validate:
- Script existence and permissions
- Proper structure and shebang
- Required functions and dependencies
- Docker integration
- Help documentation
- Tool-specific features

### Coverage Philosophy

We use **structural testing** for shell scripts, which is the industry-standard approach:

- ✅ **100% File Coverage** - Every script has a corresponding test file
- ✅ **107 Test Assertions** - Comprehensive validation of script structure and behavior
- ✅ **Docker Integration Verification** - All containerized tool interactions tested
- ✅ **Function Existence Checks** - Critical functions validated in each script

**Why Structural Testing for Bash?**

Line-by-line execution coverage tools (like kcov) are **not used** for shell scripts because:
- **Conflicts with tooling**: Can interfere with SonarQube analysis and other tools
- **Not industry standard**: Shell script testing focuses on structure/integration over execution paths
- **Diminishing returns**: Structural validation provides sufficient confidence for bash automation
- **Maintenance burden**: Execution coverage adds complexity without proportional value

This approach aligns with enterprise DevOps practices where shell scripts are tested for:
- Correct structure and dependencies
- Proper error handling patterns
- Integration with external tools (Docker, AWS, etc.)
- Expected function definitions

For detailed testing documentation, see [tests/shell/README.md](tests/shell/README.md).

## 🔄 Enterprise Maintenance & Operations

### 📊 Regular Security Operations
```bash
# Weekly comprehensive enterprise scan
./scripts/shell/run-target-security-scan.sh "/path/to/enterprise/app" full

# Daily quick security check  
./scripts/shell/run-target-security-scan.sh "/path/to/enterprise/app" quick

# Container security monitoring
./scripts/shell/run-target-security-scan.sh "/path/to/enterprise/app" images
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
- **[documentation/README.md](documentation/README.md)** - Documentation index and navigation guide
- **[documentation/SCAN_DIRECTORY_ARCHITECTURE.md](documentation/SCAN_DIRECTORY_ARCHITECTURE.md)** - Scan output organization and isolation model
- **[documentation/SCAN_MANIFEST_GUIDE.md](documentation/SCAN_MANIFEST_GUIDE.md)** - Cryptographic manifest creation and verification
- **[documentation/DEPLOYMENT_SUMMARY_MANIFEST_SYSTEM.md](documentation/DEPLOYMENT_SUMMARY_MANIFEST_SYSTEM.md)** - Manifest system deployment and validation
- **[documentation/IGNORE_RULES_GUIDE.md](documentation/IGNORE_RULES_GUIDE.md)** - `.epyon-ignore.yml` suppression configuration guide
- **[documentation/DEDUPLICATION_IMPLEMENTATION.md](documentation/DEDUPLICATION_IMPLEMENTATION.md)** - Finding deduplication logic and implementation
- **[documentation/SECURITY_REVIEW_AND_TEST_COVERAGE.md](documentation/SECURITY_REVIEW_AND_TEST_COVERAGE.md)** - Security review and test coverage analysis
- **[documentation/STIG_COMPLIANCE_GUIDE.md](documentation/STIG_COMPLIANCE_GUIDE.md)** - STIG and RMF compliance documentation
- **[documentation/OFFLINE_AIR_GAPPED_SETUP.md](documentation/OFFLINE_AIR_GAPPED_SETUP.md)** - Air-gapped and offline deployment guide
- **[documentation/AI Integration Strategy for Epyon.md](documentation/AI%20Integration%20Strategy%20for%20Epyon.md)** - CIO roadmap for AI/ML integration opportunities

### 🎯 Quick Reference Commands
```bash
# Complete enterprise security scan
./scripts/shell/run-target-security-scan.sh "/path/to/project" full

# Open latest scan dashboard
LATEST_SCAN=$(ls -t scans/ | head -1)
open scans/$LATEST_SCAN/consolidated-reports/dashboards/security-dashboard.html

# Individual layer execution (TARGET_DIR method)
TARGET_DIR="/path/to/project" ./scripts/shell/run-[tool]-scan.sh

# SonarQube with LCOV coverage format
TARGET_DIR="/path/to/project" ./scripts/shell/run-sonar-analysis.sh

# CI/CD integration
export TARGET_DIR="/workspace" && ./scripts/shell/run-target-security-scan.sh "$TARGET_DIR" full
```

---

**Created**: November 3, 2025  
**Updated**: May 14, 2026  
**Version**: 3.2.0  
**Status**: ✅ **ENTERPRISE PRODUCTION READY**

### 🆕 Latest Updates (v3.2.0) - STIG Sortable Table, SBOM Improvements & UI Fixes
- ✅ **STIG findings table sortable**: all columns (STIG #, Severity, Status, Confidence, Title) now sortable with click-to-toggle asc/desc; active column highlighted
- ✅ **STIG applicability accuracy**: `build_app_profile` now detects web frameworks, session/auth signals, UI files, and login/logout routes so session-management controls are correctly scoped
- ✅ **Interactive SBOM table**: sort, search, type filter, and path column
- ✅ **Suppressed findings section** in web UI
- ✅ **Run Scan URL pre-fill**
- ✅ **Scan pipeline visibility fixes**: Checkov output buffering, Docker VirtioFS mount failures
- ✅ **Deduplication of suppressed findings** across both dashboards

### 🆕 Previous Updates (v3.1.0) - HuggingFace Scanning Suite & STIG Confidence
- ✅ **Layer 14 — Pickle/Serialization Safety** (`run-picklescan.sh`): scans ML model repos for malicious pickle opcodes in `.pkl`, `.pt`, `.pth`, `.bin`, `.ckpt`, `.npy`, `.npz`, `.joblib`, `.h5`, `.hdf5` files using `picklescan`; outputs normalized `picklescan/picklescan-results.json`; auto-installs via pip
- ✅ **Layer 15 — Model Card Compliance** (`run-modelcard-check.sh`): validates HuggingFace-style model cards against 10 documentation standards (required sections, YAML frontmatter fields, safetensors format recommendation); flexible pattern matching handles diverse card conventions
- ✅ **`scan-huggingface.yml` workflow**: dedicated GitHub Actions entry-point for scanning HuggingFace model, Space, and dataset repositories; resolves HF URLs automatically by type; supports optional Garak LLM probing for model repos
- ✅ **`huggingface` scan mode**: new scan mode in `run-epyon-scan-ci.sh` that enables Layers 14–15 by default and skips irrelevant layers; added to all scan mode dropdowns
- ✅ **STIG confidence scoring**: each STIG control now receives an AI-generated confidence score (0–100) based on evidence quality, specificity, and certainty; displayed as color-coded badges in the web UI and appended to `.md`/`.cklb` findings
- ✅ **HF scan result cards in web UI**: scan detail view renders dedicated cards for picklescan (file count, infected list) and model card compliance (passed/failed/warned checks with per-finding detail)
- ✅ **Scan type labels**: scan history rows now show accurate type labels ("Hugging Face scan", "STIG scan", etc.) with HF-specific status badges (🥒 pickle safety, 📋 model card compliance)
- ✅ **Scan info panel on Run Scan page**: two-column layout shows which layers run for each scan mode, with API key notices for AI-powered layers

### 🆕 Previous Updates (v3.0.0) - CycloneDX SBOM & Supply Chain Security
- ✅ **CycloneDX SBOM at scan time**: `run-sbom-scan.sh` now outputs both `syft-json` and `cyclonedx-json` simultaneously — no silent post-hoc conversion failures
- ✅ **License compliance gate**: `check-severity-gate.sh` reads CycloneDX SBOM and fails the build on copyleft licenses (GPL, AGPL, SSPL, EUPL, CDDL, MPL, LGPL); configurable denied-license regex
- ✅ **Supply chain hash verification**: `verify-sbom-hashes.sh` cross-references SHA-256 of all `pkg:pypi` components against PyPI published digests; exits 2 on tampered packages; outputs `sbom/hash-verification.json`
- ✅ **Dependency lineage**: `generate-sbom-lineage.sh` builds parent→child dependency trees via `pipdeptree` (Python) and `npm ls` (Node.js); enriches the CycloneDX SBOM in-place with a `dependencies[]` array
- ✅ **VEX document management**: `run-vex.sh` creates, lists, and applies OpenVEX 0.2.0 justification documents; suppresses accepted false positives from Grype results
- ✅ **Consolidated SBOM panel**: all enrichment data (license compliance, lineage, hash verification, VEX) shown inline per-package within the SBOM dashboard accordion

### 🆕 Previous Updates (v2.9.0) - Dashboard Metrics Charts & Checkov Fix
- ✅ **Dual metrics charts**: dashboard now renders two separate panels — "90 Day Vulnerability Metrics" (stacked severity bars) and "PR Activity & CVE Discipline" (PR bars + net CVE change line with red/green data points)
- ✅ **PR/CVE discipline analysis**: Chart 2 story banner automatically diagnoses whether PR merges correlate with rising CVE counts; stat cards show 90d and 7d PR totals, net CVE change, and average CVE delta on PR days
- ✅ **Default branch auto-detection**: `epyon-scan.yml` queries the GitHub API to resolve the repo's actual default branch rather than assuming `main`
- ✅ **Checkov findings now counted**: fixed `jq` query in `generate-scan-findings-summary.sh` to handle Checkov 3.x array-format output; failures now correctly flow into `total_critical/high/medium/low`

### 🆕 Previous Updates (v2.8.0) - Cross-Scan Metrics
- ✅ **`get-scan-metrics.sh`**: aggregates findings across all local scan directories into a JSON time-series and color-coded terminal table, filterable by target, user, and date range
- ✅ **GitHub Actions fetch (`--from-github`)**: pulls metrics from `metrics-{scan_id}` artifacts via `gh` CLI; auto-detects repo from git remote; `--repos` supports multi-repo aggregation; `--fetch-legacy` handles pre-2.8.0 full-scan artifact zips
- ✅ **Lightweight metrics artifact per CI run**: `epyon-scan.yml` uploads a tiny `scan-metrics-row.jsonl` with 90-day retention so findings history outlives full-scan artifact expiry
- ✅ **Local metrics cache**: downloaded GitHub rows cached in `metrics/github-cache/` for fast repeat invocations

### 🆕 Previous Updates (v2.7.0) - Jira Integration & Garak Controls
- ✅ **Jira ticket creation for all four severity tiers**: critical, high, medium, and low findings each generate deduplicated Jira tickets
- ✅ **Jira deduplication**: existing open tickets are detected by label before creating new ones
- ✅ **Garak workflow controls**: `workflow_dispatch` exposes target type, model preset, and probe set as UI controls
- ✅ **Garak run summary**: CI step summary now includes Garak status, target, probe set, hit count, and exit code

### 🆕 Previous Updates (v2.6.x) - GitHub Actions Architecture
- ✅ **Sonar Project Key Auto-Derivation**: `scan-private-repo.yml` and `scan-public-repo.yml` now auto-derive a stable `SONAR_PROJECT_KEY` from `GITHUB_REPOSITORY` when the Actions variable is not set — no manual configuration required
- ✅ **Subdirectory-Aware Sonar Keys**: Monorepo subdirectory scans produce unique, sanitized project keys (e.g., `owner_repo_apps_api`)
- ✅ **Branch/PR Context**: Workflows export `SONAR_BRANCH`, `SONAR_PR_BRANCH`, and `SONAR_PR_BASE` for scanner context
- ✅ **Sonar Project Name**: Workflows now set `SONAR_PROJECT_NAME` for human-readable display in SonarQube

### 🆕 Previous Updates (v2.4) - Complete Scan Isolation
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
✅ **Graceful Degradation** - Tools show skip status when not configured

#### Understanding Dashboard Status Messages

| Message | Meaning | Action |
|---------|---------|--------|
| **"No [Tool] data available"** | Tool was not run or skipped due to missing configuration | Check scan logs or ensure tool prerequisites are met |
| **"SonarQube Analysis Skipped"** | `.env.sonar` not found or authentication not provided | Create `.env.sonar` with credentials to enable |
| **"✅ Analysis complete"** | Tool ran successfully | Review findings in expandable section |
| **"❌ [Count] findings"** | Tool found security issues | Expand section to see details |

**Common Skip Reasons:**
- **SonarQube**: No `.env.sonar` file or missing `SONAR_TOKEN`
- **Helm**: No `Chart.yaml` found in target directory
- **All tools**: Missing `SCAN_DIR` environment variable (if running standalone)
- **All tools**: Docker not running or not available  

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

---

## 🔧 Troubleshooting

### Docker Permission Denied / "Cannot connect to Docker daemon"

**Symptom**: Error messages like:
- `permission denied while trying to connect to the Docker daemon socket`
- `Cannot connect to the Docker daemon at unix:///var/run/docker.sock`
- Scripts report "Container runtime not responding"

**Cause**: Your user doesn't have permission to access the Docker socket

**Solution**:

1. **Add your user to the docker group** (one-time setup):
   ```bash
   sudo usermod -aG docker $USER
   ```

2. **Activate the group membership** (choose one):
   ```bash
   # Option A: Log out and log back in (recommended)
   # Just log out of your Linux session completely, then log back in
   
   # Option B: Open a new terminal session
   # Close this terminal and open a new one
   
   # Option C: Refresh current session (advanced)
   exec su -l $USER
   ```

3. **Verify it works**:
   ```bash
   # Check your groups include 'docker'
   groups
   
   # Test Docker access (should work without sudo)
   docker info
   
   # Run the runtime check
   ./scripts/shell/check-docker-runtime.sh
   ```

**Temporary Workaround** (until you refresh your session):
```bash
# Run scripts with sudo
sudo ./scripts/shell/run-trivy-scan.sh /path/to/project
```

**Alternative**: Use Podman instead of Docker:
```bash
# Install Podman (rootless container runtime)
sudo apt update && sudo apt install -y podman

# Scripts will auto-detect and use Podman
./scripts/shell/check-docker-runtime.sh
```

### Dashboard Shows "No Data Available"

If a security tool shows "No data available" in the dashboard, check:

1. **Scan Logs**: Look in `scans/{scan_id}/[tool]/` for scan logs
2. **Docker Status**: Ensure Docker is running (`docker info`)
3. **Tool Configuration**: 
   - SonarQube requires `.env.sonar` with credentials
   - Helm requires `Chart.yaml` in target directory
4. **Scan Type**: Some tools only run with specific scan types (e.g., `full` vs `quick`)
5. **Manual Check**: Try running the tool individually:
   ```bash
   TARGET_DIR="/path/to/project" ./scripts/shell/run-[tool]-scan.sh
   ```

### SonarQube Skipped

**Symptom**: Dashboard shows "SonarQube Analysis Skipped"  
**Cause**: No `.env.sonar` configuration file found  
**Solution**:
```bash
# Create .env.sonar in one of these locations:
# 1. Project directory: /path/to/project/.env.sonar
# 2. Home directory: ~/.env.sonar

cat > ~/.env.sonar << 'EOF'
export SONAR_HOST_URL='https://your-sonarqube-server.com'
export SONAR_TOKEN='your_token_here'
EOF

# Re-run the scan
./scripts/shell/run-target-security-scan.sh "/path/to/project" full
```

### Tool Won't Run

**Check Prerequisites**:
```bash
# Verify Docker is running
docker info

# Check Docker images
docker images | grep -E "trivy|grype|clamav|checkov"

# Test Docker pull access
docker pull anchore/grype:latest

# Verify scan directory structure
echo "SCAN_DIR should be set: ${SCAN_DIR}"
ls -la "${SCAN_DIR}"
```

### Getting Detailed Logs

Each tool writes detailed logs to its subdirectory:
```bash
# Find your latest scan
LATEST_SCAN=$(ls -td scans/*/ 2>/dev/null | head -n 1)

# View tool-specific logs
cat "${LATEST_SCAN}trivy/trivy-scan.log"
cat "${LATEST_SCAN}grype/grype-scan.log"  
cat "${LATEST_SCAN}sonar/sonar-scan.log"

# Check for errors
grep -i error "${LATEST_SCAN}"*/scan.log
```

