# Security Scripts Directory

This directory contains security scanning and analysis scripts organized by platform.

## 📁 Directory Structure

```
scripts/
├── shell/          # Shell scripts for Linux/macOS/WSL
├── powershell/     # PowerShell scripts for Windows
└── README.md       # This file
```

## 🐧 Shell Scripts (`shell/`)

**Location**: `./shell/`

**Platform**: Linux, macOS, WSL (Windows Subsystem for Linux), Git Bash

### Usage
```bash
cd shell
./script-name.sh
```

### Available Scripts
- Security scanners (Trivy, Grype, Xeol, Checkov, ClamAV, TruffleHog, etc.)
- SBOM generation (run-sbom-scan.sh)
- Dashboard generation and management
- Report consolidation
- Target-aware security scanning orchestration

## 🪟 PowerShell Scripts (`powershell/`)

**Location**: `./powershell/`

**Platform**: Windows (PowerShell 5.1+)

**Total Scripts**: 9 (converted from bash)

**Conversion Progress**: 25.8% complete

### Usage
```powershell
cd powershell
.\script-name.ps1
```

### Available Scripts
- `open-dashboard.ps1` - Opens security dashboard
- `open-compliance-dashboard.ps1` - Opens compliance dashboard for audit tracking
- `force-refresh-dashboard.ps1` - Refreshes dashboard with cache busting
- `test-desktop-default.ps1` - Tests default behavior
- `demo-portable-scanner.ps1` - Scanner demonstration
- `run-clamav-scan.ps1` - Antivirus scanning
- `run-trufflehog-scan.ps1` - Secret detection
- `analyze-clamav-results.ps1` - ClamAV results analysis
- `create-stub-dependencies.ps1` - Helm stub creation
- `compliance-logger.ps1` - PowerShell compliance logging
- `Convert-AllScripts.ps1` - Conversion tracker tool

### Documentation
See `./powershell/` directory for:
- `QUICK-START-WINDOWS.md` - Getting started guide
- `README-PowerShell-Conversion.md` - Conversion guide
- `CONVERSION-STATUS.md` - Conversion progress
- `CONVERSION-SUMMARY.md` - Project overview

## 🚀 Quick Start

### For Windows Users

**Option 1: Use PowerShell Scripts** (Recommended)
```powershell
cd powershell
.\run-target-security-scan.ps1 -TargetDir "C:\path\to\project"
.\run-clamav-scan.ps1
```

**Option 2: Use Shell Scripts** (Via WSL or Git Bash)
```bash
cd shell
./run-target-security-scan.sh /path/to/project
./run-grype-scan.sh
```

### For Linux/macOS Users

```bash
cd shell
./run-target-security-scan.sh /path/to/project full
./open-latest-dashboard.sh
```

## 📊 Script Categories

### Security Scanners
- **ClamAV** - Antivirus/malware scanning
- **TruffleHog** - Secret detection
- **Trivy** - Container vulnerability scanning
- **Grype** - Vulnerability detection with SBOM
- **Xeol** - End-of-life software detection
- **Checkov** - Infrastructure-as-Code security
- **SonarQube** - Code quality analysis

### Analysis Tools
- Result analyzers for each scanner
- Report consolidation
- Dashboard generation

### Management Tools
- Dashboard management
- Helm dependency resolution
- AWS ECR authentication
- Portable app scanner

## 🔄 Platform-Specific Notes

### Container Runtime Support (All Platforms)

**Epyon is container-engine-agnostic!** All scanner scripts automatically detect and work with:
- **Docker** (Docker Engine, Docker Desktop)
- **Podman** (rootless or rootful)
- **nerdctl** (containerd CLI)
- **Alternative Docker distributions** (Colima, Rancher Desktop, OrbStack)

**First-time setup on Linux**:
```bash
# Add your user to the docker group (one-time)
sudo usermod -aG docker $USER

# Then log out and log back in, OR open a new terminal session, OR run:
exec su -l $USER
```

**Check your container runtime**:
```bash
./shell/check-docker-runtime.sh
```

**Using Podman instead of Docker**:
```bash
# Install Podman (Debian/Ubuntu)
sudo apt update && sudo apt install -y podman

# The scripts will automatically detect and use Podman
./shell/check-docker-runtime.sh

# For rootless Podman service (optional)
systemctl --user enable --now podman.socket
```

### Windows (PowerShell)
- Requires PowerShell 5.1 or later
- May need to set execution policy:
  ```powershell
  Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
  ```
- Docker required (Docker Desktop, Rancher Desktop, or Windows containers)

### Linux/macOS/WSL (Bash)
- Requires bash shell
- Container runtime required for most scanners (see Container Runtime Support above)
- Some scripts may require additional tools (helm, aws-cli, etc.)

## 📝 Output Directories

Scan results are saved in their respective directories (created in parent directory):
- `../clamav-reports/`
- `../trufflehog-reports/`
- `../trivy-reports/`
- `../grype-reports/`
- `../xeol-reports/`
- `../checkov-reports/`
- `../reports/security-reports/`

## 🛠️ Prerequisites

### All Platforms
- **Container Runtime** (choose one):
  - Docker (Docker Engine, Docker Desktop) - *recommended*
  - Podman (rootless or rootful) - *Docker-compatible alternative*
  - nerdctl with containerd
  - Alternative distributions (Colima, Rancher Desktop, OrbStack)
- Git

### Optional Tools
- Helm (for Kubernetes chart scanning)
- AWS CLI (for ECR authentication)
- Node.js (for Node.js specific scanners)

## 📚 Documentation

### PowerShell Documentation
Located in `./powershell/`:
- Quick start guide
- Conversion guide
- Status tracking
- Troubleshooting

### General Documentation
- See individual script headers for usage information
- Run scripts with `--help` or `-h` for options

## 🔗 Related Directories

- `../reports/` - Consolidated security reports
- `../chart/` - Helm charts for scanning
- `../helm-packages/` - Helm build outputs

## 💡 Tips

1. **Check which platform you're on**:
   ```powershell
   # PowerShell
   $PSVersionTable.PSVersion
   ```
   ```bash
   # Bash
   echo $SHELL
   ```

2. **Use the conversion tracker** (PowerShell):
   ```powershell
   cd powershell
   .\Convert-AllScripts.ps1
   ```

3. **Run complete scans**:
   ```bash
   # Bash
   cd bash
   ./run-complete-security-scan.sh
   ```

4. **View results**:
   ```powershell
   # PowerShell
   cd powershell
   .\open-dashboard.ps1
   ```

## 🎯 Next Steps

1. Navigate to the appropriate directory for your platform
2. Review the available scripts
3. Run your first security scan
4. View the dashboard to see results

---

**Note**: The PowerShell scripts are conversions of the bash scripts. Not all bash scripts have been converted yet. Use the bash versions for any scripts not yet available in PowerShell.
