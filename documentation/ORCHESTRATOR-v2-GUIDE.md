# 🎯 Security Scan Orchestrator v2.0 - User Guide

## Overview

The enhanced orchestrator script (`run-target-security-scan.ps1`) now includes comprehensive improvements:

✅ **Docker Status Checking** - Verifies Docker availability before running scans  
✅ **Timing Information** - Tracks and displays duration for each scan  
✅ **Progress Indicators** - Shows real-time progress and completion percentage  
✅ **Error Handling** - Graceful failure handling with detailed error reporting  
✅ **Report Validation** - Verifies scan outputs were generated  
✅ **Summary Statistics** - Comprehensive results table at completion  
✅ **Script Validation** - Checks all tool scripts exist before execution  
✅ **Parallel Execution** - Support for concurrent scan execution (flag available)  
✅ **WSL Compatibility** - Fixed line endings for cross-platform use  
✅ **Detailed Logging** - Complete scan log with timestamps and status  

---

## 🚀 Quick Start

### Basic Usage

```powershell
# Full scan of current directory
.\scripts\powershell\run-target-security-scan.ps1

# Full scan of specific directory
.\scripts\powershell\run-target-security-scan.ps1 "C:\path\to\project" full

# Quick scan (core tools only)
.\scripts\powershell\run-target-security-scan.ps1 "C:\path\to\project" quick

# Container image security scan
.\scripts\powershell\run-target-security-scan.ps1 "C:\path\to\project" images

# Analysis mode (process existing reports)
.\scripts\powershell\run-target-security-scan.ps1 "C:\path\to\project" analysis
```

---

## 📊 New Features Explained

### 1. Docker Status Checking 🐳

The orchestrator now automatically checks if Docker is installed and running:

```
🐳 Checking Docker availability...
   ✅ Docker installed: Docker version 28.4.0, build d8eb465
   ✅ Docker daemon is running
```

**Behavior:**
- If Docker is not running, container-based scans are **skipped** (not failed)
- Non-Docker scans continue normally
- Use `-SkipDockerCheck` to bypass Docker validation

```powershell
# Skip Docker check entirely
.\run-target-security-scan.ps1 "C:\project" full -SkipDockerCheck
```

### 2. Real-Time Progress Tracking 📊

During execution, you'll see progress updates after each scan:

```
📊 Progress: 3/15 (20.0%) | ⏱️  Elapsed: 2.5m
   ✅ Success: 2 | ⚠️  Failed: 1 | ⏭️  Skipped: 0
```

**Information Displayed:**
- Current scan number / Total scans
- Completion percentage
- Elapsed time
- Success/Failed/Skipped counts

### 3. Enhanced Scan Output 🔍

Each scan now shows detailed information:

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ 🔍 Scan 1/15: TruffleHog Secret Detection
└──────────────────────────────────────────────────────────────────────────────┘

   📂 Target: C:\Users\ronni\Projects\myapp
   📜 Script: run-trufflehog-scan.ps1
   ⏰ Started: 14:23:15

   ✅ TruffleHog Secret Detection completed successfully
   ⏱️  Duration: 45.3s
```

### 4. Comprehensive Final Summary 📋

At completion, you get a detailed results table:

```
🎉 Security Scan Complete!

   📊 Scan Summary:
      • Total Scans:     15/15
      • ✅ Successful:    12
      • ❌ Failed:        1
      • ⏭️  Skipped:       2
      • ⏱️  Total Time:    8.5m

   📋 Detailed Results:

Tool                              Status         Duration  Details
----                              ------         --------  -------
TruffleHog Secret Detection       ✅ Success     45.3s
ClamAV Antivirus Scan            ✅ Success     2.1m
Grype Vulnerability Scanning      ✅ Success     1.3m
Trivy Security Analysis           ⚠️  Warning    52.1s     Exit code: 1
SonarQube Analysis               ⏭️  Skipped     0s        Docker not available
```

### 5. Intelligent Docker Handling 🐳

**Automatic Detection:**
- Checks Docker before each Docker-dependent scan
- Skips container scans if Docker unavailable
- Continues with non-Docker scans
- Clear messaging about why scans were skipped

**Docker-Dependent Tools:**
- TruffleHog
- ClamAV
- Grype
- Trivy
- Xeol
- Checkov
- SonarQube
- Helm

### 6. Enhanced Error Handling ⚠️

**Graceful Failure:**
- Individual scan failures don't stop the orchestrator
- Failed scans are tracked and reported
- Exit codes indicate overall success/failure
- Detailed error messages in logs

**Exit Codes:**
- `0` = All scans successful
- `1` = Some scans failed
- `2` = All scans were skipped (likely Docker issue)

### 7. Detailed Logging 📝

Every run creates a timestamped log file:

```
Location: reports/security-reports/scan-orchestrator-2025-11-17_14-23-15.log
```

**Log Contains:**
- Start/end timestamps for each scan
- Docker status checks
- Error messages and warnings
- File validations
- Report generation status

**View Log:**
```powershell
# Open log in default editor
notepad "reports\security-reports\scan-orchestrator-*.log"

# View most recent log
Get-Content (Get-ChildItem "reports\security-reports\scan-orchestrator-*.log" | Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName
```

### 8. Project Type Detection 🔍

The orchestrator now intelligently detects project types:

```
📊 Target Directory Analysis
   📦 Size:               448.2 MB (0.44 GB)
   📄 Files:              15,234
   📦 Node.js Project:    my-app v1.2.3
   🐳 Docker Project:     Detected
   📂 Git Repository:     Detected
```

**Supported Detections:**
- Node.js (package.json)
- Docker (Dockerfile)
- Git (.git)
- Maven (pom.xml)
- Python (requirements.txt)
- .NET (*.csproj)

### 9. Script Validation 🔧

Before execution, the orchestrator validates:
- ✅ Target directory exists
- ✅ All scan scripts are present
- ✅ Reports directory is accessible
- ✅ Docker is available (if needed)

**Benefits:**
- Fail fast on configuration issues
- Clear error messages
- No partial runs with missing tools

### 10. Parallel Execution Support ⚡

*Coming Soon* - Framework ready for parallel execution:

```powershell
# Run independent scans concurrently (future feature)
.\run-target-security-scan.ps1 "C:\project" full -Parallel
```

---

## 🎯 Scan Type Comparison

| Scan Type | Tools Run | Typical Duration | Use Case |
|-----------|-----------|------------------|----------|
| **quick** | 4 core tools | 3-5 minutes | Quick security check, CI/CD |
| **full** | All 15 scans | 15-30 minutes | Comprehensive audit, weekly scans |
| **images** | 6 container scans | 8-12 minutes | Docker image security |
| **analysis** | Report processing only | < 1 minute | Review existing results |

---

## 💡 Usage Examples

### Example 1: Daily Quick Scan
```powershell
# Quick scan for daily security checks
.\scripts\powershell\run-target-security-scan.ps1 "C:\MyApp" quick
```

### Example 2: Weekly Full Audit
```powershell
# Comprehensive weekly security audit
.\scripts\powershell\run-target-security-scan.ps1 "C:\MyApp" full
```

### Example 3: Container Security Check
```powershell
# Focus on container image vulnerabilities
.\scripts\powershell\run-target-security-scan.ps1 "C:\MyApp" images
```

### Example 4: Scan Without Docker
```powershell
# Run scans when Docker isn't available
.\scripts\powershell\run-target-security-scan.ps1 "C:\MyApp" full -SkipDockerCheck
```

### Example 5: Multiple Projects
```powershell
# Scan multiple projects sequentially
$projects = @("C:\Project1", "C:\Project2", "C:\Project3")
foreach ($project in $projects) {
    Write-Host "`n=== Scanning $project ===" -ForegroundColor Cyan
    .\scripts\powershell\run-target-security-scan.ps1 $project quick
}
```

### Example 6: CI/CD Integration
```powershell
# Run in CI/CD pipeline with error handling
$exitCode = & .\scripts\powershell\run-target-security-scan.ps1 "C:\BuildArtifacts" quick
if ($exitCode -ne 0) {
    Write-Error "Security scan failed with exit code $exitCode"
    exit $exitCode
}
```

---

## 🔧 Troubleshooting

### Docker Not Running
**Symptom:** Scans are skipped with "Docker not available"

**Solutions:**
1. Start your Docker runtime:
   - Docker Engine: `sudo systemctl start docker` (Linux)
   - Docker Desktop: open -a Docker (macOS)
   - Colima: `colima start` (macOS)
   - Rancher Desktop: open -a "Rancher Desktop" (macOS)
   - OrbStack: open -a OrbStack (macOS)
2. Wait for Docker to fully initialize (30-60 seconds)
3. Verify Docker is running: `docker info`
4. Run scan again
5. Or use `-SkipDockerCheck` for non-Docker scans only

### Scans Taking Too Long
**Symptom:** Full scan takes > 30 minutes

**Solutions:**
1. Use `quick` scan type for faster results
2. Exclude large directories (modify individual scan scripts)
3. Check Docker resource allocation (CPU/Memory)
4. Consider running `images` or specific tools separately

### Script Not Found Errors
**Symptom:** "Script not found: .\run-xxx-scan.ps1"

**Solutions:**
1. Verify all scan scripts exist in `scripts/powershell/`
2. Check file permissions
3. Re-clone repository if files are missing
4. Review orchestrator log for detailed path information

### Line Ending Issues (WSL)
**Symptom:** "cannot execute: required file not found" in WSL

**Solution:**
```bash
# Fix line endings for all PowerShell scripts
cd /mnt/c/Users/ronni/.../scripts/powershell
find . -name "*.ps1" -exec sed -i 's/\r$//' {} \;
```

---

## 📚 Related Documentation

- **README.md** - Main project documentation
- **DEPLOYMENT_SUMMARY_NOV_4_2025.md** - Deployment guide
- **DASHBOARD_QUICK_REFERENCE.md** - Dashboard usage
- **Individual scan scripts** - Tool-specific documentation

---

## 🎉 What's New in v2.0

### Major Enhancements
✨ **Docker Awareness** - Intelligent Docker detection and handling  
✨ **Progress Tracking** - Real-time progress and timing information  
✨ **Enhanced UI** - Beautiful colored output with emoji indicators  
✨ **Comprehensive Logging** - Detailed logs for debugging and auditing  
✨ **Error Resilience** - Graceful failure handling with continuation  
✨ **Report Validation** - Automatic verification of scan outputs  
✨ **Script Validation** - Pre-flight checks before execution  
✨ **Project Detection** - Automatic identification of project types  
✨ **Summary Tables** - Detailed results in easy-to-read format  
✨ **WSL Compatible** - Fixed line endings for cross-platform use  

### Performance Improvements
⚡ Faster failure detection  
⚡ Reduced unnecessary processing  
⚡ Optimized error handling  
⚡ Better resource management  

### User Experience
🎨 Modern UI with color coding  
🎨 Clear status indicators (✅ ⚠️ ❌)  
🎨 Progress percentage and time estimates  
🎨 Organized output sections  
🎨 Helpful error messages  

---

## 🚀 Next Steps

1. **Try the orchestrator** with a quick scan
2. **Review the logs** to understand execution flow
3. **Check the dashboard** for consolidated results
4. **Schedule regular scans** for continuous security monitoring
5. **Integrate with CI/CD** for automated security checks

---

**Version:** 2.0  
**Updated:** November 17, 2025  
**Status:** ✅ Production Ready  
**Compatibility:** PowerShell 5.1+, Windows 10/11, WSL
