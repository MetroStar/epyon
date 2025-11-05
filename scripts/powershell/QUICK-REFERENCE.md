# PowerShell Security Scripts - Quick Reference Card

## 🚀 Most Common Commands

### Complete Security Scan
```powershell
cd scripts\powershell
.\run-complete-security-scan.ps1 full
```

### Quick Scan (Core Tools Only)
```powershell
.\run-complete-security-scan.ps1 quick
```

### Scan External Project
```powershell
.\run-target-security-scan.ps1 "C:\path\to\project" full
```

### View Dashboard
```powershell
.\open-dashboard.ps1
```

---

## 📋 Individual Scanners

### Vulnerability Scanners
```powershell
.\run-trivy-scan.ps1 all          # Multi-target security
.\run-grype-scan.ps1 filesystem   # Filesystem vulnerabilities
.\run-xeol-scan.ps1               # End-of-life detection
```

### Secret & Malware Detection
```powershell
.\run-trufflehog-scan.ps1         # Secret detection
.\run-clamav-scan.ps1             # Antivirus scan
```

### Infrastructure Security
```powershell
.\run-checkov-scan.ps1            # IaC security
.\run-helm-build.ps1              # Helm chart building
```

### Code Quality
```powershell
.\run-sonar-analysis.ps1          # SonarQube analysis
```

---

## 📊 Analysis Tools

```powershell
.\analyze-clamav-results.ps1
.\analyze-trivy-results.ps1
.\analyze-grype-results.ps1
.\analyze-trufflehog-results.ps1
```

---

## 🎯 Scan Modes

### Complete Scan
```powershell
.\run-complete-security-scan.ps1 full
```

### Quick Scan
```powershell
.\run-complete-security-scan.ps1 quick
```

### Images Only
```powershell
.\run-complete-security-scan.ps1 images
```

### Analysis Mode
```powershell
.\run-complete-security-scan.ps1 analysis
```

---

## 📁 Output Locations

| Tool | Output Directory |
|------|------------------|
| Trivy | `.\trivy-reports\` |
| Grype | `.\grype-reports\` |
| ClamAV | `.\clamav-reports\` |
| TruffleHog | `.\trufflehog-reports\` |
| Xeol | `.\xeol-reports\` |
| Checkov | `.\checkov-reports\` |

---

## 🛠️ Utilities

### Check Conversion Status
```powershell
.\Convert-AllScripts.ps1
```

### Force Refresh Dashboard
```powershell
.\force-refresh-dashboard.ps1
```

### Create Stub Dependencies
```powershell
.\create-stub-dependencies.ps1
```

---

## 💡 Tips

1. **Run from powershell directory**: `cd scripts\powershell`
2. **Check Docker is running**: `docker info`
3. **View logs**: Check `*-reports\*-scan.log` files
4. **All scripts support `-?` for help**

---

## 📖 Documentation

- `README.md` - Main guide
- `QUICK-START-WINDOWS.md` - Getting started
- `FINAL-CONVERSION-SUMMARY.md` - Complete overview
- `CONVERSION-STATUS.md` - Detailed status

---

## ✅ Prerequisites

- Windows 10/11
- PowerShell 5.1+
- Docker Desktop for Windows
- Optional: Helm, AWS CLI (for specific scripts)

---

## 🎯 Common Workflows

### First Time Setup
```powershell
# 1. Navigate to scripts
cd C:\...\comprehensive-security-architecture\scripts\powershell

# 2. Check Docker
docker info

# 3. Run quick scan to test
.\run-complete-security-scan.ps1 quick

# 4. View results
.\open-dashboard.ps1
```

### Daily Security Check
```powershell
cd scripts\powershell
.\run-complete-security-scan.ps1 quick
.\open-dashboard.ps1
```

### Full Security Audit
```powershell
cd scripts\powershell
.\run-complete-security-scan.ps1 full
# Wait for completion...
.\open-dashboard.ps1
```

### Scan New Project
```powershell
cd scripts\powershell
.\run-target-security-scan.ps1 "C:\path\to\new-project" full
.\open-dashboard.ps1
```

---

## 🆘 Troubleshooting

### Docker Not Running
```powershell
# Start Docker Desktop, then verify:
docker info
```

### Script Not Found
```powershell
# Make sure you're in the right directory:
cd scripts\powershell
Get-Location  # Should show: ...\scripts\powershell
```

### Permission Denied
```powershell
# Run PowerShell as Administrator or set execution policy:
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

---

## 📞 Quick Help

```powershell
# List all scripts
Get-ChildItem *.ps1 | Select-Object Name

# Get help for any script
Get-Help .\run-complete-security-scan.ps1

# View script parameters
Get-Help .\run-complete-security-scan.ps1 -Parameter *
```

---

**Last Updated**: November 4, 2024  
**Total Scripts**: 33 PowerShell files  
**Status**: ✅ All converted and ready to use!
