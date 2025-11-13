# � Enterprise Security Architecture - Quick Reference

**Production-Ready Commands & Usage Patterns**  
**Updated:** November 4, 2025

## Understanding Your Security Dashboard

### ❓ **Are scans cumulative?**
**NO** - Each scan **overwrites** previous results. The dashboard shows the **latest** scan from each tool.

### 🔄 **How to clear and re-run scans:**

#### Quick Management (Recommended):
```bash
# Use the interactive management script
./manage-dashboard-data.sh

# Options available:
# 1) Show current scan status & timestamps  
# 2) Show dashboard status
# 3) Explain how dashboard works
# 4) Clear all results
# 5) Clear specific tool results  
# 6) Run fresh scans
# 7) Open security dashboard
```

#### Manual Commands:
```bash
# Clear all scan results
rm -rf reports/*-reports reports/security-reports

# Run fresh complete scan
./run-all-security-scans.sh

# Regenerate dashboard
./consolidate-security-reports.sh

# Open dashboard
./open-dashboard.sh
```

### 📊 **What's in the dashboard:**
- **SonarQube**: Code quality & test coverage
- **TruffleHog**: Secret detection  
- **ClamAV**: Malware scanning
- **Helm**: Kubernetes chart validation
- **Checkov**: Infrastructure security
- **Trivy**: Container vulnerabilities
- **Grype**: Advanced vulnerability analysis
- **Xeol**: End-of-Life software detection

### 🕐 **Data freshness:**
- Each tool creates timestamped files
- Dashboard shows when each tool was last run
- Old data is clearly marked with timestamps
- **Check timestamps before trusting results**

### 🛠️ **For Node.js projects specifically:**
```bash
# Use the enhanced Node.js scanner (handles dependencies automatically)
./nodejs-security-scanner.sh /path/to/your/nodejs/project

# With options:
./nodejs-security-scanner.sh /path/to/project --no-install --verbose
```

### 🎯 **Best practices:**
1. **Clear old data** before important scans
2. **Run scans frequently** - daily for secrets, weekly for vulnerabilities  
3. **Check timestamps** to ensure data is current
4. **Use management script** for easy control
5. **Archive important results** manually if needed

### 🚀 **Quick scan workflows:**

#### Daily Security Check:
```bash
./nodejs-security-scanner.sh /path/to/project  # For Node.js projects
# OR
./run-trufflehog-scan.sh && ./run-grype-scan.sh  # Quick scan
./consolidate-security-reports.sh  # Update dashboard
```

#### Full Security Audit:
```bash
./manage-dashboard-data.sh  # Choose option 4 (Clear All)
./run-all-security-scans.sh  # Complete scan
./open-dashboard.sh  # View results
```

#### Project-Specific Analysis:
```bash
# Use portable scanner for any project
./portable-app-scanner.sh /path/to/any/project

# Or Node.js optimized scanner  
./nodejs-security-scanner.sh /path/to/nodejs/project
```

---
**Key Takeaway**: Your dashboard shows **current snapshot**, not history. Clear old data and run fresh scans for accurate security posture assessment.