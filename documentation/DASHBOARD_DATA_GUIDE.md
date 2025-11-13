# 📊 Security Dashboard & Data Guide

**Interactive Security Dashboards and Data Analytics Guide**  
**Updated:** November 4, 2025  
**Status:** Production Ready

## 🔍 Understanding Your Dashboard Data

### How Scans Work (NOT Cumulative)
Your security dashboard displays **the latest scan results** from each tool, not historical data:

- **Fresh Data**: Each time you run a security tool, it overwrites the previous results
- **Latest Only**: The dashboard shows the most recent scan from each of the 8 security tools
- **No History**: Previous scan results are not preserved unless manually backed up

### What's in the Dashboard?

#### 8 Security Tools Tracked:
1. **SonarQube** - Code quality and test coverage
2. **TruffleHog** - Secret detection in code and containers
3. **ClamAV** - Malware and virus scanning
4. **Helm** - Kubernetes chart validation
5. **Checkov** - Infrastructure-as-Code security
6. **Trivy** - Container vulnerability scanning
7. **Grype** - Advanced vulnerability analysis with SBOM
8. **Xeol** - End-of-Life software detection

#### Data Storage Structure:
```
reports/
├── sonar-reports/          # SonarQube results
├── trufflehog-reports/     # Secret detection results
├── clamav-reports/         # Malware scan results
├── helm-reports/           # Chart validation results
├── checkov-reports/        # IaC security results
├── trivy-reports/          # Container vulnerability results
├── grype-reports/          # Advanced vulnerability results
├── xeol-reports/           # EOL software results
└── security-reports/       # Consolidated dashboard
    ├── dashboards/
    │   └── security-dashboard.html    # Interactive dashboard
    ├── consolidated-report.md
    └── navigation/
```

## 📊 Dashboard Data Lifecycle

### When Data Updates:
- **Individual Scans**: Running any tool script updates only that tool's data
- **Dashboard Refresh**: Running `consolidate-security-reports.sh` rebuilds the dashboard with current data
- **Automatic**: Some tools may auto-update their data when run

### Data Freshness Indicators:
- Each scan creates timestamped files
- Dashboard shows when each tool was last run
- Stale data is clearly marked with timestamps

## 🧹 Clearing and Re-running Scans

### Quick Management Script:
```bash
# Use the new management script
./manage-dashboard-data.sh
```

This interactive script provides:
- **Scan Status**: View when each tool was last run
- **Clear Options**: Remove all results or specific tool results
- **Fresh Scans**: Run new scans with various options
- **Dashboard Control**: Regenerate or open the dashboard

### Manual Commands:

#### Clear All Results:
```bash
# Remove all scan results
rm -rf reports/sonar-reports
rm -rf reports/trufflehog-reports
rm -rf reports/clamav-reports
rm -rf reports/helm-reports
rm -rf reports/checkov-reports
rm -rf reports/trivy-reports
rm -rf reports/grype-reports
rm -rf reports/xeol-reports
rm -rf reports/security-reports

# Then run fresh scans
./run-all-security-scans.sh
```

#### Clear Specific Tool:
```bash
# Example: Clear only TruffleHog results
rm -rf reports/trufflehog-reports
./run-trufflehog-scan.sh

# Regenerate dashboard
./consolidate-security-reports.sh
```

## 🚀 Running Fresh Scans

### Complete Fresh Start:
```bash
# 1. Clear all old data
./manage-dashboard-data.sh  # Choose option 4 (Clear All)

# 2. Run full security suite
./run-all-security-scans.sh

# 3. Generate fresh dashboard
./consolidate-security-reports.sh

# 4. Open the dashboard
./open-dashboard.sh
```

### Quick Refresh (Recommended):
```bash
# Run key security tools only
./run-trufflehog-scan.sh    # Secrets
./run-clamav-scan.sh        # Malware
./run-grype-scan.sh         # Vulnerabilities

# Update dashboard
./consolidate-security-reports.sh
```

### Individual Tool Updates:
```bash
# Update just one tool's data
./run-sonar-analysis.sh     # For code quality
./consolidate-security-reports.sh  # Refresh dashboard
```

## 📈 Understanding Dashboard Results

### Security Score Calculation:
The dashboard calculates an overall security score based on:
- **Critical Issues**: High-impact vulnerabilities and secrets
- **Tool Coverage**: How many tools have been run recently
- **Pass/Fail Ratios**: Percentage of checks passing
- **Trend Analysis**: Improvement or degradation over time

### Key Metrics Displayed:
- **Vulnerability Count**: Total high/medium/low vulnerabilities
- **Secret Exposure**: Detected secrets and sensitive data
- **Code Quality**: Test coverage and code smells
- **Compliance Status**: Security policy adherence
- **Container Security**: Image vulnerability assessment
- **Infrastructure Security**: IaC misconfigurations

## 🔄 Best Practices

### Regular Scanning Schedule:
1. **Daily**: Run TruffleHog for secret detection
2. **Weekly**: Full vulnerability scan (Trivy + Grype)
3. **Before Deployment**: Complete security suite
4. **After Dependencies**: Update vulnerability scans

### Data Management:
- **Archive Results**: Manually backup important scan results
- **Monitor Trends**: Compare results over time
- **Clean Regularly**: Clear old results to avoid confusion
- **Verify Currency**: Check scan timestamps before trusting results

### Dashboard Maintenance:
- **Regenerate Often**: Run `consolidate-security-reports.sh` after any scans
- **Check All Tools**: Ensure all 8 security tools have recent data
- **Review Regularly**: Open dashboard weekly to track security posture
- **Share Safely**: Dashboard contains sensitive security information

## 🛠️ Troubleshooting

### Dashboard Shows Old Data:
```bash
# Check when tools were last run
./manage-dashboard-data.sh  # Option 1: Show Current Scan Status

# Run fresh scans
./manage-dashboard-data.sh  # Option 6: Run Fresh Scans

# Regenerate dashboard
./consolidate-security-reports.sh
```

### Missing Tool Data:
```bash
# Check which tools have no data
ls -la reports/

# Run missing tool specifically
./run-[tool-name]-scan.sh

# Update dashboard
./consolidate-security-reports.sh
```

### Dashboard Won't Open:
```bash
# Check if dashboard exists
ls -la reports/security-reports/dashboards/

# Regenerate if missing
./consolidate-security-reports.sh

# Open with launcher
./open-dashboard.sh
```

## 📝 Summary

**Key Points to Remember:**
- ✅ **Not Cumulative**: Each scan overwrites previous results
- ✅ **Latest Data**: Dashboard shows most recent scan from each tool
- ✅ **Manual Management**: Use the management script for easy control
- ✅ **Regular Updates**: Run scans frequently for current security posture
- ✅ **Fresh Starts**: Clear old data when starting new analysis cycles

**Quick Commands:**
- View status: `./manage-dashboard-data.sh`
- Clear all: Choose option 4 in management script
- Fresh scans: Choose option 6 in management script
- Open dashboard: `./open-dashboard.sh`