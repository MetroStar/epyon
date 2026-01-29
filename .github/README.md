# Epyon GitHub Actions Integration

Automated security scanning for your repositories using GitHub Actions.

## 🚀 Quick Start

### Option 1: Scan Your Own Repository

Add Epyon to your repository to automatically scan on every push and PR:

1. **Copy the workflow file** to your repository:
   ```bash
   mkdir -p .github/workflows
   cp .github/workflows/security-scan.yml your-repo/.github/workflows/
   ```

2. **Commit and push**:
   ```bash
   git add .github/workflows/security-scan.yml
   git commit -m "Add Epyon security scanning"
   git push
   ```

3. **View results** in the Actions tab of your repository

### Option 2: Scan External Repositories

Use Epyon as a centralized security scanning service:

1. Go to **Actions** → **Scan External Repository**
2. Click **Run workflow**
3. Enter the Git repository URL
4. Select scan mode (quick/full/baseline)
5. View results in artifacts

## 📋 Workflows

### 1. Security Scan (`security-scan.yml`)

Automatically scans your repository on push, PR, or schedule.

**Triggers:**
- Push to `main` or `develop`
- Pull requests to `main` or `develop`
- Daily at 2 AM UTC
- Manual dispatch

**Features:**
- ✅ Runs full Epyon security suite
- ✅ Uploads dashboard and reports as artifacts
- ✅ Posts summary to PR comments
- ✅ Fails build on critical vulnerabilities
- ✅ Generates GitHub Step Summary

**Artifacts:**
- `security-dashboard` - Interactive HTML dashboard
- `security-reports-html` - HTML formatted reports
- `security-reports-markdown` - Markdown summaries
- `security-reports-csv` - CSV exports
- `security-raw-data` - Raw JSON data

### 2. Scan External Repository (`scan-external-repo.yml`)

Manually scan any Git repository.

**Usage:**
1. Navigate to Actions tab
2. Select "Scan External Repository"
3. Click "Run workflow"
4. Enter repository URL (e.g., `https://github.com/owner/repo.git`)
5. Select scan mode

**Artifacts:**
- `external-repo-security-scan` - Complete scan results (90 day retention)

## 🛡️ Security Features

### Scanners Included
- **Trivy** - Container and dependency vulnerabilities
- **Grype** - Software composition analysis
- **TruffleHog** - Secret detection
- **Checkov** - Infrastructure as Code security
- **ClamAV** - Malware detection
- **Xeol** - End-of-life detection
- **Syft** - SBOM generation
- **SonarQube** - Code quality analysis

### Severity Thresholds
- **Critical** - Build fails automatically
- **High** - Warning in PR comments
- **Medium/Low** - Tracked in reports

## 🔧 Configuration

### Scan Modes

**Quick Mode** (`quick`)
- Fast scan for immediate feedback
- Essential security checks only
- ~2-5 minutes

**Full Mode** (`full`) - Default
- Comprehensive security analysis
- All scanners enabled
- ~10-20 minutes

**Baseline Mode** (`baseline`)
- Creates security baseline
- Compares against previous scans
- Tracks security posture over time

### Customize Workflow

Edit `.github/workflows/security-scan.yml`:

```yaml
env:
  SCAN_MODE: full  # Change default mode
  
  # Fail on high severity (not just critical)
  FAIL_ON_HIGH: true
```

### Schedule Changes

Modify the cron schedule:

```yaml
schedule:
  - cron: '0 2 * * *'  # Daily at 2 AM UTC
  # - cron: '0 */6 * * *'  # Every 6 hours
  # - cron: '0 0 * * 1'  # Weekly on Monday
```

## 📊 Viewing Results

### In Pull Requests
Epyon automatically comments on PRs with:
- Severity summary
- Executive summary (expandable)
- Links to detailed artifacts

### In Actions Tab
1. Go to **Actions** in your repository
2. Click on the workflow run
3. Scroll to **Artifacts** section
4. Download any report package

### Dashboard Access
1. Download `security-dashboard` artifact
2. Extract and open `index.html`
3. Navigate to full dashboard

## 🔐 Permissions Required

The workflow needs these permissions:

```yaml
permissions:
  contents: read          # Read repository code
  pull-requests: write    # Comment on PRs
  security-events: write  # Upload SARIF results
  issues: write          # Create issues for findings
```

## 🚫 Excluding Files

Create `.epyonignore` in your repository root:

```
# Ignore test data
tests/fixtures/**
data/samples/**

# Ignore build outputs
dist/**
build/**

# Ignore dependencies
node_modules/**
vendor/**
```

## 📈 Advanced Usage

### Matrix Scanning

Scan multiple branches or configurations:

```yaml
strategy:
  matrix:
    branch: [main, develop, staging]
    scan_mode: [quick, full]
```

### Conditional Scanning

Only scan on specific conditions:

```yaml
- name: Run Scan
  if: contains(github.event.head_commit.message, '[security-scan]')
  run: ./scripts/shell/run-target-security-scan.sh
```

### Custom Notifications

Send results to Slack, Teams, or email:

```yaml
- name: Notify Slack
  if: steps.check-severity.outputs.has_issues == 'true'
  uses: slackapi/slack-github-action@v1
  with:
    payload: |
      {
        "text": "Security issues found in ${{ github.repository }}"
      }
```

## 🐛 Troubleshooting

### Scan Fails to Start

**Problem:** Docker daemon not available

**Solution:** Ensure `docker/setup-buildx-action@v3` is included

### No Artifacts Generated

**Problem:** Scan directory not found

**Solution:** Check that scan completed successfully in logs

### Dashboard Doesn't Open

**Problem:** CORS restrictions on local files

**Solution:** Use the provided index.html or serve via HTTP server

### Out of Disk Space

**Problem:** Large repository or many dependencies

**Solution:** Use `quick` mode or increase runner disk space

## 🎯 Best Practices

1. **Start with Quick Mode** - Get familiar with results
2. **Enable Branch Protection** - Require passing scans before merge
3. **Review Weekly** - Check scheduled scan results regularly
4. **Baseline Scans** - Track security improvements over time
5. **Custom Exceptions** - Document and justify any ignored findings

## 📚 Resources

- [Epyon Documentation](../documentation/)
- [Scan Directory Architecture](../documentation/SCAN_DIRECTORY_ARCHITECTURE.md)
- [Dashboard Guide](../documentation/DASHBOARD_QUICK_REFERENCE.md)
- [Security Validation](../documentation/security-validation-guide.md)

## 🤝 Contributing

Found an issue or want to improve the workflows? See [CONTRIBUTING.md](../CONTRIBUTING.md)

## 📄 License

See [LICENSE.md](../LICENSE.md)
