# Epyon GitHub Actions Integration

Automated security scanning for your repositories using GitHub Actions.

## 🚀 Quick Start

### Option 1: Scan Your Own Repository

Add Epyon to your repository to automatically scan on every push and PR:

1. **Download the workflow file** to your repository:
   ```bash
   # In your repository directory
   mkdir -p .github/workflows
   
   # If MetroStar/epyon is public:
   curl -o .github/workflows/epyon-security-scan.yml \
     https://raw.githubusercontent.com/MetroStar/epyon/main/.github/workflows/scan-private-repo.yml
   
   # If MetroStar/epyon is private, clone and copy:
   git clone https://github.com/MetroStar/epyon.git /tmp/epyon
   cp /tmp/epyon/.github/workflows/scan-private-repo.yml .github/workflows/epyon-security-scan.yml
   rm -rf /tmp/epyon
   ```

2. **Commit and push**:
   ```bash
   git add .github/workflows/epyon-security-scan.yml
   git commit -m "Add Epyon security scanning"
   git push
   ```

3. **View results** in the Actions tab of your repository

**How it works:**
- The workflow checks out **both** your repo and Epyon
- Epyon scans your repository code
- Results are uploaded as artifacts
- PRs get automatic security comments

### Option 2: Scan External Repositories

Use Epyon as a centralized security scanning service:

1. Go to **Actions** → **Scan External Repository**
2. Click **Run workflow**
3. Enter the Git repository URL
4. **Optional**: Enter subdirectory path (for monorepos - e.g., `apps/api`)
5. Select scan mode (quick/full/baseline)
6. View results in artifacts

**Subdirectory Scanning (NEW):**
- Scan specific directories within large repositories
- Uses git sparse-checkout for faster cloning
- Perfect for monorepos with multiple applications
- Example: `apps/sapphire-splunk/sapphire-ai-api`

## 📋 Workflows

### 1. Baseline Security Scan (`baseline-scan.yml`) - NEW

Manual-only workflow for creating security baselines with git commit tracking.

**Triggers:**
- Manual dispatch only (not triggered by push/PR/schedule)

**Setup Instructions:**

Add the baseline workflow to your repository:

```bash
# In your repository directory
mkdir -p .github/workflows

# If MetroStar/epyon is public:
curl -o .github/workflows/baseline-scan.yml \
  https://raw.githubusercontent.com/MetroStar/epyon/main/.github/workflows/baseline-scan.yml

# If MetroStar/epyon is private, clone and copy:
git clone https://github.com/MetroStar/epyon.git /tmp/epyon
cp /tmp/epyon/.github/workflows/baseline-scan.yml .github/workflows/baseline-scan.yml
rm -rf /tmp/epyon

# Commit and push
git add .github/workflows/baseline-scan.yml
git commit -m "Add Epyon baseline security scanning"
git push
```

**Important:** After pushing the workflow file, you must:
1. Navigate to your repository's **Actions** tab on GitHub
2. The workflow may take a few minutes to appear
3. Look for "**Baseline Security Scan**" in the workflows list (left sidebar)
4. If it doesn't appear, check that:
   - The YAML file is valid (no syntax errors)
   - The file is in `.github/workflows/` directory
   - You've pushed the commit to the default branch
   - Repository Actions are enabled (Settings → Actions → General)

**Features:**
- 🎯 **Git SHA Capture**: Records exact commit SHA for future comparison
- 📌 **Metadata Tracking**: Creates `baseline-metadata.json` with SHA, date, and repo info
- 🔄 **Smart Naming**: Directory named `baseline_{repo}_{sha}_{user}_{timestamp}`
- 📊 **Reduced Scan**: Runs 5 essential layers (SBOM, Secrets, IaC, Trivy, Grype)
- ⚡ **Faster Execution**: Excludes SonarQube, ClamAV, Helm, Xeol, Anchore, API Discovery
- 💾 **Long-Term Storage**: 90-day artifact retention for baseline comparison
- 🔒 **Portable**: Works in any repository by checking out MetroStar/epyon

**Usage:**
1. Go to **Actions** → **Baseline Security Scan**
2. Click **Run workflow**
3. Download artifacts containing baseline with git SHA
4. Use SHA to compare future scans against this baseline

**Artifacts:**
- `baseline-security-scan` - Complete baseline scan with SHA metadata (90 days)

**Use Cases:**
- Establish initial security posture for new projects
- Create snapshots before major releases
- Track security improvements between versions
- Compliance audit baselines with commit references

### 2. Security Scan (`security-scan.yml`)

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

### Build Gates (Severity Thresholds)

Control when the workflow should fail based on security findings:

**Default Behavior (Push/PR/Schedule):**
- ✅ **ALWAYS fails on Critical** severity findings
- ✅ **ALWAYS fails on High** severity findings  
- ℹ️ Reports **Medium** and **Low** findings
- ℹ️ **Container vulnerabilities excluded** from build failures (informational only)

**Important:** For automatic triggers (push, pull_request, schedule), the workflow will ALWAYS fail on both Critical and High severity findings to prevent vulnerable code from being merged.

**Container Exclusion Logic:**
- ❌ **Excluded from gates**: Grype image scans, Trivy base image scans
- ✅ **Included in gates**: Grype SBOM scans, Trivy filesystem scans, TruffleHog secrets, Checkov IaC
- **Rationale**: Base image vulnerabilities often outside developer control; focus on remediable issues

**Customization Options:**

When running manually (workflow_dispatch), you can configure:
- `fail_on_critical` - Fail build on critical findings (default: true)
- `fail_on_high` - Fail build on high findings (default: true)
- `warning_only` - Report all findings without failing build (default: false)

**Warning-Only Mode:**
Set `warning_only: true` to:
- ✅ Run all security scans
- ✅ Generate complete reports and dashboards
- ✅ Upload all artifacts
- ❌ Never fail the build regardless of findings
- **Use case**: Initial adoption, exploratory scans, informational reports

**For Scheduled/Push Scans:**

Edit the workflow file to change defaults:

```yaml
env:
  SCAN_MODE: full
  FAIL_ON_CRITICAL: true   # Fail on critical findings (default: true)
  FAIL_ON_HIGH: true       # Fail on high findings (default: true)
  WARNING_ONLY: false      # Report only without failing (default: false)
```

**Automatic Trigger Behavior:**
- **Push to main/develop**: `FAIL_ON_CRITICAL=true`, `FAIL_ON_HIGH=true` (NOT configurable)
- **Pull Requests**: `FAIL_ON_CRITICAL=true`, `FAIL_ON_HIGH=true` (NOT configurable)  
- **Scheduled scans**: `FAIL_ON_CRITICAL=true`, `FAIL_ON_HIGH=true` (NOT configurable)
- **Manual runs**: Use workflow_dispatch inputs to customize behavior

**Security Rationale:** Automatic triggers enforce strict security standards to prevent vulnerable code from reaching production. Use manual workflow_dispatch with custom settings for exploratory scans or initial adoption.

**What's Checked:**
- 🔴 **Critical**: CVE vulnerabilities, exposed secrets, critical IaC misconfigurations
- 🟠 **High**: High-severity CVEs, failed security checks
- 🟡 **Medium/Low**: Tracked but don't fail builds by default

### Scan Modes

**Quick Mode** (`quick`)
- Fast scan for immediate feedback
- Essential security checks only
- ~2-5 minutes

**Full Mode** (`full`) - Default
- Comprehensive security analysis
- All scanners enabled
- ~10-20 minutes

**Baseline Mode** (separate workflow: `baseline-scan.yml`)
- Manual-only workflow with git SHA capture
- Reduced scan with 5 essential layers
- Creates baseline for future comparison
- 90-day artifact retention
- See "Baseline Security Scan" workflow above

### Subdirectory Scanning (Monorepo Support)

**NEW**: Scan specific directories within repositories, perfect for monorepos.

**For Private Repositories (scan-private-repo.yml):**

Add subdirectory parameter when running manually:
1. Go to **Actions** → **Private Security Scan**
2. Click **Run workflow**
3. Enter subdirectory path (e.g., `apps/api`, `services/auth`)
4. Leave empty to scan entire repository

**For External Repositories (scan-public-repo.yml):**

The workflow now accepts a subdirectory input:
1. Go to **Actions** → **Scan External Repository**
2. Enter repository URL: `https://github.com/MetroStar/sapphire.git`
3. Enter subdirectory: `apps/sapphire-splunk/sapphire-ai-api`
4. Click **Run workflow**

**How It Works:**
- Uses git sparse-checkout for efficient cloning
- Only downloads files in specified subdirectory
- Scan results named after subdirectory (not full repo)
- Example: `sapphire-ai-api_user_2026-02-06` instead of `sapphire_user_2026-02-06`

**Benefits:**
- 🚀 **Faster**: 50-90% faster clone times for large monorepos
- 💾 **Less storage**: Only downloads needed files
- 🎯 **Focused findings**: Security results for specific component
- 📊 **Better tracking**: Track security trends per application

**SonarQube Project Keys (Monorepo):**

When `SONAR_PROJECT_KEY` is not set as an Actions variable, project keys are auto-derived:
- Full-repo scan → `owner_repo`
- Subdirectory `apps/api` → `owner_repo_apps_api`

Set the `SONAR_PROJECT_KEY` variable in **Settings → Secrets and variables → Actions → Variables** to override auto-derivation.

**Use Cases:**
```yaml
# Microservices monorepo
Repository: https://github.com/company/platform.git
Subdirectory: services/auth-service

# Multi-app repository
Repository: https://github.com/company/apps.git
Subdirectory: mobile-app

# Nested structure
Repository: https://github.com/MetroStar/sapphire.git
Subdirectory: apps/sapphire-splunk/sapphire-ai-api
```

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
