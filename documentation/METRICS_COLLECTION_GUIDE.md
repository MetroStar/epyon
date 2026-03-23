# Dashboard Metrics Collection

Automatically collect and visualize security scan metrics from the last 90 days on your dashboard.

## Overview

This system automatically:
1. **Collects** metrics from all GitHub Actions scan artifacts (nightly via workflow)
2. **Aggregates** them into a time-series JSON file
3. **Embeds** an interactive chart into your security dashboard
4. **Displays** trends across all severity levels (Critical, High, Medium, Low)

## Components

### Scripts

#### `collect-metrics-from-github.sh`
Pulls all `metrics-{scan_id}` artifacts from GitHub Actions for the last 90 days.

**Usage:**
```bash
./scripts/shell/collect-metrics-from-github.sh \
  --repo MetroStar/epyon \
  --days 90 \
  --dashboard-dir ./metrics/
```

**Features:**
- Auto-detects repository from git remote
- Caches downloaded metrics locally to avoid redundant API calls
- Generates JSON time-series output
- Supports multi-repo aggregation
- Shows summary statistics in terminal

**Output:**
```json
{
  "generated_at": "2026-03-23T10:30:00Z",
  "collected_from": "github-actions",
  "time_range_days": 90,
  "total_scans": 24,
  "scans_with_findings": 18,
  "summary": {
    "critical_total": 12,
    "high_total": 45,
    "medium_total": 128,
    "low_total": 342
  },
  "targets": ["iris", "sapphire", "comet-starter"],
  "users": ["rnelson", "ci-bot"],
  "metrics": [
    {
      "scan_id": "iris_rnelson_2026-03-17_16-07-33",
      "timestamp": "2026-03-17T16:07:33Z",
      "target_name": "iris",
      "scan_user": "rnelson",
      "critical": 0,
      "high": 2,
      "medium": 15,
      "low": 42,
      "has_findings_summary": true
    },
    ...
  ]
}
```

#### `embed-metrics-in-dashboard.sh`
Injects an interactive Chart.js visualization into the dashboard HTML.

**Usage:**
```bash
./scripts/shell/embed-metrics-in-dashboard.sh \
  --metrics metrics-90d.json \
  --dashboard security-dashboard.html \
  --chart-type line \
  --max-points 90
```

**Chart Features:**
- Line/area/bar chart visualization
- Separate datasets for Critical, High, Medium, Low
- Interactive tooltips with target names
- Summary statistics cards (latest values, averages)
- Responsive design
- Built with Chart.js

## Workflows

### `update-dashboard-metrics.yml`

**Schedule:** Runs nightly at 2 AM UTC (configurable via cron)

**Manual Trigger:** Can be manually triggered with custom day range

**What it does:**
1. Collects metrics from last N days (default: 90)
2. Generates/updates security dashboard
3. Embeds metrics chart in the dashboard
4. Uploads metrics and dashboard as artifacts
5. Posts summary to GitHub workflow summary

**Artifacts:**
- `metrics-90d.json` - Raw aggregated metrics (90-day retention)
- `dashboard-with-metrics` - Updated dashboard HTML (90-day retention)

## Usage Examples

### Automatic Collection (CI/CD)

The workflow runs automatically every night. You can also trigger it manually:

```bash
# Via GitHub CLI
gh workflow run update-dashboard-metrics.yml --ref main

# With custom day range (manual trigger)
gh workflow run update-dashboard-metrics.yml \
  --ref main \
  --raw-field days=60
```

### Manual Local Collection

```bash
# Collect last 90 days of metrics
./scripts/shell/collect-metrics-from-github.sh --repo MetroStar/epyon

# The script will prompt you to authenticate if needed
# and create metrics/metrics-90d.json

# Then embed in dashboard
./scripts/shell/embed-metrics-in-dashboard.sh \
  --metrics metrics/metrics-90d.json \
  --dashboard /path/to/dashboard.html
```

### Collecting Specific Time Range

```bash
# Last 30 days only
./scripts/shell/collect-metrics-from-github.sh --days 30

# Last 180 days
./scripts/shell/collect-metrics-from-github.sh --days 180

# Multiple repositories
./scripts/shell/collect-metrics-from-github.sh \
  --repos MetroStar/epyon,MetroStar/iris,MyOrg/sapphire
```

### Dashboard Integration with Existing Scans

If you want to embed metrics in a scan that's already running:

```bash
# In your scan workflow, after dashboard generation:
- name: Collect 90-Day Metrics
  run: |
    ./scripts/shell/collect-metrics-from-github.sh \
      --repo ${{ github.repository }} \
      --days 90
      
- name: Embed Metrics in Dashboard
  run: |
    ./scripts/shell/embed-metrics-in-dashboard.sh \
      --metrics metrics/metrics-90d.json \
      --dashboard scans/${{ steps.run-scan.outputs.scan_dir }}/consolidated-reports/dashboards/security-dashboard.html
```

## Chart Visualization

The embedded chart shows:

**X-Axis:** Timeline (dates from scans)
**Y-Axis:** Number of findings
**Datasets:**
- 🔴 **Critical** (red) - Most urgent
- 🟠 **High** (orange) - High priority  
- 🟡 **Medium** (yellow) - Medium priority
- 🟢 **Low** (green) - Low priority

**Interaction:**
- Hover over points to see exact values and target name
- Legend items can be clicked to toggle dataset visibility
- Responsive to window resize
- Summary cards below show latest and average values

## Requirements

- **GitHub CLI**: `gh` (installed and authenticated)
- **jq**: For JSON processing
- **curl**: For downloading artifacts (optional)
- **Access**: Read permissions for GitHub Actions artifacts

### Install Dependencies

```bash
# macOS
brew install gh jq

# Ubuntu/Debian
sudo apt-get install gh jq

# Fedora
sudo dnf install gh jq

# Authenticate GitHub CLI
gh auth login
```

## Data Structure

### Metrics JSON Format

```json
{
  "scan_id": "iris_user_2026-03-17_14-30-00",
  "timestamp": "2026-03-17T14:30:00Z",
  "target_name": "iris",
  "scan_user": "rnelson",
  "scan_type": "full",
  "repository": "MetroStar/iris",
  "run_id": "123456789",
  "run_url": "https://github.com/MetroStar/epyon/actions/runs/123456789",
  "has_findings_summary": true,
  "critical": 5,
  "high": 12,
  "medium": 34,
  "low": 89
}
```

## Caching Strategy

The metrics collection script caches downloaded artifacts locally in `metrics/github-cache/` to:
- Avoid redundant GitHub API calls
- Speed up subsequent runs
- Reduce rate limit usage

**Force re-download:**
```bash
./scripts/shell/collect-metrics-from-github.sh --no-cache
```

## Troubleshooting

### "GitHub CLI is not authenticated"

```bash
gh auth login
# Choose "GitHub.com"
# Choose "HTTPS"
# Choose "Paste an authentication token"
# Or use SSH and let it generate one
```

### "No runs found in the specified time range"

Check that:
1. Scans are actually running in your repository
2. Metrics are being uploaded (check with: `gh run list`)
3. Time range is correct
4. Workflow has permission to read artifacts

### "Metrics file not found in artifact"

The metrics artifact is only created if:
- `scan-metrics.json` is generated during the scan
- The workflow uploads it with `--upload-metrics` flag
- The scan completes successfully

If metrics aren't being uploaded, check:
1. The scan workflow has the metrics generation step
2. Artifacts are configured for upload
3. Retention policy hasn't expired (default: 90 days)

### Chart not appearing in dashboard

Make sure:
1. `chart.js` CDN is accessible
2. Metrics JSON is valid
3. Dashboard HTML is being updated (check file modification time)
4. Browser console doesn't show JavaScript errors

## Customization

### Change Collection Schedule

Edit `.github/workflows/update-dashboard-metrics.yml`:

```yaml
schedule:
  - cron: '0 2 * * *'  # Change to whatever you prefer
```

Cron format: `minute hour day month day-of-week`

### Change Chart Type

```bash
./scripts/shell/embed-metrics-in-dashboard.sh \
  --chart-type area  # or 'bar'
```

### Limit Data Points

```bash
./scripts/shell/embed-metrics-in-dashboard.sh \
  --max-points 30  # Show only last 30 days
```

### Filter by Target

When collecting metrics, filter by specific target:

```bash
./scripts/shell/get-scan-metrics.sh --target iris
```

## Integration with Existing Dashboards

The metrics collection is designed to work with existing epyon dashboards:

1. **Generate dashboard normally** via existing workflow
2. **Collect metrics** as a post-processing step  
3. **Embed chart** into generated HTML
4. **Upload updated** dashboard as artifact

This way, you keep all existing dashboard features and add metrics visualization on top.

## Performance Notes

- **Small repos** (< 100 runs): < 1 minute
- **Medium repos** (100-500 runs): 1-3 minutes
- **Large repos** (500+ runs): 3-10 minutes (with caching: much faster)

Typical cron job completes in under 2 minutes after first run.

## Examples

### Example 1: Daily Metrics Update with Email

```bash
# Add to cron (runs at 3 AM)
0 3 * * * /path/to/scripts/shell/collect-metrics-from-github.sh \
  --repo MetroStar/epyon \
  --days 90 && \
  echo "✅ Metrics updated" | mail -s "Dashboard Updated" team@example.com
```

### Example 2: Pre-release Security Check

```bash
# Before release, check metrics for last 7 days
./scripts/shell/collect-metrics-from-github.sh --days 7

# Generate metrics summary
jq '.summary' metrics/metrics-90d.json

# If critical > 0, block release
TEST=$(jq '.summary.critical_total' metrics/metrics-90d.json)
[ "$TEST" -gt 0 ] && echo "❌ Critical issues found!" && exit 1
```

### Example 3: Trend Analysis

```bash
# Show trend: compare weekly metrics
./scripts/shell/get-scan-metrics.sh --since 2026-03-16 --until 2026-03-23
./scripts/shell/get-scan-metrics.sh --since 2026-03-09 --until 2026-03-16

# Manually diff the JSON files to see weekly trend
jq '.summary' metrics-week2.json
jq '.summary' metrics-week1.json
```

---

**Last Updated:** March 23, 2026
