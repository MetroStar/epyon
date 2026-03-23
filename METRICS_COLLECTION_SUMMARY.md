# Automatic Metrics Collection & Dashboard Integration

You now have a complete metrics collection system that automatically pulls scan metrics from the last 90 days and adds them to your dashboard with interactive charts.

## What Was Created

### 1. **Scripts** (in `scripts/shell/`)

#### `collect-metrics-from-github.sh` (10 KB)
- Pulls all `metrics-{scan_id}` artifacts from GitHub Actions
- Aggregates them into a time-series JSON file
- Auto-detects your repository
- Caches results locally to avoid redundant API calls

**Quick start:**
```bash
./scripts/shell/collect-metrics-from-github.sh --repo MetroStar/epyon --days 90
```

#### `embed-metrics-in-dashboard.sh` (12 KB)
- Takes metrics JSON and embeds an interactive Chart.js visualization
- Creates line/area/bar charts showing Critical, High, Medium, Low trends
- Adds summary stat cards (latest values, averages)
- Fully responsive and interactive

**Quick start:**
```bash
./scripts/shell/embed-metrics-in-dashboard.sh --metrics metrics-90d.json --dashboard dashboard.html
```

#### `update-metrics-dashboard.sh` (9 KB) ⭐ **Recommended**
- One-command wrapper that does everything
- Collects metrics → Embeds in dashboard → Done
- Auto-detects your latest dashboard
- Shows progress and summary statistics

**Quick start:**
```bash
./scripts/shell/update-metrics-dashboard.sh
```

### 2. **Workflow** (`.github/workflows/`)

#### `update-dashboard-metrics.yml`
- Runs nightly at 2 AM UTC (configurable)
- Can be manually triggered with custom day ranges
- Automatically:
  - Collects metrics from last 90 days
  - Generates dashboard
  - Embeds metrics chart
  - Uploads artifacts (90-day retention)
  - Posts summary to GitHub actions

**Trigger manually:**
```bash
gh workflow run update-dashboard-metrics.yml --ref main
```

### 3. **Documentation** (`documentation/`)

#### `METRICS_COLLECTION_GUIDE.md`
Complete guide covering:
- How the system works
- Usage examples
- Troubleshooting
- Customization options
- Integration patterns

## How It Works

```
Run scans → Create scan-metrics.json → Upload metrics-{scan_id} artifact
                                                          ↓
                                    Scheduled job (nightly)
                                                          ↓
                        collect-metrics-from-github.sh (pull all metrics)
                                                          ↓
                    generate-security-dashboard.sh (create/update dashboard)
                                                          ↓
                       embed-metrics-in-dashboard.sh (add chart visualization)
                                                          ↓
                    Upload to artifacts (available to download/view)
```

## Quick Examples

### Example 1: Update Dashboard Right Now (Recommended)

```bash
cd scripts/shell
./update-metrics-dashboard.sh
```

Output:
```
→ Step 1/3: Collecting metrics from last 90 days...
✅ Metrics collected: /path/to/metrics/metrics-90d.json
→ Step 2/3: Preparing dashboard...
✅ Dashboard template created
→ Step 3/3: Embedding metrics chart...
✅ Metrics embedded in dashboard

════════════════════════════════════════════════
✅ Dashboard Update Complete
════════════════════════════════════════════════

  📊 Metrics:   /path/to/metrics/metrics-90d.json
  📄 Dashboard: /path/to/scans/iris.../security-dashboard.html
  📈 Chart Type: line
  📅 Time Range: Last 90 days

  📌 Quick Stats:
     Total Scans: 24
     Critical: 5
     High: 12
```

### Example 2: Collect Metrics Only

```bash
./scripts/shell/collect-metrics-from-github.sh --repo MetroStar/epyon --days 90
```

### Example 3: Custom Chart Settings

```bash
./scripts/shell/update-metrics-dashboard.sh \
  --days 30 \
  --chart-type area \
  --max-points 30
```

### Example 4: Specific Dashboard File

```bash
./scripts/shell/update-metrics-dashboard.sh scans/iris_rnelson_2026-03-17/consolidated-reports/dashboards/security-dashboard.html
```

### Example 5: Just Embed (Metrics Already Collected)

```bash
./scripts/shell/embed-metrics-in-dashboard.sh \
  --metrics metrics/metrics-90d.json \
  --dashboard scans/latest/dashboard.html
```

## What the Dashboard Chart Shows

**Interactive Line Chart with 4 Datasets:**
- 🔴 **Critical** (red) - Top priority issues
- 🟠 **High** (orange) - High priority issues
- 🟡 **Medium** (yellow) - Medium priority issues
- 🟢 **Low** (green) - Low priority issues

**Summary Cards Below Chart:**
- Latest Critical count
- Latest High count
- Average Critical (across all scans)
- Average High (across all scans)

**Interactivity:**
- Hover over points to see exact values and target name
- Click legend items to toggle datasets on/off
- Responsive design (works on mobile too)
- Built with Chart.js 4.4

## Integration Points

### For Your Existing Workflows

If you want to add metrics to your running scans:

```yaml
- name: Update Dashboard with Metrics
  if: always()
  run: |
    ./scripts/shell/collect-metrics-from-github.sh \
      --repo ${{ github.repository }} \
      --days 90
      
    ./scripts/shell/embed-metrics-in-dashboard.sh \
      --metrics metrics/metrics-90d.json \
      --dashboard scans/${{ steps.run-scan.outputs.scan_dir }}/consolidated-reports/dashboards/security-dashboard.html
    
    # Upload updated dashboard
    - uses: actions/upload-artifact@v4
      with:
        name: dashboard-with-metrics
        path: scans/${{ steps.run-scan.outputs.scan_dir }}/consolidated-reports/dashboards/security-dashboard.html
```

### With Existing Dashboard Generation

The scripts work with your existing `generate-security-dashboard.sh`. Just run them after dashboard generation:

```bash
# Your normal dashboard generation
./generate-security-dashboard.sh

# Then add metrics
./collect-metrics-from-github.sh --days 90
./embed-metrics-in-dashboard.sh \
  --metrics metrics-90d.json \
  --dashboard <path-to-generated-dashboard.html>
```

## Data Flow

**What Gets Collected:**
```json
{
  "scan_id": "iris_user_2026-03-17_14-30-00",
  "timestamp": "2026-03-17T14:30:00Z",
  "target_name": "iris",
  "scan_user": "rnelson",
  "critical": 5,
  "high": 12,
  "medium": 34,
  "low": 89
}
```

For each scan run that produces metrics.

**What's Aggregated:**
```json
{
  "generated_at": "2026-03-23T10:30:00Z",
  "total_scans": 24,
  "scans_with_findings": 18,
  "summary": {
    "critical_total": 45,
    "high_total": 156,
    "medium_total": 287,
    "low_total": 892
  },
  "metrics": [...]  // All individual scans
}
```

## Requirements

All scripts handle requirements checking automatically, but you need:

- **GitHub CLI** (`gh`) - For pulling artifacts
- **jq** - For JSON processing
- **Git** - For auto-detecting your repo
- **Bash 4.0+** - For script execution

**Install on macOS:**
```bash
brew install gh jq
```

**Install on Ubuntu/Debian:**
```bash
sudo apt-get install gh jq
```

**Authenticate GitHub CLI:**
```bash
gh auth login
```

## Troubleshooting

### "GitHub CLI not authenticated"
```bash
gh auth login
```

### "No metrics found"
Make sure:
1. Your scans are actually running
2. They produce `scan-metrics.json` files
3. Those files are uploaded as `metrics-{scan_id}` artifacts
4. Artifacts haven't expired (default 90-day retention)

### Chart not showing
- Check browser console for errors
- Verify metrics JSON is valid: `jq '.' metrics-90d.json`
- Make sure Chart.js CDN is accessible

### "jq: command not found"
```bash
# Install jq
brew install jq  # macOS
sudo apt-get install jq  # Linux
```

## Next Steps

1. **Try it now:**
   ```bash
   ./scripts/shell/update-metrics-dashboard.sh
   ```

2. **Set it to run automatically:**
   - The workflow is already configured in `.github/workflows/update-dashboard-metrics.yml`
   - It runs nightly at 2 AM UTC
   - You can manually trigger it anytime

3. **Integrate with your CI/CD:**
   - Add metrics collection to your existing scan workflows
   - Follow examples in `METRICS_COLLECTION_GUIDE.md`

4. **Customize:**
   - Change chart type (line/area/bar)
   - Adjust time range (30/60/90/180 days)
   - Filter by target or user
   - See `METRICS_COLLECTION_GUIDE.md` for all options

## Files Created

```
scripts/shell/
├── collect-metrics-from-github.sh    (10 KB, executable)
├── embed-metrics-in-dashboard.sh     (12 KB, executable)
└── update-metrics-dashboard.sh        (9 KB, executable) ⭐ Use this one!

.github/workflows/
└── update-dashboard-metrics.yml       (Scheduled nightly job)

documentation/
└── METRICS_COLLECTION_GUIDE.md        (Complete guide)
```

## Summary

You now have:
- ✅ Automatic metrics collection (last 90 days)
- ✅ Interactive dashboard charts
- ✅ Summary statistics
- ✅ Nightly scheduled updates
- ✅ Manual override capability
- ✅ Full documentation
- ✅ Easy one-command usage

**To get started:** Run `./scripts/shell/update-metrics-dashboard.sh` right now!

---

**Created:** March 23, 2026
**Metrics Window:** 90 days (configurable)
**Schedule:** Nightly at 2 AM UTC
