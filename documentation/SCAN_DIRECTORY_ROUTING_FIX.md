# Scan Directory Routing Fix
**Date:** November 17, 2025  
**Issue:** Reports were still being routed to `scripts/reports` instead of individual scan directories

## Problem Summary

After running a security scan, the output message showed:
```
Reports: /Users/rnelson/Desktop/CDAO Marketplace/app/comprehensive-security-architecture/scripts/reports
```

However, the architecture was designed to store all scan artifacts in individual scan directories like:
```
scans/advana-marketplace_rnelson_2025-11-17_09-25-12/
```

## Root Causes Identified

### 1. **Orchestrator Script Issues** (`run-target-security-scan.sh`)
- Report discovery still looked in `$REPORTS_ROOT/reports/*-reports/`
- High-priority issue detection checked `$REPORTS_ROOT/reports/*/` paths
- Analysis section checked `$REPO_ROOT/reports/*/` paths
- Consolidation and findings summary used old report paths
- Final output message displayed old reports directory

### 2. **Individual Tool Scripts Had Hardcoded Paths**
Several tool scripts had hardcoded `REPORTS_DIR` or `OUTPUT_DIR` variables that bypassed the scan directory template:

- **Anchore** (`run-anchore-scan.sh`): Used `REPORTS_DIR="$REPO_ROOT/reports/anchore-reports"`
- **SonarQube** (`run-sonar-analysis.sh`): Used `$REPO_ROOT/reports/sonar-reports/`
- **ClamAV** (`run-clamav-scan.sh`): Had duplicate `OUTPUT_DIR` definition
- **Helm** (`run-helm-build.sh`): Had hardcoded `OUTPUT_DIR` and `SCAN_LOG`
- **Grype** (`run-grype-scan.sh`): Had duplicate `OUTPUT_DIR` definition

### 3. **Findings Summary Output Path** (`generate-scan-findings-summary.sh`)
- Output file path was `$project_root/reports/security-reports/${scan_id}_security-findings-summary.json`
- Should have been `$SCAN_DIR/security-findings-summary.json`

## Changes Made

### A. Orchestrator Script Updates (`run-target-security-scan.sh`)

1. **Report Discovery** - Changed from scanning `reports/*-reports/` to scanning `$SCAN_DIR/*/`:
```bash
# OLD:
find "$REPORTS_ROOT/reports" -name "*-reports" -type d 2>/dev/null

# NEW:
find "$SCAN_DIR" -mindepth 1 -maxdepth 1 -type d 2>/dev/null
```

2. **High-Priority Issue Detection** - Updated all file paths:
```bash
# OLD:
"$REPORTS_ROOT/reports/grype-reports/${SCAN_ID}_grype-filesystem-results.json"

# NEW:
"$SCAN_DIR/grype/${SCAN_ID}_grype-filesystem-results.json"
```

3. **Analysis Operations** - Changed to check `$SCAN_DIR` instead of `$REPO_ROOT/reports`:
```bash
# OLD:
if [[ -f "$REPO_ROOT/reports/trufflehog-reports/trufflehog-filesystem-results.json" ]]

# NEW:
if [[ -d "$SCAN_DIR/trufflehog" ]] && ls "$SCAN_DIR/trufflehog"/*.json &>/dev/null
```

4. **Consolidation Section** - Added note about legacy structure:
```bash
echo -e "${YELLOW}ℹ️  Note: consolidate-security-reports.sh uses legacy reports/ structure${NC}"
echo -e "${YELLOW}ℹ️  Scan results are in: $SCAN_DIR${NC}"
```

5. **Findings Summary** - Updated output path:
```bash
# OLD:
"$REPO_ROOT/reports/security-reports/${SCAN_ID}_security-findings-summary.json"

# NEW:
"$SCAN_DIR/security-findings-summary.json"
```

6. **Final Output** - Updated success message:
```bash
# OLD:
echo -e "${CYAN}Reports: $REPO_ROOT/reports${NC}"

# NEW:
echo -e "${CYAN}All scan artifacts stored in: $SCAN_DIR${NC}"
```

### B. Individual Tool Script Updates

1. **Anchore** (`run-anchore-scan.sh`)
   - Removed `REPORTS_DIR="$REPO_ROOT/reports/anchore-reports"`
   - Changed to use `$OUTPUT_DIR` from scan template
   - Updated all file paths to use `$OUTPUT_DIR`
   - Added `finalize_scan_results` call

2. **SonarQube** (`run-sonar-analysis.sh`)
   - Removed `mkdir -p "$REPO_ROOT/reports/sonar-reports"`
   - Changed output file to `$OUTPUT_DIR/${SCAN_ID}_sonar-analysis-results.json`
   - Updated success message to reference `$OUTPUT_DIR`

3. **ClamAV** (`run-clamav-scan.sh`)
   - Removed duplicate `OUTPUT_DIR` and `SCAN_LOG` definitions
   - Now uses values from scan template

4. **Helm** (`run-helm-build.sh`)
   - Removed hardcoded `OUTPUT_DIR`, `SCAN_LOG`, and `CURRENT_LOG`
   - Now uses values from scan template

5. **Grype** (`run-grype-scan.sh`)
   - Removed duplicate `OUTPUT_DIR` definition
   - Now uses value from scan template

### C. Findings Summary Update (`generate-scan-findings-summary.sh`)

Changed output paths to use scan directory:
```bash
# OLD:
OUTPUT_FILE="$project_root/reports/security-reports/${scan_id}_security-findings-summary.json"
OUTPUT_HTML="$project_root/reports/security-reports/${scan_id}_security-findings-summary.html"

# NEW:
OUTPUT_FILE="$SCAN_DIR/security-findings-summary.json"
OUTPUT_HTML="$SCAN_DIR/security-findings-summary.html"
```

## Directory Structure

### Before (Incorrect - Mixed)
```
scripts/
  reports/
    anchore-reports/
      advana-marketplace_rnelson_2025-11-17_09-25-12_*.json
    sonar-reports/
      sonar-analysis-results.json

scans/
  advana-marketplace_rnelson_2025-11-17_09-25-12/
    grype/
      *.json
    trivy/
      *.json
    # ... other tools
```

### After (Correct - Unified)
```
scans/
  advana-marketplace_rnelson_2025-11-17_09-25-12/
    anchore/
      advana-marketplace_rnelson_2025-11-17_09-25-12_anchore-results.json
    clamav/
      *.log
    grype/
      *.json
    helm/
      *.log
    sonar/
      advana-marketplace_rnelson_2025-11-17_09-25-12_sonar-analysis-results.json
    trivy/
      *.json
    trufflehog/
      *.json
    xeol/
      *.json
    security-findings-summary.json
```

## Backward Compatibility

The `scan-directory-template.sh` creates symlinks from `reports/*-reports/` to the scan directory for backward compatibility:

```bash
reports/
  grype-reports/
    grype-results.json -> ../../scans/{SCAN_ID}/grype/results.json
```

This ensures any existing scripts or tools that reference the old paths will still work.

## Benefits

1. ✅ **Clean Organization** - All scan artifacts in one directory per scan
2. ✅ **Easy Comparison** - Can compare scans by browsing scan directories
3. ✅ **Historical Preservation** - Each scan is self-contained and preserved
4. ✅ **Clear Audit Trail** - Scan ID identifies when and who ran the scan
5. ✅ **No Pollution** - Old `scripts/reports` directory no longer receives new files
6. ✅ **Backward Compatible** - Symlinks maintain compatibility with old paths

## Testing

To verify the fix, run a new scan:
```bash
./scripts/bash/run-target-security-scan.sh "/path/to/target" full
```

Expected output:
```
✅ All scan artifacts stored in: /path/to/scans/{SCAN_ID}
```

Check that all reports are in the scan directory:
```bash
ls -la scans/{SCAN_ID}/*/
```

## Future Work

The `consolidate-security-reports.sh` script still uses the legacy `reports/` structure for consolidated dashboards. This could be updated to:
1. Read from scan directories
2. Output consolidated reports to `scans/{SCAN_ID}/consolidated/`
3. Maintain a `latest` symlink for quick access

## Related Documentation

- `SCAN_DIRECTORY_ARCHITECTURE.md` - Overall architecture documentation
- `scan-directory-template.sh` - Template used by all tools
- Individual tool scripts in `scripts/bash/`
