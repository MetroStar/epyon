# Vulnerability Deduplication Implementation

## Overview
Implemented deduplication logic in `generate-scan-findings-summary.sh` to eliminate duplicate vulnerability counting when the same issue is detected by multiple security tools.

## Problem Statement
Prior to this implementation, the same vulnerability could be counted multiple times:
- **CVE-2025-13465** in **lodash@4.17.21** detected by:
  - Grype (SBOM scan)
  - Grype (image scan)  
  - Trivy (filesystem scan)
  - Trivy (base image scan)
- **Result**: Counted 4 times instead of 1 unique vulnerability

This caused:
- **Inflated vulnerability counts** in security summaries
- **Inaccurate severity gate decisions** (build pass/fail based on wrong counts)
- **Discrepancies between dashboards** (different scan types = different duplicate counts)

### Example Discrepancy
- **Epyon Local Dashboard**: 33 critical, 101 high
- **GitHub Actions Summary**: 22 critical, 67 high
- **Cause**: Local runs more scan types, creating more duplicates

## Solution

### Unique Key Generation
Findings are deduplicated using composite keys:

**Vulnerabilities** (CVE-based):
```
CVE-ID | Package-Name | Package-Version
Example: "CVE-2025-13465|lodash|4.17.21"
```

**Secrets** (TruffleHog):
```
Detector-Type | File-Path | Line-Number
Example: "Grafana|/workspace/README.md|62"
```

**IaC Issues** (Checkov):
```
Check-ID | File-Path | Line-Number
Example: "CKV_DOCKER_2|Dockerfile|15"
```

### Deduplication Process

1. **Group by Unique Key**: All findings at each severity level grouped by their composite key
2. **Keep First Occurrence**: First detection preserved with all original metadata
3. **Add Detection Metadata**: Enhanced with:
   - `detected_by`: Array of tools that found the issue (e.g., `["Grype", "Trivy"]`)
   - `occurrences`: Number of times detected across all tools
4. **Recalculate Totals**: Counts updated to reflect unique findings only

### Implementation Location
**File**: `scripts/shell/generate-scan-findings-summary.sh`
**Lines**: ~490-575 (before final summary update)

## Results

### Sapphire Scan Example
**Before Deduplication**:
- 🔴 Critical: 2
- 🟡 High: 0
- 🔵 Medium: 2
- ⚪ Low: 0

**After Deduplication**:
- 🔴 Critical: 1 (unique) ← Grafana secret detected 2x, now counted once
- 🟡 High: 0 (unique)
- 🔵 Medium: 1 (unique) ← CVE-2025-13465 detected 2x, now counted once
- ⚪ Low: 0 (unique)

### Detection Transparency
Example deduplicated finding:
```json
{
  "id": "CVE-2025-13465",
  "package": "lodash",
  "version": "4.17.21",
  "tool": "Trivy-filesystem",
  "detected_by": ["Trivy-filesystem"],
  "occurrences": 2,
  "severity": "MEDIUM",
  "description": "Lodash prototype pollution vulnerability..."
}
```

**Key Points**:
- Original `tool` field preserved (first detection)
- `detected_by` array shows all tools that found it
- `occurrences` shows total detection count
- Allows tracking tool coverage without inflating counts

## Impact on Other Systems

### Severity Gates (check-severity-gate.sh)
- **Before**: Gates triggered on inflated counts (e.g., 33 critical when only 15 unique)
- **After**: Gates use accurate unique counts for pass/fail decisions
- **Files Using Summary**: 
  - `run-target-security-scan.sh`
  - `run-baseline-scan.sh`
  - `check-severity-gate.sh`
  - GitHub Actions workflows

### Dashboard Displays
- **Consolidated Reports**: Show unique counts with "(unique)" label
- **Tool Attribution**: `detected_by` array allows showing which tools found each issue
- **Future Enhancement**: Could display "Detected by 3 tools" badge in UI

### API Endpoints (Future)
When REST API is implemented:
- `/api/findings` returns deduplicated results
- `?include_duplicates=true` optional parameter to show all detections
- `detected_by` field enables tool-specific filtering

## Testing

### Manual Verification
```bash
# Run on existing scan
source ./scripts/shell/generate-scan-findings-summary.sh
generate_scan_findings_summary "sapphire_rnelson_2026-02-06_15-32-13" "/tmp/sapphire" "$PWD"

# Check results
jq '.critical_findings[0] | {id, package, detected_by, occurrences}' \
  scans/sapphire_rnelson_2026-02-06_15-32-13/security-findings-summary.json
```

### Expected Behavior
- Duplicate CVEs from different tools → 1 count
- Same secret in same file/line → 1 count  
- Same IaC check failure → 1 count
- Different packages with same CVE → Separate counts (correct)
- Same package, different versions → Separate counts (correct)

## Technical Details

### jq Function: `vuln_key`
```jq
def vuln_key:
  if .vulnerability_id or .id then 
    # Vulnerability: CVE + package + version
    ((.vulnerability_id // .id) + "|" + 
     (.package_name // .package // "") + "|" + 
     (.package_version // .version // ""))
  elif .detector then
    # Secret: detector + file + line (convert numbers to string)
    ((.detector // "") + "|" + 
     (.file_path // .file // "") + "|" + 
     ((.line_number // .line // "unknown") | tostring))
  elif .check_id then
    # IaC: check + file + line
    ((.check_id // "") + "|" + 
     (.file_path // .file // "") + "|" + 
     ((.line_number // "unknown") | tostring))
  else
    # Fallback: type + file + description
    ((.type // "unknown") + "|" + 
     (.file_path // .file // "") + "|" + 
     ((.description // "")[0:50] // ""))
  end;
```

### Key Design Decisions

**Why not deduplicate across severity levels?**
- Different severities = different vulnerabilities (e.g., CVSS score varies by context)
- Maintains tool-reported severity without reinterpretation

**Why keep `tool` field when we have `detected_by`?**
- Preserves original data structure (backward compatibility)
- `tool`: First detection (deterministic)
- `detected_by`: All detections (complete picture)

**Why use `tostring` for line numbers?**
- TruffleHog/Checkov may return `line_number` as integer
- String concatenation requires all parts to be strings
- Prevents "string and number cannot be added" errors

## Future Enhancements

### Cross-Severity Deduplication
If same CVE appears as both HIGH and CRITICAL (rare), consider:
- Taking highest severity
- Merging into single finding with severity range

### Duplicate History Tracking
Add to scan manifest:
```json
{
  "deduplication_stats": {
    "total_before": 200,
    "total_after": 145,
    "duplicates_removed": 55,
    "duplicate_rate": "27.5%"
  }
}
```

### Tool Coverage Analysis
Generate report showing:
- Which tools find unique issues
- Which tools overlap completely
- Coverage gaps (issues only one tool finds)

### Dashboard Enhancements
- Color-code findings by tool consensus (red = 1 tool, yellow = 2 tools, green = 3+ tools)
- Filter findings by "detected_by" to compare tool effectiveness
- Show "Duplicate Removed" badge in detailed view

## Validation Checklist

- [x] Deduplication runs before total calculation
- [x] Unique keys handle null/missing fields gracefully
- [x] Line numbers converted to strings (avoid type errors)
- [x] `detected_by` array shows all tools
- [x] `occurrences` count reflects true detection count
- [x] Output labeled "(unique)" to clarify deduplicated counts
- [x] Tested on real scan with duplicates (sapphire)
- [ ] Tested on GitHub Actions workflow scan
- [ ] Validated severity gate uses correct unique counts
- [ ] Confirmed no breaking changes to API consumers

## Related Documentation
- [DASHBOARD_DATA_GUIDE.md](./DASHBOARD_DATA_GUIDE.md) - Data structure reference
- [SCAN_DIRECTORY_ARCHITECTURE.md](./SCAN_DIRECTORY_ARCHITECTURE.md) - Scan result organization
- [COMPREHENSIVE_SECURITY_ARCHITECTURE.md](./COMPREHENSIVE_SECURITY_ARCHITECTURE.md) - Security scanning overview
