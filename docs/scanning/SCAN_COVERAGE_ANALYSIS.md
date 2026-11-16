# Epyon Scan Tool Coverage Analysis

## Issue Summary

After analyzing the scan `midas_2026-07-30_23-35-58` (scan type: `full`), I've identified the following tool coverage gaps:

### Missing Layers in Full Scans

| Layer | Tool | Status | Reason |
|-------|------|--------|--------|
| 14 | Picklescan (Model File Analysis) | ✓ Running | No model weight files found - normal for non-ML projects |
| 15 | ModelCard (Compliance) | ✓ Running | Generates findings (4 failed, 3 warnings) |
| 17 | Mobile Code Detection | ❌ NOT RUNNING | Missing from layer-timing.json |
| 18 | Model Provenance | ❌ NOT RUNNING | Missing from scan output |
| 19 | Inference Security | ❌ NOT RUNNING | Missing from scan output |
| 20 | ML Runtime Analysis | ⏭️ Opt-in only | Requires `RUN_ML_RUNTIME=true` |

### Tools Present in Scan Directory

The scan directory contains:
```
anchore/          ✓ Layer 10
api/              ✓ Layer 11  
checkov/          ✓ Layer 6
clamav/           ✓ Layer 4
grype/            ✓ Layer 8
helm/             ✓ Layer 5
modelcard/        ✓ Layer 15
network/          ✓ Layer 16 (was Layer 13)
picklescan/       ✓ Layer 14
pip-audit/        ✓ Layer 8.5
safety/           ✓ Layer 8.6
sbom/             ✓ Layer 1
sonar/            ✓ Layer 3
trivy/            ✓ Layer 7
trufflehog/       ✓ Layer 2
xeol/             ✓ Layer 9
```

### Layer Timing Data

The `layer-timing.json` file shows:
- Layers 1-11 are tracked ✓
- Layers 14-20 are NOT in the timing file ❌

This suggests that:
1. Layers 14-15 (picklescan, modelcard) ARE running but not being tracked in timing
2. Layers 17-19 (mobile-code, model-provenance, inference-security) are NOT running at all
3. Layer 20 (ml-runtime) is opt-in only and correctly skipped

## Root Causes

### 1. Layer Timing Not Updated for ML Layers

The layer timing infrastructure doesn't track layers 14-20. This is a monitoring/observability issue, not a functional issue.

**Fix**: Update the timing tracker to include all 20 layers.

### 2. Layers 18 & 19 Scripts May Be Failing Silently

The scripts `run-model-provenance-check.sh` and `run-inference-security-scan.sh`:
- Check for `TARGET_DIR` environment variable
- Exit gracefully with "skipped" status if conditions aren't met
- May not be creating output directories in some cases

**Hypothesis**: These scripts may be hitting a silent failure path or condition that causes them to skip without logging.

### 3. Web UI Parser Coverage

The web UI parsers (`web/api/parsers.py`) include functions for all ML layers:
- `parse_picklescan_dir()` ✓
- `parse_modelcard_dir()` ✓  
- `parse_model_provenance_dir()` ✓
- `parse_inference_security_dir()` ✓
- `parse_ml_runtime_dir()` ✓
- `parse_mobile_code_dir()` ✓

However, the `parse_scan_findings()` function does NOT call `parse_mobile_code_dir()`, so mobile code findings won't appear in the web UI even if they run.

**Fix**: Add `parse_mobile_code_dir(scan_dir)` to the `parse_scan_findings()` function.

## Recommended Fixes

### Priority 1: Add Mobile Code to Findings Parser

**File**: `web/api/parsers.py`

In the `parse_scan_findings()` function, add:
```python
+ parse_mobile_code_dir(scan_dir)
```

### Priority 2: Debug Layers 18 & 19

Check why `run-model-provenance-check.sh` and `run-inference-security-scan.sh` aren't producing output:

1. Add debug logging to these scripts
2. Check if `TARGET_DIR` is being set correctly
3. Verify the scripts are actually being invoked
4. Check for Python dependency issues (these call `.py` scripts)

### Priority 3: Update Layer Timing Tracker

Add layers 14-20 to the timing infrastructure so they appear in `layer-timing.json`.

### Priority 4: Web UI Display

Ensure all tool cards are being rendered in `app.js`:
- Check that `buildModelSecurityCard()` displays all ML layers
- Verify that mobile code findings would be displayed if present
- Add UI cards for any missing tools

## Testing Recommendations

### Test 1: Verify Mobile Code Parser Integration

```bash
# Run a scan that produces mobile code findings
# Check if they appear in the web UI
```

### Test 2: Force Layers 18 & 19 to Run

```bash
# Run with explicit environment
TARGET_DIR=/path/to/target \
SCAN_ID=test_scan_$(date +%Y-%m-%d_%H-%M-%S) \
SCAN_DIR=scans/test_scan_$(date +%Y-%m-%d_%H-%M-%S) \
./scripts/shell/run-model-provenance-check.sh

TARGET_DIR=/path/to/target \
SCAN_ID=test_scan_$(date +%Y-%m-%d_%H-%M-%S) \
SCAN_DIR=scans/test_scan_$(date +%Y-%m-%d_%H-%M-%S) \
./scripts/shell/run-inference-security-scan.sh
```

### Test 3: Verify Web UI Parsing

```python
# Test that all tool directories are being parsed
from web.api.parsers import parse_scan_findings
from pathlib import Path

scan_dir = Path("scans/midas_2026-07-30_23-35-58")
findings = parse_scan_findings(scan_dir)
print(f"Tools in findings: {findings['summary']['tools_analyzed']}")
```

## Quick Wins

1. **Add mobile code to findings parser** - 5 minute fix
2. **Add debug logging** to layers 18 & 19 scripts - 10 minute fix
3. **Test layer 18 & 19 manually** - 15 minute test

## Long-term Improvements

1. Create a comprehensive scan validation tool that checks:
   - All expected layer directories are present
   - All expected result files exist
   - All parsers successfully read the data
   - All findings appear in the web UI

2. Add integration tests that verify:
   - Each layer produces output
   - Each parser can read each layer's output
   - The web UI displays all tool results

3. Implement scan health monitoring:
   - Dashboard showing which layers ran vs expected
   - Alerts when layers fail silently
   - Metrics on tool success rates
