# Mobile Code Scanner Validation Baseline

**Date**: 2026-07-27  
**Scanner Version**: 1.0.0  
**Test Corpus**: tests/fixtures/mobile-code/

## Baseline Metrics

| Metric | Value |
|--------|-------|
| True Positives | 2 |
| False Positives | 9 |
| False Negatives | 7 |
| True Negatives | 3 |
| **Precision** | **18.2%** |
| **Recall** | **22.2%** |
| **F1 Score** | **0.200** |

## Issues Identified

### 1. Duplicate Findings
The scanner creates multiple findings for the same line when multiple regex patterns match. For example:
- `category-1b/external-js-cdn.html` line 6 creates 3 separate findings:
  - Pattern: `<script[^>]*>`
  - Pattern: `<script[^>]*src=`
  - Pattern: `\.js[\"\']`

**Impact**: Inflates finding counts, creates noise  
**Fix Needed**: Deduplication logic to merge findings from same file/line

### 2. Risk Level Misclassification
The scanner doesn't correctly map mobile code types to DoD risk categories:
- **JavaScript** (all forms) → classified as "medium" (Category 2) instead of:
  - Inline JavaScript → "critical" (Category 1A)
  - External JavaScript → "high" (Category 1B)
- **Java Applet** → "high" (Category 1B) instead of "critical" (Category 1A)
- **Flash** → "high" instead of "critical"
- **Downloadable Executables** → "high" instead of "medium"

**Impact**: False categorization leads to incorrect risk prioritization  
**Fix Needed**: Update `MOBILE_CODE_PATTERNS` risk_level mappings in scanner

### 3. Type Name Inconsistencies
Scanner uses generic type names that don't match the expected fine-grained classifications:
- Uses `javascript_web` for both inline and external JS
- Uses `webstart` instead of `java_webstart`

**Impact**: Cannot distinguish between inline (unsigned) vs external (signed) JavaScript  
**Fix Needed**: Separate patterns for inline vs external JavaScript

### 4. Missing Pattern: VBScript Detection
Scanner detects VBScript but classifies it as "high" instead of "critical" (unsigned executable code).

### 5. No Deduplication by File Location
Multiple patterns match the same code, creating redundant findings.

## Expected vs Actual Type Mappings

| Expected Type | Expected Risk | Actual Type | Actual Risk | Match |
|---------------|---------------|-------------|-------------|-------|
| `inline_javascript` | critical | `javascript_web` | medium | ❌ |
| `external_javascript` | high | `javascript_web` | medium | ❌ |
| `java_applet` | critical | `java_applet` | high | ❌ |
| `flash` | critical | `flash` | high | ❌ |
| `activex` | critical | `activex` | critical | ✅ |
| `vbscript` | critical | `vbscript` | high | ❌ |
| `java_webstart` | high | `webstart` | high | ❌ |
| `browser_extension` | medium | `browser_extension` | medium | ✅ |
| `downloadable_executable` | medium | `downloadable_executable` | high | ❌ |

## Test Corpus Coverage

**✅ Category 1A (Unsigned/Critical):**
- Inline JavaScript
- Java Applet
- Flash embed
- ActiveX objects
- VBScript

**✅ Category 1B (Signed/High):**
- External JavaScript from CDN
- Java Web Start (signed)

**✅ Category 2 (Controlled/Medium):**
- Browser extension with manifest
- Downloadable executables (.exe, .msi, .dmg, .deb)

**✅ Legitimate (No findings expected):**
- Static HTML with CSS (no JavaScript)
- JSON data files

**✅ Ignored Directories:**
- node_modules/ with suspicious code (should be skipped)

## Recommendations for Improvement

1. **Add deduplication logic** to merge findings from same file/line/type
2. **Fix risk level mappings** to match DoD categories correctly
3. **Separate inline vs external JavaScript detection** with distinct patterns
4. **Add confidence scores** to distinguish certain matches from potential false positives
5. **Track files scanned vs skipped** in scan_metadata (next task)
6. **Create acceptance threshold**: Target F1 score ≥ 0.90 (90%)

## Next Steps

1. Update scanner risk level mappings (`scripts/shell/run-mobile-code-scan.py`)
2. Add deduplication logic
3. Re-run validation to measure improvement
4. Add scanner diagnostics metadata (Task 4)
5. Iterate until F1 ≥ 0.90

## Usage

```bash
# Run validation test
cd tests
python3 validate-mobile-code-scanner.py

# Run BATS tests
bats tests/shell/test-mobile-code-validation.bats
```

## Success Criteria

- **Precision** ≥ 90% (few false positives)
- **Recall** ≥ 90% (few false negatives)
- **F1 Score** ≥ 0.90
- Zero findings on legitimate code
- node_modules correctly ignored
