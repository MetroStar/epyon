# Epyon Ignore Rules Guide

Suppress security findings with documented justifications using `.epyon-ignore.yml`.

## Overview

The `.epyon-ignore.yml` file allows you to:
- Suppress known false positives
- Accept risks with documented justification
- Temporarily ignore findings pending fixes
- Exclude test/fixture files from scans
- Track who approved each exception

## Quick Start

1. **Create `.epyon-ignore.yml` in your repository root:**
   ```yaml
   version: "1.0"
   ignores:
     - type: cve
       value: CVE-2024-12345
       reason: "Not vulnerable - we don't use this function"
       expires: "2026-06-01"
   ```

2. **Run scan** - ignored findings won't fail the build

3. **Review suppressed findings** in `suppressed-findings.md` artifact

## Ignore Types

### CVE IDs
Ignore specific vulnerabilities across all tools:
```yaml
- type: cve
  value: CVE-2024-12345
  reason: "False positive - not exploitable in our context"
  expires: "2026-12-31"
  approved_by: "security-team@company.com"
```

**Applies to:** Grype, Trivy, Anchore

### Package Versions
Ignore specific package version:
```yaml
- type: package
  value: urllib3@2.3.0
  reason: "Waiting for upstream fix, mitigated by network controls"
  expires: "2026-03-15"
```

Ignore all versions of a package:
```yaml
- type: package
  value: pyasn1
  reason: "Transitive dependency, cannot upgrade yet"
  expires: "2026-06-01"
```

**Matching rules:**
- `urllib3@2.3.0` - Only matches version 2.3.0 exactly
- `urllib3` - Matches all versions

**Applies to:** Grype, Trivy, Anchore

### File Paths
Ignore findings in specific files/directories:
```yaml
- type: path
  value: "tests/**"
  reason: "Test fixtures with intentional vulnerabilities"
```

```yaml
- type: path
  value: "vendor/legacy-lib.js"
  reason: "Being replaced in next sprint"
  expires: "2026-03-01"
```

**Pattern matching:**
- `tests/**` - All files under tests/ recursively
- `*.test.js` - All test files
- `src/legacy/*` - Files directly in src/legacy/
- `config.example.yml` - Specific file

**Applies to:** All tools

### Tools
Disable an entire scanning tool:
```yaml
- type: tool
  value: checkov
  reason: "No IaC files in this repository"
```

**Tool names:** `grype`, `trivy`, `trufflehog`, `checkov`, `clamav`, `anchore`, `xeol`

### Secret Detectors
Ignore specific secret types in certain paths:
```yaml
- type: secret-detector
  value: "PrivateKey"
  paths:
    - "tests/**"
    - "fixtures/**"
  reason: "Test SSH keys only"
```

Ignore everywhere (not recommended):
```yaml
- type: secret-detector
  value: "GenericSecret"
  reason: "Known false positive pattern"
  expires: "2026-02-15"
```

**Applies to:** TruffleHog

### Secret Patterns
Ignore secrets matching regex patterns:
```yaml
- type: secret-pattern
  value: "test_api_key_.*"
  reason: "Test API keys with 'test_' prefix"
```

**Applies to:** TruffleHog

## Required Fields

| Field | Required | Description |
|-------|----------|-------------|
| `type` | ✅ Yes | Ignore type (see above) |
| `value` | ✅ Yes | What to ignore |
| `reason` | ✅ Yes | Justification (audit trail) |
| `expires` | ⚠️ Recommended | Expiration date (YYYY-MM-DD) |
| `approved_by` | ℹ️ Optional | Who approved (compliance) |
| `paths` | ℹ️ Optional | Limit to specific paths (secret-detector only) |

## Expiration Handling

**Behavior when ignore expires:**
- ⚠️ **Warning displayed** during scan
- ❌ **Build does NOT fail** automatically
- 📋 **Finding is NOT ignored** (counted again)
- 📝 **Listed in suppressed-findings.md** as expired

**Best practices:**
- Always set `expires` for temporary ignores
- Review expired ignores monthly
- Permanent ignores (tests, tools) don't need expiration

## Audit Trail

Every scan generates **`suppressed-findings.md`** with:
- What was ignored
- Why it was ignored
- Who approved it
- Expiration status

**Example output:**
```markdown
## Suppressed: CVE-2024-12345
- **Tool**: Grype
- **Type**: cve
- **Severity**: High
- **Reason**: Not vulnerable - we don't use this function

## Suppressed: urllib3@2.3.0
- **Tool**: Grype
- **Type**: package
- **Severity**: High
- **Reason**: Waiting for upstream fix, mitigated by WAF
```

## Example Workflows

### False Positive
```yaml
- type: cve
  value: CVE-2024-99999
  reason: "False positive - scanner incorrectly detects our internal version string"
  approved_by: "security-team@company.com"
  # No expiration - permanent false positive
```

### Accepted Risk
```yaml
- type: package
  value: old-package@1.2.3
  reason: "Risk accepted: Low severity, app not exposed to internet"
  expires: "2026-12-31"
  approved_by: "ciso@company.com"
```

### Pending Fix
```yaml
- type: cve
  value: CVE-2024-12345
  reason: "Fix scheduled for Sprint 23, mitigated by authentication layer"
  expires: "2026-03-15"
  approved_by: "tech-lead@company.com"
```

### Test Files
```yaml
- type: path
  value: "tests/**"
  reason: "Test fixtures with intentional vulnerabilities for security testing"
  # No expiration - always ignore tests
```

## Validation

**Invalid YAML is silently skipped** - scan continues without ignores.

To test your ignore file:
```bash
python3 -c "import yaml; yaml.safe_load(open('.epyon-ignore.yml'))"
```

## Security Considerations

**⚠️ Important:**
- **Ignores bypass security checks** - use responsibly
- **Require code review** for all ignore additions
- **Mandate `reason` field** - no blank justifications
- **Set expiration dates** - prevent "ignore forever"
- **Audit suppressed findings** - review monthly
- **Track approvers** - use `approved_by` field

**Compliance:**
- SOC 2: Requires documented risk acceptance
- ISO 27001: Requires approval and periodic review
- PCI-DSS: May require compensating controls

## Integration

The ignore system works with:
- ✅ Local scans (`run-target-security-scan.sh`)
- ✅ GitHub Actions workflows
- ✅ All security tools (Grype, Trivy, TruffleHog, etc.)
- ✅ Severity gate checks
- ✅ Dashboard reports

## Troubleshooting

**Ignores not working:**
1. Check file location: `.epyon-ignore.yml` in repository root
2. Validate YAML syntax
3. Check for typos in `type` field
4. Verify `value` matches exactly (CVE-2024-12345 vs cve-2024-12345)
5. Check if ignore has expired

**Still counting findings:**
- Ignores with expired dates are not applied
- Package version must match exactly (`urllib3@2.3.0` ≠ `urllib3@2.3.1`)
- Path patterns are case-sensitive

**Debug mode:**
```bash
# Check what was parsed
cat /tmp/epyon-ignore-cache.json

# Check what was suppressed
cat scans/{SCAN_ID}/suppressed-findings.md
```

## Best Practices

1. ✅ **Always provide detailed `reason`**
2. ✅ **Set `expires` for temporary ignores**
3. ✅ **Use `approved_by` for compliance**
4. ✅ **Version control `.epyon-ignore.yml`**
5. ✅ **Review suppressed findings monthly**
6. ✅ **Require PR approval for ignore changes**
7. ⛔ **Don't ignore Critical without CISO approval**
8. ⛔ **Don't use wildcards excessively**
9. ⛔ **Don't leave expired ignores unaddressed**

## Example Complete File

See [`.epyon-ignore.example.yml`](../.epyon-ignore.example.yml) for a complete example with all ignore types.
