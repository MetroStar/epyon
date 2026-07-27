# STIG Findings - Manual Documentation Guide

This document provides guidance on creating and maintaining manual STIG documentation in target repositories (e.g., `docs/stig-findings.md` or `docs/security/stig-findings.md`) to document STIG assessments and overrides.

## Purpose

The Epyon STIG assessment engine (Layer 13) automatically collects and reads documentation files from target repositories, including:
- `docs/stig-findings.md` or `docs/security/stig-findings.md` (highest priority)
- `COMPLIANCE.md`
- `STIG.md`
- `SECURITY.md`
- Any markdown/JSON files in `docs/`, `documentation/`, `security/`, `.github/`, or `.compliance/` directories

These files are provided to the AI assessment engine as **priority context**. When humans have explicitly documented STIG controls with evidence, the AI will respect those assessments unless specific code changes invalidate them.

## When to Use Manual Documentation

Use manual STIG documentation in these scenarios:

1. **Runtime-Only Controls**: Controls that cannot be assessed statically (e.g., "System displays a warning banner at logon" requires seeing the actual running application)
2. **Policy-Based Controls**: Controls satisfied by organizational policies rather than code (e.g., "Training on secure coding practices is provided annually")
3. **Environment-Specific Controls**: Controls that vary by deployment environment and cannot be determined from source code alone
4. **Complex Architectural Assessments**: Controls requiring deep understanding of system architecture that static analysis might miss
5. **Overriding AI Assessments**: When the AI incorrectly assesses a control and you have definitive evidence of compliance or non-compliance

## Recommended Format

Create `docs/stig-findings.md` (or `docs/security/stig-findings.md`) in your target repository with this structure:

```markdown
# STIG Findings - [Application Name]

Last Updated: YYYY-MM-DD
Assessed By: [Name/Team]

## Manual Assessments

### APSC-DV-000070 — Session Lock Implementation

**Status**: Not a Finding  
**Confidence**: 95

**Evidence**:
The application implements automatic session lock after 15 minutes of inactivity.
- File: `src/middleware/sessionMiddleware.ts` — `SESSION_TIMEOUT = 900` (15 minutes in seconds)
- File: `src/auth/sessionManager.ts` — `checkInactivityTimeout()` function enforces logout at 15 minutes
- Configuration: Keycloak realm policy sets `sso-session-idle-timeout = 900`
- Tested manually on 2026-07-01 — session automatically locked after 15 minutes of no activity
- Requirement: SATISFIED — session timeout ≤ 15 minutes as required by APSC-DV-000070

**Justification for Manual Assessment**:
This control requires runtime verification. While the configuration values are correct in source code, we verified actual behavior in a deployed environment to confirm the timeout is enforced.

---

### APSC-DV-001240 — Security Training Documentation

**Status**: Not Applicable  
**Confidence**: 100

**Evidence**:
This application is an internal library/SDK with no user-facing components or authentication mechanisms.
- File: `README.md` — Documents that this is a "reusable component library"
- File: `package.json` — No web framework dependencies (Express, Flask, Django, etc.)
- No UI files (HTML, JSX, Vue, etc.) in the repository
- No authentication/session logic present in source code

**Justification for Manual Assessment**:
Security training requirements apply to applications with user authentication. This is a library with no users, sessions, or authentication — training controls do not apply.

---

### APSC-DV-003320 — DoD PKI Certificate Implementation

**Status**: Open  
**Confidence**: 80

**Evidence**:
The application is configured to accept DoD PKI certificates but requires manual validation in the production environment.
- File: `config/tls.yaml` — `client_ca_file: /etc/ssl/dod-root-ca.pem` references DoD root CA
- File: `src/auth/certAuth.ts` — `verifyClientCertificate()` function validates certificate chain
- Configuration: Production Nginx config includes `ssl_client_certificate` directive

**Missing Evidence**:
- Need to verify the actual DoD root CA bundle is deployed in production at `/etc/ssl/dod-root-ca.pem`
- Need to test with actual DoD CAC card to confirm certificate validation works end-to-end
- Certificate revocation checking (OCSP) is not implemented — this is a gap

**Justification for Manual Assessment**:
Static analysis shows the code is configured correctly, but actual PKI integration requires deployment validation. Status remains Open until production testing confirms full compliance.

---

## Controls Already Assessed by Epyon

The following controls are automatically assessed by Epyon's static analysis and do not require manual documentation unless you disagree with the automated assessment:

- APSC-DV-000160 — Session ID Randomness (automatically verified from session library source)
- APSC-DV-001460 — Password Complexity (automatically verified from Keycloak realm config)
- APSC-DV-002440 — SQL Injection Prevention (automatically verified from ORM usage patterns)
- APSC-DV-002520 — XSS Protection (automatically verified from template engine auto-escaping)
- APSC-DV-003270 — Cryptographic Key Storage (automatically verified from key management code)

Only document these if you have specific evidence that contradicts the automated assessment.
```

## Best Practices

### 1. **Cite Specific Files and Values**

**Good**:
```markdown
- File: `src/config/database.ts` — `ssl: true, sslMode: 'require'`
- TLS 1.2+ enforced via PostgreSQL `ssl_min_protocol_version = 'TLSv1.2'`
```

**Bad**:
```markdown
- The application uses secure database connections
- TLS is configured properly
```

### 2. **Include Confidence Scores**

Use the same 0-100 scale as Epyon:
- **90-100**: Definitive evidence; personally verified in running system
- **70-89**: Strong evidence with minor gaps (e.g., config correct but not runtime-tested)
- **40-69**: Partial evidence; key verification missing
- **1-39**: Minimal evidence; mostly architectural inference

### 3. **Explain Why Manual Assessment Was Needed**

Every manual assessment should include a "Justification" section explaining why static analysis was insufficient. This helps reviewers understand your reasoning.

### 4. **Update Dates When Re-Assessing**

When code changes affect a manually documented control, update the "Last Updated" date and revise the evidence. Outdated manual documentation confuses the AI and reviewers.

### 5. **Use Standard STIG Status Values**

Always use exactly one of these four statuses:
- `Not a Finding` — Control is satisfied
- `Not Applicable` — Control does not apply to this application
- `Open` — Control is not satisfied (default)
- `Not Reviewed` — Reserved for runtime-only controls with zero static indicators

## How Epyon Uses Manual Documentation

When processing STIG controls, Epyon:

1. **Collects all markdown/JSON** files from your repository's `docs/`, `.github/`, and root directories
2. **Provides them as priority context** to the AI assessment engine
3. **Instructs the AI to defer** to explicit manual assessments unless code changes invalidate them
4. **Combines manual evidence** with automated static analysis for a comprehensive view

The AI is specifically instructed:
> "Manual STIG documentation from the target repository (e.g., docs/stig-findings.md, docs/security/stig-findings.md, COMPLIANCE.md, STIG.md) containing human-authored STIG assessments, manual overrides, compliance notes, and human-verified evidence. **THESE FILES TAKE PRIORITY** — if a human has explicitly documented a control as satisfied with specific evidence, respect that assessment unless you find concrete code changes that invalidate it."

## Example Workflow

1. **Run initial Epyon scan** to get baseline AI assessments
2. **Review STIG findings** in the generated `stig-findings.md` report
3. **Identify controls requiring manual assessment** (runtime checks, policy-based, etc.)
4. **Create manual documentation** at `docs/stig-findings.md` or `docs/security/stig-findings.md` with your manual evidence
5. **Re-run Epyon scan** — AI will incorporate your manual assessments
6. **Update manual documentation** when code changes affect documented controls

## Common Mistakes to Avoid

### ❌ Don't Document Automatically-Assessed Controls

If Epyon already correctly assesses a control from source code, don't duplicate that in manual documentation. This creates maintenance burden and can drift out of sync.

### ❌ Don't Use Vague Evidence

"The application is secure" or "This control is implemented" provides no value. Always cite specific files and configuration values.

### ❌ Don't Forget Justifications

Without explaining why manual assessment was needed, reviewers can't distinguish between legitimate runtime-only controls and lazy documentation.

### ❌ Don't Leave Stale Documentation

When you update code that affects a manually documented control, update the documentation too. Outdated evidence misleads the AI and reviewers.

## Integration with Freeze Logic

Epyon's STIG freeze logic works with both automated and manual assessments:

- **Automated assessments** with `confidence ≥ 85` and status `Not a Finding`/`Not Applicable` freeze automatically
- **Manual assessments** in `docs/stig-findings.md` or `docs/security/stig-findings.md` with high confidence are respected by the AI
- **Changes to documented code** trigger AI re-assessment, but the AI will reference your manual evidence when making the new assessment

This creates a layered defense:
1. Manual documentation provides the baseline
2. Freeze logic prevents frivolous re-assessments
3. AI monitors for code changes that affect compliance

## Further Reading

- [STIG Compliance Guide](STIG_COMPLIANCE_GUIDE.md) — Full documentation on Epyon's STIG assessment process
- [Freeze Logic Documentation](STIG_COMPLIANCE_GUIDE.md#freeze-logic) — How Epyon prevents status changes without evidence
- [AI Assessment Methodology](../scripts/shell/run-stig-assessment.py) — See the SYSTEM_PROMPT in the source code
