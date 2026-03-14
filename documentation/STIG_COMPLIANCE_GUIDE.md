# STIG Compliance Guide for Epyon

**Document Version**: 1.0  
**Last Updated**: February 6, 2026  
**Status**: Active

## Overview

This guide maps Epyon's security scanning capabilities to Security Technical Implementation Guide (STIG) controls. While Epyon does not provide automated STIG checklist generation (planned for future releases), it can provide critical evidence and validation for many STIG requirements.

## Important Notes

⚠️ **Limitations:**
- Epyon provides **evidence collection** and **technical validation**, not complete STIG compliance
- Manual review and documentation are still required for many controls
- STIG compliance requires organizational processes beyond technical scanning
- This guide covers common STIGs; specific applications may have additional requirements

✅ **Best Use:**
- Evidence collection for STIG control validation
- Continuous monitoring for security drift
- Technical validation before submission to security teams
- Automated security baseline enforcement

---

## STIG Control Mapping by Category

### 1. Application Security Development STIG (V5R3)

#### APSC-DV-000160: The application must protect the confidentiality and integrity of transmitted information.

**Epyon Tools:**
- **Checkov** - Validates TLS/SSL configurations in IaC
- **Trivy** - Scans for weak crypto libraries and configurations
- **TruffleHog** - Detects exposed certificates/keys

**Evidence Collection:**
```bash
# Run full scan
./scripts/shell/run-target-security-scan.sh "/path/to/app" full

# Check specific findings
grep -r "TLS\|SSL\|crypto" scans/*/checkov/
grep -r "certificate\|private.*key" scans/*/trufflehog/
```

**Report Location:**
- `scans/{scan_id}/checkov/checkov-results.json` - Look for TLS/SSL misconfigurations
- `scans/{scan_id}/trivy/trivy-results.json` - Search for crypto vulnerabilities
- `scans/{scan_id}/trufflehog/trufflehog-results.json` - Check for exposed credentials

---

#### APSC-DV-000500: The application must prevent non-privileged users from executing privileged functions.

**Epyon Tools:**
- **Checkov** - Validates RBAC configurations, privilege escalation
- **Trivy** - Scans for containers running as root
- **SonarQube** - Code analysis for authorization checks

**Evidence Collection:**
```bash
# Check for privilege escalation issues
grep -i "privilege\|root\|sudo\|setuid" scans/*/checkov/checkov-results.json
grep -i "USER root\|privileged" scans/*/trivy/trivy-results.json

# Review SonarQube security hotspots
cat scans/*/sonar/sonar-results.json | jq '.issues[] | select(.type=="SECURITY_HOTSPOT")'
```

**Dashboard View:**
- Open interactive dashboard: `./scripts/shell/open-latest-dashboard.sh`
- Filter by "High" severity → Look for privilege escalation findings

---

#### APSC-DV-000190 (V-222399): Messages protected with WS_Security must use time stamps with creation and expiration times.

**Severity:** CAT I | **SRG:** SRG-APP-000014 | **Rule:** SV-222399r960759

**Applicability to Epyon:** NOT APPLICABLE

Epyon does not use WS-Security tokens or SOAP messaging. The Check Text explicitly states: *"If the application does not utilize WS-Security tokens, this check is not applicable."* This is the third control in the same WS-Security/SAML requirement family (see also APSC-DV-000200, APSC-DV-000230, APSC-DV-000240).

**Basis for Not Applicable determination:**

| Criterion | Epyon Behavior |
|---|---|
| WS-Security tokens | Not used |
| SOAP messages with timestamps / sequence numbers / expiration | None — no SOAP messaging |
| Replay attack surface via WS-Security | N/A |

**Evidence Commands:**
```bash
# Confirm no WS-Security or SOAP references
grep -rn 'wss:\|wsu:\|wsse:\|soap\|ws-security\|timestamp\|Created\|Expires' scripts/shell/
# Expected: no matches
```

**Report Location:** N/A — Epyon does not implement WS-Security or SOAP.

---

#### APSC-DV-000200 (V-222400): Validity periods must be verified on all application messages using WS-Security or SAML assertions.

**Severity:** CAT I | **SRG:** SRG-APP-000014 | **Rule:** SV-222400r960759

**Applicability to Epyon:** NOT APPLICABLE

Epyon does not use WS-Security (WSS), SOAP, or SAML assertions. The Check Text explicitly states: *"If the application does not utilize WSS or SAML assertions, this requirement is not applicable."* This control is part of the same SAML/WS-Security requirement family as APSC-DV-000230 and APSC-DV-000240.

**Basis for Not Applicable determination:**

| Criterion | Epyon Behavior |
|---|---|
| WS-Security (WSS) token profiles | Not used |
| SAML assertions with validity periods | Not produced or consumed |
| SOAP messaging | None — Epyon communicates via REST/HTTPS only |
| Replay attack surface via expired tokens | N/A — no message-level token framework |

**Evidence Commands:**
```bash
# Confirm no WS-Security or SAML references
grep -rn 'wss\|ws-security\|wstrust\|saml\|soap\|wsdl\|replay' scripts/shell/
# Expected: no matches
```

**Report Location:** N/A — Epyon does not implement WS-Security or SAML.

---

#### APSC-DV-000230 (V-222403): The application must use the NotOnOrAfter condition when using the SubjectConfirmation element in a SAML assertion.

**Severity:** CAT I | **SRG:** SRG-APP-000014 | **Rule:** SV-222403r960759

**Applicability to Epyon:** NOT APPLICABLE

Epyon does not use SAML assertions or SOAP messaging. The Check Text explicitly states: *"If the application does not utilize SAML assertions, this check is not applicable."* This control is part of the same SAML/SOAP requirement family as APSC-DV-000240 — see that entry for the full technical basis.

**Basis for Not Applicable determination:**

| Criterion | Epyon Behavior |
|---|---|
| SAML `<SubjectConfirmation>` elements | Not produced or consumed |
| SAML `<NotOnOrAfter>` condition | Not applicable |
| SOAP message exchange | None |
| Identity Provider / Service Provider role | Neither |

**Evidence Commands:**
```bash
# Confirm no SAML or SubjectConfirmation references
grep -rn 'SubjectConfirmation\|NotOnOrAfter\|saml\|soap' scripts/shell/
# Expected: no matches
```

**Report Location:** N/A — Epyon does not implement SAML or SOAP.

---

#### APSC-DV-000240 (V-222404): The application must use both the NotBefore and NotOnOrAfter elements or OneTimeUse element when using the Conditions element in a SAML assertion.

**Severity:** CAT I | **SRG:** SRG-APP-000014 | **Rule:** SV-222404r960759

**Applicability to Epyon:** NOT APPLICABLE

Epyon does not use SAML assertions or SOAP messaging. The Check Text explicitly states: *"If the application does not utilize SAML assertions, this check is not applicable."*

**Basis for Not Applicable determination:**

| Criterion | Epyon Behavior |
|---|---|
| SAML identity federation / SSO | None — Epyon has no authentication layer |
| SAML assertions (`<Subject>`, `<Conditions>`, `<NotBefore>`, etc.) | Not produced or consumed |
| SOAP messaging | None — Epyon communicates via REST (SonarQube API, AWS CLI HTTPS) |
| Identity Provider (IdP) / Service Provider (SP) role | Neither — Epyon is a CLI pipeline tool |
| Web services with `<Conditions>` elements | None |

**Evidence Commands:**
```bash
# Confirm no SAML or SOAP references anywhere in scripts
grep -rn 'saml\|soap\|NotBefore\|NotOnOrAfter\|OneTimeUse\|Assertion\|IdP\|saml2' scripts/shell/
# Expected: no matches
```

**Report Location:** N/A — Epyon does not implement SAML or SOAP.

---

#### APSC-DV-000460 (V-222425): The application must enforce approved authorizations for logical access to information and system resources in accordance with applicable access control policies.

**Severity:** CAT I | **SRG:** SRG-APP-000033 | **Rule:** SV-222425r960792

**Applicability to Epyon:** NOT APPLICABLE

Epyon has no authentication or authorization layer. There are no user accounts, no roles, no access control policies, and no protected resources that are differentiated by identity. The STIG check procedure requires a test user account and an application resource with access restrictions — neither construct exists in Epyon.

**Basis for Not Applicable determination:**

| Criterion | Epyon Behavior |
|---|---|
| User accounts / identities | None — Epyon is a CLI pipeline tool with no login mechanism |
| Role-Based Access Control (RBAC) | Not implemented |
| Protected URLs, folders, files, or records requiring per-user authorization | None — all output files are written to the local filesystem under standard OS permissions |
| Authentication access control enforcement | N/A — no authentication layer exists to enforce against |
| Database records requiring access control | None — no database |

**Access control for Epyon's own outputs:**
Epyon writes scan results to the local `scans/` directory. Access to these files is governed entirely by the host OS filesystem permissions — not by any application-level access control mechanism. Operators are responsible for ensuring appropriate OS-level permissions on the `scans/` output directory. This is an operational / deployment concern, not an application design gap.

**Clarification on Checkov/Trivy RBAC checks:**
Epyon's `run-checkov-scan.sh` and `run-trivy-scan.sh` check for RBAC misconfigurations in the *target* Kubernetes and IaC resources being scanned. This is an access-control *enforcement* capability Epyon provides to its users — it has no bearing on whether Epyon itself implements access control over its own resources.

**Evidence Commands:**
```bash
# Confirm no authentication/authorization logic in Epyon scripts
grep -rn 'rbac\|role.based\|authz\|authorize\|acl\b\|access.control\|deny.*access\|require.*role' scripts/shell/
# Expected: only advisory strings in scan-output generation code

# Confirm no web listener / API endpoint exposed
grep -rn 'listen\|bind.*port\|http.server\|flask\|fastapi\|express' scripts/shell/
# Expected: no matches
```

**Report Location:** N/A — no access control layer exists in Epyon.

---

#### APSC-DV-000510 (V-222430): The application must execute without excessive account permissions.

**Severity:** CAT I | **SRG:** SRG-APP-000342 | **Rule:** SV-222430r961359

**Applicability to Epyon:** APPLICABLE — Compliant

Epyon runs as a CLI pipeline tool invoked by the operator's current OS user session. It requires no dedicated service account, holds no admin rights of its own, and passes no elevated privileges to the containers it launches.

**Privilege Model:**

| Component | Execution context | Privilege level |
|---|---|---|
| Epyon shell scripts | Caller's OS user session | No elevation; inherits the invoking user's standard permissions |
| `docker run` invocations | Docker daemon (host) | No `--privileged`; no `--cap-add`; no `-u root`; scan targets mounted `:ro` (read-only) |
| `sudo` usage | `check-docker-runtime.sh` only — diagnostic info script | Used for `docker info` connectivity test only; not invoked by any scan script |
| AWS CLI / SonarQube calls | Caller's session via env vars | Credentials scoped to the specific IAM role or token provided |
| No database connection | N/A | No DB account / DBA role to audit |

**Docker container launch pattern:**
All Epyon scanner containers are launched with `--rm` (auto-remove) and no privilege escalation flags:
```bash
# run-anchore-scan.sh — representative example
docker run --rm \
    -v "$REPO_PATH:/scan:ro" \
    -v "$OUTPUT_DIR:/output" \
    anchore/grype:latest \
    dir:/scan -o json --file /output/anchore-filesystem-results.json
```
The source repository is always mounted read-only (`:ro`). No `--privileged`, `--cap-add`, `--security-opt=apparmor:unconfined`, or `-u 0` flags appear anywhere in the codebase.

**`sudo` scope:**
`check-docker-runtime.sh` uses `sudo docker info` as a fallback diagnostic to detect whether Docker permissions are the cause of a failure. This is a one-time health-check helper — it is never called by the scan scripts themselves. If `sudo` is required just to run Docker, operators are directed to add their user to the `docker` group (rootless operation), eliminating the need for `sudo` entirely.

**Evidence Commands:**
```bash
# Confirm no --privileged or --cap-add flags in any docker run call
grep -rn 'docker run' scripts/shell/ | grep -v grep
# Expected: only --rm, -v mount flags

# Confirm sudo is limited to the diagnostic check script only
grep -rn 'sudo' scripts/shell/
# Expected: check-docker-runtime.sh only (docker info test)

# Confirm no setuid / chown / privilege-escalation calls
grep -rn 'setuid\|setgid\|chown\|chmod 777\|chmod +s' scripts/shell/
# Expected: no matches
```

**Report Location:**
- `scans/epyon_*/checkov/` — Checkov IaC checks flag `privileged: true` and containers running as root in target repos
- `scans/epyon_*/trivy/` — Trivy flags `USER root` and excess capabilities in target container images

---

#### APSC-DV-000530 (V-222432): The application must enforce the limit of three consecutive invalid logon attempts by a user during a 15-minute time period.

**Severity:** CAT I | **SRG:** SRG-APP-000065 | **Rule:** SV-222432r960840

**Applicability to Epyon:** NOT APPLICABLE

Epyon has no user authentication layer. There are no accounts, no login screens, no passwords, and no sessions. The Check Text procedure — *"Log on to the application with a test user account"* — cannot be performed because no such mechanism exists.

**Basis for Not Applicable determination:**

| Criterion | Epyon Behavior |
|---|---|
| User accounts | None — Epyon is a pipeline CLI tool with no account management |
| Login screen / authentication prompt | None |
| Password / PIN entry | None (interactive `read -s` for `AWS_SECRET_ACCESS_KEY` is a one-time key provisioning step, not a repeated-logon flow) |
| Session management | None |
| Account lockout mechanism | Not implemented and not required |

**Clarification on Epyon's credential prompts:**
The single interactive credential prompt in `run-checkov-scan.sh` (`read -s -p "AWS Secret Access Key"`) is a key-provisioning helper used during initial setup, not a repeated logon mechanism. It is not subject to brute-force attacks because:
1. It runs locally under the operator's own OS session — there is no network-facing authentication endpoint to attack
2. The value entered is stored in a process-scoped environment variable for the duration of one scan run, not validated against a stored credential
3. There is no lockout concept because there is nothing to lock

**Evidence Commands:**
```bash
# Confirm no login/session/lockout logic anywhere in scripts
grep -rn 'login\|logon\|lockout\|lock_account\|failed.attempt\|max.attempt\|bad.attempt' scripts/shell/
# Expected: no authentication-related matches

# Confirm no web server or API endpoint is exposed by Epyon
grep -rn 'listen\|server\|bind.*port\|http.server\|flask\|fastapi\|express' scripts/shell/
# Expected: no server/listener references
```

**Report Location:** N/A — no authentication layer exists in Epyon.

---

#### APSC-DV-000590: The application must not be vulnerable to SQL Injection.

**Epyon Tools:**
- **SonarQube** - SQL injection detection via code analysis
- **Checkov** - Database security configurations

**Evidence Collection:**
```bash
# Run SonarQube analysis
./scripts/shell/run-sonar-analysis.sh

# Search for SQL injection vulnerabilities
cat scans/*/sonar/sonar-results.json | jq '.issues[] | select(.rule | contains("sql"))'
```

**Manual Validation Required:**
- Dynamic testing with OWASP ZAP (not included in Epyon)
- Penetration testing results
- Code review of database queries

---

#### APSC-DV-001620: The application must not be subject to input handling vulnerabilities.

**Epyon Tools:**
- **SonarQube** - Input validation analysis
- **Grype/Trivy** - Known vulnerabilities in parsing libraries

**Evidence Collection:**
```bash
# Check for input handling issues in code
cat scans/*/sonar/sonar-results.json | jq '.issues[] | select(.rule | contains("input\|validation\|sanitiz"))'

# Check for vulnerable parsing libraries
cat scans/*/grype/grype-results.json | jq '.matches[] | select(.vulnerability.description | contains("input\|parse\|deserializ"))'
```

---

#### APSC-DV-002485 (V-222601): The application must not store sensitive information in hidden fields.

**Severity:** CAT I | **SRG:** SRG-APP-000441 | **Rule:** SV-222601r961638

**Applicability to Epyon:** NOT APPLICABLE — Epyon has no web server, no HTTP forms, and no session management. The HTML it generates contains no `<input type="hidden">` elements.

**Rationale:**

The hidden-fields attack surface requires a web application with server-side form submission and session management. Epyon satisfies none of those conditions:

| Prerequisite | Epyon's Status |
|---|---|
| Web server / HTTP listener | None — Epyon is a CLI tool |
| HTML forms with POST/GET actions | None — generated HTML contains no `<form>` elements |
| `<input type="hidden">` elements | None — confirmed absent from all generated HTML |
| Session IDs or auth tokens in HTML | None — no user sessions or authentication flow exists |
| Server-side state passed back via hidden fields | None — no server-side rendering at all |

**HTML elements that do exist in generated dashboards:**

Epyon's HTML dashboards (`generate-security-dashboard.sh`) contain two types of `<input>` elements, neither of which involves sensitive data:

| Element | Purpose | Sensitive Data? |
|---|---|---|
| `<input type="checkbox" class="fp-check">` | Local false-positive checkbox — client-side only, never submitted | No |
| `<input type="text" id="trivy-search">` | In-browser search filter — filters pre-rendered DOM, no server round-trip | No |

Both are purely client-side UI elements. Neither is submitted to any server, and neither contains or transmits authentication, session, or other sensitive data.

**Evidence Commands:**
```bash
# Confirm no hidden input fields in any generated HTML
grep -rn 'type=["'\'']*hidden' scripts/shell/
# Expected: no output

# Confirm no <form> elements with action/method in generated HTML
grep -rn '<form\|action=.*post\|method=.*post' scripts/shell/
# Expected: no output

# Confirm the only input elements present are checkbox and text (search)
grep -n '<input' scripts/shell/generate-security-dashboard.sh
# Expected: only type="checkbox" and type="text" entries
```

**Report Location:**
- `scans/epyon_*/consolidated-reports/dashboards/security-dashboard.html` — inspect generated HTML directly; no hidden fields present

---

#### APSC-DV-002490 (V-222602): The application must protect from Cross-Site Scripting (XSS) vulnerabilities.

**Severity:** CAT I | **SRG:** SRG-APP-000251 | **Rule:** SV-222602r961158

**Applicability to Epyon:** APPLICABLE — Epyon generates HTML output (security dashboards, sub-reports) that embeds scan data sourced from scanned repositories. Attacker-controlled content in a scanned repo (crafted package names, CVE descriptions, file paths) could become XSS payloads if interpolated into HTML without escaping.

**XSS Attack Surface Assessment:**

| Output Type | Contains Scan Data | XSS Mitigation |
|---|---|---|
| `consolidate-security-reports.sh` — HTML sub-reports | Yes — CVE IDs, descriptions, package names, secret detector names, file paths | `html.escape()` applied to **all** scan-data fields before interpolation into HTML |
| `generate-security-dashboard.sh` — main HTML dashboard | Yes — summary counts and classification label injected via bash heredoc | Counts are integers computed by `jq` (no string injection); `CLASS_LABEL` is resolved from an enum `case` statement with a hardcoded string per level — raw `$CLASSIFICATION_LEVEL` is never emitted to HTML unescaped |
| `generate-interactive-dashboard.sh` — standalone HTML dashboard | Minimal — scan metadata embedded at generation time | `innerHTML` assignments use template literals with fixed-format values (status messages, format names), not user- or scan-supplied strings |
| Markdown reports | Plain text `.md` files; not rendered as HTML by Epyon | No HTML context; no escaping needed |
| JSON outputs | Structured data; not rendered as HTML | No HTML context |

**No reflected or stored XSS attack path exists** because:
1. Epyon has no web server, no HTTP endpoints, and no URL request-response cycle — the XSS vectors described in the STIG (URL parameters, form fields, cookies) do not exist.
2. All HTML is **generated offline** as static files and opened locally in a browser; there is no server-side rendering that could reflect user input.
3. Every scan-data value appearing in HTML output passes through Python's `html.escape()` in `consolidate-security-reports.sh`, which encodes `<`, `>`, `&`, `"`, and `'`.

**`html.escape()` coverage in `consolidate-security-reports.sh`:**
```python
# SonarQube issues
html.escape(issue.get('message', 'Unknown Issue'))
html.escape(issue.get('rule', 'Unknown'))
html.escape(issue.get('component', 'Unknown'))

# Grype/Trivy CVEs
html.escape(vulnerability.get('id', 'Unknown CVE'))
html.escape(vulnerability.get('description', 'No description available')[:200])
html.escape(artifact.get('name', 'Unknown'))
html.escape(artifact.get('version', 'Unknown'))

# TruffleHog secrets
html.escape(detector)
html.escape(secret.get('SourceName', 'Unknown'))

# Xeol EOL data
html.escape(artifact.get('name', 'Unknown Package'))
html.escape(str(eol_data.get('eolDate', 'Unknown')))

# Raw JSON fallback
html.escape(json.dumps(data, indent=2)[:5000])
```

**Evidence Commands:**
```bash
# Confirm html.escape() is applied to all scan-data fields in HTML generation
grep -n 'html\.escape' scripts/shell/consolidate-security-reports.sh
# Expected: 15+ matches covering all scan data categories

# Confirm CLASS_LABEL is resolved via enum case (not raw user input) before HTML injection
grep -n 'CLASS_LABEL\|CLASSIFICATION_LEVEL.*=\|case.*CLASSIFICATION' \
  scripts/shell/generate-security-dashboard.sh | head -20
# Expected: case statement maps known strings to CLASS_LABEL; raw env var never hits HTML

# Confirm no innerHTML assignments use scan-data variables
grep -n 'innerHTML' scripts/shell/generate-security-dashboard.sh
# Expected: only template-literal status messages with fixed strings and formatInfo.name

# SonarQube static analysis for XSS patterns in Epyon's Python code
cat scans/epyon_*/sonar/sonar-results.json | \
  jq '.issues[] | select(.rule | test("xss|cross.*site|html.*inject"; "i"))'
# Expected: no results

# Verify no direct string interpolation of scan data into HTML (would bypass html.escape)
grep -n 'f".*{.*get(\|f".*{.*\[' scripts/shell/consolidate-security-reports.sh | \
  grep -v 'html\.escape'
# Expected: no unescaped scan data interpolations
```

**Report Location:**
- `scans/epyon_*/sonar/sonar-results.json` — static analysis of Epyon's Python code for XSS patterns
- `scans/epyon_*/consolidated-reports/` — the generated HTML files themselves; inspect for unescaped content

---

#### APSC-DV-002510 (V-222604): The application must protect from command injection.

**Severity:** CAT I | **SRG:** SRG-APP-000251 | **Rule:** SV-222604r961158

**Applicability to Epyon:** APPLICABLE — Epyon is a bash-heavy orchestrator that invokes Docker, `jq`, `python3`, and other OS commands. Unquoted variables, `eval`, or `shell=True` subprocess calls could allow command injection if user-supplied input reached those execution paths.

**Epyon's Compliance Status:**

| Attack Vector | Risk to Epyon | Control in Place |
|---|---|---|
| Bash `eval` of user input | None | No `eval` exists in any active `.sh` script |
| Unquoted variable expansion in `docker run -v` | None | All user-supplied paths are double-quoted |
| Python `os.system()` / `os.popen()` | None | Neither function is called anywhere in Epyon |
| Python `subprocess(shell=True)` | None | No `subprocess` calls exist in Epyon's Python code |
| Python `exec()` / `eval()` / `compile()` | None | Not present in `convert-kcov-to-sonar.py` or any inline Python |
| User input concatenated into shell command strings | None | Scan IDs sanitized; paths are validated and quoted, not concatenated into shell strings |
| `jq` expression built from user data | None | `jq` filter expressions are hardcoded literals; only data payloads (JSON files) varying per run |

**Key protective controls:**

- **No `eval` in active scripts** — Epyon's 60 active `.sh` files contain zero `eval` calls. (A legacy `.old` archived file contains `eval` but is not deployed or executed.)
  ```bash
  grep -rn 'eval' scripts/shell/*.sh
  # Expected: no output
  ```

- **Double-quoting of all user-controlled variables** — Every `docker run -v` mount uses `"$VAR"` syntax, preventing word-splitting and globbing that could inject extra flags:
  ```bash
  # run-trufflehog-scan.sh
  docker run --rm \
    -v "$target:/workspace" \
    ...
  ```

- **Scan ID sanitization before filesystem and command use** — `run-epyon-scan-ci.sh` strips all non-alphanumeric characters from user-supplied subdirectory names before those values are used in paths or passed to sub-scripts:
  ```bash
  SANITIZED_SUBDIR=$(echo "$SUBDIR" | sed -E "s#[/[:space:]]+#_#g; s#[^A-Za-z0-9._:-]#_#g")
  ```

- **No shell=True in Python** — `convert-kcov-to-sonar.py` invokes no subprocesses at all; it only reads XML and writes XML. No `os.system`, `os.popen`, `subprocess`, `exec`, or `eval` appear anywhere in Epyon's Python code.

- **Structured data handling** — All scan result JSON is processed via `jq` with hardcoded filter expressions or via Python's `json.loads()` / `json.dumps()`, never via shell string interpolation or `eval`.

**Evidence Commands:**
```bash
# Confirm no eval in active scripts
grep -rn 'eval' scripts/shell/*.sh
# Expected: no output

# Confirm no os.system / subprocess shell=True / exec in Python code
grep -n 'os\.system\|os\.popen\|shell=True\|exec(\|eval(' scripts/shell/convert-kcov-to-sonar.py
# Expected: no output

# Confirm all docker -v mounts use double-quoted variables
grep -n '\-v ' scripts/shell/run-checkov-scan.sh scripts/shell/run-trufflehog-scan.sh \
  scripts/shell/run-grype-scan.sh scripts/shell/run-trivy-scan.sh
# Expected: all -v entries use "$VAR" form

# Confirm scan ID sanitization is present
grep -n 'SANITIZED_SUBDIR\|sed.*A-Za-z0-9' scripts/shell/run-epyon-scan-ci.sh

# SonarQube static analysis of Epyon's code for injection patterns
cat scans/epyon_*/sonar/sonar-results.json | \
  jq '.issues[] | select(.rule | test("command.*inject|shell.*inject|os\.system"; "i"))'
# Expected: no results
```

**Report Location:**
- `scans/epyon_*/sonar/sonar-results.json` — static analysis for command injection patterns in Epyon's Python code
- `scans/epyon_*/trufflehog/trufflehog-results.json` — Epyon self-scan (TruffleHog would not detect command injection, but confirms no secret exfiltration via injected commands)

---

#### APSC-DV-002540 (V-222607): The application must not be vulnerable to SQL Injection.

**Severity:** CAT I | **SRG:** SRG-APP-000251 | **Rule:** SV-222607r961158

**Applicability to Epyon:** NOT APPLICABLE — Epyon does not use a relational database and constructs no SQL queries.

**Rationale:**

Epyon is a CLI security-scanning orchestrator composed entirely of bash scripts and inline Python 3. It has no database backend, no ORM, no SQL client library, and no persistence layer of any kind:

| Component | Status |
|---|---|
| Relational database (PostgreSQL, MySQL, SQLite, etc.) | None — Epyon uses none |
| SQL client libraries (`psycopg2`, `pymysql`, `sqlite3`, `SQLAlchemy`, etc.) | Not imported anywhere |
| SQL query construction or execution | Not present in any script |
| Database connection strings | Not present in any script |
| ORM models or schema definitions | Not present |

All state is stored as flat files (JSON, text logs) in the `scans/` directory. No data is persisted to or retrieved from a database at any point in Epyon's execution path.

**Evidence Commands:**
```bash
# Confirm no SQL library imports or database connections exist in Epyon
grep -rn "sqlite3\|psycopg\|pymysql\|sqlalchemy\|mysql\|postgres\|db\.execute\|cursor\.execute" \
  scripts/shell/
# Expected: no output

# Confirm no JDBC/ODBC connection strings
grep -rn "jdbc:\|odbc:\|host=.*dbname=\|DSN=" scripts/shell/
# Expected: no output

# SonarQube static analysis of Epyon Python code for SQL issues
cat scans/epyon_*/sonar/sonar-results.json | \
  jq '.issues[] | select(.rule | test("sql"; "i"))'
# Expected: no results
```

**Report Location:**
- `scans/epyon_*/sonar/sonar-results.json` — static analysis of Epyon's Python code (no SQL findings expected)
- `scans/epyon_*/trufflehog/trufflehog-results.json` — would surface any accidentally committed database connection strings

---

#### APSC-DV-002550 (V-222608): The application must not be vulnerable to XML-oriented attacks.

**Severity:** CAT I | **SRG:** SRG-APP-000251 | **Rule:** SV-222608r961158

**Applicability to Epyon:** APPLICABLE — Epyon processes XML in two narrowly scoped contexts; neither is reachable from external or untrusted input.

**Epyon's XML Usage:**

| Context | File | XML Role | Input Source |
|---|---|---|---|
| Coverage report conversion | `convert-kcov-to-sonar.py` | Reads kcov-generated `cobertura.xml`; writes SonarCloud `sonar-coverage.xml` | Locally generated file on the same host — not user-supplied |
| SBOM export | `export-sbom.sh` | **Writes** CycloneDX XML via syft; never parses it | Output-only |

**Attack Classes vs. Epyon:**

| Attack Class | Risk to Epyon | Reason |
|---|---|---|
| XML Injection | None | No user-controlled data is inserted into XML output; syft constructs CycloneDX XML internally |
| XXE (External Entity) | Mitigated | `xml.etree.ElementTree` in Python 3.8+ has XXE disabled by default (CVE-2019-20907 patch); `expat`-backed, entities are not resolved against external URIs |
| XPath Injection | None | No XPath queries are constructed from user input; `ET.find()` uses hardcoded string literals only |
| XML DoS (billion laughs / deep nesting) | Low | Input is always a locally generated kcov file; no network-sourced XML is ever parsed |
| XML Spoofing | None | No XML-based authentication or authorization decisions are made |
| SOAP/REST XML web service attacks | Not applicable | Epyon exposes no XML web service endpoints |

**Python `xml.etree.ElementTree` security baseline:**
- XXE disabled by default since Python 3.8 (`expat` 2.4.1+, `CVE-2019-20907` mitigated)
- `ET.parse()` raises `ET.ParseError` on malformed input — caught and handled in `convert-kcov-to-sonar.py`:
  ```python
  try:
      tree = ET.parse(input_path)
  except ET.ParseError as exc:
      print(f"[ERROR] Cannot parse {input_path}: {exc}", file=sys.stderr)
      return 1
  ```
- No `xml.sax`, `xml.dom.minidom`, `lxml`, or other parsers with external entity resolution are used anywhere in Epyon.

**Evidence Commands:**
```bash
# Confirm only stdlib ET is used — no lxml or external XML parsers
grep -rn "import.*xml\|from.*xml\|lxml\|xmllint\|xpath" scripts/shell/
# Expected: only xml.etree.ElementTree in convert-kcov-to-sonar.py

# Confirm ET.ParseError is caught (no unhandled XML parse crash)
grep -n "ParseError\|ET\.parse" scripts/shell/convert-kcov-to-sonar.py

# Confirm no XML input is accepted from CLI args or environment
grep -rn "xml\|XML" scripts/shell/*.sh | grep -v "cyclonedx\|#.*xml\|sonar.*xml\|coverage\.xml"

# Verify Python version (XXE protection requires Python 3.8+)
python3 --version

# Grype CVE scan of tool images for XML library vulnerabilities
cat scans/epyon_*/grype/grype-results.json | \
  jq '.matches[] | select(.artifact.name | test("expat|libxml|lxml"; "i")) | {pkg: .artifact.name, version: .artifact.version, cve: .vulnerability.id, severity: .vulnerability.severity}'
```

**Report Location:**
- `scans/epyon_*/grype/grype-results.json` — CVE scan covering `expat`/`libxml2` in tool container images
- `scans/epyon_*/sonar/sonar-results.json` — static analysis of `convert-kcov-to-sonar.py`

---

#### APSC-DV-001750 (V-222543): The application must transmit only cryptographically-protected passwords.

**Severity:** CAT I | **SRG:** SRG-APP-000172 | **Rule:** SV-222543r961029

**Applicability to Epyon:** NOT APPLICABLE

Epyon does not use passwords for user authentication. The Check Text explicitly states: *"If the application does not use passwords, the requirement is not applicable."* Epyon has no login screen, no user accounts, and no password-based authentication layer.

**Basis for Not Applicable determination:**

| Credential type | Transmission method | Cleartext risk |
|---|---|---|
| `SONAR_TOKEN` (Bearer token) | HTTPS to SonarQube/SonarCloud | No — TLS-encrypted channel; validated this session (APSC-DV-002440) |
| `AWS_SECRET_ACCESS_KEY` | AWS CLI via HTTPS SigV4 | No — never transmitted as a raw password; used to sign requests |
| ECR password (ephemeral token) | Local pipe only: `aws ecr get-login-password \| docker login --password-stdin` | No — never leaves the local process; piped directly to Docker daemon stdin |
| `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` | HTTPS API calls made by external tools | No — TLS-encrypted; Epyon does not transmit these directly |
| User passwords to Epyon | N/A — no authentication layer exists | Not applicable |

**ECR authentication detail:**
`run-helm-build.sh` line 136 uses the AWS-recommended pattern for ECR login:
```bash
aws ecr get-login-password --region "$AWS_REGION" | \
  docker login --username AWS --password-stdin "$ECR_REGISTRY"
```
The `get-login-password` command retrieves a short-lived token from AWS STS over HTTPS. That token is piped directly to `docker login` via stdin — it is never written to disk or logged, and it is never transmitted over a network in cleartext.

**Evidence Commands:**
```bash
# Confirm no plaintext password transmission (no curl/wget with -u user:pass or --password)
grep -rn 'curl.*-u\s\|curl.*--user\|wget.*--password\|--password=\|:.*@http://' scripts/shell/
# Expected: no matches

# Confirm ECR uses --password-stdin (not --password <value>)
grep -n 'docker login' scripts/shell/run-helm-build.sh
# Expected: --password-stdin pattern only

# Confirm all Sonar communication uses HTTPS (not HTTP)
grep -n 'SONAR_HOST_URL' scripts/shell/run-sonar-analysis.sh
# Expected: https:// default and HTTPS guard validation
```

**Report Location:** N/A — no password-based authentication exists in Epyon.

---

#### APSC-DV-001810 (V-222550): The application, when utilizing PKI-based authentication, must validate certificates by constructing a certification path (which includes status information) to an accepted trust anchor.

**Severity:** CAT I | **SRG:** SRG-APP-000175 | **Rule:** SV-222550r961038

**Applicability to Epyon:** NOT APPLICABLE

Epyon does not use PKI-based authentication. No certificates are presented or validated as an authentication mechanism by Epyon itself. The Check Text's conditional scope — *"if the application does not construct a certificate path to an accepted trust anchor"* — applies only when the application uses PKI auth; since Epyon does not, this requirement does not apply.

**Basis for Not Applicable determination:**

| Criterion | Epyon Behavior |
|---|---|
| PKI-based authentication to Epyon | None — Epyon has no authentication layer |
| PKI-based authentication **by** Epyon to external services | None — Epyon authenticates to SonarQube via Bearer token (`SONAR_TOKEN`), to AWS via access key + secret, and to container registries via Docker login; no client certificates |
| Certificate path construction | Not implemented by Epyon — no custom TLS/PKI logic |
| Trust anchor configuration | Not managed by Epyon — delegated entirely to the host OS trust store |

**HTTPS connections in Epyon:**
Epyon's `run-sonar-analysis.sh` makes one outbound HTTPS call via `curl` to retrieve metrics after a scan completes:
```bash
# run-sonar-analysis.sh line ~299
_api_response=$(curl -s -H "$_auth_header" "$_api_url" 2>/dev/null) || _api_response=""
```
This call uses `curl`'s default behavior, which delegates all certificate path validation (including revocation checking via CRL/OCSP depending on OS configuration) to the host OS trust store. No `-k` / `--insecure` flag is used, so TLS validation is never disabled.

All other external tool invocations (`docker pull`, `sonar-scanner`, `trivy`, `grype`, AWS CLI, TruffleHog) handle their own TLS via their respective runtime libraries — none are configured by Epyon to bypass certificate validation.

**Evidence Commands:**
```bash
# Confirm no -k / --insecure flag is used in any curl call
grep -rn 'curl.*-k\b\|curl.*--insecure' scripts/shell/
# Expected: no matches

# Confirm no custom cacert or ssl-no-verify options set
grep -rn 'cacert\|--no-verify\|verify=False\|NODE_TLS_REJECT\|ssl_verify' scripts/shell/
# Expected: no matches
```

**Report Location:** N/A — Epyon does not implement or configure PKI certificate path validation.

---

#### APSC-DV-001820 (V-222551): The application, when using PKI-based authentication, must enforce authorized access to the corresponding private key.

**Severity:** CAT I | **SRG:** SRG-APP-000176 | **Rule:** SV-222551r961041

**Applicability to Epyon:** NOT APPLICABLE

Epyon does not use PKI-based authentication and holds no private keys of its own. The Check Text explicitly states: *"If the application does not perform code signing or other cryptographic tasks requiring a private key, this requirement is not applicable."*

**Basis for Not Applicable determination:**

| Criterion | Epyon Behavior |
|---|---|
| Code signing | No — Epyon does not sign any artifacts |
| TLS client certificates / mTLS | No — Epyon is a consumer of HTTPS endpoints (SonarQube, AWS CLI); it does not present client certificates |
| Private key storage | No `.pem`, `.p12`, `.pfx`, or `.key` files exist in the Epyon repository or runtime directories |
| Cryptographic operations requiring a private key | None — Epyon performs no encryption, decryption, or digital signing |
| PKI-based user authentication to Epyon | No — Epyon has no authentication layer; it runs as a CI/CD pipeline tool |

**Clarification on private-key-related code in Epyon:**
Epyon's `run-trufflehog-scan.sh` and `generate-scan-findings-summary.sh` contain logic that *detects and reports* private keys found in the repositories it scans. This is a security-control feature, not evidence that Epyon itself holds or uses private keys.

```bash
# run-trufflehog-scan.sh — counting key files in the TARGET repo (not Epyon)
KEY_COUNT=$(find "$REPO_PATH" -name "*.key" -o -name "*.pem" -o -name "*.crt" 2>/dev/null | wc -l)

# generate-scan-findings-summary.sh — reporting PrivateKey findings from TruffleHog output
local private_keys=$(jq -s '[.[] | select(.DetectorName == "PrivateKey")]' "$trufflehog_file")
```

These references are entirely within Epyon's output-analysis logic, not Epyon's own key management.

**Evidence Commands:**
```bash
# Confirm no private key material exists in Epyon repository
find . -name "*.pem" -o -name "*.p12" -o -name "*.pfx" -o -name "*.key" | grep -v '.git'
# Expected: no output

# Confirm no code-signing or PKI auth invocations
grep -r 'openssl\|gpg --sign\|codesign\|jarsigner\|keytool\|pkcs' scripts/shell/
# Expected: no matches outside of detection/scanning logic
```

**Report Location:** N/A — no private keys exist in Epyon to audit.

---

#### APSC-DV-001850 (V-222554): The application must not display passwords/PINs as clear text.

**Severity:** CAT I | **SRG:** SRG-APP-000178 | **Rule:** SV-222554r961047

**Applicability to Epyon:** APPLICABLE — Epyon accepts credentials via interactive terminal prompts and environment variables. All secret values must be obscured during entry.

**Epyon's Credential Input Mechanisms:**

| Credential | Input Method | Display Behavior |
|---|---|---|
| `AWS_SECRET_ACCESS_KEY` | `read -s -p "AWS Secret Access Key: "` in `run-checkov-scan.sh` | Silent — no echo to terminal |
| `SONAR_TOKEN` | Env var or git-ignored `.env.sonar` file | Never prompted interactively; never echoed |
| `AWS_ACCESS_KEY_ID` | `read -p "AWS Access Key ID: "` (visible) | Displayed during entry — acceptable: this is an identifier (analogous to a username), not a password |
| `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` | Env var only | Never prompted interactively; never echoed |
| `JIRA_API_TOKEN` | GitHub Actions `secrets.*` | Masked by GitHub Actions runner; never echoed in logs |

**Token masking in diagnostic output:**
`check-sonar-config.sh` displays only the first and last few characters of `SONAR_TOKEN` when showing configuration status:
```bash
TOKEN_PREFIX="${SONAR_TOKEN:0:4}"
TOKEN_SUFFIX="${SONAR_TOKEN: -4}"
echo "Token: ${TOKEN_PREFIX}...${TOKEN_SUFFIX} (${TOKEN_LENGTH} chars)"
```
The full token value is never printed.

**No web UI / no login screen:**
Epyon has no browser-based authentication flow. The STIG's UI scenarios (asterisks, momentary display, clipboard paste) apply only to the single interactive `read -s` prompt for `AWS_SECRET_ACCESS_KEY`.

**Evidence Commands:**
```bash
# Confirm AWS_SECRET_ACCESS_KEY uses read -s (silent input)
grep -n 'read.*SECRET\|read.*password\|read.*pass\|read.*token' scripts/shell/*.sh
# Expected: only read -s for SECRET_ACCESS_KEY; all other credential refs use env vars

# Confirm SONAR_TOKEN is never echoed in full
grep -n 'echo.*SONAR_TOKEN\|echo.*\$SONAR_TOKEN' scripts/shell/*.sh
# Expected: only masked display (prefix...suffix) in check-sonar-config.sh

# Confirm no credential values are logged to scan output files
cat scans/epyon_*/sonar/sonar-results.json | jq 'keys'
# Expected: no token/password fields
```

**Report Location:**
- `scans/epyon_*/trufflehog/trufflehog-results.json` — Epyon self-scan; TruffleHog would surface any accidentally logged credential values

---

#### APSC-DV-001860 (V-222555): The application must use mechanisms meeting the requirements of applicable federal laws for authentication to a cryptographic module.

**Severity:** CAT I | **SRG:** SRG-APP-000179 | **Rule:** SV-222555r961050

**Applicability to Epyon:** NOT APPLICABLE — Epyon does not provide, manage, or expose authenticated access to any cryptographic module.

**Rationale:**

The check text states explicitly: *"If the application does not provide authenticated access to a cryptographic module, the requirement is not applicable."*

Epyon satisfies this exclusion:

| Cryptographic Module Requirement | Epyon's Status |
|---|---|
| Manages a cryptographic module (HSM, PKCS#11, TPM, etc.) | None — Epyon has no crypto module integration |
| Exposes a crypto API for authenticated users | None — Epyon is a CLI tool with no multi-user access layer |
| Stores or manages cryptographic keys | None — no key material is generated or held by Epyon |
| Performs bulk encryption/decryption operations | None — Epyon does not encrypt data |
| Uses `openssl`, `gpg`, `pkcs12`, or similar CLI tools | None — not called anywhere in active scripts |

**What Epyon does with crypto-adjacent components (why this is still N/A):**

- **HTTPS transmission** — TLS for `SONAR_HOST_URL`, Docker registry pulls, and AWS API calls is handled entirely by the OS networking stack, the Docker daemon, and the AWS CLI — not by Epyon code. Epyon does not authenticate to or configure those TLS implementations.
- **`dhi/caddy:debian-13-2-fips-dev`** — This FIPS-enabled image appears as a *scan target* in `run-target-security-scan.sh`, `run-grype-scan.sh`, `run-trivy-scan.sh`, and `run-xeol-scan.sh`. Epyon scans it for vulnerabilities but does not manage its cryptographic module.
- **`generate-scan-manifest.sh`** — Creates SHA-256 file hashes of scan outputs using the system `sha256sum` utility. This is integrity verification (hash comparison), not cryptographic module authentication.
- **TruffleHog `.pem`/`.key` detection** — Epyon detects exposed key material in scanned repos; it does not store or use those keys.

**Evidence Commands:**
```bash
# Confirm no openssl / gpg / pkcs / HSM CLI calls in Epyon's own scripts
grep -rn 'openssl\|gpg --\|pkcs12\|p11-kit\|tpm2\|softhsm\|keytool\|certutil' scripts/shell/*.sh
# Expected: no output

# Confirm SHA-256 manifest hashing uses system sha256sum (not crypto module management)
grep -n 'sha256\|hash\|digest' scripts/shell/generate-scan-manifest.sh | head -10
# Expected: sha256sum invocations for integrity, no crypto module authentication

# Confirm FIPS image references are scan targets, not Epyon crypto config
grep -n 'fips' scripts/shell/run-target-security-scan.sh | head -5
# Expected: image name strings passed to scanning tools, not crypto module config
```

**Report Location:**
- `scans/epyon_*/sonar/sonar-results.json` — static analysis of Epyon's Python code (no crypto module calls expected)

---

#### APSC-DV-002310 (V-222585): The application must fail to a secure state if system initialization fails, shutdown fails, or aborts fail.

**Severity:** CAT I | **SRG:** SRG-APP-000225 | **Rule:** SV-222585r961122

**Applicability to Epyon:** APPLICABLE — mitigated by design. Epyon is a stateless CLI tool; failure scenarios cannot leave open database connections, disabled access controls, or active user sessions, because none of those persistent resources exist.

**Failure Mode Analysis:**

| Failure Scenario | Risk if it Occurs | Epyon's Behavior |
|---|---|---|
| Initialization failure (missing env var, missing scan dir) | Could leave a partial scan output | `set -euo pipefail` causes immediate non-zero exit before any output is written; pre-flight validation rejects missing inputs |
| Abort during scan (SIGINT, SIGTERM, Docker kill) | Scan tool container stops; partial JSON may exist on disk | Scan output is incomplete but inert — no credentials, no sessions, no network listeners left open |
| Shutdown failure | No persistent daemon or listener to leave open | Epyon has no server process; termination = complete stop |
| Database connection left open | Not applicable | Epyon has no database |
| Access control mechanism disabled | Not applicable | Epyon has no authentication layer, RBAC, or session tokens to disable |
| Sensitive data in temp files after abort | Low risk | Temp files hold intermediate scan results (not credentials); most scripts use `trap ... EXIT` or `mktemp` with explicit cleanup |

**Fail-secure controls present:**

- **`set -euo pipefail`** in all primary scripts — any unexpected command failure immediately aborts the script with a non-zero exit code, preventing execution from continuing in a degraded state:
  ```bash
  # generate-remediation-suggestions.sh, embed-dashboard-data.sh,
  # generate-interactive-dashboard.sh, check-docker-runtime.sh, etc.
  set -euo pipefail
  ```

- **`trap ... ERR`** in `generate-security-dashboard.sh` — logs the failing line number and exits:
  ```bash
  trap 'echo "ERROR: Dashboard generation failed at line $LINENO with exit code $?" >&2' ERR
  ```

- **`trap ... EXIT` for temp file cleanup** in `generate-remediation-suggestions.sh`:
  ```bash
  trap 'rm -f $TEMP_DATA' EXIT
  ```
  This fires on both normal exit and abort, preventing temp data from persisting after a crash.

- **Atomic file writes** — `generate-scan-findings-summary.sh` and `generate-scan-manifest.sh` use `jq > file.tmp && mv file.tmp file` patterns, ensuring output files are either complete or unchanged if a write is interrupted.

- **Pre-flight validation** — scripts validate required env vars and directory existence before performing any work; an invalid starting state produces an immediate error exit rather than a partial scan.

- **Docker container isolation** — each scan tool runs in a separate, short-lived Docker container. If a container is killed, it takes no Epyon state with it; the host filesystem is only written to when the container exits successfully.

**Known limitation — no SIGINT/SIGTERM cleanup trap in all scripts:**
Most scripts do not register an explicit `trap ... SIGINT SIGTERM` handler. On interrupt, `/tmp/epyon-*` cache files and any partially-written scan output may remain. These files contain scan data (CVE lists, file paths) but not credentials, session tokens, or authentication material. The security impact of leftover temp files is low (no elevation of privilege, no access control bypass), but operators on shared systems should be aware.

**Evidence Commands:**
```bash
# Confirm set -e / set -euo pipefail is present in primary scripts
grep -n 'set -e\|set -euo\|set -o pipefail' scripts/shell/run-target-security-scan.sh \
  scripts/shell/generate-remediation-suggestions.sh scripts/shell/check-severity-gate.sh

# Confirm trap ERR is set in dashboard generator
grep -n 'trap' scripts/shell/generate-security-dashboard.sh

# Confirm trap EXIT cleans temp files in remediation generator
grep -n 'trap' scripts/shell/generate-remediation-suggestions.sh

# Confirm atomic write pattern (tmp + mv) for output integrity
grep -n '\.tmp.*&&.*mv\|mv.*\.tmp' scripts/shell/generate-scan-findings-summary.sh | head -5

# Confirm no server/listener/daemon is started by Epyon
grep -rn 'listen\|bind\|accept\|nc -l\|socat\|ncat' scripts/shell/*.sh
# Expected: no server-start commands

# Confirm no database is opened
grep -rn 'sqlite3\|psql\|mysql\|mongod' scripts/shell/*.sh
# Expected: no output
```

**Report Location:**
- Exit code of any Epyon script: non-zero exit on failure is the primary evidence of fail-secure behavior
- `scans/epyon_*/sonar/sonar-results.json` — static analysis of Epyon's Python code for exception-handling patterns

---

#### APSC-DV-002440 (V-222596): The application must protect the confidentiality and integrity of transmitted information.

**Severity:** CAT I | **SRG:** SRG-APP-000439 | **Rule:** SV-222596r961632

**Applicability to Epyon:** APPLICABLE — Epyon transmits sensitive data (source code, API tokens, scan results) to external services. All network transmission paths must use TLS/HTTPS.

**Epyon's Network Transmission Inventory:**

| Transmission | Destination | Protocol Enforced | Notes |
|---|---|---|---|
| SonarQube/SonarCloud scan upload | `SONAR_HOST_URL` (default: `https://sonarcloud.io`) | HTTPS by default | User-configurable — see gap below |
| Docker image pulls (trivy, grype, syft, trufflehog, etc.) | Docker Hub / private registry | HTTPS (Docker daemon default) | Docker rejects plain-HTTP registries by default unless explicitly configured with `insecure-registries` |
| AWS ECR authentication | `sts.amazonaws.com`, ECR endpoint | HTTPS — enforced by AWS SDK / `aws` CLI | AWS CLI never uses plain HTTP for API calls |
| Baseline repo clone | `https://github.com/MetroStar/comet-starter.git` | HTTPS — hardcoded URL | Hardcoded `https://` in `run-baseline-scan.sh` |
| GitHub Actions CI workflows | `github.com` / GitHub API | HTTPS — enforced by GitHub Actions runner | All GitHub infrastructure is TLS-only |

**Remediated — `SONAR_HOST_URL` HTTPS enforcement:**
The default value `https://sonarcloud.io` was always secure, but Epyon previously did not reject a user-supplied `http://` URL. A guard was added to `run-sonar-analysis.sh` immediately after `SONAR_HOST_URL` is resolved:

```bash
if [[ "$SONAR_HOST_URL" != https://* ]]; then
  echo "[ERROR] SONAR_HOST_URL must use HTTPS to protect transmitted credentials and source code." >&2
  echo "[ERROR] Current value: $SONAR_HOST_URL" >&2
  exit 1
fi
```
This rejects any plaintext HTTP URL at startup, before credentials or source code are transmitted.

**Evidence Commands:**
```bash
# Confirm SonarQube default URL is HTTPS
grep -n 'SONAR_HOST_URL' scripts/shell/run-sonar-analysis.sh | head -5
# Expected: default is https://sonarcloud.io

# Confirm baseline repo clone uses hardcoded HTTPS
grep -n 'BASELINE_REPO_URL\|github.com' scripts/shell/run-baseline-scan.sh
# Expected: https://github.com/...

# Confirm no --insecure or http:// flags passed to Docker or curl
grep -rn 'insecure\|http://[^/]' scripts/shell/*.sh | grep -v '#\|echo\|nvd.nist\|docs.\|owasp\|github.com\|example.com'
# Expected: no active insecure flags (only comments and documentation strings)

# Confirm no Docker insecure-registry config in Epyon
grep -rn 'insecure-registr' scripts/shell/
# Expected: no output

# Verify AWS CLI transmit encryption (aws commands always use HTTPS)
grep -n 'aws ecr\|aws sts\|aws s3' scripts/shell/run-helm-build.sh
# Expected: aws CLI commands — all use HTTPS by design
```

**Report Location:**
- `scans/epyon_*/checkov/checkov-results.json` — Checkov checks for TLS in IaC that Epyon runs against (not Epyon itself, but provides evidence for scanned apps)
- `scans/epyon_*/sonar/sonar-results.json` — SonarQube static analysis; confirm `SONAR_HOST_URL` value used during scan

---

#### APSC-DV-002560 (V-222609): The application must not be subject to input handling vulnerabilities.

**Severity:** CAT I | **SRG:** SRG-APP-000447 | **Rule:** SV-222609r961656

**Applicability to Epyon:** APPLICABLE — Epyon accepts user-supplied file system paths, scan directory names, format selectors, and environment variable values as inputs. All must be validated before use.

**Epyon's Attack Surface (CLI tool — no web interface):**

Epyon is a command-line tool. The STIG examples (forms, cookies, URL parameters, HTTP headers) do not apply. Epyon's actual input boundaries are:

| Input Type | Source | Risk |
|---|---|---|
| Scan directory path | CLI positional arg / env var | Path traversal, non-existent path |
| Scan ID / app name | CLI arg used in filenames | Directory traversal if unsanitized |
| Format selector (`json`, `xml`, etc.) | CLI arg passed to syft | Unexpected value handled? |
| `CLASSIFICATION_LEVEL` | Env var injected into HTML/JSON | XSS through HTML output if unescaped |
| JSON data from scan tools | Files on disk parsed by `jq` / Python | Malformed JSON; not direct user input |

**Input Validation Controls Present:**

- **Path existence checks** — all scripts validate the scan directory exists before proceeding:
  ```bash
  # check-severity-gate.sh
  if [[ -z "$SCAN_DIR" || ! -d "$SCAN_DIR" ]]; then
      echo "❌ Error: SCAN_DIR not set or directory doesn't exist"
  ```
- **Scan ID sanitization** — `run-epyon-scan-ci.sh` strips path separators and non-alphanumeric characters from user-supplied subdirectory input:
  ```bash
  SANITIZED_SUBDIR=$(echo "$SUBDIR" | sed -E "s#[/[:space:]]+#_#g; s#[^A-Za-z0-9._:-]#_#g")
  ```
- **HTML output escaping** — `consolidate-security-reports.sh` uses Python's `html.escape()` on all scan-data values interpolated into HTML reports, preventing XSS in generated output:
  ```python
  html.escape(vulnerability.get('id', 'Unknown CVE'))
  html.escape(issue.get('message', 'Unknown Issue'))
  html.escape(artifact.get('name', 'Unknown'))
  ```
- **Double-quoting** — all user-supplied variables are double-quoted in shell expansions and Docker `-v` mount arguments, preventing word-splitting and globbing injection.
- **`jq` / structured parsing** — scan result JSON is never `eval`'d or interpolated directly into shell; always processed via `jq` or Python's `json` module.

**Known Gap — Path Traversal:**
Paths are checked for existence but not canonicalized. A path like `scans/../../../etc/passwd` would pass the `-d` existence check if that path resolves to a real directory. Since Epyon only *reads* scan data from these paths and does not write secrets or credentials to arbitrary locations, exploitation impact is low (read-only access to directories the user already has access to). No remediation is required for the current use model, but future versions should consider adding `realpath` canonicalization.

**Evidence Commands:**
```bash
# Verify path existence checks are present in main scripts
grep -n "! -d\|! -f\|SCAN_DIR.*not\|does not exist" scripts/shell/check-severity-gate.sh \
  scripts/shell/generate-remediation-suggestions.sh scripts/shell/export-api-discovery.sh

# Verify scan ID sanitization
grep -n "SANITIZED_SUBDIR\|sed.*A-Za-z0-9" scripts/shell/run-epyon-scan-ci.sh

# Verify html.escape() usage in HTML generation
grep -n "html\.escape" scripts/shell/consolidate-security-reports.sh

# Verify double-quoting of paths in Docker volume mounts
grep -n '\-v.*"\$' scripts/shell/run-checkov-scan.sh scripts/shell/run-trufflehog-scan.sh

# SonarQube scan of Epyon's Python code for input validation issues
cat scans/epyon_*/sonar/sonar-results.json | \
  jq '.issues[] | select(.rule | test("injection|xss|validation|path.*traversal"; "i"))'
```

**Report Location:**
- `scans/epyon_*/sonar/sonar-results.json` — static analysis for injection/validation findings
- `scans/epyon_*/checkov/checkov-results.json` — IaC-level input misconfigurations

---

#### APSC-DV-002590 (V-222612): The application must not be vulnerable to overflow attacks.

**Severity:** CAT I | **SRG:** SRG-APP-000450 | **Rule:** SV-222612r961665

**Applicability to Epyon:** APPLICABLE — mitigated by language design.

**Epyon's Compliance Status:**

Epyon is composed entirely of **bash shell scripts** (60 files) and **inline Python 3** snippets. Neither language has a memory model susceptible to traditional overflow attacks:

| Attack Class | Risk to Epyon | Reason |
|---|---|---|
| Stack/heap buffer overflow | None | Bash and Python have no fixed-size C-style buffers or manual heap allocation |
| Integer overflow | None | Python uses arbitrary-precision integers; bash `$(( ))` uses signed 64-bit with defined wrap behavior but no memory implications |
| Format string overflow | None | Bash `printf` is not equivalent to C `printf`; Python's `str.format()` has no memory writes |
| Return-oriented programming / shellcode injection | None | No native stack frames to corrupt; no executable memory regions controlled by script logic |

The Fix Text for this STIG explicitly states: *"Design the application to use a language or compiler that performs automatic bounds checking."* Bash and Python inherently satisfy this by design.

**Residual risk — tool container binaries:**
Epyon executes compiled Go binaries (syft, grype, trivy, trufflehog, etc.) inside Docker containers. These binaries *are* compiled and could theoretically carry overflow CVEs in their own dependencies. This risk is mitigated by Grype and Trivy CVE scanning of those images before use.

**Evidence Commands:**
```bash
# Confirm Epyon contains no compiled binaries — only scripts
file scripts/shell/*.sh
# Expected: all "ASCII text" or "Bourne-Again shell script"

# Confirm no compiled artifacts exist in Epyon's own tree
find . -name "*.o" -o -name "*.so" -o -name "*.dylib" -o -name "*.exe" \
       -o -name "*.out" -o -name "*.class" -o -name "*.jar" \
  | grep -v ".git"
# Expected: no output

# Verify no native build system exists for Epyon itself
ls go.mod Cargo.toml pom.xml CMakeLists.txt Makefile 2>&1
# Expected: all "No such file or directory"

# SonarQube static analysis of any Python code in Epyon
cat scans/epyon_*/sonar/sonar-results.json | \
  jq '.issues[] | select(.rule | test("overflow|buffer|format-string"; "i"))'

# Grype scan of tool container images for overflow CVEs
cat scans/epyon_*/grype/grype-results.json | \
  jq '.matches[] | select(.vulnerability.description | test("overflow|buffer"; "i")) | {cve: .vulnerability.id, pkg: .artifact.name, severity: .vulnerability.severity}'
```

**Report Location:**
- Language check: `file scripts/shell/*.sh` — confirms script-only codebase
- `scans/epyon_*/sonar/sonar-results.json` — static analysis of Python code
- `scans/epyon_*/grype/grype-results.json` — CVE scan of tool container images

---

#### APSC-DV-003110 (V-222642): The application must not contain embedded authentication data.

**Severity:** CAT I | **SRG:** SRG-APP-000516 | **Rule:** SV-222642r961863

**Applicability to Epyon:** APPLICABLE — Epyon itself must not contain hardcoded passwords, API keys, tokens, or other authentication data in its own scripts, configuration files, or committed assets.

**Epyon's Compliance Status:**

Epyon satisfies this control. All authentication data is handled exclusively through environment variables or interactive prompts — no literal credentials exist in the codebase:

| Credential | Mechanism | Location |
|---|---|---|
| `SONAR_TOKEN` | Env var or `.env.sonar` (git-ignored) | `run-sonar-analysis.sh` |
| `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` | Env var or interactive `read -s` prompt | `run-checkov-scan.sh`, `aws-ecr-helm-auth.sh` |
| `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` | Env var only | `run-epyon-scan-ci.sh`, `run-garak-scan.sh` |
| `JIRA_API_TOKEN` | GitHub Actions `secrets.*` only | `epyon-scan.yml` |

**Protective controls in place:**
- `.env.sonar`, `.env`, `.env.local`, `.env.production`, `.env.*.local` are all listed in `.gitignore`
- `.env.sonar.example` ships with placeholder strings (`your-sonarqube-token-here`) — not real credentials
- GitHub Actions workflows use `${{ secrets.X }}` exclusively — no values in workflow YAML
- Interactive credential entry uses `read -s` (silent input, never logged)

**Evidence Commands:**
```bash
# Verify no hardcoded credentials exist in Epyon's own scripts
grep -rn --include="*.sh" \
  -E "(password|passwd|api_key|api-key|secret_key|auth_token|private_key)\s*=\s*[^\$\"\{\(\\]" \
  scripts/shell/

# Verify .env.sonar is git-ignored (should show .env.sonar in output)
cat .gitignore | grep -i env

# Verify no .env.sonar or .env files are tracked
git ls-files | grep -E "^(\.env|\.env\.)"

# Confirm no verified secrets in Epyon's own last self-scan
cat scans/epyon_*/trufflehog/trufflehog-results.json | \
  jq '.results[] | select(.verified==true)'
```

**Remediation if a credential is ever found:**
1. Remove it from the file immediately
2. Rotate the credential — treat it as compromised
3. Add the file pattern to `.gitignore` if not already present
4. Run `git filter-repo` or BFG Repo Cleaner to purge from history

**Report Location:**
- `scans/epyon_*/trufflehog/trufflehog-results.json` — Epyon self-scan secret detections
- `scans/epyon_*/checkov/checkov-results.json` — IaC hardcoded credential checks (`CKV_SECRET_*`)

---

#### APSC-DV-003235: The application must not be vulnerable to race conditions.

**Epyon Tools:**
- **SonarQube** - Concurrency bug detection
- **Code Coverage Analysis** - Identifies untested concurrent code

**Evidence Collection:**
```bash
# Search for concurrency issues
cat scans/*/sonar/sonar-results.json | jq '.issues[] | select(.rule | contains("concurrent\|thread\|race\|synchroniz"))'
```

**Manual Validation Required:**
- Stress testing and load testing results
- Concurrency testing documentation

---

### 2. Container Platform STIG (V2R1)

#### CNTR-K8-000150: The Kubernetes API server must have anonymous authentication disabled.

**Epyon Tools:**
- **Checkov** - Kubernetes security policy validation
- **Trivy** - Kubernetes manifest scanning

**Evidence Collection:**
```bash
# Check Kubernetes configurations
grep -i "anonymous\|authentication" scans/*/checkov/checkov-results.json
grep -i "anonymous" scans/*/trivy/trivy-results.json

# Review Helm chart security
cat scans/*/helm/helm-lint-results.txt
```

---

#### CNTR-K8-000380: Kubernetes Kubelet must deny hostname override.

**Epyon Tools:**
- **Checkov** - Kubelet configuration validation
- **Helm** - Chart security validation

**Evidence Collection:**
```bash
# Scan Helm charts and manifests
./scripts/shell/run-checkov-scan.sh filesystem

# Check for kubelet misconfigurations
grep -i "kubelet\|hostname-override" scans/*/checkov/checkov-results.json
```

---

#### CNTR-K8-001360: Kubernetes must separate user functionality.

**Epyon Tools:**
- **Checkov** - RBAC and namespace policies
- **Trivy** - Security context validation

**Evidence Collection:**
```bash
# Validate RBAC configurations
grep -i "rbac\|role\|namespace\|securitycontext" scans/*/checkov/checkov-results.json

# Check container security contexts
grep -i "securityContext\|runAsUser\|capabilities" scans/*/trivy/trivy-results.json
```

---

#### CNTR-K8-002010: Kubernetes must have a pod security policy set.

**Epyon Tools:**
- **Checkov** - Pod Security Policy validation
- **Trivy** - Pod security standards compliance

**Evidence Collection:**
```bash
# Check for PSP/PSS configurations
grep -i "podsecuritypolicy\|podsecurity\|psp\|pss" scans/*/checkov/checkov-results.json

# Review security dashboard for pod security issues
./scripts/shell/generate-security-dashboard.sh
```

---

### 3. Docker Enterprise STIG (V2R2)

#### DKER-EE-001010: All Docker Enterprise components must be compatible with Docker Enterprise.

**Epyon Tools:**
- **Trivy** - Image vulnerability scanning with version detection
- **SBOM** - Component inventory and version tracking

**Evidence Collection:**
```bash
# Generate SBOM for version tracking
./scripts/shell/run-sbom-scan.sh

# Export SBOM for compliance documentation
./scripts/shell/export-sbom.sh "scans/latest" json

# Review component versions
cat scans/*/sbom/sbom.json | jq '.components[] | {name, version}'
```

---

#### DKER-EE-002000: Only trusted container images must be used.

**Epyon Tools:**
- **Baseline Scanning** - DHI approved image validation
- **Trivy** - Image provenance and signature validation
- **Configuration** - Approved base images list

**Evidence Collection:**
```bash
# Run baseline scan against DHI images
./scripts/shell/run-baseline-scan.sh

# Compare against approved base images
cat configuration/approved-base-images.conf

# Generate comparison report
cat scans/*/baseline-comparison.json
```

---

#### DKER-EE-002140: Docker Enterprise images must be scanned for vulnerabilities.

**Epyon Tools:**
- **Grype** - Comprehensive vulnerability scanning
- **Trivy** - Container image CVE detection
- **Xeol** - End-of-life software detection

**Evidence Collection:**
```bash
# Full image security scan
./scripts/shell/run-target-security-scan.sh "/path/to/app" images

# Export vulnerability reports
cat scans/*/grype/grype-results.json | jq '.matches[] | {vulnerability: .vulnerability.id, severity: .vulnerability.severity}'
cat scans/*/trivy/trivy-results.json | jq '.Results[] | .Vulnerabilities[]?'

# Check for EOL software
cat scans/*/xeol/xeol-results.json
```

---

#### DKER-EE-005170: Secrets must not be stored in Docker Enterprise images.

**Epyon Tools:**
- **TruffleHog** - Secret detection in images and code
- **Checkov** - Secret management configuration validation

**Evidence Collection:**
```bash
# Scan for secrets
./scripts/shell/run-trufflehog-scan.sh filesystem

# Export secrets report
cat scans/*/trufflehog/trufflehog-results.json | jq '.results[] | select(.verified==true)'

# Check dashboard for secret findings
./scripts/shell/open-latest-dashboard.sh
# → Filter by "TruffleHog" in interactive dashboard
```

---

### 4. Application Security and Development STIG - DevSecOps (V2R1)

#### ASDV-DV-000010: The DevSecOps platform must scan all application code for security vulnerabilities.

**Epyon Tools:**
- **All 10 Security Layers** - Comprehensive scanning
- **Automated Orchestration** - Full pipeline execution

**Evidence Collection:**
```bash
# Run complete security scan
./scripts/shell/run-target-security-scan.sh "/path/to/app" full

# Generate consolidated dashboard
./scripts/shell/generate-security-dashboard.sh

# Export all results
./scripts/shell/export-api-discovery.sh "scans/latest" json
./scripts/shell/export-sbom.sh "scans/latest" json
```

**Dashboard Evidence:**
- Interactive dashboard shows all 10 layers: `./scripts/shell/open-latest-dashboard.sh`
- Consolidated JSON: `scans/{scan_id}/consolidated-reports/consolidated-security-report.json`

---

#### ASDV-DV-000030: The DevSecOps platform must scan all application dependencies for security vulnerabilities.

**Epyon Tools:**
- **Grype** - Dependency vulnerability scanning with SBOM
- **Trivy** - Package vulnerability detection
- **SBOM Generation** - Complete dependency inventory

**Evidence Collection:**
```bash
# Generate SBOM
./scripts/shell/run-sbom-scan.sh

# Scan dependencies
./scripts/shell/run-grype-scan.sh filesystem
./scripts/shell/run-trivy-scan.sh filesystem

# Export dependency report
./scripts/shell/export-sbom.sh "scans/latest" json
cat scans/*/sbom/sbom.json | jq '.components[] | select(.type=="library")'
```

---

#### ASDV-DV-000070: The DevSecOps platform must identify end-of-life software.

**Epyon Tools:**
- **Xeol** - EOL software detection
- **SBOM Analysis** - Version tracking

**Evidence Collection:**
```bash
# Run EOL detection
./scripts/shell/run-xeol-scan.sh filesystem

# Review EOL findings
cat scans/*/xeol/xeol-results.json | jq '.matches[] | {name: .artifact.name, version: .artifact.version, eolDate: .cycle.eolDate}'

# Check baseline for EOL software
./scripts/shell/run-baseline-scan.sh
```

---

#### ASDV-DV-000100: The DevSecOps platform must scan container images for security vulnerabilities.

**Epyon Tools:**
- **Trivy** - Multi-layer container scanning
- **Grype** - Container image CVE detection
- **Baseline Scanning** - DHI image comparison

**Evidence Collection:**
```bash
# Image-focused scan
./scripts/shell/run-target-security-scan.sh "/path/to/app" images

# Baseline comparison
./scripts/shell/run-baseline-scan.sh

# Review image scan results
cat scans/*/trivy/trivy-results.json | jq '.Results[] | select(.Type=="container")'
```

---

#### ASDV-DV-000220: The DevSecOps platform must scan for malware.

**Epyon Tools:**
- **ClamAV** - Antivirus and malware detection

**Evidence Collection:**
```bash
# Run malware scan
./scripts/shell/run-clamav-scan.sh

# Review clean status
cat scans/*/clamav/clamav-scan.log
grep "Infected files: 0" scans/*/clamav/clamav-scan.log
```

---

#### ASDV-DV-000320: The DevSecOps platform must enforce severity-based quality gates.

**Epyon Tools:**
- **Severity Gate Checker** - Automated quality gate enforcement
- **Dashboard** - Severity-based filtering and reporting

**Evidence Collection:**
```bash
# Check severity gate
./scripts/shell/check-severity-gate.sh "scans/latest"

# Configure thresholds (example)
CRITICAL_THRESHOLD=0 HIGH_THRESHOLD=5 ./scripts/shell/check-severity-gate.sh "scans/latest"

# Review severity breakdown in dashboard
./scripts/shell/open-latest-dashboard.sh
```

---

#### ASDV-DV-000500: The DevSecOps platform must provide automated remediation recommendations.

**Epyon Tools:**
- **Remediation Suggestions** - Automated fix recommendations

**Evidence Collection:**
```bash
# Generate remediation suggestions
./scripts/shell/generate-remediation-suggestions.sh

# Review recommendations
cat scans/*/consolidated-reports/remediation-suggestions.json
cat scans/*/consolidated-reports/remediation-suggestions.md
```

---

### 5. Red Hat OpenShift STIG (V2R1)

#### CNTR-OS-000010: OpenShift must use TLS 1.2 or greater for secure communication.

**Epyon Tools:**
- **Checkov** - TLS configuration validation
- **Trivy** - Weak crypto library detection

**Evidence Collection:**
```bash
# Check TLS configurations
grep -i "tls\|ssl\|cipher" scans/*/checkov/checkov-results.json

# Verify no weak crypto
cat scans/*/trivy/trivy-results.json | jq '.Results[] | .Vulnerabilities[]? | select(.Title | contains("TLS\|SSL\|crypto"))'
```

---

#### CNTR-OS-000390: OpenShift must prohibit the use of cached authenticators.

**Epyon Tools:**
- **Checkov** - Authentication configuration validation
- **TruffleHog** - Cached credential detection

**Evidence Collection:**
```bash
# Check authentication configurations
grep -i "auth\|cache\|token" scans/*/checkov/checkov-results.json

# Scan for cached credentials
cat scans/*/trufflehog/trufflehog-results.json | jq '.results[] | select(.raw | contains("token\|cache"))'
```

---

## Compliance Workflow

### Step 1: Run Full Security Scan

```bash
# Execute comprehensive scan
./scripts/shell/run-target-security-scan.sh "/path/to/application" full

# Include baseline validation for approved images
./scripts/shell/run-baseline-scan.sh
```

### Step 2: Generate Reports

```bash
# Create interactive dashboard
./scripts/shell/generate-security-dashboard.sh

# Generate remediation guidance
./scripts/shell/generate-remediation-suggestions.sh

# Export structured data
./scripts/shell/export-api-discovery.sh "scans/latest" json
./scripts/shell/export-sbom.sh "scans/latest" json
```

### Step 3: Review Findings by STIG Category

```bash
# Open interactive dashboard
./scripts/shell/open-latest-dashboard.sh

# Filter by:
# - Severity (Critical, High, Medium, Low)
# - Tool (Trivy, Grype, Checkov, etc.)
# - Category (Infrastructure, Vulnerabilities, Secrets, etc.)
```

### Step 4: Document Evidence

**Key Files for STIG Documentation:**

```
scans/{scan_id}/
├── consolidated-reports/
│   ├── consolidated-security-report.json    # Master report
│   ├── dashboards/security-dashboard.html   # Visual evidence
│   └── remediation-suggestions.md           # Fix guidance
├── trivy/trivy-results.json                 # Container security
├── grype/grype-results.json                 # Vulnerability scanning
├── checkov/checkov-results.json             # IaC security
├── trufflehog/trufflehog-results.json       # Secret detection
├── clamav/clamav-scan.log                   # Malware scan
├── xeol/xeol-results.json                   # EOL software
├── sbom/sbom.json                           # Component inventory
└── baseline-comparison.json                 # Approved image validation
```

### Step 5: Address Findings

```bash
# Generate fix recommendations
cat scans/*/consolidated-reports/remediation-suggestions.json | jq '.vulnerabilities[] | select(.severity=="CRITICAL")'

# Check severity gate compliance
./scripts/shell/check-severity-gate.sh "scans/latest"

# Re-scan after remediation
./scripts/shell/run-target-security-scan.sh "/path/to/application" full
```

---

## STIG Evidence Matrix

| STIG Control | Category | Epyon Tool(s) | Evidence Location | Automated/Manual |
|--------------|----------|---------------|-------------------|------------------|
| APSC-DV-000160 | TLS/Crypto | Checkov, Trivy, TruffleHog | checkov/, trivy/, trufflehog/ | Automated |
| APSC-DV-000190 | WS-Security Timestamps | Not applicable — no WS-Security tokens, no SOAP messaging | N/A | N/A |
| APSC-DV-000200 | WS-Security / SAML Validity Periods | Not applicable — no WS-Security, no SAML, no SOAP messaging | N/A | N/A |
| APSC-DV-000230 | SAML SubjectConfirmation NotOnOrAfter | Not applicable — no SAML assertions, no SOAP, no identity federation | N/A | N/A |
| APSC-DV-000240 | SAML Assertion Conditions | Not applicable — no SAML assertions, no SOAP, no identity federation | N/A | N/A |
| APSC-DV-000460 | Access Control Enforcement | Not applicable — no authentication or authorization layer; no user accounts or roles | N/A | N/A |
| APSC-DV-000500 | Privilege Escalation | Checkov, Trivy, SonarQube | checkov/, trivy/, sonar/ | Automated |
| APSC-DV-000510 | Least Privilege Execution | No --privileged/--cap-add; :ro mounts; sudo limited to diagnostic only | checkov/, trivy/ | Code review + Automated |
| APSC-DV-000530 | Account Lockout | Not applicable — no authentication layer, no user accounts, no login mechanism | N/A | N/A |
| APSC-DV-000590 | SQL Injection | SonarQube | sonar/ | Partial (code only) |
| APSC-DV-001620 | Input Validation | SonarQube, Grype | sonar/, grype/ | Automated |
| APSC-DV-001750 | Password Transmission | Not applicable — no password auth; ECR token via local pipe; all APIs over HTTPS | N/A | N/A |
| APSC-DV-001810 | PKI Certificate Path Validation | Not applicable — no PKI auth; HTTPS via OS trust store with no cert-skip flags | N/A | N/A |
| APSC-DV-001820 | PKI Private Key Access | Not applicable — no private keys, no code signing, no PKI auth | N/A | N/A |
| APSC-DV-001850 | Password Display | read -s for secrets; env vars; masked token display | trufflehog/ | Automated + Code review |
| APSC-DV-001860 | Crypto Module Auth | Not applicable — no crypto module management | N/A | N/A |
| APSC-DV-002310 | Fail Secure | set -euo pipefail; trap ERR/EXIT; atomic writes; stateless design | sonar/ | Code review |
| APSC-DV-002440 | Transmitted Data Protection | HTTPS defaults; Docker TLS; AWS CLI; hardcoded HTTPS URLs | sonar/, checkov/ | Automated + Config review |
| APSC-DV-002485 | Hidden Fields | Not applicable — no web server, no forms, no hidden inputs | N/A | N/A |
| APSC-DV-002490 | XSS | html.escape() on all scan data; static HTML output; no web server | sonar/, consolidated-reports/ | Automated + Code review |
| APSC-DV-002510 | Command Injection | No eval; quoted vars; sanitized IDs; SonarQube | sonar/ | Automated + Code review |
| APSC-DV-002540 | SQL Injection | Not applicable — no database | N/A | N/A |
| APSC-DV-002550 | XML Attacks | Language design + Grype, SonarQube | grype/, sonar/ | Automated (mitigated by design) |
| APSC-DV-002590 | Overflow Attacks | Language (bash/Python) + Grype, SonarQube | grype/, sonar/ | Automated (mitigated by design) |
| APSC-DV-003235 | Race Conditions | SonarQube | sonar/ | Manual review required |
| CNTR-K8-000150 | K8s Auth | Checkov, Trivy | checkov/, trivy/ | Automated |
| CNTR-K8-000380 | Kubelet Config | Checkov, Helm | checkov/, helm/ | Automated |
| CNTR-K8-001360 | User Separation | Checkov, Trivy | checkov/, trivy/ | Automated |
| CNTR-K8-002010 | Pod Security | Checkov, Trivy | checkov/, trivy/ | Automated |
| DKER-EE-001010 | Component Versions | Trivy, SBOM | trivy/, sbom/ | Automated |
| DKER-EE-002000 | Trusted Images | Baseline Scan, Trivy | baseline/, trivy/ | Automated |
| DKER-EE-002140 | Image Scanning | Grype, Trivy, Xeol | grype/, trivy/, xeol/ | Automated |
| APSC-DV-003110 | Embedded Auth Data | TruffleHog, Checkov | trufflehog/, checkov/ | Automated |
| DKER-EE-005170 | Secrets in Images | TruffleHog | trufflehog/ | Automated |
| ASDV-DV-000010 | Code Scanning | All Layers | consolidated-reports/ | Automated |
| ASDV-DV-000030 | Dependency Scanning | Grype, Trivy, SBOM | grype/, trivy/, sbom/ | Automated |
| ASDV-DV-000070 | EOL Detection | Xeol, SBOM | xeol/, sbom/ | Automated |
| ASDV-DV-000100 | Container Scanning | Trivy, Grype, Baseline | trivy/, grype/, baseline/ | Automated |
| ASDV-DV-000220 | Malware Scanning | ClamAV | clamav/ | Automated |
| ASDV-DV-000320 | Quality Gates | Severity Gate Checker | consolidated-reports/ | Automated |
| ASDV-DV-000500 | Remediation | Remediation Suggestions | remediation-suggestions.json | Automated |
| CNTR-OS-000010 | TLS Config | Checkov, Trivy | checkov/, trivy/ | Automated |
| CNTR-OS-000390 | Cached Auth | Checkov, TruffleHog | checkov/, trufflehog/ | Automated |

---

## Query Examples for Common STIG Requirements

### Find All Critical Vulnerabilities (ASDV-DV-000320)

```bash
# Critical findings across all tools
cat scans/*/consolidated-reports/consolidated-security-report.json | \
  jq '.findings[] | select(.severity=="CRITICAL")'

# Critical CVEs only
cat scans/*/grype/grype-results.json | \
  jq '.matches[] | select(.vulnerability.severity=="Critical")'
```

### Verify No Secrets in Code (DKER-EE-005170)

```bash
# Verified secrets (confirmed true positives)
cat scans/*/trufflehog/trufflehog-results.json | \
  jq '.results[] | select(.verified==true)'

# All secret detections
cat scans/*/trufflehog/trufflehog-results.json | \
  jq '.results[] | {detector: .detector_name, verified: .verified, file: .source_metadata.filename}'
```

### Check Infrastructure Security (CNTR-K8-001360)

```bash
# Checkov security findings
cat scans/*/checkov/checkov-results.json | \
  jq '.results.failed_checks[] | {check_id: .check_id, check_name: .check_name, severity: .severity}'

# Kubernetes-specific issues
grep -i "kubernetes\|k8s\|pod\|deployment" scans/*/checkov/checkov-results.json
```

### Validate Dependency Security (ASDV-DV-000030)

```bash
# All vulnerable dependencies
cat scans/*/grype/grype-results.json | \
  jq '.matches[] | {package: .artifact.name, version: .artifact.version, vulnerability: .vulnerability.id, severity: .vulnerability.severity}'

# Group by severity
cat scans/*/grype/grype-results.json | \
  jq '[.matches[] | .vulnerability.severity] | group_by(.) | map({severity: .[0], count: length})'
```

### Check for EOL Software (ASDV-DV-000070)

```bash
# All EOL components
cat scans/*/xeol/xeol-results.json | \
  jq '.matches[] | {name: .artifact.name, version: .artifact.version, eol_date: .cycle.eolDate}'

# Already EOL (past end date)
cat scans/*/xeol/xeol-results.json | \
  jq --arg today "$(date +%Y-%m-%d)" '.matches[] | select(.cycle.eolDate < $today)'
```

### Verify Clean Malware Scan (ASDV-DV-000220)

```bash
# Check for infections
grep "Infected files:" scans/*/clamav/clamav-scan.log

# Verify clean status (should return 0)
grep -c "Infected files: 0" scans/*/clamav/clamav-scan.log
```

---

## Automated Evidence Collection Script

Save this as `scripts/shell/collect-stig-evidence.sh`:

```bash
#!/bin/bash
# Collect STIG Evidence from Latest Scan

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
SCANS_DIR="$PROJECT_ROOT/scans"

# Find latest scan
LATEST_SCAN=$(ls -t "$SCANS_DIR" | head -1)
SCAN_DIR="$SCANS_DIR/$LATEST_SCAN"
OUTPUT_DIR="$SCAN_DIR/stig-evidence"

mkdir -p "$OUTPUT_DIR"

echo "🔍 Collecting STIG Evidence from: $LATEST_SCAN"

# 1. Critical Vulnerabilities (ASDV-DV-000320)
echo "📋 Extracting Critical Vulnerabilities..."
cat "$SCAN_DIR/grype/grype-results.json" | \
  jq '.matches[] | select(.vulnerability.severity=="Critical")' \
  > "$OUTPUT_DIR/critical-vulnerabilities.json" 2>/dev/null || echo "[]" > "$OUTPUT_DIR/critical-vulnerabilities.json"

# 2. Secrets Detection (DKER-EE-005170)
echo "🔐 Extracting Secrets Findings..."
cat "$SCAN_DIR/trufflehog/trufflehog-results.json" | \
  jq '.results[]' \
  > "$OUTPUT_DIR/secrets-detected.json" 2>/dev/null || echo "[]" > "$OUTPUT_DIR/secrets-detected.json"

# 3. Infrastructure Security (Multiple STIGs)
echo "🏗️  Extracting Infrastructure Findings..."
cat "$SCAN_DIR/checkov/checkov-results.json" | \
  jq '.results.failed_checks[]' \
  > "$OUTPUT_DIR/infrastructure-findings.json" 2>/dev/null || echo "[]" > "$OUTPUT_DIR/infrastructure-findings.json"

# 4. EOL Software (ASDV-DV-000070)
echo "⏰ Extracting EOL Components..."
cat "$SCAN_DIR/xeol/xeol-results.json" | \
  jq '.matches[]' \
  > "$OUTPUT_DIR/eol-software.json" 2>/dev/null || echo "[]" > "$OUTPUT_DIR/eol-software.json"

# 5. Malware Scan (ASDV-DV-000220)
echo "🦠 Extracting Malware Scan Results..."
cp "$SCAN_DIR/clamav/clamav-scan.log" "$OUTPUT_DIR/malware-scan.log" 2>/dev/null || echo "No ClamAV scan found" > "$OUTPUT_DIR/malware-scan.log"

# 6. Container Security (DKER-EE-002140)
echo "🐳 Extracting Container Findings..."
cat "$SCAN_DIR/trivy/trivy-results.json" | \
  jq '.Results[] | .Vulnerabilities[]?' \
  > "$OUTPUT_DIR/container-vulnerabilities.json" 2>/dev/null || echo "[]" > "$OUTPUT_DIR/container-vulnerabilities.json"

# 7. SBOM for Compliance (DKER-EE-001010)
echo "📦 Copying SBOM..."
cp "$SCAN_DIR/sbom/sbom.json" "$OUTPUT_DIR/sbom.json" 2>/dev/null || echo "{}" > "$OUTPUT_DIR/sbom.json"

# 8. Summary Report
echo "📊 Generating Summary..."
cat > "$OUTPUT_DIR/stig-evidence-summary.txt" <<EOF
STIG Evidence Collection Summary
=================================
Scan ID: $LATEST_SCAN
Collection Date: $(date)

Files Generated:
- critical-vulnerabilities.json    (ASDV-DV-000320)
- secrets-detected.json            (DKER-EE-005170)
- infrastructure-findings.json     (CNTR-K8-*, CNTR-OS-*)
- eol-software.json                (ASDV-DV-000070)
- malware-scan.log                 (ASDV-DV-000220)
- container-vulnerabilities.json   (DKER-EE-002140)
- sbom.json                        (DKER-EE-001010)

Statistics:
- Critical Vulnerabilities: $(cat "$OUTPUT_DIR/critical-vulnerabilities.json" | jq '. | length')
- Secrets Detected: $(cat "$OUTPUT_DIR/secrets-detected.json" | jq '. | length')
- Infrastructure Issues: $(cat "$OUTPUT_DIR/infrastructure-findings.json" | jq '. | length')
- EOL Components: $(cat "$OUTPUT_DIR/eol-software.json" | jq '. | length')
- Container Vulnerabilities: $(cat "$OUTPUT_DIR/container-vulnerabilities.json" | jq '. | length')
- Malware Infections: $(grep "Infected files:" "$OUTPUT_DIR/malware-scan.log" | awk '{print $3}')

Dashboard: file://$SCAN_DIR/consolidated-reports/dashboards/security-dashboard.html
EOF

echo "✅ STIG Evidence collected at: $OUTPUT_DIR"
cat "$OUTPUT_DIR/stig-evidence-summary.txt"
```

Make it executable:
```bash
chmod +x scripts/shell/collect-stig-evidence.sh
```

Usage:
```bash
# After running a scan, collect STIG evidence
./scripts/shell/collect-stig-evidence.sh
```

---

## Manual STIG Validation Still Required

Epyon **cannot** automatically validate the following (requires manual process):

### Process & Documentation Controls
- **Organizational policies** (e.g., security training, incident response plans)
- **Change management procedures** (e.g., approval workflows, documentation)
- **Personnel security** (e.g., background checks, access reviews)
- **Physical security** (e.g., facility access, hardware controls)

### Runtime & Dynamic Testing
- **Dynamic application security testing (DAST)** - penetration testing, fuzzing
- **Runtime behavioral analysis** - monitoring application behavior in production
- **Network security testing** - firewall rules, network segmentation validation
- **Authentication/authorization testing** - session management, access control validation

### Configuration Management
- **Production configurations** - Epyon scans code/images, not live deployments
- **Operational procedures** - backup schedules, patching processes, monitoring
- **Third-party service validation** - cloud provider configurations, SaaS security

### Compliance Documentation
- **POA&M creation** - requires manual risk assessment and remediation planning
- **Authority to Operate (ATO) packages** - requires security team review
- **Control implementation statements** - narrative descriptions for each STIG control

---

## Best Practices for STIG Compliance with Epyon

### 1. Establish Baseline Scans

```bash
# Scan approved baseline images
./scripts/shell/run-baseline-scan.sh

# Document baseline as "known good" state
cp scans/baseline_*/consolidated-reports/consolidated-security-report.json \
   documentation/stig-baseline-approved.json
```

### 2. Continuous Scanning Schedule

```bash
# Daily scans during development
0 9 * * * cd /path/to/epyon && ./scripts/shell/run-target-security-scan.sh "/path/to/app" full

# Weekly baseline validation
0 0 * * 0 cd /path/to/epyon && ./scripts/shell/run-baseline-scan.sh
```

### 3. Quality Gate Integration

```bash
# Fail builds on critical vulnerabilities
./scripts/shell/check-severity-gate.sh "scans/latest"
CRITICAL_THRESHOLD=0 HIGH_THRESHOLD=10 ./scripts/shell/check-severity-gate.sh "scans/latest"
```

### 4. Evidence Archival

```bash
# Archive scan results for compliance audit trail
SCAN_DATE=$(date +%Y-%m-%d)
tar -czf "stig-evidence-$SCAN_DATE.tar.gz" scans/*/stig-evidence/
```

### 5. Remediation Tracking

```bash
# Track fixes across scans
SCAN1="scans/app_2026-02-01"
SCAN2="scans/app_2026-02-06"

# Compare critical findings
diff <(cat $SCAN1/stig-evidence/critical-vulnerabilities.json | jq -r '.[].vulnerability.id' | sort) \
     <(cat $SCAN2/stig-evidence/critical-vulnerabilities.json | jq -r '.[].vulnerability.id' | sort)
```

---

## Future STIG Enhancements (Roadmap)

As noted in the main README, full STIG compliance features are planned for future releases:

- **Automated STIG Checklist Generation** - Direct mapping to STIG control IDs
- **POA&M Integration** - Track findings as POA&M items with remediation plans
- **RMF Support** - Risk Management Framework documentation and categorization
- **Control Traceability Matrix** - Map scan findings to specific STIG controls
- **Compliance Dashboards** - STIG-specific reporting with pass/fail by control
- **Evidence Package Export** - ATO-ready documentation bundles

---

## Additional Resources

### STIG References
- **DISA STIG Library**: https://public.cyber.mil/stigs/
- **Application Security Development STIG**: https://public.cyber.mil/stigs/downloads/?_dl_facet_stigs=app-security
- **Container Platform STIG**: https://public.cyber.mil/stigs/downloads/?_dl_facet_stigs=container-platform
- **DevSecOps STIG**: https://public.cyber.mil/stigs/downloads/?_dl_facet_stigs=application-security-devsecops

### Epyon Documentation
- **Security Review**: [SECURITY_REVIEW_AND_TEST_COVERAGE.md](./SECURITY_REVIEW_AND_TEST_COVERAGE.md)
- **Scan Architecture**: [SCAN_DIRECTORY_ARCHITECTURE.md](./SCAN_DIRECTORY_ARCHITECTURE.md)
- **Offline Setup**: [OFFLINE_AIR_GAPPED_SETUP.md](./OFFLINE_AIR_GAPPED_SETUP.md)

---

## Support

For questions about STIG compliance with Epyon:
1. Review the [Security Review](./SECURITY_REVIEW_AND_TEST_COVERAGE.md) for security architecture
2. Check scan results in the interactive dashboard: `./scripts/shell/open-latest-dashboard.sh`
3. Use the evidence collection script: `./scripts/shell/collect-stig-evidence.sh`

**Note**: This guide provides technical evidence collection only. Formal STIG compliance requires security team review, documentation, and ATO approval processes beyond the scope of automated scanning tools.

---

**Document History:**
- **v1.0** (Feb 6, 2026): Initial STIG compliance guide created with control mappings for Application Security Development STIG, Container Platform STIG, Docker Enterprise STIG, DevSecOps STIG, and Red Hat OpenShift STIG
