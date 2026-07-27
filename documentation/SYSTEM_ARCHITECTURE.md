# Epyon System Architecture

## Overview

Epyon is a 16-layer DevSecOps security scanner designed for human-centered cybersecurity workflows. It orchestrates multiple security tools in a single run, produces comprehensive reports, and integrates with external systems like Jira and GitHub.

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          External Interfaces                            │
├─────────────────┬──────────────────┬──────────────────┬─────────────────┤
│ GitHub Actions  │  Jira Cloud      │  GitHub Issues   │  Webhook Sink   │
│  - Workflows    │  - Tickets       │  - Findings      │  - Barbatos     │
│  - Secrets      │  - Auto-close    │  - Tracking      │  - Real-time    │
└─────────────────┴──────────────────┴──────────────────┴─────────────────┘
                                    ▲
                                    │
┌───────────────────────────────────┴─────────────────────────────────────┐
│                           Core Components                                │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                           │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                    CLI Orchestrator Layer                        │   │
│  ├─────────────────────────────────────────────────────────────────┤   │
│  │  • epyon.sh (entry point)                                        │   │
│  │  • run-target-security-scan.sh (main orchestrator)               │   │
│  │  • Container runtime detection (Docker/Podman/nerdctl/Colima)    │   │
│  │  • Scan mode routing (quick/nightly/full/stig)                   │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                           │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │              16-Layer Security Scan Engine                       │   │
│  ├─────────────────────────────────────────────────────────────────┤   │
│  │  Layer 1:  SBOM Generation (Syft)                                │   │
│  │  Layer 2:  Secret Detection (TruffleHog)                         │   │
│  │  Layer 3:  Code Quality (SonarQube)                              │   │
│  │  Layer 4:  Malware Detection (ClamAV)                            │   │
│  │  Layer 5:  Helm Chart Build                                      │   │
│  │  Layer 6:  IaC Security (Checkov)                                │   │
│  │  Layer 7:  Container Security (Trivy)                            │   │
│  │  Layer 8:  Vulnerability Scanning (Grype)                        │   │
│  │  Layer 8.5: Direct Dependency Scanning (pip-audit)               │   │
│  │  Layer 9:  EOL Detection (Xeol)                                  │   │
│  │  Layer 10: Container Analysis (Anchore)                          │   │
│  │  Layer 11: API Discovery                                         │   │
│  │  Layer 11.6: Python Safety Check (Safety)                        │   │
│  │  Layer 12: LLM Security (Garak) [opt-in]                         │   │
│  │  Layer 13: STIG Compliance (AI)                                  │   │
│  │  Layer 14: Pickle Safety (picklescan)                            │   │
│  │  Layer 15: Model Card Compliance                                 │   │
│  │  Layer 16: Network Discovery (nmap)                              │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                           │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                  Consolidation & Reporting                       │   │
│  ├─────────────────────────────────────────────────────────────────┤   │
│  │  • generate-scan-findings-summary.sh (parse tool outputs)        │   │
│  │  • consolidate-security-reports.sh (HTML + Markdown)             │   │
│  │  • generate-dashboard.py (self-contained HTML)                   │   │
│  │  • embed-metrics-in-dashboard.sh (Chart.js injection)            │   │
│  │  • generate-trl-score.py (6D weighted score → TRL 1-9)           │   │
│  │  • generate-scan-manifest.sh (SHA-256 integrity)                 │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                           │
└───────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌───────────────────────────────────────────────────────────────────────┐
│                        Web UI & API Layer                              │
├────────────────────────────────────┬──────────────────────────────────┤
│         FastAPI Backend            │       Frontend (Vanilla JS)      │
│  ┌──────────────────────────────┐  │  ┌────────────────────────────┐ │
│  │ main.py (~2500 lines)        │  │  │ app.js (~7000+ lines)      │ │
│  │  • REST API endpoints        │  │  │  • Hash routing SPA        │ │
│  │  • Scan management           │  │  │  • Scan detail views       │ │
│  │  • Async job queue           │  │  │  • STIG history charts     │ │
│  ├──────────────────────────────┤  │  │  • Score card display      │ │
│  │ parsers.py                   │  │  │  • Findings tables         │ │
│  │  • Parse tool outputs        │  │  │  • Suppression badges      │ │
│  │  • Normalize findings        │  │  └────────────────────────────┘ │
│  │  • Apply suppression rules   │  │                                  │
│  ├──────────────────────────────┤  │  ┌────────────────────────────┐ │
│  │ jira_client.py               │  │  │ app.css                    │ │
│  │  • Ticket lifecycle mgmt     │  │  │  • Dark theme optimized    │ │
│  │  • Auto-close (always on)    │  │  │  • Responsive layout       │ │
│  │  • Fingerprint tracking      │  │  └────────────────────────────┘ │
│  ├──────────────────────────────┤  │                                  │
│  │ github_sync.py               │  │                                  │
│  │  • Metrics collection        │  │                                  │
│  │  • Issue creation/sync       │  │                                  │
│  └──────────────────────────────┘  │                                  │
└────────────────────────────────────┴──────────────────────────────────┘
                                    │
                                    ▼
┌───────────────────────────────────────────────────────────────────────┐
│                         Data Persistence Layer                         │
├───────────────────────────────────────────────────────────────────────┤
│  Scan Directories: scans/{app}_{YYYY-MM-DD_HH-MM-SS}/                 │
│    • Tool-specific JSON outputs                                        │
│    • security-findings-summary.json                                    │
│    • security-dashboard.html (self-contained deliverable)              │
│    • stig-findings.md, stig-results-{slug}.json                        │
│    • scan-manifest.json (integrity hash)                               │
│                                                                         │
│  Configuration:                                                         │
│    • .epyon-ignore.yml (suppression rules in target repo)              │
│    • configuration/stigs/*.cklb, *.xml (STIG baselines)                │
│    • configuration/approved-base-images.conf                           │
│    • configuration/monitored-apps.json                                 │
│                                                                         │
│  Web Data (web/data/):                                                 │
│    • jira-config.json (credentials, preferences)                       │
│    • jira-tickets.json (fingerprint → ticket map)                      │
│    • github-config.json                                                │
│    • ai-config.json (OpenAI endpoint)                                  │
└───────────────────────────────────────────────────────────────────────┘
```

## Component Details

### 1. CLI Orchestrator Layer

**Entry Point:** `epyon.sh`
- Container runtime detection and validation
- Version compatibility checks
- Delegates to `run-target-security-scan.sh`

**Main Orchestrator:** `scripts/shell/run-target-security-scan.sh`
- Scan mode routing (quick/nightly/full/stig)
- Layer execution with dependency management
- Error handling and recovery
- Webhook progress notifications
- Post-scan Jira reconciliation trigger

**Scan Scripts:** `scripts/shell/run-*.sh` and `scripts/shell/run-*.py`
- Standardized interface: `--target`, `--scan-dir`, `--app-name`
- Tool-specific configuration and execution
- JSON output normalization
- Graceful degradation on tool failures

### 2. Security Scan Engine

**Architecture:**
- **Modular design:** Each layer is independently skippable via `SKIP_<LAYER>=true`
- **Parallel execution:** Independent layers can run concurrently
- **Progressive enhancement:** Failed layers don't block subsequent layers
- **Scan mode matrix:** Different tool combinations for quick/nightly/full/stig

**Layer Categories:**
- **Supply Chain:** SBOM (Syft), Vulnerabilities (Grype, Trivy, Anchore, pip-audit), EOL (Xeol)
- **Code Security:** Secrets (TruffleHog), Code Quality (SonarQube), Malware (ClamAV)
- **Infrastructure:** IaC (Checkov), Container (Trivy), Helm, Network (nmap)
- **Compliance:** STIG (AI-powered), Model Cards, Pickle Safety
- **API/LLM:** API Discovery, Garak (opt-in)

### 3. STIG Compliance Engine

**Core Component:** `scripts/shell/run-stig-assessment.py`

**Assessment Flow:**
1. **Context Collection:**
   - Source code from target repository
   - Configuration files (YAML, JSON, properties)
   - Markdown documentation (COMPLIANCE.md, STIG.md, findings.md)
   - Current scan findings (security-findings-summary.json)
   - Suppression rules (.epyon-ignore.yml)

2. **STIG Detection:**
   - Auto-detect applicable STIGs from tech stack
   - Parse CKLB/XCCDF files from `configuration/stigs/`
   - Currently supported: ASD v6r4, Tomcat 9, Postgres 16, Database SRG, .NET 4.0

3. **AI Assessment:**
   - Per-control context window (top-5 most relevant files)
   - Batched API calls (10 controls per batch)
   - Confidence scoring (0-100)
   - Evidence collection with file/line references

4. **Freeze Logic:**
   - Controls with confidence ≥ 85 and status "Not a Finding" or "Not Applicable" → frozen
   - Frozen controls skip re-assessment in subsequent scans
   - Human overrides persist indefinitely

5. **Output:**
   - `stig-results-{slug}.json` (state tracking)
   - `stig-findings.md` (human-readable report)
   - Automatic PR creation in target repo via `create-stig-pr.sh`

**STIG Statuses:**
- `"Not a Finding"` — Control is satisfied
- `"Not Applicable"` — Control doesn't apply to this system
- `"Open"` — Control is not satisfied (default when in doubt)
- `"Not Reviewed"` — Runtime-only control with zero static indicators

### 4. Web UI & API

**Backend (FastAPI):**

**Endpoints:**
- `GET/POST /api/scans` — List scans, trigger new scans (async jobs)
- `GET /api/scans/{scan_id}` — Full parsed scan data
- `POST /api/scans/{scan_id}/scorecard` — Calculate TRL score
- `POST /api/scans/{scan_id}/executive-summary` — AI-generated summary
- `POST /api/applications/{name}/isso-summary` — ISSO compliance report
- `GET /api/stig/history` — Cross-scan STIG trend data
- `GET/POST /api/jira/config` — Jira credentials and preferences
- `POST /api/jira/sync/{app_name}` — Manual Jira reconciliation
- `GET/POST /api/github/config` — GitHub token and settings
- `POST /api/github/sync` — Sync GitHub metrics
- `GET/POST /api/ai/config` — OpenAI endpoint configuration
- `GET /api/metrics` — Aggregate metrics (MTTR, top CVEs, SLA compliance)
- `POST /api/export/summary-docx` — Export Word document

**Parser System (`parsers.py`):**
- Tool-specific parsers for all 16 layers
- Suppression rule application
- Fingerprint-based deduplication
- Source classification (container/code/iac/secret/eol)
- Severity normalization

**Jira Integration (`jira_client.py`):**
- Automatic ticket closure when findings are remediated (always enabled)
- Fingerprint-based tracking (stable across scans)
- Project-key isolation (prevent cross-project duplicates)
- Configurable ticket creation for new findings (opt-in)

**Frontend (Vanilla JS SPA):**
- Hash-based routing (`#/`, `#/scan/:id`, `#/stig`, `#/settings`)
- No framework dependencies
- Progressive rendering for large datasets
- Severity badges, source badges, suppression indicators
- Chart.js for STIG history trends and score cards

### 5. Integration Layer

**GitHub Actions:**
- **Reusable workflow:** `.github/workflows/epyon-scan.yml`
- **Caller template:** `.github/workflows/security-scan-template.yml`
- **Features:**
  - Automatic PR scans (quick mode by default)
  - Scheduled nightly scans
  - Manual workflow_dispatch with configurable scan modes
  - SBOM artifact support (skip Layer 1 if SBOM provided)
  - GitHub Issue creation with findings summary
  - Jira ticket creation/closure via `create-jira-tickets.sh`
  - Severity gate with configurable thresholds
  - STIG PR automation

**Jira Cloud:**
- **Shell script path:** `scripts/shell/create-jira-tickets.sh` (called from GitHub Actions)
- **Python API path:** `web/api/jira_client.py` (called from Web UI)
- **Ticket modes:**
  - `severity` — One ticket per severity tier (critical/high/medium/low)
  - `hybrid` — Severity parent + CVE children (max 50 per tier)
- **Auto-close:** Always enabled on both paths
  - Shell script: Closes when severity count = 0
  - Python API: Closes when finding fingerprint absent from current scan

**GitHub Issues:**
- Automatic issue creation for scan results
- Bidirectional linking between Jira and GitHub
- Issue deduplication via body fingerprinting
- Comment updates with new findings

**Webhooks:**
- Real-time progress notifications to external systems (e.g., Barbatos)
- HMAC-SHA256 signature validation
- Events: scan start, tool start, tool complete, scan complete
- Graceful degradation if webhook endpoint unavailable

### 6. Data Flow

**Scan Execution Flow:**
```
1. User triggers scan (CLI, Web UI, or GitHub Actions)
2. CLI orchestrator validates inputs and routes to scan mode
3. Security layers execute in sequence (with parallelization where safe)
4. Each layer writes JSON output to scan directory
5. Consolidation scripts parse and merge all tool outputs
6. Dashboard generator creates self-contained HTML deliverable
7. Web UI detects new scan and invalidates cache
8. Jira reconciliation compares current vs previous findings
9. Tickets are created for new findings (if enabled)
10. Tickets are closed for remediated findings (always)
11. GitHub issue updated with summary and links
12. Webhook notifies external systems of completion
```

**STIG Assessment Flow:**
```
1. STIG scan mode invoked (full scan includes STIG by default)
2. AI config validated (fail gracefully if missing)
3. Applicable STIGs auto-detected from target tech stack
4. Context collected (code, config, docs, findings, suppressions)
5. Per-control context window built (top-5 relevant files)
6. Frozen controls skipped (confidence ≥ 85, Not a Finding/Not Applicable)
7. Remaining controls assessed in batches of 10
8. Results merged with frozen state
9. Markdown findings written to scan directory
10. PR created/updated in target repo with stig-findings.md
```

**Web UI Data Path:**
```
Option A (shell-generated JSON):
  1. load_enriched_findings() reads security-findings-summary.json
  2. Suppression rules applied by shell script during consolidation
  3. Web UI displays pre-filtered findings

Option B (raw tool outputs):
  1. parse_scan_findings() calls tool-specific parsers
  2. Suppression rules applied in parsers.py
  3. Findings marked with suppressed=True flag
  4. Web UI displays with suppression badges
```

## Data Contracts

### Scan Directory Structure
```
scans/{app}_{YYYY-MM-DD_HH-MM-SS}/
├── sbom-*.json                         # Layer 1: Syft
├── trufflehog-results.json             # Layer 2: TruffleHog
├── sonarqube/                          # Layer 3: SonarQube
├── clamav-results.txt                  # Layer 4: ClamAV
├── helm-*.tgz                          # Layer 5: Helm
├── checkov-results.json                # Layer 6: Checkov
├── trivy-*.json                        # Layer 7: Trivy
├── grype-results.json                  # Layer 8: Grype
├── pip-audit-consolidated-results.json # Layer 8.5: pip-audit
├── xeol-results.json                   # Layer 9: Xeol
├── anchore-results.json                # Layer 10: Anchore
├── api-discovery-results.json          # Layer 11: API Discovery
├── safety-consolidated-results.json    # Layer 11.6: Safety
├── garak-results.json                  # Layer 12: Garak (opt-in)
├── stig-results-*.json                 # Layer 13: STIG
├── stig-findings.md                    # Layer 13: STIG (human-readable)
├── picklescan-results.json             # Layer 14: picklescan
├── model-card-compliance.json          # Layer 15: Model Cards
├── nmap-results.xml                    # Layer 16: nmap
├── security-findings-summary.json      # Consolidated findings
├── security-findings-filtered.json     # After suppression
├── security-dashboard.html             # Self-contained deliverable
├── scan-manifest.json                  # SHA-256 integrity hash
└── consolidated-reports/
    ├── dashboards/
    │   └── security-dashboard.html
    └── findings/
        ├── grype-findings.md
        ├── trivy-findings.md
        └── ...
```

### Key JSON Schemas

**security-findings-summary.json:**
```json
{
  "critical": [{
    "id": "CVE-2024-1234",
    "severity": "critical",
    "tool": "grype",
    "package": "pkg-name",
    "version": "1.0.0",
    "fix_version": "1.0.1",
    "description": "...",
    "references": ["https://..."],
    "suppressed": false
  }],
  "high": [...],
  "medium": [...],
  "low": [...],
  "suppressed_critical": 0,
  "suppressed_high": 6,
  "suppressed_medium": 0,
  "suppressed_low": 0
}
```

**stig-results-{slug}.json:**
```json
{
  "assessments": {
    "APSC-DV-000160": {
      "status": "Not a Finding",
      "evidence": "Source code repository uses GitHub branch protection...",
      "confidence": 90,
      "file_references": ["path/to/file.yml:25"],
      "frozen": true
    }
  },
  "token_usage": {
    "prompt_tokens": 12500,
    "completion_tokens": 3400
  }
}
```

**jira-tickets.json (fingerprint → ticket map):**
```json
{
  "abc123def456...": {
    "issue_key": "SEC-123",
    "app": "myapp",
    "project_key": "SEC",
    "finding_id": "CVE-2024-1234",
    "severity": "high",
    "tool": "grype",
    "created_at": "2026-07-15T12:00:00Z",
    "closed_at": null
  }
}
```

## Security Model

### Input Validation
- Path traversal prevention at all file system boundaries
- Regex validation for application names, scan IDs
- SSRF guard for user-supplied URLs (private IP blocklist)
- Content-type validation for API requests

### Secrets Management
- Never log API tokens or credentials
- Environment variables take precedence over config files in CI
- API tokens scoped narrowly (Jira: read+write issues only)
- GitHub tokens: read repo + write issues
- OpenAI tokens: inference only (no fine-tuning access)

### Sandboxing
- Shell scripts run in container sandbox by default
- Filesystem: read-only outside workspace and $TMPDIR
- Network: egress policy should be enforced by the runner/container runtime (no `requestAllowNetwork` flag is implemented in Epyon)
- Scan targets are untrusted — never execute code from target repos

### OWASP Top 10 Mitigations
- **A01 (Broken Access Control):** No authentication required (internal tool), but input validation at boundaries
- **A02 (Cryptographic Failures):** API tokens base64-encoded in transit, HMAC-SHA256 for webhooks
- **A03 (Injection):** Parameterized shell commands, JSON schema validation
- **A07 (SSRF):** Private IP blocklist for user-supplied URLs
- **A08 (Software/Data Integrity):** SHA-256 scan manifests for tamper detection

## Performance Characteristics

### Scan Duration (typical)
- **Quick mode:** ~3–5 minutes (Syft, TruffleHog, Trivy, Grype, pip-audit, Safety)
- **Nightly mode:** 20–40 minutes (all non-AI layers; STIG skipped unless explicitly enabled)
- **Full mode:** 30–60 minutes (all non-AI layers; STIG runs only when explicitly enabled)
- **STIG-only mode:** 10–20 minutes (Layer 13 only, depends on control count)

### Bottlenecks
- **SonarQube:** Can hang on large codebases (timeout: 30 minutes)
- **STIG AI assessment:** OpenAI API rate limits, context window constraints
- **Anchore:** Slow CVE database sync on first run
- **ClamAV:** Virus definition updates can be slow

### Scalability
- **Horizontal:** Multiple scan jobs can run in parallel (separate scan directories)
- **Vertical:** CPU-bound during tool execution, I/O-bound during consolidation
- **Web UI:** In-memory cache with TTL, invalidated on new scans
- **Jira/GitHub sync:** Batched API calls, exponential backoff on rate limits

## Deployment Topologies

### 1. GitHub Actions (CI/CD)
```
Repository → Workflow Trigger → Epyon Reusable Workflow
                                      ↓
                              Scan in Runner Container
                                      ↓
                              Findings → GitHub Issue
                                      ↓
                              Findings → Jira Tickets
                                      ↓
                              Dashboard → Artifact
```

### 2. Local Development
```
Developer Workstation → epyon.sh → Container Runtime
                                         ↓
                                    Scan Execution
                                         ↓
                                    scans/ directory
                                         ↓
                            Web UI (localhost:8056)
```

### 3. Centralized Scan Server
```
Cron/Scheduler → epyon.sh → Target Repos (cloned)
                                  ↓
                            scans/ directory
                                  ↓
                        Web UI (shared access)
                                  ↓
                        Jira/GitHub sync
```

## Extension Points

### Adding a New Security Layer
1. Create `scripts/shell/run-{tool}-scan.sh` with standard interface
2. Add tool to `run-target-security-scan.sh` orchestrator
3. Add parser function to `web/api/parsers.py`
4. Update `consolidate-security-reports.sh` to include new findings
5. Add tool to `SKIP_` environment variable list
6. Update scan mode matrix in `SCAN_MATRIX.md`
7. Add to `README.md` feature table

### Adding a New Integration
1. Create `web/api/{integration}_client.py` with async API methods
2. Add config endpoints to `web/api/main.py`
3. Add UI settings panel in `web/static/app.js`
4. Add environment variable support for CI contexts
5. Document in `documentation/` folder

### Custom STIG Baselines
1. Drop `.cklb` or XCCDF `.xml` files into `configuration/stigs/`
2. Files are auto-detected at runtime
3. No code changes required

## Monitoring & Observability

### Logs
- **CLI:** Color-coded console output (GREEN/YELLOW/RED)
- **Web API:** Uvicorn access logs + application logs
- **GitHub Actions:** Step summaries in `$GITHUB_STEP_SUMMARY`

### Metrics (Web UI `/api/metrics`)
- Total scans, scans by status, scans by application
- MTTR (Mean Time To Remediate) by severity
- Top CVEs across all scans
- SLA compliance (% scans meeting thresholds)
- STIG control pass/fail trends

### Webhooks (Real-time Progress)
- `scan.started` — Scan begins
- `tool.started` — Tool execution begins
- `tool.completed` — Tool execution completes
- `scan.completed` — Scan finishes
- HMAC-SHA256 signature in `X-Epyon-Signature` header

## Future Architecture Considerations

### Planned Enhancements
- **Async scan queue:** Replace in-process jobs with Celery/RQ for distributed execution
- **PostgreSQL backend:** Replace JSON files with relational database for better querying
- **GraphQL API:** Enable more flexible client queries
- **Scan diffs:** Visual comparison between consecutive scans
- **Policy-as-Code:** Codify severity gates, suppression rules, STIG mappings
- **Multi-tenant support:** Separate scan data by organization/team
- **Scan history pruning:** Automatic cleanup of old scans (currently manual)

### Performance Optimizations
- **Layer parallelization:** Run independent layers concurrently (Layer 1-6 in parallel)
- **Incremental scans:** Only re-scan changed files (Git diff-based)
- **STIG caching:** Reuse frozen controls across multiple scans of same codebase
- **Dashboard lazy loading:** Paginate large findings lists

---

**Document Version:** 1.0  
**Last Updated:** 2026-07-22  
**Maintainer:** Epyon Core Team
