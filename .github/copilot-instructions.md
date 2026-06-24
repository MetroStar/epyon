# Epyon — Copilot Instructions

Epyon is a 16-layer DevSecOps security scanner that installs a GitHub Actions workflow into target repositories. It is built for **human-centered cybersecurity workflows**: the tool must be as usable as it is secure.

## What Epyon Does

- Orchestrates 16 security tool layers in a single run (quick / nightly / full / stig modes)
- Produces a self-contained `security-dashboard.html` deliverable for stakeholders
- Provides a FastAPI-backed web UI for scan management, findings review, STIG history, and score card
- Pushes findings to Jira Cloud and GitHub Issues
- Tracks STIG compliance across scans with AI-generated evidence and freeze logic for human-verified controls

## Security Scan Layers

| # | Layer | Tool | Scan modes |
|---|-------|------|-----------|
| 1 | SBOM Generation | Syft (CycloneDX + SPDX) | quick, nightly, full |
| 2 | Secret Detection | TruffleHog | quick, nightly, full |
| 3 | Code Quality | SonarQube | nightly, full |
| 4 | Malware Detection | ClamAV | nightly, full |
| 5 | Helm Chart Build | Helm | nightly, full |
| 6 | IaC Security | Checkov | nightly, full |
| 7 | Container Security | Trivy | quick, nightly, full |
| 8 | Vulnerability Scanning | Grype | quick, nightly, full |
| 8.5 | Direct Dependency Scanning | pip-audit | quick, nightly, full, stig |
| 9 | EOL Detection | Xeol | nightly, full |
| 10 | Container Analysis | Anchore | nightly, full |
| 11 | API Discovery | Custom | nightly, full |
| 12 | LLM Security Probing | Garak | opt-in only (`RUN_GARAK=true`) |
| 13 | STIG Compliance | AI (OpenAI) | full, stig |
| 14 | Pickle Safety | picklescan | nightly, full |
| 15 | Model Card Compliance | Custom | nightly, full |
| 16 | Network Discovery | nmap/static | nightly, full |

Every layer can be skipped with `SKIP_<LAYERNAME>=true`. See `documentation/SCAN_MATRIX.md` for the full matrix.

## Architecture

| Component | Path | Notes |
|---|---|---|
| CLI / orchestration | `epyon.sh`, `scripts/shell/run-target-security-scan.sh` | Bash. Entry point is `epyon.sh`. Container-runtime-agnostic (Docker, Podman, nerdctl, Colima). |
| Scan scripts | `scripts/shell/run-*.sh`, `scripts/shell/run-*.py` | One script per tool. All accept `--target`, `--scan-dir`, `--app-name`. |
| STIG engine | `scripts/shell/run-stig-assessment.py` + `run-stig-scan.sh` | AI-powered static STIG assessment. Reads `stig-results-{slug}.json` for previous state. Auto-detects applicable STIGs from tech stack. Collects source code, config files, and **all markdown/JSON files** from target repo (including `findings.md`, `COMPLIANCE.md`, `STIG.md`) as context. Additionally reads **security findings** (`security-findings-summary.json`) and **suppression rules** (`.epyon-ignore.yml`) to inform vulnerability management and risk acceptance assessments. Freeze logic: controls with `confidence ≥ 85` and status `Not a Finding`/`Not Applicable` carry forward without re-assessment. After assessment, automatically creates/updates a PR with `stig-findings.md` in the target repo when running in CI with `GITHUB_TOKEN`. |
| STIG PR automation | `scripts/shell/create-stig-pr.sh` | Creates or updates a PR in the target repository with `stig-findings.md` when STIG assessment completes. Runs automatically after `run-stig-scan.sh`. Uses branch naming `stig-update-YYYY-MM-DD`, updates existing PR if open. Requires `GITHUB_TOKEN` or `GH_PAT`. Soft-fails without token — never blocks the scan. Skip with `SKIP_STIG_PR=true`. |
| STIG files | `configuration/stigs/` | Drop any `.cklb` or XCCDF `.xml` here — picked up automatically. Current: ASD v6r4, Tomcat 9, Postgres 16, Database SRG, .NET 4.0. |
| Ignore rules | `.epyon-ignore.yml` (in target repo) | Parsed by `scripts/shell/parse-epyon-ignore.sh`. Suppresses findings with expiration dates. |
| FastAPI backend | `web/api/main.py` | ~2500 lines. REST API for the SPA. `parsers.py` parses scan directories. `jira_client.py` handles Jira Cloud. `jobs.py` manages async scan jobs. `github_metrics.py` / `github_sync.py` handle GitHub signals. |
| SPA frontend | `web/static/app.js`, `web/static/app.css` | Vanilla JS, hash routing, no framework. ~7000+ lines. Primary views: `renderScanDetail`, `renderStaticScanDetail`. Helper functions `sevBadge`, `findingSourceBadge`, `sourcesBadges` defined near the top. |
| Score Card | `scripts/shell/generate-trl-score.py` | 6-dimensional weighted score: Security 30%, Supply Chain 20%, Code Quality 15%, Compliance 15%, Operational 10%, MOSA 10%. Maps to TRL 1–9. |
| Findings parser | `scripts/shell/generate-scan-findings-summary.sh` | Parses all tool outputs (Grype, Trivy, TruffleHog, ClamAV, Helm, SonarQube, Checkov, Xeol) and consolidates into `security-findings-summary.json` with critical/high/medium/low severity arrays. Handles tool-specific JSON structures and cross-tool deduplication. |
| Report consolidator | `scripts/shell/consolidate-security-reports.sh` | Consolidates all tool outputs into HTML dashboards and markdown reports. Calls `generate-scan-findings-summary.sh` then uses embedded Python to render tool findings to both HTML (for `security-dashboard.html`) and Markdown (for review). Creates `/consolidated-reports/dashboards/security-dashboard.html` and per-tool findings markdown files. |
| Dashboard generator | `scripts/shell/generate-dashboard.py` | Produces a self-contained `security-dashboard.html`. Embeds `app.css`, scan JSON as `window.__SCAN__`, and `app.js` verbatim. Inject point is `<!-- __EPYON_METRICS__ -->` marker before `</body>` — **never** match raw `</body>` tags (app.js contains them in template literals). |
| Metrics embedder | `scripts/shell/embed-metrics-in-dashboard.sh` | Injects Chart.js metrics into the dashboard at `<!-- __EPYON_METRICS__ -->` (falls back to last `</body>` in the file, never first). |
| Scan manifest | `scripts/shell/generate-scan-manifest.sh` | Produces `scan-manifest.json` with SHA-256 hash for scan integrity verification. |
| ISSO summary | `POST /api/applications/{name}/isso-summary` | AI-generated ISSO compliance report combining STIG controls, severity findings, and suppression data. |
| Tests | `tests/shell/*.bats` | 789 BATS tests across 50 files. Run with `./run-tests.sh`. |
| CI/CD | `.github/workflows/epyon-scan.yml` | Primary reusable workflow installed into target repos. |
| Baseline | `scripts/shell/run-baseline-scan.sh` | Scans DHI baseline images. Scheduled every 89 days. |

## Key Data Contracts

- **Scan directory**: `scans/{app}_{YYYY-MM-DD_HH-MM-SS}/` — all tool output goes here.
- **STIG state**: `stig-results-{slug}.json` → `{ "assessments": { "APSC-DV-XXXXXX": { "status", "evidence", "confidence" } }, "token_usage": {} }`. The markdown findings file written to the scan output directory is **output only** — never read back by the scanner. However, markdown and JSON files within the **target repository** (e.g., `findings.md`, `COMPLIANCE.md`, `STIG.md`) ARE collected as context to inform the assessment.
- **STIG context sources**: The AI assessment reads three additional context sources beyond source code: (1) **Security findings** from `security-findings-summary.json` in the current scan directory (CVEs, secrets, IaC issues, malware), (2) **Suppression rules** from `.epyon-ignore.yml` in the target repo (risk acceptances with justifications), (3) **All markdown/JSON** files in the target repo for existing documentation.
- **STIG statuses**: `"Not a Finding"` | `"Not Applicable"` | `"Open"` | `"Not Reviewed"`. `"Not Reviewed"` is reserved for runtime-only controls with zero static indicators — use `"Open"` when in doubt.
- **STIG split**: `stig_na` counts `"Not Applicable"` only; `stig_nr` counts `"Not Reviewed"` only. Never conflate them — they have different compliance meanings.
- **CVE source classification**: `type == "container_vulnerability"` or `tool == "anchore"` → container; `tool == "checkov"` → iac; `tool == "trufflehog"` → secret; `tool == "xeol"` → eol; otherwise → code.
- **Jira credentials**: `JIRA_BASE_URL`, `JIRA_USER_EMAIL`, `JIRA_API_TOKEN`, `JIRA_PROJECT_KEY` env vars take priority over `web/data/jira-config.json`. The `_from_env` flag passes through the API to the UI.
- **AI config**: `OPENAI_API_KEY` or self-hosted endpoint. SSRF guard enforced on any user-supplied base URL. Without a key, STIG controls are marked `Not Reviewed`.

## Web UI — FastAPI API Surface

Key endpoint groups (all under `/api/`):
- `GET /scans/{scan_id}` — full parsed scan data
- `POST /scans` — trigger a new scan (async job)
- `GET/POST /jira/config`, `POST /jira/sync/{app_name}` — Jira integration
- `GET/POST /github/config`, `POST /github/sync` — GitHub metrics sync
- `GET/POST /ai/config` — AI/OpenAI configuration
- `GET /stig/history` — cross-scan STIG trend data
- `POST /scans/{scan_id}/scorecard` — calculate TRL score card
- `POST /scans/{scan_id}/executive-summary`, `/technical-summary` — AI summaries
- `POST /applications/{name}/isso-summary` — ISSO compliance report
- `POST /export/summary-docx` — export summary as Word document
- `GET /metrics` — aggregate metrics with MTTR, top CVEs (with source classification), SLA compliance

## Security Requirements

- **Never expose secrets** in logs, API responses, or dashboard HTML. Scan dirs may contain `.env` files — the STIG engine explicitly skips `.env` (only `.env.example` / `.env.template` are safe to read).
- **Input validation at system boundaries**: validate all external inputs (scan directory paths, STIG file paths, API request bodies). Reject path traversal attempts.
- **SSRF guard**: any feature that fetches a user-supplied URL must validate the hostname against a private IP blocklist. Do not follow redirects to private/loopback addresses.
- **Jira API tokens** are write-capable — scope them narrowly, never log them, always load from env vars in CI contexts.
- **OWASP Top 10**: treat every FastAPI endpoint as a trust boundary. Validate content types and avoid reflecting unsanitized user input.

## Usability Principles

- **Human-readable output first**: every scan produces a markdown findings file alongside the JSON. The markdown is the artifact a human reviewer reads.
- **Progressive disclosure**: the web UI shows severity badges, source badges (📦 Container / 💻 Code / 🔧 IaC / 🔑 Secret / ⏱ EOL), and STIG status counts without requiring the user to open raw JSON.
- **Don't break the dashboard**: `security-dashboard.html` is a self-contained deliverable shared with stakeholders. Avoid changes that could silently corrupt the embedded JS or inject `<script>` tags into the middle of the app.js template literal.
- **Confidence scores are load-bearing**: the STIG freeze logic relies on `confidence ≥ 85`. Never silently zero out confidence values; if a control can't be assessed, use a low non-zero value and status `Open`.
- **Manual overrides must persist**: when a human marks a STIG control as `Not a Finding` in the JSON with `confidence ≥ 85`, the next scan must freeze it. Don't overwrite human-reviewed findings with AI re-assessments.
- **Per-control context**: `build_code_context_for_batch` guarantees each control gets its top-5 most-relevant files in the context window regardless of what other controls in the batch need. Don't regress to the combined-keyword approach.

## Code Conventions

- **Shell scripts**: `set -euo pipefail` at the top. Use `[[ ]]` for conditionals. Colour output with `GREEN`/`YELLOW`/`RED` variables already defined at each script's top. All scan scripts accept `--target`, `--scan-dir`, and `--app-name` in a consistent pattern.
- **Python (scripts)**: stdlib + `openai` only in scan scripts — no heavy dependencies. Type-annotate function signatures. Use `Path` over string concatenation for file paths.
- **Python (web/api)**: FastAPI conventions. Pydantic models for request/response schemas. Async where I/O-bound.
- **JavaScript (app.js)**: no bundler, no framework. Helper functions (`sevBadge`, `findingSourceBadge`, `sourcesBadges`) are defined near the top. Keep rendering logic in the `render*` functions. Do not introduce framework dependencies.
- **Commit style**: conventional commits (`feat:`, `fix:`, `docs:`, `chore:`).

## Releases & Versioning

Every change that ships must update three files in the same commit:

1. **`VERSION`** — single line, semver (`MAJOR.MINOR.PATCH`):
   - `PATCH` — bug fixes, documentation, internal refactors
   - `MINOR` — new features, backward-compatible changes
   - `MAJOR` — breaking changes to the CLI, scan output schema, or workflow contract

2. **`CHANGELOG.md`** — [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) format. Add a new `## [X.Y.Z] - YYYY-MM-DD` section with `### Added`, `### Changed`, and/or `### Fixed` subsections. Never edit past entries.

3. **`README.md`** — update any section that references the changed behaviour (feature table, usage examples, CLI flags, scan layers list, config options). Do not rewrite sections that are still accurate.

## Build & Test

```bash
# Run all BATS shell tests
./run-tests.sh

# Run a single test file
bats tests/shell/test-run-trivy-scan.bats

# Start the web UI (dev — hot reload)
cd web && pip install -q -r api/requirements.txt
python3 -m uvicorn api.main:app --host 127.0.0.1 --port 8000 --app-dir . --reload

# Run a full scan against a local target
./epyon.sh --target /path/to/app --app-name myapp

# Run STIG assessment only
python3 scripts/shell/run-stig-assessment.py \
  --stigs-dir configuration/stigs \
  --target /path/to/app \
  --scan-dir scans/myapp_$(date +%Y-%m-%d_%H-%M-%S) \
  --app-name myapp

# Generate a self-contained dashboard from an existing scan
python3 scripts/shell/generate-dashboard.py scans/myapp_2026-06-09_12-00-00
```

See `documentation/` for extended guides (STIG, scan matrix, ignore rules, deployment, ISSO).
