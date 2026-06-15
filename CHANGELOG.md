# Changelog

All notable changes to the EPYON Security Scanner will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.6.7] - 2026-06-15

### Changed
- **GitHub Issues alerts: critical-only** — The `Create Scan Notification Issues` workflow step now creates/updates issues only for **critical** severity findings. High, medium, and low findings no longer generate GitHub issues, reducing inbox noise for repository watchers. The step condition was also tightened to skip the step entirely when the critical count is zero. Updated the `create_github_issue` input description to reflect the new behaviour.

## [3.6.6] - 2026-06-10

### Fixed
- **Jira CVE tickets: required custom fields** — Jira projects that enforce required custom fields (e.g. `customfield_12709` “Definition of Done”) rejected all CVE child tickets with HTTP 400. Added a fallback retry that detects `errors` containing `customfield_*` keys, builds a merged payload with ADF paragraph placeholders for rich-text fields and plain-string placeholders for others, and retries creation. Works generically for any number of required custom fields without board-specific configuration.

## [3.6.5] - 2026-06-10

### Fixed
- **Jira CVE tickets: garbage parent key from cleared stale marker** — `clear_jira_key_in_github` was printing its status message (`"📎 Cleared Jira key..."`) to stdout. Because it was called inside `find_existing_jira_ticket` (a stdout-capture context), that string was returned as the parent key. Every child CVE ticket was then sent with `parent: {key: "📎 Cleared Jira key..."}`, causing an unconditional 400 `errors.parent` rejection. Fixed by redirecting all `clear_jira_key_in_github` output to stderr.
- **Jira CVE tickets: priority field rejection** — added a fallback retry that strips the `priority` field when Jira returns 400 `errors.priority`, matching the existing `parent` and `issuetype` fallback pattern.

## [3.6.4] - 2026-06-10

### Fixed
- **Jira CVE child tickets: invalid issue type** — the workflow hardcoded `CVE_ISSUE_TYPE: 'Subtask'` as the fallback, causing all CVE child-ticket creation attempts to fail with HTTP 400 `"Specify a valid issue type"` on boards where `Subtask` is not a valid independent issue type. Changed the workflow fallback to `'Task'` (near-universally available). Added a preflight validation at the start of `create_cve_tickets` that queries `GET /rest/api/3/project/{PROJECT_KEY}` to verify the configured type is valid and auto-selects the best available alternative (`Task → Story → Bug → ...`) when it is not, so the script self-heals without needing a manual `JIRA_CVE_ISSUE_TYPE` override. Result is cached for the run to avoid redundant API calls.

## [3.6.3] - 2026-06-10

### Fixed
- **Jira duplicate tickets — race condition** — the automatic post-scan hook and the manual `/api/jira/sync` endpoint both called `read_ticket_map()` independently; if they ran concurrently (e.g. scan completes while user clicks Sync) both would see the same stale map, create tickets for the same findings, and the second write would overwrite the first’s entries. Added `asyncio.Lock`-protected `reconcile_and_save()` in `jira_client.py`; both callers now use it, eliminating the TOCTOU window.
- **Jira duplicate tickets — fingerprint instability** — `finding_fingerprint` included raw absolute `target` and `package` paths (e.g. `/tmp/clone-abc123/terraform/main.tf`) reported by Checkov, ClamAV, and TruffleHog. These paths contain the temp clone directory which changes every scan, producing a new fingerprint — and a new Jira ticket — for the same finding on every run. Added `_norm_path()` to reduce absolute paths to their last two components (`terraform/main.tf`) before hashing, making fingerprints stable across scans.

## [3.6.2] - 2026-06-10

### Fixed
- **STIG mode: skip Docker image pulls** — `Pull Security Tool Images` step now has `if: inputs.scan_mode != 'stig'`; in stig mode only Layer 13 (Python-based STIG assessment) runs so pulling grype, trivy, trufflehog, syft, clamav, checkov, and xeol was pure waste (~3–4 min and several GB per run)
- **STIG token overflow: drop manifest on last retry** — `_MAX_MANIFEST_LINES` reduced 400 → 150 (≈ 2 300 tokens); `_MAX_BATCH_RETRIES` increased 2 → 3; third retry drops the repo manifest entirely and restores the full code budget, unblocking batches where the manifest alone exceeded the 128 K context window

## [3.6.1] - 2026-06-09

### Fixed
- **STIG freeze logic** — human-locked controls (`locked_by_human=True`) are now preserved across scans regardless of status or confidence, preventing the Web UI lock badge from disappearing on the next scan run

## [3.6.0] - 2026-06-09

### Added
- **STIG compliance (APSC-DV-001600)** — `Content-Security-Policy` header on all responses via `_SecurityHeadersMiddleware`; restricts default sources to `'self'` with `'unsafe-inline'` allowed pending JS refactor
- **STIG compliance (APSC-DV-001670)** — `Referrer-Policy: strict-origin-when-cross-origin` header
- **STIG compliance (APSC-DV-000530 / Permissions-Policy)** — `Permissions-Policy` header blocking geolocation, microphone, camera, payment, and USB access
- **STIG compliance (APSC-DV-002360)** — CORS restricted from wildcard `*` to `localhost` by default; configurable via `EPYON_ALLOWED_ORIGINS` env var
- **STIG compliance (APSC-DV-000070 / APSC-DV-000080)** — 15-minute inactivity timeout in the web UI with 60-second warning banner and expired session modal
- **STIG compliance (APSC-DV-002390)** — Global FastAPI exception handler returns generic 500 message; internal error details are no longer reflected to clients
- **Audit logging** — All sensitive operations (scan trigger, scan/application delete, AI config change, Jira config change) are written to `web/data/audit.log` with timestamp, action, and client IP
- `Cache-Control: no-store` and `Pragma: no-cache` on all `/api/` responses to prevent caching of security-sensitive data (APSC-DV-001630)
- `X-XSS-Protection: 0` header to disable legacy browser XSS filter (modern browsers only)

### Changed
- `_sec_headers()` helper now sets the full header suite (previously only `X-Content-Type-Options` and `X-Frame-Options`)



### Added
- Version control system with VERSION file
- Version display in security dashboard footer
- Version display in consolidated reports
- SonarQube GitHub secrets support with .env.sonar fallback
- Suppressed findings display on security dashboard
- Vulnerability summary in GitHub Actions output

### Changed
- Reordered workflow steps: severity gate now runs before dashboard generation
- Removed duplicate vulnerability summary from GitHub Actions (kept severity gate output only)
- Removed "Next Steps" section from executive summary

### Fixed
- Invalid cron expression in baseline-scan workflow
- Missing find-scan step ID in baseline workflow
- ClamAV virus detection already counted as CRITICAL (verified)

## [3.1.0] - 2026-05-08

### Added
- **Layer 14 — Pickle/Serialization Safety** (`run-picklescan.sh`): scans ML model repositories for malicious pickle opcodes in `.pkl`, `.pt`, `.pth`, `.bin`, `.ckpt`, `.npy`, `.npz`, `.joblib`, `.h5`, and `.hdf5` files using `picklescan`. Auto-installs `picklescan` via pip when missing. Outputs normalized `picklescan/picklescan-results.json` with file count, flagged count, infected file list, and per-finding detail. Exits non-zero when infected files are found.
- **Layer 15 — Model Card Compliance** (`run-modelcard-check.sh`): validates HuggingFace-style model cards (`README.md` / `MODEL_CARD.md`) against 10 documentation standards covering required sections (Model Details, Intended Use, Limitations, Training Data, Bias/Risks, Evaluation), YAML frontmatter fields (license, language, tags), and safetensors format recommendation. Uses flexible regex patterns to handle diverse real-world card conventions. Outputs `modelcard/modelcard-results.json`.
- **`scan-huggingface.yml` GitHub Actions workflow**: dedicated entry-point for scanning HuggingFace model, Space, and dataset repositories. Accepts `hf_repo` (e.g. `mistralai/Mistral-7B`), `hf_type` (model/space/dataset), `run_garak`, and `garak_probes` inputs. Resolves HuggingFace URLs automatically by type and delegates to `epyon-scan.yml` with `scan_mode=huggingface`.
- **`huggingface` scan mode**: new orchestration mode in `run-epyon-scan-ci.sh` that enables Layers 14–15 by default alongside standard layers 1–11. Added to all workflow scan mode dropdowns including `scan-public-repo.yml`.
- **STIG control confidence scoring**: `run-stig-assessment.py` now generates an AI confidence score (0–100) per STIG control based on evidence quality, specificity, and certainty. Scores are stored in results JSON, appended to `.md` and `.cklb` findings output, and passed through the `stig-data` API endpoint.
- **HF scan result cards in web UI** (`app.js`): scan detail view renders `buildPicklescanCard()` and `buildModelCardCard()` — dedicated result cards with stat counters, status badges, and per-finding detail rows for the two new layers.
- **`hfStatusBadge()` in scan history rows**: HF-specific status indicators (🥒 pickle safety, 📋 model card compliance) appear inline in the scan timeline alongside severity badges.
- **Scan type auto-inference for HuggingFace scans** (`parsers.py`): `load_scan()` now sets `scan_type = "huggingface"` when `picklescan/` or `modelcard/` directories are present and no explicit `scan-metadata.json` exists.
- **`parse_picklescan_dir()` and `parse_modelcard_dir()` parsers** (`parsers.py`): read and normalize Layer 14/15 result JSON into the unified scan data structure returned by `/api/scans/{scan_id}`.
- **Scan info panel on Run Scan page**: two-column layout with a dynamic right panel showing which layers run for the selected scan mode, including API key notices for AI-powered layers (STIG, Garak).
- **Scan type labels**: `scanTypeLabel()` maps internal type keys to human-readable display names ("Hugging Face scan", "STIG scan", etc.) across all scan list and detail views.

### Changed
- `_VALID_SCAN_TYPES` in `web/api/main.py` extended with `"huggingface"`.
- Model card section matching patterns broadened to handle real-world HuggingFace README conventions (e.g. "Key Features" → model-details, "Usage" / "Inference" → intended-use, "Benchmarks" → evaluation).
- `limitations` severity downgraded from `high` to `medium`; `training-data` from `medium` to `low` to better reflect real-world card completeness norms.
- STIG viewer ID column now shows `group_id` (V-XXXXXX format) instead of `vuln_id` (APSC-DV-XXXXXX) for easier cross-reference against published STIGs.

## [Unreleased]

### Fixed
- **Self-hosted / OpenAI-compatible endpoints now work without an OpenAI key** —
  the AI summary and STIG-triage features previously failed with
  "OpenAI API key not configured" whenever `OPENAI_API_KEY` was empty, even when
  `OPENAI_BASE_URL` pointed at a keyless local backend (Ollama, vLLM, LocalAI,
  an in-cluster AI gateway). `get_api_key()` now falls back to a non-secret
  placeholder when a non-OpenAI base URL is configured; a real `api.openai.com`
  endpoint still requires a user-supplied key.
- **Custom `OPENAI_BASE_URL` from the Settings UI is now honored** — the OpenAI
  SDK only auto-reads the base URL from the environment, so a value saved in
  Settings was silently ignored. The resolved base URL is now passed explicitly
  to every `AsyncOpenAI` client.
- **ISSO summaries honor the configured model** — `generate_global_isso_summary`
  and `generate_app_isso_summary` hard-coded `gpt-4o-mini` instead of resolving
  the model via `get_model()`, so they failed against self-hosted models
  (e.g. `gemma4:26b`) while the executive/technical summaries succeeded.

### Changed
- **AI config API accepts self-hosted setups** — `POST /api/ai/config` now
  accepts a `base_url` (http:// allowed for in-cluster endpoints) and arbitrary
  model ids (e.g. `gemma4:26b`, `llama3.1:8b`) instead of only a fixed OpenAI
  model allowlist, and no longer rejects non-`sk-` API tokens. `GET /api/ai/config`
  surfaces the configured and effective base URL.

## [3.5.0] - 2026-06-03

### Added
- **Quick-scan CI performance** — `pull_request` events now automatically run in `quick` mode even when the caller workflow specifies `full`, cutting scan time from >10 min back to <4 min. Applies to `epyon-scan.yml` and `scan-private-repo.yml`.
- **PR trigger in `scan-private-repo.yml`** — `pull_request` event added with automatic quick-mode downgrade; includes a `security-scan-pr` job that runs the quick gate on every PR.
- **`quick` mode skips for CI** — The following steps are now skipped in quick mode to eliminate unnecessary overhead: NVD enrichment step, checkov and xeol image pre-pulls, `openai` pip install.
- **`SKIP_CLAMAV=true` in quick mode** — ClamAV is automatically bypassed in quick scans, consistent with the existing quick-mode skip list.
- **GitHub signals tracking** (`web/api/github_metrics.py`) — New API module that fetches PR merge history, open issues, and contributor activity from the GitHub API. Persisted to `web/data/github-signals-history.json` for trend analysis.
- **GitHub signals frontend** — Metrics page gains a GitHub Signals card showing PRs merged to primary branch, open security issues, and a contributor activity sparkline. Clicking a bar navigates to that app's scan history.
- **Merges-to-main metrics** — Metrics page now tracks and displays PR merges to the configured primary branch with filter options and a "Primary Branch" rename from "main" for accuracy.
- **SLA compliance, risk trends, and suppression rate cards** — Three new metric cards added to the Metrics dashboard.
- **ISSO compliance summary endpoint** (`POST /api/scans/{scan_id}/isso-summary`) — Generates a per-application ISSO compliance summary combining STIG controls, severity findings, and suppression data. Integrated into the frontend and the summary document export flow.
- **Summary document export** — New export button on scan detail pages produces a structured Markdown/PDF-ready summary document embedding AI summaries, metrics, and ISSO compliance data.
- **`OPENAI_MODEL` env variable honored in web UI** — AI summary generation now reads `OPENAI_MODEL` from the environment; the AI/Config model field in the UI is display-only and shows the active model rather than overriding it.
- **Interactive dashboard generation script** (`scripts/shell/generate-dashboard.py`) — Python-based dashboard generator that produces filterable, sortable HTML dashboards from raw scan JSON.
- **`cleanup-scripts.sh`** — New utility to purge scan directories older than a configurable retention period (default 30 days).
- **Test coverage scanner** (`run-test-coverage-scan.sh`) — Detects and runs test frameworks (Jest, pytest, Go test, Cargo test) in the target repo and produces a normalized coverage JSON. Includes a gate check script that fails CI when coverage drops below threshold.
- **Trivy vulnerability scanner auto-discovery** — `run-trivy-scan.sh` now auto-detects base images from Dockerfiles in the target repo and runs targeted image scans without manual configuration.
- **Executive and technical summary sections in dashboard** — The generated HTML dashboard now includes a collapsible executive summary (one-paragraph risk posture) and a technical summary (tool-by-tool breakdown) powered by OpenAI when `OPENAI_API_KEY` is set.
- **CVSS/KEV enrichment metadata banner** — NVD enrichment cards replaced with inline CVSS score and KEV flag per finding, plus an enrichment metadata banner showing enrichment coverage percentage.
- **ISSO compliance summary in export** — Summary document export now embeds the ISSO compliance table alongside severity findings for audit-ready output.
- **STIG applicability improvements** — `run-stig-assessment.py` now correctly infers applicability for Kubernetes, Nginx, Redis, and Node.js targets; unknown STIG types default to skip rather than run.
- **`scan-matrix.md` documentation** — New document describing which scan layers run under each scan mode (quick, full, nightly, stig, huggingface).
- **`nightly` scan mode** — New orchestration mode that runs Layers 1–12 on a schedule without STIG (Layer 13), allowing full security coverage without the AI-gated STIG assessment.
- **npm package support** (`package.json`, `bin/prepare.js`, `bin/install.js`) — Epyon can now be installed via `npm install github:MetroStar/epyon --save-dev`; postinstall automatically writes `scan-private-repo.yml` into the consumer project.
- **Scan type inference fallback** — `parsers.py` and the web UI now infer `scan_type` from directory contents (presence of `picklescan/`, `modelcard/`, STIG dirs) when `scan-metadata.json` is absent or missing the `scan_type` key.
- **30-day metrics trend in dashboard** — `embed-metrics-in-dashboard.sh` now embeds a 30-day rolling window trend instead of an all-time window when the scan mode is `full` or `nightly`.

### Changed
- **`scan-private-repo.yml` renamed** — Workflow files follow a consistent naming convention; internal step references updated.
- **NVD enrichment conditional** — Enrichment step now uses `if: always() && inputs.scan_mode != 'quick'` so it is skipped in quick mode without blocking downstream steps.
- **Scan mode auto-downgrade logic** — `SCAN_MODE` env var in `epyon-scan.yml` automatically coerces `full` → `quick` for `pull_request` event triggers.
- **Dashboard metrics default to 30-day window** — Previous default was all-time; switched to a rolling 30-day window for higher signal-to-noise on Metrics page charts.
- **Parallel GitHub artifact download** — `embed-metrics-in-dashboard.sh` now downloads metrics artifacts in parallel batches instead of serially, reducing dashboard generation time for repos with many scans.
- **STIG selection workflow diagrams updated** — Both `.drawio` diagrams restructured with improved layout and new assessment steps reflecting the updated applicability logic.

### Fixed
- **`.epyon-ignore.yml` tool suppression not respected in severity gate** — `check-severity-gate.sh` and the Apply Suppression Rules block in `run-epyon-scan-ci.sh` previously only looked for `.epyon-ignore.yml` at `$TARGET_DIR`. When the target repo is checked out to `$GITHUB_WORKSPACE` (caller workflow layout), the file was not found and the ignore cache remained empty. Both scripts now probe multiple candidate paths (`$TARGET_DIR`, `$GITHUB_WORKSPACE`, script parent dir) in order, logging exactly which path was used. Tool-level suppressions (e.g. `type: tool, value: anchore`) now correctly zero out the corresponding findings from the severity gate.
- **Quick scan regression (>10 min)** — Four unnecessary operations were running in quick mode: NVD enrichment (slow network call), checkov/xeol Docker image pulls, openai pip install, and ClamAV. All four now skip in quick mode.
- **PR events running full scans** — `scan-private-repo.yml` `push` trigger was matching PR merge commits on protected branches, causing full scans where quick scans were expected. Fixed by adding an explicit `pull_request` trigger with auto-quick-mode.
- **STIG source file context budget overflow** — Files exceeding the per-file token budget were truncated without notification. Added explicit truncation logging and adjusted the context budget allocation to prefer more files at lower per-file limits over fewer files at higher limits.
- **OpenAI model env not honored** — AI summary endpoint was always using the hardcoded default model regardless of `OPENAI_MODEL` env var.



### Added
- **Security Score Card system**: 6-dimensional weighted scoring framework evaluating Security (30%), Supply Chain (20%), Code Quality (15%), Compliance (15%), Operational (10%), and MOSA (10%) dimensions. Maps 0-100 weighted scores to DoD/NASA TRL levels 1-9 and letter grades (A+ through F).
- **Score Card generation script** (`generate-trl-score.py`): 591-line Python engine that reads 15+ scan output files, calculates dimension scores with evidence-based logic, and outputs `trl-assessment.json`. Includes 4 weight profiles: DEFAULT (web apps), ML (ML models), STIG (compliance-focused), QUICK (fast scan subset).
- **Score Card Web UI integration**: Auto-generates on scan detail page load via POST `/api/scans/{scan_id}/scorecard` endpoint. Renders collapsible card with overall grade, TRL level, weighted score, and 6 clickable dimension cards showing individual scores and progress bars.
- **Score Card dimension modals**: Click any dimension card to open detailed modal with large score display, progress bar, weight percentage, and full breakdown of all contributing metrics and their values.
- **Score Card CI integration**: Added to `run-epyon-scan-ci.sh` after dashboard generation step. Automatically produces `trl-assessment.json` in every CI scan output directory.
- **23 BATS tests for Score Card**: Full test coverage in `test-generate-trl-score.bats` validating shebang, CLI args, dimension scoring functions, JSON output structure, TRL range (1-9), score range (0-100), and graceful handling of missing files.
- **STIG history evidence tracking in Web UI**: STIG History & MTTR tab now displays AI-generated evidence explaining why each control status was assigned.
  - **Evidence tooltips**: Hover over matrix cells to see tooltip with status, confidence level, and evidence text (truncated to 200 chars)
  - **Change indicators**: 🔄 emoji appears on matrix cells when evidence changed from previous scan
  - **Visual highlighting**: Changed cells highlighted with blue border and glow effect (`.evidence-changed` CSS class)
  - **Detailed timeline table**: Control detail drawer shows 4-column table (Date | Status | Confidence | Evidence/Reasoning) with full evidence text and line breaks preserved
  - **Evidence change detection**: Timeline rows highlighted when evidence differs from previous scan
- **STIG status change validation**: AI assessments now validate status changes against previous scan results, requiring concrete, file-cited evidence for any status change.
  - **Previous scan lookup** (`find_previous_scan_dir()`, `load_previous_stig_results()`): Automatically finds most recent previous scan for the same app and loads STIG results
  - **Enhanced SYSTEM_PROMPT**: Added STEP 5 validation rules requiring strong evidence for status changes; AI must keep previous status unless new code/config files, specific file modifications, or architectural changes are found
  - **`previous_status` in API calls**: Each control sent to OpenAI includes its previous status; AI must justify any deviation with specific repository artifacts
  - **Environment-aware behavior**: Web UI/local scans automatically load previous results and validate changes; GitHub Actions CI treats all assessments as fresh (scans/ directory not persisted)
  - **Logging**: Clear messages indicate whether previous assessments were loaded ("Loaded X previous assessments from {scan_dir}") or not found ("No previous scan found — all controls assessed fresh")
- **Timeline newest-first sorting**: STIG control history timeline now displays most recent scans at the top (descending chronological order) for easier review of latest changes.

### Changed
- **Evidence-based Code Quality scoring**: Changed from penalty-based (100 - deductions) to evidence-based (0 + earned points). Tools that don't run now contribute 0 points instead of 90, fixing the bug where code quality showed 90% when no tools executed.
- **Score Card placement**: Positioned as collapsible section above "Tools Analyzed" on scan detail page, matching the visual hierarchy of other scan sections.
- **Progress bar styling**: Increased height from 6px to 8px, added margin-top: 8px, and background color for better visibility of score progress.
- **Dimension card interactivity**: Added hover effects (lift + shadow) and cursor:pointer to indicate clickability.
- **STIG timeline sort order**: Changed from ascending (oldest first) to descending (newest first) with `b.date.localeCompare(a.date)`.
- **STIG evidence change comparison logic**: Updated to compare each entry with the next (older) entry in the array after sort reversal.
- **`run-stig-assessment.py` documentation**: Added comprehensive "Status Change Validation" section explaining behavior in Web UI vs CI environments and listing acceptable/unacceptable reasons for status changes.

### Fixed
- **Missing --pass CSS variable**: Added `--pass: #3fb950` to `:root` in app.css, fixing Score Card dimension cards that referenced undefined variable.
- **SBOM detection in Score Card**: Fixed fallback logic to check both `filesystem.cyclonedx.json` (period) and `filesystem-cyclonedx.json` (hyphen) naming conventions.
- **Garak parsing robustness**: Added `isinstance()` checks for dict/list validation to handle varying Garak output structures.
- **Score Card weight display**: Fixed dimension cards showing 0% by changing from `d.weight * 100` to `(weights[key] || 0) * 100`.
- **Dimension modal JSON errors**: Stored dimension data in global `window._scorecardDimensions` object instead of inline JSON in onclick attributes, preventing parsing errors.
- **SonarQube graceful skip**: Made SONAR_TOKEN optional; when missing, script prints INFO messages, creates minimal output with `status: "skipped"`, and exits 0 instead of failing.
- **STIG history API timeline data**: Added `evidence` and `confidence` fields to each timeline entry, including gap-filled "Not Reviewed" entries with appropriate fallback evidence.

## [3.3.0] - 2026-05-15

### Added
- **Metrics page — MTTR card**: Mean Time to Remediate displayed beside Fix Rate donut; shows overall average in days, "N/A" when scan history is insufficient, and a fastest-remediating app pill. `mttr_days` and `fastest_remediator` fields added to `/api/metrics` response.
- **Metrics page — stacked bar vulnerability trend chart**: replaces the previous line chart; bars broken down by Critical / High / Medium / Low severity; hover tooltip shows app name, date, and per-severity counts; clicking a bar navigates to that application's detail page.
- **Metrics page — Findings by Tool hover + click**: mousing over a bar in the horizontal tool chart reveals the top contributing app; clicking navigates to that app's detail page. `top_app` field added to each `by_tool` entry in the `/api/metrics` response.
- **Metrics page — collapsible Top CVEs table**: collapsed by default; sortable by CVE ID, severity, count, and affected-apps count.
- **Metrics page — collapsible Scan Frequency table**: collapsed by default; sortable by app name, total scans, first scan date, and last scan date.
- **App monitoring classification**: each application can be toggled between **Continuous** (accent badge) and **Evaluation** (muted badge). Toggle available from the Applications list (new "Type" column) and the Application detail page header. Classifications stored in `configuration/monitored-apps.json`.
- **`POST /api/applications/{name}/monitored`** and **`DELETE /api/applications/{name}/monitored`** endpoints to set and unset continuous monitoring for an application.
- **Metrics filtering by monitored apps**: when any apps are marked Continuous, `GET /api/metrics` filters `by_target`, `trend`, and `scan_frequency` to only those apps; response includes `metrics_filtered: bool` and `monitored_count: int`. If no apps are marked, all apps are included (backward compatible).
- **Metrics filter notice**: when `metrics_filtered` is true, a banner reading "Filtered to N continuously monitored apps · manage" appears at the top of the Metrics page, linking to the Applications list.
- **`monitored` field in `GET /api/applications`**: every application object now includes `"monitored": bool`.
- **Suppressed findings in web UI**: scan detail page now shows a collapsible **Suppressed Findings** section listing every rule from the scanned repo's `.epyon-ignore.yml`, with columns for Type, Value/ID, Tool, Reason, Approved By, and Severity.
- **SBOM sort & search**: SBOM package table is now fully interactive — sort by any column header (Name, Version, Type, License, Path); filter by text search; click a type chip to filter by ecosystem; "Clear filters" resets all.
- **SBOM path column**: each package row now shows the file where the dependency was found, sourced from Syft's `locations[0].path`.
- **Run Scan URL pre-fill**: "Run Scan" buttons on scan detail and application detail pages pre-populate the GitHub URL field from `source_url`, registered application URL, or CI source.
- **`source_url` persistence**: `jobs.py` now saves the original target URL to `scan-metadata.json` at scan start; `parsers.py` reads it back into the scan API response.

### Fixed
- **Scan pipeline appearing frozen after Checkov**: Checkov's `--output json` flag was streaming 400 000+ lines of JSON findings to stdout via `tee`, exhausting the 1 000-line rolling output buffer in `jobs.py` so all later layers (Trivy, Grype, Anchore, etc.) were invisible in the UI. Fixed by redirecting all four Checkov `docker run` calls to the scan log file only (`>> "$SCAN_LOG" 2>&1`). Results are unchanged — they are written via `--output-file`.
- **Duplicate suppressed findings**: `suppressed-findings.md` contained duplicate entries when the same `.epyon-ignore.yml` rule matched multiple scan files. Both `parsers.py` and `generate-security-dashboard.sh` now deduplicate by `(type, value)` before rendering.
- **Web UI output buffer too small**: `OUTPUT_BUFFER_MAX` raised from 1 000 to 10 000 lines so all 15 scan layers remain visible in the live log panel simultaneously.
- **Docker VirtioFS mount failure for ClamAV and Checkov**: Docker Desktop 29.x with `UseContainerdSnapshotter: true` corrupts `~/Desktop` VirtioFS metadata. Fixed by staging source via `rsync` to `/tmp/epyon-<tool>-src-$$` before mounting.
- **MTTR N/A false negative**: MTTR calculation was slicing only the 20 most-recent scans, causing the oldest scans (where remediations originated) to be excluded for high-volume targets. Fixed by using all eligible full/nightly scans in chronological order.

## [3.0.0] - 2026-03-27

### Added
- **CycloneDX SBOM generation at scan time**: `run-sbom-scan.sh` now outputs both `syft-json` and `cyclonedx-json` formats simultaneously via `syft scan -o "syft-json=..." -o "cyclonedx-json=..."`, replacing the previous post-hoc `syft convert` step that silently failed.
- **License compliance gate** (`check-severity-gate.sh`): reads CycloneDX SBOM and fails the build when copyleft licenses (GPL, AGPL, SSPL, EUPL, CDDL, MPL, LGPL) are detected. Configurable denied-license regex.
- **Supply chain hash verification** (`verify-sbom-hashes.sh`): cross-references SHA-256 hashes of all `pkg:pypi` components in the CycloneDX SBOM against PyPI's published digests; outputs `sbom/hash-verification.json`; exits 2 on tampered packages.
- **Dependency lineage** (`generate-sbom-lineage.sh`): uses `pipdeptree --json-tree` (Python) and `npm ls --json` (Node.js) to build parent→child dependency trees; enriches the CycloneDX SBOM in-place with a `dependencies[]` array.
- **VEX document management** (`run-vex.sh`): create, list, and apply OpenVEX 0.2.0 justification documents; applies suppressions to Grype results via `--vex` flag with JSON post-processing fallback; outputs `grype/vex-applied-results.json` and `grype/vex-summary.json`.
- **Consolidated SBOM panel in security dashboard**: all SBOM enrichment data (license compliance, dependency lineage, supply chain integrity, VEX suppressions) is now shown inline per-package within the single SBOM accordion — replacing four separate tool cards. Each package row shows type, version, license badge (color-coded by risk), dep/used-by counts, hash status, and VEX suppression badges; expanded detail shows full attribution.
- **On-the-fly CycloneDX generation in dashboard**: `generate-security-dashboard.sh` automatically runs `syft scan` against the target directory when no `*.cyclonedx.json` is found in the scan's sbom directory, using `TARGET_DIR` env var or the path from `scan-metadata.json` as fallback.
- **`pipdeptree` added to CI install step** in `epyon-scan.yml`.

### Changed
- SBOM panel stats box now summarises all enrichment dimensions: total packages, license counts (allowed/denied/unknown), dependency relationship count, PyPI hash verification results, and VEX suppressions applied.
- `consolidate-security-reports.sh` now prefers pre-generated `*-cyclonedx.json` files; only falls back to `syft convert` as a last resort.
- Export SBOM buttons removed from security dashboard (replaced by file written directly to scan directory at scan time).

## [2.9.0] - 2026-03-24

### Added
- **Dual dashboard metrics charts** (`embed-metrics-in-dashboard.sh`): the single combined chart is now split into two focused panels:
  - **Chart 1 — 90 Day Vulnerability Metrics**: stacked bar chart (Critical / High / Medium / Low) per day; PR line overlay removed to reduce noise; story banner, and stat cards (Latest Critical, Latest High, Latest Total, Peak Day).
  - **Chart 2 — PR Activity & CVE Discipline**: daily PR merges to the default branch (bars) overlaid with net CVE count change (line); data points colored red when CVEs rose and green when they fell; story banner diagnoses CVE discipline automatically; stat cards show PRs (90d), PRs (last 7d), Net CVE Change (90d), and Average CVE Δ on PR merge days.
- **Default branch auto-detection for PR metrics**: `epyon-scan.yml` now queries the GitHub API (`gh api repos/{repo}`) to resolve the repository's actual default branch before passing `--pr-base-branch` to the embed script, eliminating the previous hardcoded assumption of `main`.

### Fixed
- **Checkov findings not counted in vulnerability summary** (`generate-scan-findings-summary.sh`): Checkov 3.x writes an array of per-check-type objects (`[{check_type, results:{failed_checks:[...]}}, ...]`) rather than a single object. The previous `jq` query used `.results.failed_checks[]?` which silently returned nothing for array-format files, causing every Checkov failure to be omitted from the `total_critical/high/medium/low` counts. Fixed by handling both formats: `(if type == "array" then .[].results.failed_checks[] else .results.failed_checks[]? end)`. The `.severity` field is now respected when present (Prisma/Bridgecrew configurations); otherwise defaults to `High`.

## [2.8.0] - 2026-03-16

### Added
- **Cross-scan metrics aggregator** (`get-scan-metrics.sh`): new script that reads all local scan directories (`scans/`, `baseline/scans/`) and produces a JSON time-series (`scan-history.json`) plus a color-coded terminal table of findings trends across all time.
- **GitHub Actions metrics fetch** (`--from-github`): `get-scan-metrics.sh` now supports pulling metrics directly from GitHub Actions artifacts via the `gh` CLI. Auto-detects the repo from the git remote; supports `--repos` for multi-repo aggregation, `--since` for date filtering, `--no-cache` to force re-download, and `--fetch-legacy` to extract metrics from older full-scan artifact zips.
- **Lightweight metrics artifact per CI run**: `epyon-scan.yml` now writes a `scan-metrics-row.jsonl` file containing scan ID, target, type, actor, severity counts, repository, run ID, and a direct Actions run URL; this is uploaded as a separate `metrics-{scan_id}` artifact with 90-day retention so metrics persist well beyond the 30-day full-scan artifact window.
- **Metrics row cache**: downloaded GitHub metrics rows are cached in `metrics/github-cache/` to avoid re-downloading on subsequent invocations; local-directory scans always take precedence over cached GitHub rows for the same scan ID.

## [2.7.0] - 2026-03-12

### Added
- **Jira ticket creation expanded to all four severity tiers**: medium (`🟡 epyon-medium`, priority `Medium`) and low (`🔵 epyon-low`, priority `Low`) findings now each generate their own deduplicated Jira ticket in addition to critical and high.
- **Jira deduplication**: before creating a ticket, the workflow searches Jira for an existing unresolved issue with matching `epyon-critical`/`epyon-high` and repo-slug labels. If one is found, creation is skipped and the existing ticket URL is logged to the GitHub Step Summary.
- **Jira auth and project validation**: connectivity to `JIRA_BASE_URL` and accessibility of `JIRA_PROJECT_KEY` are verified upfront before any ticket operations, with descriptive failure messages.
- **New workflow secrets**: `JIRA_BASE_URL`, `JIRA_USER_EMAIL`, `JIRA_API_TOKEN`, `JIRA_PROJECT_KEY` declared on `epyon-scan.yml`'s `workflow_call` block.
- **New workflow inputs**: `create_jira_tickets` (boolean, default `true`), `jira_issue_type` (string, default `Bug`) added to `epyon-scan.yml`; forwarded by both `scan-private-repo.yml` and `scan-public-repo.yml`.
- **GitHub notification issue deduplication**: the "Create Scan Notification Issue" step now checks for an existing open GitHub issue with matching severity labels before creating a new one, preventing duplicate issues across repeated scans.
- **Improved `check-severity` step**: outputs (`critical`, `high`, `has_issues`) are now always written with defaults of `0`/`false` so downstream steps are never skipped due to missing output values. The step now reads from `security-findings-summary.json` (authoritative deduplicated JSON) before falling back to the executive summary markdown.

### Changed
- **`create_jira_tickets` defaults to `true`**: ticket creation is driven entirely by the presence of `JIRA_*` secrets — if secrets are not configured, the step exits gracefully without error.
- **Payload delivery**: Jira ticket payload is written to a temp file (`/tmp/jira_payload.json`) and passed via `--data @file` instead of `--data-raw` to prevent shell interpolation issues with special characters in finding descriptions.

### Added
- **Garak workflow controls in GitHub Actions**: `workflow_dispatch` forms now expose Garak settings as UI-friendly controls, including target type, target model preset, optional custom model override, and probe set selection.
- **Garak run summary visibility**: workflow summaries now include Garak status, target, probe set, hit count, and exit code for quicker CI triage.

### Changed
- **Automated scan-mode policy**: `scan-private-repo.yml` now runs `quick` for `pull_request` events and `full` for `push` (including merge-result pushes) and scheduled runs; manual dispatch remains user-selectable.
- **Production-ready Garak defaults**: workflows now default Garak target configuration to `openai` + `gpt-4o-mini` (with `promptinject`) instead of test targets.

### Fixed
- **Garak installation reliability in CI**: `run-garak-scan.sh` now uses resilient pip installation fallbacks (`standard`, `--break-system-packages`, and `--user`) and emits last pip error lines on failure to improve diagnostics on hosted runners.
- **Garak hit readability in dashboard**: Garak findings now parse and display decoded prompt/response content (when present) plus probe/detector metadata, with raw JSON retained as fallback evidence.

### Fixed
- **Checkov suppression display**: `find` now uses `-type f` when locating Checkov result JSON files, preventing a directory (`checkov-results.json/`) from masquerading as a file and causing the entire Checkov block to be silently skipped in both `check-severity-gate.sh` and `generate-security-dashboard.sh`.
- **SonarCloud coverage reporting**: Coverage XML paths are now stored as absolute paths (not relative) so the SonarCloud scanner still resolves them correctly after it `cd`s to the properties-file directory. Discovery now also searches for `cobertura.xml` in addition to `coverage.xml`, and reads `pyproject.toml`, `setup.cfg`, and `.coveragerc` for configured XML output paths.
- **Python test results visible to SonarCloud**: `run-sonar-analysis.sh` now runs tests through the project's own Makefile/tox/pyproject task runner when present, passes `--junitxml=pytest-report.xml` to all pytest invocations, discovers the resulting JUnit XML file and sets `sonar.python.xunit.reportPaths`, and detects test directories to set `sonar.tests`.
- **Python coverage always 0% when source uses package imports**: The fallback pytest run now passes an absolute filesystem path to `--cov` (`$PROPS_BASE/$COV_SRC`) instead of the relative module name from `sonar.sources`. Passing a relative name like `core` to pytest-cov triggers module-name matching, which silently collects no data when the code is imported as part of a larger package (e.g. `midas.core`). Using an absolute directory path forces filesystem-level coverage tracking regardless of import mechanism. Also increased `tail` buffer from 30 to 50 lines so warning messages like `No data was collected` are visible in the log.
- **`sonar.python.version` auto-detection**: `run-sonar-analysis.sh` now detects the project's Python version from `.python-version`, `pyproject.toml` (`requires-python`), `runtime.txt`, or `setup.cfg` (`python_requires`), falling back to the live interpreter. The detected major.minor version is passed as `-Dsonar.python.version` to both SonarCloud scanner invocations, eliminating the "analyzed as compatible with all Python 3 versions" warning.

### Planned
- Automated version bumping script
- Git tag synchronization
- Release automation workflow

## [2.6.2] - 2026-03-11

### Changed
- **GitHub workflow architecture simplification**: `scan-private-repo.yml` and `scan-public-repo.yml` now operate as thin caller workflows that delegate execution to reusable `epyon-scan.yml`, reducing duplicated CI logic and keeping layer behavior centralized.
- **Reusable external-repo scan support**: `epyon-scan.yml` now accepts `repository_url`, `pr_number`, and `target_ref` inputs and conditionally performs checkout or external clone flows so public and private scan entry points share one execution path.
- **Node runtime deprecation hardening**: active workflows now set `FORCE_JAVASCRIPT_ACTIONS_TO_NODE24=true` to avoid Node.js 20 deprecation warnings in GitHub-hosted runs.

### Fixed
- **`scan-private-repo.yml` replacement reliability**: private scan workflow was rebuilt as a clean Epyon-native caller after prior merge-content corruption risk, restoring a stable and maintainable entry workflow.
- **Public scan parity after private workflow replacement**: `scan-public-repo.yml` now uses the same reusable workflow contract as private scans, preserving consistent outputs (`scan_dir`, `scan_id`) and downstream reporting behavior.

## [2.6.1] - 2026-03-11

### Changed
- **Layer 3 Sonar JS coverage generation safety**: `run-sonar-analysis.sh` now runs only `npm run test:coverage` or `npm run coverage` (no plain `npm run test` fallback) and applies `SONAR_JS_TEST_TIMEOUT_SECONDS` (default 600s) to prevent CI hangs on watch/interactive test scripts.
- **Garak workflow resiliency across CI entry points**: Layer 12 in `scan-private-repo.yml`, `scan-public-repo.yml`, `epyon-scan.yml`, and `baseline-scan.yml` now includes secret-aware target fallback and skip guards so Garak still runs predictably when provider API keys are unavailable.

### Fixed
- **Sonar step appearing stuck after `/tmp/epyon-env`**: the actual stall was caused by fallback execution of long-running `npm run test` in JS coverage auto-generation; removing that fallback and adding a timeout eliminates indefinite waits.
- **Garak not running on merge/pull requests**: workflows now avoid hard dependency on provider secrets by falling back to local `test.Blank` target when configured provider keys are absent, and honor explicit skip controls.

## [2.6.0] - 2026-02-27

### Added
- **IOC mini donut charts**: each of the 7 IOC summary cards now renders a 100×100px donut ring coloured by C/H/M/L severity instead of a plain count number; hover tooltip shows tool name and per-severity breakdown
- **IOC panel unified layout**: large CVE severity donut and 7 IOC mini-donuts now share a single `ioc-body` flex row inside the Indicators of Compromise panel — donut on the left, 4-column mini-donut grid filling the remaining width
- **`.badge-skipped` CSS class**: dark-indigo badge style (`#1e1b4b` bg, `#818cf8` text, `#4338ca` border) added to the tool stat badge palette
- Sonar project key auto-derivation in `scan-private-repo.yml` and `scan-public-repo.yml`: derives a stable key from `GITHUB_REPOSITORY` when `SONAR_PROJECT_KEY` Actions variable is not set
- Subdirectory-aware Sonar project keys: appends sanitized subdirectory path suffix for monorepo scans (e.g., `owner_repo_apps_api`)
- Branch and PR context exports in workflow Sonar step: `SONAR_BRANCH`, `SONAR_PR_BRANCH`, `SONAR_PR_BASE`
- `SONAR_PROJECT_NAME` export in workflow Sonar step for human-readable project display in SonarQube

### Changed
- **Pull request scans auto-select quick mode**: `SCAN_MODE` defaults to `quick` on `pull_request` events, skipping Layers 3 (SonarQube), 4 (ClamAV), 6 (Checkov), and 10 (Anchore) to significantly reduce PR feedback time; push and schedule events continue to use `full` mode
- Main CVE severity donut enlarged 30%: canvas 220 → 286px, outer radius 90 → 117, inner radius 58 → 75
- CVE donut and IOC summary merged into a single panel; standalone `.donut-layout` wrapper removed
- IOC grid changed from `repeat(auto-fit, minmax(148px, 1fr))` to fixed `repeat(4, 1fr)` to fill available space beside the donut

### Fixed
- **Suppression count always zero**: `Check Severity Gate` step now runs before `Generate Reports & Dashboard` in both `scan-private-repo.yml` and `scan-public-repo.yml`; previously the dashboard was generated before `suppressed-findings.md` was created, so `SUPPRESSED_COUNT` was always 0
- **Trivy and TruffleHog suppressions never logged**: both tools were wrapped in `if [[ ! -f "$FINDINGS_SUMMARY" ]]` guards in `check-severity-gate.sh`; since the dedup summary is always present in CI, `is_cve_ignored`/`is_secret_ignored` were never called for these tools, so `log_suppressed` never fired — now both always run their full filter loop and only skip adding to totals when the dedup summary exists
- **Checkov path suppressions double-counted**: `is_path_ignored` already calls `log_suppressed` internally; the gate had an additional explicit `log_suppressed` call for Checkov path matches, causing every Checkov path suppression to inflate `SUPPRESSED_COUNT` by 2 — duplicate call removed
- **Checkov results silently skipped in gate and dashboard**: Checkov's `--output-file` flag creates a directory named `checkov-results.json/` containing `results_json.json`; the gate's `find` command matched the directory name first (no `-type f` guard), causing `[[ -f ]]` to fail and the entire Checkov block to be skipped silently; the dashboard's `*.json` glob similarly resolved to directories, making `[ -f ]` fail for every iteration — fixed by using `find -type f` with proper parentheses in the gate and `while IFS= read -r ... done < <(find -type f ...)` in both dashboard loops
- **Dashboard ignore file search**: `$TARGET_DIR` added as first lookup path for `.epyon-ignore.yml` so the dashboard correctly locates rules before its own Checkov filtering
- **ClamAV accordion badge shows "✅ Clean" when skipped**: added `SCAN_MODE=quick` guard — now shows `⏭️ Not run in quick mode` (matching the IOC mini-donut skipped state)
- **Anchore accordion badge shows "✅ Clean" when skipped**: same quick-mode guard added; also simplified multi-`if` badge logic to a clean `elif` chain
- `run-sonar-analysis.sh`: now reads `sonar.organization` from `sonar-project.properties` as a fallback when the `SONAR_ORGANIZATION` env var is not set — fixes SonarCloud scans failing with "The 'organization' parameter is missing"
- `run-sonar-analysis.sh`: Python test execution now fully reported to SonarCloud:
  - **Makefile/tox/pyproject detection**: before running raw pytest, checks for `make coverage`, `make test`, `tox`, and pyproject task runners (Hatch/PDM/taskipy) and runs them first — respects the project's own test setup (dependency installs, virtualenvs, configuration)
  - **JUnit XML generation**: `--junitxml=pytest-report.xml` added to all pytest invocations so SonarCloud receives test execution results via `sonar.python.xunit.reportPaths`
  - **JUnit XML discovery**: broad `find` for `pytest-report.xml`, `test-results.xml`, `*junit*.xml`, `TEST-*.xml` after test runs; all found paths passed as absolute paths to `-Dsonar.python.xunit.reportPaths`
  - **`sonar.tests` detection**: test file directories auto-discovered and passed as `-Dsonar.tests` so SonarCloud correctly links test results to source files
  - **`coverage.xml` discovery improvements**: searches `pyproject.toml`, `setup.cfg`, `.coveragerc` for configured XML output paths; also finds `cobertura.xml` in addition to `coverage.xml`; all paths stored as absolutes to survive `cd` into properties-file directory

---

## Version Format

EPYON follows [Semantic Versioning](https://semver.org/):
- **MAJOR** version: Incompatible API/breaking changes
- **MINOR** version: New functionality (backwards compatible)
- **PATCH** version: Bug fixes (backwards compatible)
