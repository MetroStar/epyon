# Changelog

All notable changes to the EPYON Security Scanner will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.5.0] - 2026-02-12

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

## [Unreleased]

### Planned
- Automated version bumping script
- Git tag synchronization
- Release automation workflow

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
- `run-sonar-analysis.sh`: added broad `coverage.xml` discovery — after pytest generates coverage, a `find` search locates every `coverage.xml` under the repo (excluding `node_modules`, `.venv`, `dist`, `build`, `.git`) and passes all paths as `-Dsonar.python.coverage.reportPaths` to both scanner invocations; previously only ran if `sonar-project.properties` already had that key configured

---

## Version Format

EPYON follows [Semantic Versioning](https://semver.org/):
- **MAJOR** version: Incompatible API/breaking changes
- **MINOR** version: New functionality (backwards compatible)
- **PATCH** version: Bug fixes (backwards compatible)
