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

### Added
- **Garak workflow controls in GitHub Actions**: `workflow_dispatch` forms now expose Garak settings as UI-friendly controls, including target type, target model preset, optional custom model override, and probe set selection.
- **Garak run summary visibility**: workflow summaries now include Garak status, target, probe set, hit count, and exit code for quicker CI triage.

### Changed
- **Automated scan-mode policy**: `scan-private-repo.yml` now runs `quick` for `pull_request` events and `full` for `push` (including merge-result pushes) and scheduled runs; manual dispatch remains user-selectable.
- **Production-ready Garak defaults**: workflows now default Garak target configuration to `openai` + `gpt-4o-mini` (with `promptinject`) instead of test targets.

### Fixed
- **Garak installation reliability in CI**: `run-garak-scan.sh` now uses resilient pip installation fallbacks (`standard`, `--break-system-packages`, and `--user`) and emits last pip error lines on failure to improve diagnostics on hosted runners.

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
