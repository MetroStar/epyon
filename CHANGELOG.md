# Changelog

All notable changes to the EPYON Security Scanner will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [3.33.1] - 2026-10-05

### Fixed
- **A failed baseline-image `docker pull` always blamed "missing registry credentials (docker login)"**, even when the image was a genuinely public one (e.g. `python:3.12-slim-bookworm`, `ubuntu:22.04`) that failed to pull for an unrelated reason — almost always Docker Hub's anonymous-pull rate limit (100 pulls/6h per IP without `docker login`, 200/6h with a free account) on shared CI runners, not a per-image access problem. This produced a confusing, inaccurate "Environment Notes" banner on the dashboard telling users to log into Docker for images that never required any credentials in the first place.
- Added `classify_docker_pull_failure()` (`scripts/shell/scan-directory-template.sh`), which inspects the actual captured `docker pull` output and reports the real cause: Docker Hub rate limiting (not a credentials issue — explains the real fix, i.e. wait or `docker login` to raise the *limit*, not to gain *access*), genuine registry authentication failure (private/gated image — `docker login` is the correct fix here), an unknown/nonexistent image tag (typo or removed upstream — not a credentials problem), or a generic network/registry issue. Used by both `run-anchore-scan.sh`'s baseline-image pull (feeding `anchore/status.json`'s `baseline_scan_reason` and the dashboard's Environment Notes banner) and `run-trivy-scan.sh`'s per-base-image pull loop.
- Added BATS coverage for all four classification branches.

## [3.33.0] - 2026-10-05

### Changed
- **Dockerfile base-image auto-discovery (`discover_dockerfile_base_images()`, shared by Trivy/Anchore) now only scans each Dockerfile's FINAL build stage, instead of every `FROM` line.** Multi-stage Dockerfiles commonly use a throwaway builder stage to compile a helper binary (e.g. `FROM golang:1.24-alpine AS gosu-builder`) or a private/internal-registry-only image for building (e.g. `FROM internal-registry.example.com/python:3.12-dev AS builder`) before copying the compiled artifact into a slim runtime stage. These builder images are discarded by `docker build` and never present in the shipped container, so scanning them produced large amounts of irrelevant, unfixable, and sometimes unreachable (private-registry) findings that had nothing to do with the actual deployed artifact — inflating Critical/High counts and occasionally prompting unnecessary registry-login troubleshooting for images that were never going to be part of the real scan baseline anyway.
- `FROM <stage-name>` references to an earlier named stage (e.g. `FROM base AS runtime`, which builds further on a previous stage rather than pulling a new external image) are now resolved back to that stage's real image, so the reported baseline is always the actual external image that ships — never a local stage name mistaken for a pullable image.
- Single-stage Dockerfiles, and the already-correct `FROM scratch` / unresolved build-arg (`FROM $BASE_IMAGE`) skip behavior, are unaffected. Pulling a configured/discovered image that genuinely doesn't exist or requires registry auth was already handled gracefully (pull failure logs a warning and skips that image only) — this change reduces how often that situation is even reached by no longer attempting to pull images that were never going to ship in the first place.
- Added BATS coverage in `tests/shell/test-scan-directory-template.bats` for multi-stage final-stage selection, named-stage resolution, single-stage passthrough, and `FROM scratch`/build-arg skip behavior.

## [3.32.3] - 2026-10-05

### Fixed
- **Web UI/dashboard scans could show an overall "FAIL" verdict even when every Critical/High finding had been suppressed via `.epyon-ignore.yml`** (e.g. a scan showing 0 Critical / 0 High vulnerabilities, only Medium/Low, still badged `FAIL`). Root cause: `compute_gate_status()` in `web/api/parsers.py` derives the verdict from `critical + high + misconfig_critical + misconfig_high`. The vulnerability counts (`critical`/`high`) were already suppression-filtered via `load_enriched_findings()`, but `misconfig_critical`/`misconfig_high` came from `parse_misconfiguration_findings()` (Checkov/TruffleHog/compromised-source findings), which built its severity counts directly from raw tool output and never called `_filter_suppressed_findings()` — so a suppressed Critical/High Checkov or TruffleHog finding still counted toward the gate and flipped the badge to FAIL, even though the same finding was correctly hidden from the Misconfigurations card's suppressed-findings list elsewhere.
- `parse_misconfiguration_findings()` now applies the same suppression filter used by `parse_scan_findings()`/`load_enriched_findings()`, so the PASS/FAIL gate (and the Misconfigurations summary counts feeding it) are computed strictly from pass/fail-relevant *unsuppressed* findings, matching the already-correct behavior of the Vulnerabilities card.

## [3.32.2] - 2026-10-02

### Fixed
- **`type: tool` suppression rules in `.epyon-ignore.yml` (e.g. `type: tool, value: anchore`) were silently never applied to GitHub Actions' PR comments / `security-findings-filtered.json`**, even though they were correctly applied in the Web UI/dashboard. Root cause: `check-severity-gate.sh` built a `SUPPRESSED_TOOLS_JQ` jq clause and logged `"Excluding <tool> findings from severity totals"` for every tool-suppressed rule, but never actually used that variable in the jq filter that produces `security-findings-filtered.json` — and the per-finding suppression loop that builds the suppressed-fingerprint list checked `is_secret_ignored`/`is_cve_ignored`/`is_package_ignored`/`is_path_ignored` but never `is_tool_ignored`. The log message was cosmetic; every individual finding from a whole-tool-suppressed tool (e.g. Anchore container CVEs) still passed through into `security-findings-filtered.json`'s `critical_findings`/`high_findings`/etc. arrays and the PR comment's severity counts. The Web UI/dashboard was unaffected because it uses a separate, correct suppression implementation (`_is_finding_suppressed()` in `web/api/parsers.py`), which is why the discrepancy only showed up on GitHub.
- Added an `is_tool_ignored` check as the first suppression test in `check-severity-gate.sh`'s per-finding loop, so `type: tool` rules now correctly suppress every finding from that tool everywhere `security-findings-filtered.json` is consumed (PR comments, GitHub Issues, Jira ticket creation), matching the Web UI's behavior. Verified against a real affected scan: previously 4 Critical / 68 High findings remained after "suppression" (mostly un-suppressed Anchore CVEs); after the fix, 0 Critical / 0 High remain, with the Anchore/Checkov findings correctly excluded.

## [3.32.1] - 2026-10-02

### Fixed
- **Self-assessment scans of the Epyon repo itself could pick up Dockerfiles belonging to completely unrelated target repos**, polluting Trivy/Anchore/Xeol base-image results with random, irrelevant findings (e.g. Red Hat/UBI/Iron Bank CVEs from someone else's app). Root cause: `discover_dockerfile_base_images()` (and the filesystem/config scan `--skip-dirs`) only ever hardcoded `node_modules`/`.terraform`/`.git` — they never excluded Epyon's own operational scratch directories, `tmp/` (per-job git clones and zip uploads created by `web/api/jobs.py`/`main.py` for Web UI-triggered scans of *other* repos) and `scans/` (previous scan output, including any extracted `build/Dockerfile` context). When a self-assessment scan targeted the Epyon repo root, these leftover/stale directories were traversed as if they were part of Epyon's own codebase.
- Added `tmp/**` and `scans/**` as `type: path` exclusions in Epyon's own `.epyon-ignore.yml`, which `get_epyon_ignore_exclude_paths()` already feeds into both Dockerfile base-image discovery and every tool's `--skip-dirs`/skip-path list — fixing this for every scanner that shares the helper, with no code changes required.

## [3.32.0] - 2026-10-02

### Fixed
- **`BUILD_ENABLED` (Phase 0 container image build/scan) defaulted differently per environment, a major remaining source of cross-environment vulnerability-count divergence** — GitHub Actions defaulted to `build_enabled=true` (builds the target's actual container image, then routes it into Trivy/Anchore as the baseline, surfacing real OS-package/dependency CVEs baked into the artifact), while the Web UI (`web/api/jobs.py`) never set `BUILD_ENABLED` at all and the local CLI (`run-target-security-scan.sh`) defaulted it to `false` unless `--build-image` was explicitly passed. This meant Web UI/local-CLI-without-the-flag scans only ever saw a generic Dockerfile base image (or source-only findings), while GitHub Actions scans of the identical target saw a much larger, more realistic set of findings — with no indication to the user that an entire scan phase had been silently skipped.
- `BUILD_ENABLED` now defaults to `true` everywhere (Web UI, local CLI, GitHub Actions), so every environment builds and scans the target's real container image by default. Local CLI gains a new `--no-build-image` flag to opt out (e.g. no Docker available, or a non-containerized repo) alongside the existing `--build-image` flag (now a no-op default-confirming alias). Web UI scans still skip the build phase for `local_model` (not a buildable repo target) and `stig` (narrow, fast compliance-only) scan types.
- **Fixed a latent bug in `run-build-scan.sh`'s no-Dockerfile fallback path** (generates a source-manifest + deterministic digest instead of a real image) that never wrote `build/build.log` — this would have caused `validate-scan-output.sh --require-build` to falsely report a missing/failed build artifact on every non-containerized repo now that `BUILD_ENABLED=true` is the default everywhere.

## [3.31.0] - 2026-10-02

### Fixed
- **Anchore's baseline/"Approved Base Images" scan defaulted to a gated, often-irrelevant image, causing a major and silent source of cross-environment result divergence** — `configuration/approved-base-images.conf` previously set `PRIMARY_BASELINE_IMAGE="dhi/caddy:latest"` and included another `dhi/*` tag in the core `APPROVED_BASE_IMAGES` array by default. These Docker Hardened Images (DHI) tags require a paid Docker Hub DHI entitlement (`docker login`), so whichever environment happened to have that configured got a successful baseline scan while every other environment silently got `failed_pull`/`not_configured` — and even when it succeeded, comparing (e.g.) a Caddy web-server image against an unrelated Python/Node/Go repo was never a meaningful baseline anyway. `PRIMARY_BASELINE_IMAGE` is no longer set by default (documented as opt-in for orgs with DHI access) and `APPROVED_BASE_IMAGES` is now empty by default.
- **Anchore now auto-discovers each target's own actual Dockerfile `FROM`-line image as its baseline** (mirroring logic `run-trivy-scan.sh` already had), instead of skipping the baseline scan outright when no fixed image is configured. This is public, always pullable without special credentials, and genuinely relevant to the target being scanned — eliminating the registry-access-dependent gap between local/deployed/CI runs of the same target. Surfaced via a new `baseline_image_source` field (`"configured"` vs `"auto-discovered from Dockerfile"`) in `anchore/status.json` and the Environment Notes banner.

### Changed
- **Dockerfile base-image auto-discovery logic consolidated into one shared helper** — `discover_dockerfile_base_images()` (new, in `scripts/shell/scan-directory-template.sh`) replaces the two independent, copy-pasted implementations previously maintained separately in `run-trivy-scan.sh` and `run-anchore-scan.sh`. Both tools now resolve the exact same set of candidate baseline images from a target's Dockerfiles, preventing the two scanners' baseline logic from silently drifting apart again. Trivy and Anchore/Grype remain intentionally separate scan engines (different CVE databases; Trivy additionally checks the base image for misconfigurations and secrets) — only the discovery logic was deduplicated, not the scanning itself.

## [3.30.0] - 2026-10-02

### Added
- **Overall scan PASS/FAIL gate** — every scan now gets a dashboard-only `gate_status` verdict: FAIL if any Critical or High severity vulnerability, misconfiguration (Checkov), or secret (TruffleHog)/compromised-source (Layer 21) finding is present; PASS only when none are. Deliberately the inverse of the self-assessment harness (which PASSes when a planted finding IS detected, proving the scanner works) — a real scan should PASS only when there's genuinely nothing to find. New `compute_gate_status()` in `web/api/parsers.py`, surfaced as a 🟢 PASS/🔴 FAIL badge on the Overview app cards, the per-application scan timeline, and the Scan Details page header. Does **not** change GitHub Actions workflow exit codes or CI behavior — dashboard/API only.

## [3.29.1] - 2026-10-02

### Added
- **Self-assessment results now include a reconstructed step-by-step timeline** — `run-self-assessment.sh` delegates to `run-target-security-scan.sh`, which (unlike `run-epyon-scan-ci.sh`) never writes a `layer-timing.json`/`parallel-logs` set, so the Performance page's self-assessment table previously showed only the final pass/fail verdict with no record of when each layer ran, even for a run that had already completed and reloaded the page. `compare-self-assessment.py` now derives an approximate `completed_at`/`elapsed_seconds` per layer from each layer's own output-file mtime relative to the run's start time (`scan-metadata.json`), and writes an ordered `timeline` array to `self-assessment-latest.json`. The Performance page's self-assessment table gained a "Ran at" column plus a chronological "Step-by-step timeline" list below it, both of which persist across page reloads (unlike the ephemeral live console log).

## [3.29.0] - 2026-10-01

### Added
- **"Environment Notes" warning banner on the Scan Details page** — surfaces environment-dependent gaps that make a scan's vulnerability counts non-comparable to another environment scanning the same target, instead of leaving that difference buried only in `anchore-scan.log`. A new `anchore/status.json` (written by `run-anchore-scan.sh`) records (1) whether the "Approved Base Images" baseline scan actually completed (vs. failing to pull due to missing registry credentials / `docker login`), and (2) whether the Go/Java/Node/Python build-stage auto-exclusion filter was applied and why. `parse_scan_environment_notes()` (`web/api/parsers.py`) surfaces both as a new `environment_notes` field on `GET /api/scans/{scan_id}`, rendered as an amber banner at the top of the Scan Details page when present; absent for clean/complete runs.
- **Run Scan page: granular "Scan Layers" checkbox picker** (full/nightly/baseline scan types) mirroring the self-assessment layer picker, letting users select exactly which scan layers run instead of only a scan-type preset. Backed by a new `layers` parameter on `POST /api/scans` and `/api/scans/upload`, validated against `job_store.LAYER_SKIP_ENV`.

### Fixed
- **Anchore's "Python-only runtime" (and Node/Go-only) build-stage auto-exclusion heuristic could silently drop hundreds of real vulnerability findings** — `auto_configure_scanner()` in `run-anchore-scan.sh` detected runtime languages solely via `which <lang>` inside the built image (toolchain presence), so a `python:3.x-slim`-based image that ships compiled Go binaries without the Go toolchain (e.g. this repo's own `Dockerfile`, which downloads the Docker CLI and Helm CLI as static binaries) was misclassified as "Python-only" and had `go,java,node,ruby` package types auto-excluded from the scan — 645 packages' worth of real findings in one observed run. Go binaries are now also detected by grepping for the `go1\.[0-9]+` version marker they embed regardless of toolchain presence, and Java is now also detected by the presence of any `.jar` file, not just a `java` binary on PATH.
- **Web UI scans always did a shallow (`--depth=1`) git clone, while the reusable GitHub Actions workflow does a full clone for standard targets** — this made TruffleHog's historical secret scan and Layer 21's git-log-based confidence scoring see less history via the Web UI than via GitHub Actions for an identical target, contributing to different results between the two. `web/api/jobs.py`'s clone step now mirrors the workflow's logic: full clone by default, shallow (`--depth=1 --filter=blob:limit=10m`) only for HuggingFace targets.
- **Garak (Layer 12, LLM security probing) could never actually run when triggered from the Web UI, even with the toggle enabled** — `run_scan_job()` unconditionally set `SKIP_GARAK=true` in the scan subprocess's environment, and `/tmp/epyon-env` only ever *set* `RUN_GARAK=true` on top of it, never clearing `SKIP_GARAK`. `run_garak_layer()` in `run-epyon-scan-ci.sh` treats `SKIP_GARAK` as a hard stop that wins over `RUN_GARAK`, so Garak silently no-op'd on every Web UI-triggered scan regardless of the toggle. `SKIP_GARAK` is now set to `false`/`true` based on the actual `run_garak` request flag.

### Added
- **Layer 21 — Compromised Source / Supply Chain Incident Detection** (`run-compromised-source-check.py`/`.sh`) — cross-references package manager configs (`.npmrc`, `pip.conf`/`pip.ini`, `Pipfile`, `requirements.txt`, `pom.xml`, Maven `settings.xml`, Gradle build files, `NuGet.config`, `go.mod`, `Cargo.toml`), container/orchestration manifests (`Dockerfile`, `docker-compose*.yml`, Helm `Chart.yaml`/`values.yaml`), and Layer 1 SBOMs against a new registry of disclosed artifact-repository compromises (`configuration/compromised-sources.json`). Seeded with the August–September 2026 OpenInfra Europe / Nordix JFrog Artifactory compromise (CVE-2026-82329). Each match is rated `high`/`medium`/`low` confidence based on whether the reference was last modified inside the confirmed incident window (best-effort via `git log`), and carries the incident's attack path, NIST SP 800-53 control IDs (CM-5, CM-8, SA-11, SA-12, SI-7, SR-3, SR-4, SR-11), and a remediation checklist (quarantine artifacts, compare hashes/signatures/provenance against independently retained upstream releases, rebuild from reviewed source, inventory derived deployments, rotate credentials, retain suspect packages as evidence). No Docker required; auto-enables in `full`/`nightly` (`RUN_COMPROMISED_SOURCE=true/false`, `SKIP_COMPROMISED_SOURCE=true`), skippable via `--skip-tools compromised-source`. Findings surface in the web UI's Misconfigurations card (🔗 Supply Chain badge) via a new `parse_compromised_source_dir()` parser, and in `security-findings-summary.json`. Wired into the cross-layer self-assessment harness (planted `.npmrc` fixture referencing the real Nordix incident host, `expected-findings.json` entry, `compare-self-assessment.py` counter, and a Performance-page self-diagnostic checkbox). 11 new BATS tests in `tests/shell/test-run-compromised-source-check.bats`.
- **Fixed `type: tool` suppressions in `.epyon-ignore.yml` (e.g. `checkov`, or `anchore` used bare and auto-normalized to `type: tool`) never actually expiring, even with an `expires:` date in the past** — every other suppression matcher (`is_cve_ignored`, `is_package_ignored`, `is_path_ignored`, `is_secret_ignored`) correctly filters on `.expired == false`, but `is_tool_ignored()` in `filter-ignored-findings.sh` only matched on `type == "tool"` + tool name, with no expiration check at all. This meant a whole-tool suppression (the most impactful kind — it hides every finding from that scanner) silently kept applying forever regardless of its `expires:` date, while CVE/package/path/secret-level suppressions in the same file correctly lapsed on schedule. `is_tool_ignored()` now checks `.expired == false` like every other matcher, so tool-level suppressions expire exactly as documented. Added two regression tests to `tests/shell/test-filter-ignored-findings.bats` proving an expired tool rule stops suppressing while a non-expired one still does.
- **`build_enabled` now defaults to `true` in the reusable scan workflow** — the container build/SLSA-provenance/cosign-signing phase (Phase 0) previously required manually checking a box on every `workflow_dispatch` run, and every scheduled/programmatic trigger (which never sets this input) always skipped it silently. `run-build-scan.sh` already auto-generates a synthetic Dockerfile and image name when a target has none, so this is safe to enable by default; explicitly pass `build_enabled: false` to opt back out for a given run.
- **Fixed a race condition between Layer 1 (SBOM) and Layer 11.5 (pip-audit) that could make pip-audit "fail" for no visible reason on some scans** — Layer 1's SBOM/Syft preprocessing writes throwaway `requirements-conda-env.txt`/`requirements-pyproject.txt` files directly into the target repo (next to `environment.yml`/`pyproject.toml`, respectively) so Syft's Python cataloger can see conda/pyproject dependencies, then deletes them once its own ~1-minute scan finishes. Since every scan layer runs in parallel, pip-audit's own dependency-file discovery could catch one of those files while it briefly existed, but — because pip-audit's per-file scan loop can take many minutes on a large repo — by the time it actually got around to running `pip-audit -r` on that specific file, Layer 1 had already deleted it, producing a hard, unexplained "Scan failed (exit code: 1)" for that entry instead of real results. `run-pip-audit-scan.sh` now excludes those two exact Layer-1-owned filenames from its own discovery (the pyproject one is a pure duplicate of the `pyproject.toml` project-mode scan already run for the same directory, so nothing is lost) and independently regenerates conda-environment coverage by discovering `environment.yml`/`environment.yaml` files itself and writing its own synthetic requirements file into pip-audit's own scan output directory — never into the target repo — so there's no cross-layer timing dependency at all. Added `tests/shell/test-run-pip-audit-scan.bats` with a functional regression test proving conda dependencies are still audited and the Layer 1 leftover file is never scanned.
- **GitHub Actions "Security Gate Failure Report" step summary now shows every tool that detected each CVE, not just the first one** — `generate-scan-findings-summary.sh`'s deduplication pass correctly collapses the same CVE reported by multiple tools (e.g. Grype and Trivy both flagging the same GHSA in the same `requirements.txt`-pinned package) into one line item, and already records every contributing tool in a `detected_by` array — but `check-severity-gate.sh`'s CVE list in the `$GITHUB_STEP_SUMMARY` only ever printed the single surviving `.tool` field (whichever tool's finding happened to be processed first, which is always Grype since it runs before Trivy in the summary generator). This made it look like "Trivy scans aren't showing up" any time Trivy's findings for a target fully overlapped with Grype's, even though Trivy ran successfully and agreed with Grype on every CVE. The step summary now renders `\(.detected_by | join(", "))` (falling back to `.tool` for older scans without that field), e.g. `(grype-sbom, trivy-filesystem)`, so agreement between tools is visible instead of silently attributed to only one of them.
- **Fixed a silent bug that could make vulnerability database update failures invisible, causing under-reported findings on some scans (especially ephemeral CI runners)** — `run-grype-scan.sh`, `run-trivy-scan.sh`, `run-xeol-scan.sh`, and `run-clamav-scan.sh` each run a `... | tee -a "$SCAN_LOG"` pipeline to stream the CVE/EOL-database update (or, for ClamAV, the actual scan/freshclam commands) to both the console and the scan log, then captured its exit code via `RESULT=$?`. Without `set -o pipefail`, `$?` after a pipeline reflects the **last command in the pipe** (`tee`, which almost always exits 0) — not the actual `grype db update`/`trivy image --download-db-only`/`xeol db update`/`freshclam`/`clamscan` command. This meant a failed database update (network blip, registry rate-limiting, DNS issue — all more likely on short-lived, no-persistent-cache GitHub Actions runners than on a long-running host with an already-warm cache volume) was **always** logged as "✅ updated successfully" and the scan silently proceeded with whatever stale/incomplete database happened to be present, producing a scan that looks clean but isn't. For ClamAV specifically, the same bug also masked `clamscan`'s own exit code, which signals whether malware was actually found. All five call sites now capture the real exit code via `${PIPESTATUS[0]}`, so a genuinely failed update surfaces its existing `⚠️ Database update had issues` warning instead of a false "success" message. This is one likely contributor to scans of the same target reporting drastically different vulnerability counts between a scheduled CI run and a manually-triggered scan.
- **Score Card returns a clear 422 instead of a raw 500 when a scan lacks consolidated findings data** — `POST /api/scans/{scan_id}/scorecard` previously always shelled out to `generate-trl-score.py` and surfaced whatever it printed to stderr as a generic `500 Internal Server Error`, which happens for older/interrupted/partial scans that never produced `security-findings-summary.json` (e.g. a scan where one tool crashed before the consolidation step ran). The endpoint now checks for that file up front and returns `422` with an actionable message ("Re-run the scan to generate a Score Card") instead. The Scan Details page renders this case as a muted "Unavailable" notice rather than a red "Error" badge, so it's clearly distinguished from an actual server bug.
- **"Download JSON" export alongside "Download ZIP" on the Scan Details page** — the Scan Details header's "Download ZIP" button is now a split button: the main click still downloads the full ZIP of raw scan artifacts (ATO/IATT bundle), while a caret opens a menu with a new "Download JSON" option that exports the fully parsed scan result (vulnerabilities, misconfigurations, ML/AI security findings, STIG assessment, metadata — the same data model that renders the Scan Details page) as a single `.json` file via a new `GET /api/scans/{scan_id}/download-json` endpoint. Useful for offline review or feeding scan results into other tooling without downloading the entire raw artifact bundle.
- **Cross-layer self-assessment harness (`scripts/shell/run-self-assessment.sh`)** — runs a real full (20-layer) scan against a synthetic, intentionally-vulnerable fixture (`tests/fixtures/self-assessment/`) and compares the output against a known baseline (`scripts/shell/compare-self-assessment.py`) to prove each scanner layer is actually detecting what it's supposed to detect, rather than just "not crashing." Layers that can't be deterministically planted in a static fixture (e.g. SonarQube, ClamAV under desktop AV) are reported as `not_validated`/`environment_limited` with an explanatory note instead of a false pass. Runnable in CI via `.github/workflows/self-assessment.yml` or on demand.
- **Per-layer toggle for the self-diagnostic** — the "Run Self-Diagnostic" panel now lists every togglable scanner layer (SBOM, Secret Detection, IaC, Trivy, Grype, pip-audit, STIG, ML layers, etc.) as a checkbox, defaulting to all-selected. Unchecking a layer restricts the underlying scan (`run-self-assessment.sh --layers ...`) to only the selected layers via `--skip-tools`, skipping the direct pip-audit step when Layer 8.5 isn't selected, and reports every unselected layer as `"skipped"` (with a "not selected for this run" reason) instead of pass/fail/not_validated — so you can quickly re-validate just the scanners you care about instead of waiting on a full ~5 minute run every time. `POST /api/self-assessment/run` accepts an optional `{"layers": [...]}` body and rejects unknown layer numbers (400).
- **"Run Self-Diagnostic" button on the Performance page** — triggers the self-assessment harness directly from the web UI (`POST /api/self-assessment/run`, backed by the existing generic job runner/poller) and streams its console output live. When the run finishes, the Self-Assessment table refreshes in place with a green/red/yellow/gray gumball and a plain-language reason per layer (e.g. `Found 6 (expected ≥ 2)` on pass, `Expected ≥ 1, found 0` on fail, or the environment-limitation note). Only one self-diagnostic can run at a time; clicking the button while one is already running resumes polling the existing job instead of starting a duplicate.
- **Upload a project as a .zip to scan it (`POST /api/scans/upload`)** — a typed absolute path in the "Run New Scan" form is resolved against the **server's** own filesystem, not the browser's machine, so once Epyon is deployed remotely there was no way to scan a local, not-yet-pushed project short of pushing it to a reachable Git remote first. The "Run New Scan" page now has a "Path / Git URL" vs "Upload .zip" toggle; uploading a zip streams it to disk with a size cap (`EPYON_MAX_UPLOAD_MB`, default 500MB), validates it's a real zip, and extracts it defensively (rejects path-traversal/zip-slip entries, enforces a total-uncompressed-size cap via `EPYON_MAX_UPLOAD_UNZIPPED_MB`, default 2GB) into the same host-translatable `tmp/` workspace the Git-clone flow already uses. A single top-level wrapper folder (the common case when zipping a project directory) is auto-unwrapped so the scan is named after the project, not the upload wrapper.
- **Live Mobile Code Scanner Accuracy metrics on the Performance dashboard** — the "Mobile Code Scanner Accuracy" card previously showed hardcoded F1/precision/recall values baked into `app.js`. It's now backed by a new `GET /api/metrics/mobile-code-accuracy` endpoint that runs the mobile code scanner against its labeled test corpus (`tests/fixtures/mobile-code`) on demand and returns real precision/recall/F1/true-positive/false-positive counts (cached in-memory for 5 minutes, since the corpus is static). `tests/validate-mobile-code-scanner.py` now exposes a shared `compute_accuracy_metrics()` function used by both the CLI validation script and the web API, so the two can never drift. The card degrades gracefully (shows an "unavailable" message rather than failing the whole page) if the endpoint can't be reached.
- **Triage note on Jira ticket creation** — the "Create Jira Tickets" modal now has an optional "Triage note" field (a name). When set, Epyon posts a Jira comment on each newly created ticket in the batch: `"Triaged and added by: <name> on: <date>"` (date is filled in automatically server-side). `jira_client.create_ticket()`/`create_tickets_batch()` accept a `triage_note` parameter and post it via a new `jira_client.add_comment()` helper (`POST /rest/api/3/issue/{key}/comment`) after successful issue creation; a comment-posting failure never fails ticket creation itself. Tickets that already existed (`already_exists`) are left untouched — the note is only added when a ticket is newly created in that batch.
- **Self-assessment now validates 4 more previously best-effort/broken layers (5, 9, 10, 11)** instead of unconditionally reporting them `not_validated`/failing:
  - **Layer 5 (Helm)** — added a minimal, always-buildable fixture chart (`tests/fixtures/self-assessment/helm/epyon-fixture-chart/`); validated via `helm/helm-results.json`'s `summary.charts_built`.
  - **Layer 9 (Xeol/EOL Detection)** — directory-mode Xeol scanning can never detect an EOL runtime from a Dockerfile's `FROM` line alone (its cataloger only matches real installed binaries inside a built image). `run-self-assessment.sh` now builds the fixture's `inference/Dockerfile` (pinned to a permanently-EOL `python:2.7-slim`) into a real image and runs Xeol against it in `docker:` mode, writing `xeol/xeol-image-results.json`.
  - **Layer 10 (Anchore/Container Analysis)** — `run-anchore-scan.sh` now writes a real `anchore/anchore-policy-evaluation.json` policy gate (`gate_action`: `go`/`warn`/`stop`, configurable via `ANCHORE_POLICY_MAX_CRITICAL`/`ANCHORE_POLICY_MAX_HIGH`) evaluated across all of that scan's CVE severities — this is the layer's actual differentiator from Trivy/Grype (policy-based compliance gating, not another CVE list) and is what self-assessment now validates.
  - **Layer 11 (API Discovery)** — added a minimal fixed-route FastAPI fixture (`tests/fixtures/self-assessment/api/main.py`); validated via `api/api-discovery.json`'s `summary.total_endpoints_discovered`.
- **Layer 20 (ML Runtime Behavioral Analysis) can now sandbox against a remote Docker/Podman engine** — `run-ml-runtime-analysis.py` accepts `--docker-host` (or falls back to the `DOCKER_HOST` env var) for hosts without local container support (e.g. reachable only over VPN). The sandbox execution was refactored from a `docker run -v host:/work` bind mount (which only works when the CLI and engine share a filesystem) to `docker create` + `docker cp` + `docker start`, so it works identically against a local or remote engine. `run-target-security-scan.sh` passes through a new `ML_RUNTIME_DOCKER_HOST` env var when set.

### Fixed (deployed web UI scan reliability)
- **Deployed (docker-compose) scans silently returned zero findings for Secret Detection, Malware Detection, Vulnerability Scanning, and EOL Detection, and the SBOM/SBOM-export tools produced empty/broken output** — Epyon's deployed web container runs "docker-outside-of-docker": it spawns each scan tool (TruffleHog, ClamAV, Grype, Xeol, Syft's Docker fallback) as a *sibling* container via the host's mounted `docker.sock`, and `docker run -v <path>` bind-mount sources are always resolved by the **host** daemon against the host filesystem — never against Epyon's own container filesystem. `to_host_path()` (translating a container path like `/app/tests/...` to its real host equivalent via `HOST_PROJECT_DIR`) was already applied to Trivy, Checkov, Safety, and Anchore, but was missing from `run-trufflehog-scan.sh`, `run-clamav-scan.sh`, `run-grype-scan.sh` (both `dir:` and `sbom:` scan modes), `run-xeol-scan.sh` (`dir:` mode), and `export-sbom.sh`/`run-sbom-scan.sh`'s Docker-Syft fallback — so those tools' sibling containers silently bind-mounted an empty/nonexistent directory and reported a **false-clean** "0 findings" result with no error surfaced. `run-clamav-scan.sh` additionally staged its scan input under `/tmp/epyon-clamav-*` (to work around a macOS Docker Desktop VirtioFS bug with `~/Desktop` paths), which has no host equivalent at all in the containerized deployment; it now stages under `/app/tmp/epyon-clamav-*` (host-shared per `docker-compose.yml`'s `./tmp:/app/tmp` mount) when `HOST_PROJECT_DIR` is set, matching the pattern already used by `run-checkov-scan.sh`. This bug only manifested in the deployed web UI — local `./epyon.sh` runs and the GitHub Actions CI workflow (`run-epyon-scan-ci.sh`) run scan tools directly against the real host/runner filesystem with no sibling-container indirection, so they were never affected and could show different (correct) results for the same target than the deployed instance.
- **`export-sbom.sh` was completely non-functional (bash syntax error on every invocation)** — a prior commit (`4601485`) adding classification-marking support accidentally deleted the `# Find scan directory` / `if [[ -z "$SCAN_ID" ]]; then` opening lines while inserting the classification-marking block in their place, leaving a dangling `else` with no matching `if`. Restored the missing `if`/auto-detect-latest-scan logic ahead of the classification block. Also fixed the latest-scan auto-detection glob, which matched only scan directories containing the literal substring `_rnelson_` (a specific developer's username hardcoded from testing) instead of the general `{app}_{username}_{timestamp}` naming pattern, so "export latest scan" silently found nothing for any other user/environment.

### Fixed (deployed web UI scan reliability, round 2)
- **The deployed image never installed `jq`**, which nearly every scan script's own summary/count logic depends on via a `jq ... || echo "0"` fallback pattern (~96 call sites across `run-sbom-scan.sh`, `run-checkov-scan.sh`, `run-trivy-scan.sh`, `run-grype-scan.sh`, `run-anchore-scan.sh`). Without `jq`, every one of those tools produced a **real, correct results file** but silently printed/summarized `0` findings regardless of actual content — this was the root cause of Checkov, Trivy, Grype, and Anchore all appearing to find "0" in the deployed self-assessment despite their raw JSON output containing genuine findings. `jq` is now installed in the Dockerfile alongside `git`/`curl`.
- **The self-assessment fixture (`tests/fixtures/self-assessment/`) has no host-filesystem equivalent at all on an SSH-deployed instance**, unlike real user scan targets (which are always cloned/uploaded into the host-shared `tmp/` workspace before scanning). The fixture is baked into the image via `COPY . /app` at build time, so translating its container path with `to_host_path()` just produces a different, equally nonexistent host path — this affected every layer that bind-mounts the fixture directly (TruffleHog, Grype dir-mode, Syft's Docker fallback), while layers that already staged a copy into `/app/tmp` first (ClamAV, Checkov) were unaffected. `run-self-assessment.sh` now stages the entire fixture into the host-shared `tmp/` workspace (`$REPO_ROOT/tmp/epyon-self-assessment-fixture-$$`) whenever `HOST_PROJECT_DIR` is set, before running any scan layer, and cleans it up on exit.
- **SBOM generation (Layer 1) produced no CycloneDX output in the deployed image**, because the Docker-fallback path (used when a local `syft` binary isn't installed) tried to convert syft-json to CycloneDX with a **local** `syft convert` invocation — which doesn't exist in that environment either. It now runs the same conversion via a disposable `anchore/syft:latest` container. Additionally, `compare-self-assessment.py`'s `_count_sbom_components()` only recognized CycloneDX's `components`/SPDX's `packages` keys, so a working syft-native-only scan (no CycloneDX counterpart) was still reported as `found 0`; it now falls back to the syft-native file's `artifacts` key per scan_type, without double-counting when both a CycloneDX file and its syft-native source are both present.

### Fixed (deployed web UI scan reliability, round 3)
- **Layer 8 (Grype) SBOM-based scanning was completely broken in the deployed web UI** — `run-grype-scan.sh`'s containerized SBOM-scan branch declared `local sbom_file_host` at top-level script scope (outside any function), which is invalid in bash and, combined with `set -e`, aborted the entire script immediately — so Grype's SBOM scan (and the fallback "images" scan that follows it) never ran at all, silently producing an empty results file. This is the same `to_host_path()` translation work from the "round 1" fix above, but the fix itself introduced this bug by copying a `local` declaration into a non-function context. Removed the invalid `local` keyword; the containerized dir-mode scan branch (inside `run_grype_scan()`, a real function) was unaffected.
- **Model Provenance (Layer 18) self-assessment fixture never actually triggered a typosquat finding** — the fixture's `config.json` set `_name_or_path` to `bert-base-uncased-cracked`, an appended-suffix variant of `bert-base-uncased` with a Levenshtein distance of 8, far outside the tool's `0 < distance < 3` typosquat-detection window (by design, to avoid false-positiving on legitimate fine-tuned model names). The tool was working correctly the whole time; the fixture just wasn't calibrated to trip it. Changed the fixture's `_name_or_path` to `gpt-2` (distance 1 from the blocklist's `gpt2` target — a realistic squat of the real Hugging Face model name), which now reliably produces a `typosquat_warning` finding.

### Added
- **`.epyon-ignore.yml` `type: path` rules now genuinely exclude matching paths from being scanned at all, not just from post-hoc reports** — previously, `type: path` suppression (e.g. the pre-existing `tests/fixtures/self-assessment/**` rule that keeps Epyon's own deliberately-vulnerable self-assessment fixture out of normal scans of the Epyon repo) was only wired into the CI severity gate and the Checkov section of the static dashboard; Grype, Trivy, ClamAV, TruffleHog, SBOM/Syft, picklescan (Layer 14), model-provenance (Layer 18), and pip-audit (Layer 8.5) still scanned the excluded content and merely hid it afterward. A new shared helper, `get_epyon_ignore_exclude_paths()` (`scripts/shell/scan-directory-template.sh`), reads the target directory's own `.epyon-ignore.yml` for non-expired `type: path` entries and is now wired into every one of those tools via their native exclude mechanism (Checkov `--skip-path` — converted from the shared glob syntax to Checkov's required regex form, Trivy `--skip-dirs`, ClamAV `--exclude-dir`, Syft/Grype `--exclude`, and custom path-filtering in the two Python ML scanners and the pip-audit dependency-file `find`). Because the helper looks for `.epyon-ignore.yml` *inside* the directory being scanned, this is inherently self-scoping: a normal scan of the Epyon repo (where the ignore file lives) now genuinely never touches the fixture's content, while the self-assessment harness (whose scan target *is* the fixture, which has no `.epyon-ignore.yml` of its own) is completely unaffected and still detects every planted finding. The pre-existing post-hoc dashboard/CI-gate suppression is unchanged and still applies as a second layer of defense (e.g. for cached/already-scanned data).

- **Trivy's Dockerfile-driven base-image auto-discovery scanned Epyon's own self-assessment fixture's deliberately-EOL `python:2.7-slim` Dockerfile as a real base image**, flooding normal scans of the Epyon repo with irrelevant Python 2.7 vulnerabilities — the `.epyon-ignore.yml` path-exclusion feature above was wired into Trivy's `fs`/`config` invocations but not into the separate `find "$REPO_PATH" -name 'Dockerfile*'` loop that discovers candidate base images when no `PRIMARY_BASELINE_IMAGE`/`approved-base-images.conf` entry applies. That loop now honors the same exclusion patterns, so `tests/fixtures/self-assessment/inference/Dockerfile` (pinned to `python:2.7-slim` on purpose, to validate Layer 9/Xeol EOL detection in the self-assessment harness) is never treated as a real base image outside of that harness.
- **`.epyon-ignore.yml` rules using a tool name as the rule `type` itself (e.g. `type: anchore`, instead of the correct `type: tool` / `value: anchore`) silently suppressed nothing** — neither `filter-ignored-findings.sh`'s bash matchers nor `web/api/parsers.py`'s `_is_finding_suppressed()` (used by the web UI and `generate-dashboard.py`) have a branch for a rule `type` matching a tool name; the rule was parsed and cached without error, but never matched any finding, so e.g. an "suppress all Anchore findings" rule written as `type: anchore` / `value: "*"` left every Anchore finding (container CVEs, EOL packages, etc.) fully visible with no indication anything was wrong. `parse-epyon-ignore.sh` and `parsers.parse_suppressed_findings()` now detect this specific mistake for all known tool names (`grype`, `trivy`, `trufflehog`, `checkov`, `clamav`, `anchore`, `xeol`, `pip-audit`, `safety`, `sonarqube`) and normalize the rule to `type: tool` / `value: <tool-name>` (a form both matchers already understand correctly), emitting a `[WARNING]` in the scan log pointing at the correct syntax rather than silently doing nothing. `documentation/IGNORE_RULES_GUIDE.md`'s Tools section now calls this mistake out explicitly.

### Changed
- **"Check for Deleted Tickets" no longer auto-recreates the Jira issue** — `jira_client.reassign_orphaned_tickets()` now resets an orphaned fingerprint's ticket-map entry back to its original, unsubmitted state (removing it from the map) instead of calling `create_ticket()` on its behalf. The underlying finding simply reappears as an eligible candidate in the Jira Review screen, and the user manually re-submits it via the normal "Create Jira Ticket" flow whenever they choose. Applies both to the manual "Check for Deleted Tickets" button and the automatic post-scan/sync reconciliation (`reconcile_and_save()`), so a deleted issue is never silently recreated in the background.

### Fixed
- **Clicking a scan from the Performance page's "Scan Integrity Check" (or Applications/Scans list) could show "Scan not found" right after running the Self-Diagnostic** — `scripts/shell/run-self-assessment.sh` runs a real full scan into a temporary `scans/self-assessment_<user>_<timestamp>/` directory and deletes it once it finishes comparing results (unless run with `--keep-scan`). Because `find_scan_dirs()` had no awareness of this, that transient directory could be listed like any other scan while the self-diagnostic was running (or briefly after, due to the scans-list cache), and clicking into it after the harness's cleanup step removed it produced a 404. `find_scan_dirs()` now excludes any `self-assessment_*`-named scan directory from every listing (Scan Integrity Check, Applications, Scans, metrics) so it's never surfaced as a clickable scan in the first place.
- **Layer 5 (Helm) and Layer 8.5 (pip-audit) silently produced zero/failed results on any deployed instance** — the deployed web container's `Dockerfile` never installed the `helm` CLI or `pip-audit`, both of which `run-helm-build.sh`/`run-pip-audit-scan.sh` shell out to directly (unlike Trivy/Grype/etc., which run as their own Docker containers). Added `pip-audit` to the Dockerfile's pip install step and a Helm CLI binary install (arch-mapped, pinned to `v3.16.4`) alongside the existing Docker CLI install.
- **`run-helm-build.sh` produced invalid JSON (`helm/helm-results.json`) whenever a Helm lint had zero errors/warnings — the common case** — `LINT_ERRORS=$(grep -c "Error:" "$SCAN_LOG" 2>/dev/null || echo "0")` runs `grep -c`'s own "0" stdout output *and* the `|| echo "0"` fallback together when there are zero matches (grep exits 1 despite printing "0"), concatenating "0\n0" into the variable and corrupting the JSON output. Fixed by capturing `grep -c`'s output without the `||` fallback and only defaulting via `${VAR:-0}` when the variable is genuinely unset.
- **Every Anchore filesystem/SBOM scan (Layer 10) silently returned zero vulnerabilities on arm64 hosts (e.g. Apple Silicon dev machines/CI runners)** — `run-anchore-scan.sh` always passed grype's `--platform` flag for `dir:`/`sbom:` scan sources, but that flag is only valid for image sources; grype errored with `"platform is not supported for this source type"` and the script silently wrote an empty results file. Removed `--platform` from the `dir:`/`sbom:` invocations (still applied correctly for the image/base-image scan paths, where it's valid).
- **Layer 10 (Anchore) was functionally indistinguishable from Layer 8 (Grype)** — `run-anchore-scan.sh` only ever ran `anchore/grype:latest` under a different output directory name; its `anchore-policy-evaluation.json` output file was documented but never actually written. Added a real policy evaluation step that applies configurable pass/warn/stop compliance gates (`ANCHORE_POLICY_MAX_CRITICAL`/`ANCHORE_POLICY_MAX_HIGH`) across the scan's aggregated CVE severities — mirroring Anchore Engine's classic policy-bundle behavior — so this layer now has a genuine, distinct artifact beyond another CVE list.
- **Layer 13 (STIG Compliance)'s self-assessment status was ambiguous** — its manifest entry is permanently `validate: false` (STIG status isn't a plantable finding-count problem), but the UI/CLI rendered that identically to a layer the user hadn't selected to run at all (both showed a gray "SKIP"), so selecting Layer 13 and running it looked no different from not selecting it. The gumball label for `not_validated` is now "N/A" (vs. "SKIPPED" for an actually-unselected layer), and the comparator now does a best-effort check for whether the STIG assessment actually produced `stig-results-*.json` with assessed controls, surfacing "Tool ran and produced assessed controls" vs. "⚠️ tool may not have run" instead of a blank reason.
- **`docker build`/`docker save` transferred ~4.2GB+ of build context that had nothing to do with the application image**, making `scripts/deploy.sh` feel like it was shipping an 8GB payload. `.dockerignore` (unlike `.gitignore`, which already excluded these) was missing entries for the local Scan Storage & Retention archive database (`web/data/epyon.db`/`-wal`/`-shm`, ~2.1GB of runtime data) and stray `**/tmp-clones/`/`**/.tmp-clones/` git-clone workspaces. Added the missing `.dockerignore` entries; a fresh `docker build --no-cache` now transfers ~111KB of context instead of 4.21GB.
- **Temporary Git-clone workspaces for remote scan targets could land outside the repo's `scans/` directory** (`scripts/scans/.tmp-clones/...` instead of `<repo_root>/scans/.tmp-clones/...`), which meant they escaped `.dockerignore`'s existing top-level `scans/` exclusion and, if a scan was interrupted before its normal cleanup step ran, could accumulate multi-gigabyte stale clones inside `scripts/` indefinitely. `run-target-security-scan.sh`'s `CLONE_DIR` now uses the correct repo-root-relative path (`REPORTS_ROOT`, moved earlier in the script) instead of the scripts-directory path (`REPO_ROOT`).
- **STIG compliance and TRL score card never actually ran during local/`epyon.sh` full scans** — `run-target-security-scan.sh` (the local orchestrator) never invoked `run-stig-scan.sh` or `generate-trl-score.py` at all (only the CI orchestrator, `run-epyon-scan-ci.sh`, did), so every locally-run "full" scan's NIST SP 800-53 SSP Evidence Matrix showed those controls as missing evidence even though the scan appeared to succeed. A new "Layer 13: STIG Compliance Assessment" step (`SKIP_STIG`-gated) and a TRL score card generation step have been added to the `full` scan-type path, and manifest/TRL generation now runs *before* dashboard consolidation so the embedded SSP evidence matrix and exported `.md`/`.docx` snapshots see the finished artifacts instead of a false "missing" state at generation time.
- **NIST SP 800-53 SSP Evidence Matrix showed "⚠️ Missing Evidence" for controls whose evidence existed** — `parse_ssp_evidence_matrix()` was checking for artifact filenames that Trivy/TruffleHog never actually produce (`trivy/trivy-results.json`, `trufflehog/filesystem-results.json`) instead of their real output names (`trivy-filesystem-results.json`/`trivy-config-results.json`, `trufflehog-filesystem-results.json`). Fixed the artifact-path checks for the `SI-2` and `IA-5` controls.
- **SSP Evidence Matrix and Build Artifacts cards used a misleading "ℹ️ Optional / Skipped" label and started expanded** — a control missing evidence isn't optional, it's a gap that should be investigated; the label now reads "⚠️ Missing Evidence" everywhere it's rendered (web UI table and the standalone markdown export), and both accordion cards on the Performance page now start collapsed instead of forcing the page open on load.
- **Suppressed findings still counted in the web UI's top-level severity summary cards** — `_filter_suppressed_findings()` set `total_critical`/`total_high`/`total_medium`/`total_low` to the length of the full findings list (including suppressed ones), so a scan with 3 critical findings where 1 was suppressed still showed "CRITICAL: 3" instead of "CRITICAL: 2". These totals now subtract `suppressed_counts` per severity so the headline cards reflect only active findings; suppressed findings remain visible (dimmed, tagged) in the per-section finding lists.
- **Suppressions applied by `.epyon-ignore.yml` `path`/`cve` rules never took effect in the web UI when the scan ran in CI** — `.epyon-ignore.yml` isn't copied into scan artifacts, so `parse_suppressed_findings()` falls back to parsing `suppressed-findings.md`, which logs path/cve suppressions as `"<matched finding> (matched: <rule pattern>)"`. The parser was storing that entire literal, one-off string (e.g. `"reg.mini.dev:keycloak-fips/v26.7.4-dev (matched: reg.mini.dev:keycloak-fips/*)"`) as the rule's `value` instead of extracting the reusable glob pattern, so `fnmatch` never matched any other finding against it — only `package`-type rules (which don't use the `(matched: ...)` wrapper) worked correctly. The parser now extracts the pattern out of the `(matched: ...)` suffix.
- **`.epyon-ignore.yml` suppressions detected but not actually removed from the severity gate report** — `check-severity-gate.sh` builds a list of suppressed-finding fingerprints (via `is_cve_ignored`/`is_package_ignored`/etc.) and then re-filters the findings summary with an equivalent `jq` `fingerprint` function, but the two fingerprint definitions disagreed on the file-path component: the bash side fell back to `.target // .container_image` when `.file_path` was absent, while the `jq` side only ever used `.file_path`. Anchore/Grype container findings (which populate `container_image`, not `file_path`) therefore always fingerprinted differently between the two passes, so `package`/`cve`/`path` suppression rules were logged as matched in `suppressed-findings.md` but the finding still counted toward the gate and appeared in `security-findings-filtered.json`. The `jq` `fingerprint` definition now mirrors the bash extraction exactly.
- **Web UI scans of private GitHub repos failed to clone** — `fatal: could not read Username for 'https://github.com': No such device or address`. The web UI's job runner passed `GH_PAT`/`GITHUB_TOKEN` to the scan subprocess environment but never used it for the initial `git clone` itself, so any private repo failed before scanning even started (public repos worked fine, masking the bug). `jobs.py` now injects the configured token into `https://github.com/...` clone URLs (`https://x-access-token:{token}@github.com/...`) when one is available, and redacts it from job output/logs.
- **"Failed to resolve or create the selected Epic (502)" when creating a new Epic** — `create_epic()` hardcoded `issuetype: {"name": "Epic"}`, which fails with a silent 400 on any project whose scheme renames or omits the standard "Epic" type (the same class of bug previously fixed for regular ticket creation) — including projects where Atlassian has renamed the hierarchy level to "Parent". It now resolves the project's actual Epic/Parent issue type from `list_project_issue_types()` first, and logs the exact Jira response on failure so the root cause is diagnosable instead of a bare 502. Selecting an *existing* Epic was never affected — only the "create a new Epic" path.
- **Duplicate Epic creation from quick-create** — the "Create Jira Tickets" modal's quick-create buttons (and the free-text Epic name field) now check existing Epics for a name match before creating one, both client-side and in `jira_client.resolve_epic_selection()`. Previously, re-clicking a quick-create button (e.g. "High") across separate ticket-creation sessions created a duplicate Epic instead of reusing the existing one.
- **Epic picker never showed existing Epics** — `list_project_epics()` called the legacy `GET /rest/api/3/search` endpoint, which Atlassian fully removed on 2025-08-01; every call silently returned an empty list (swallowed by the broad exception handler), so the modal always looked like there were no existing Epics. Switched to `GET /rest/api/3/search/jql`.
- **"Check for Deleted Tickets" missed issues sitting in Jira's trash** — `_issue_exists()` used a direct `GET /rest/api/3/issue/{key}`, which Jira Cloud still returns `200` for up to ~60 days after a user deletes an issue (it's moved to trash, not purged). Switched to a JQL search, which excludes trashed issues immediately, so trashed-but-not-yet-purged tickets are now correctly recreated.
- **Ticket creation silently rejected by Jira with no diagnostic info** — added logging of the exact Jira HTTP status/response body on ticket-creation failures, and the "Create Jira Tickets" result popup now explains *why* each item failed (no longer eligible in this scan, suppressed, or rejected by Jira) instead of a bare count.
- **"Check for Deleted Tickets" appeared to do nothing** — the result message was set on the status element, then immediately wiped out because `renderJiraReview()` fully re-renders the page (including that element) right afterward. The status text is now applied after the re-render completes, and it lists which issue keys were recreated (`old → new`). Also tightened `_issue_exists()`'s JQL to `project = X AND key = Y` instead of a bare `key = Y`, since Jira Cloud's direct-key-lookup fast path for unscoped `issuekey =`/`key =` clauses is known to sometimes bypass trash filtering.

### Added
- **Ticket type selection in the "Create Jira Tickets" modal** — the modal now shows a dropdown of the project's real, creatable issue types (`jira_client.list_project_issue_types()`, via the extended `GET /api/scans/{scan_id}/jira-epics` response) so users can pick the right type per batch instead of relying on a single configured default. `jira_client.create_ticket()`/`create_tickets_batch()` also auto-repair an invalid configured issue type (`_resolve_issue_type()`) by falling back to the project's first valid type — this was the root cause of Jira rejecting every ticket with `400 "Specify a valid issue type"` for projects whose scheme doesn't include "Bug".
- **STIG stability freeze for repeated zero-evidence "Open" controls** — controls that keep landing on `Open`/confidence 0 (the model finds no static evidence at all, common for runtime-only session/login/cookie controls on apps without a traditional auth system) are now frozen and skipped after that exact outcome repeats once, instead of being re-sent to the AI on every single scan indefinitely. This was the single biggest source of wasted STIG scan time/tokens — previously the vast majority of controls on such a repo re-assessed to the same non-answer every run, forever. The freeze policy is now a standalone, unit-tested `compute_frozen_assessment()` function in `run-stig-assessment.py` (`tests/python/test_stig_freeze_logic.py`); frozen controls are marked `locked_by_stability` and surfaced in the web UI with a 💤 badge (distinct from the existing 🔒 human-lock badge). They remain `Open` and are never silently reclassified as satisfied.

### Fixed
- **Web UI "Run Scan" jobs silently produced false-clean results across every filesystem-based scan layer** (SBOM/Syft, Trivy filesystem/IaC, Checkov, Anchore/Grype, Safety) — Epyon's web container runs scan tools as **sibling** containers via the host's shared Docker socket (docker-outside-of-docker), so any `docker run -v <path>:...` issued from inside the web container is resolved by the **host** daemon against the **host filesystem**, not the web container's own filesystem. The web UI clones target repos to `/app/tmp/clone-{job_id}`, a path that only exists inside the web container and was never bind-mounted from the host, so every sibling-container mount of that path resolved to an empty directory and every dir-based scan tool "succeeded" with zero findings. Scans triggered by GitHub Actions CI (no container nesting) were unaffected. Added a shared `to_host_path()` helper (`scripts/shell/scan-directory-template.sh`) that rewrites `/app/...` container paths to their real host-visible equivalent using a new `HOST_PROJECT_DIR` env var (set in `docker-compose.yml`, defaults to `${PWD}` at `docker compose up` time), plus a new `./tmp:/app/tmp` bind mount so the clone workspace is host-visible. All affected `docker run -v` invocations in `run-sbom-scan.sh`, `run-trivy-scan.sh`, `run-checkov-scan.sh`, `run-anchore-scan.sh`, and `run-safety-scan.sh` now route their bind-mount sources through `to_host_path()`. Verified with a live end-to-end Docker test (not just static/unit checks) reproducing both the old failure and the new fix against a real sibling-container mount.
- **STIG scans silently produced zero output after a redeploy** — `docker-compose.yml` bind-mounts `./configuration:/app/configuration` on the host to persist STIG state across image rebuilds, which shadows the image's baked-in `configuration/stigs/` with whatever is (or isn't) on the host filesystem. If the host-side directory was empty or missing, Layer 13 failed in ~7 seconds with `STIGS_DIR not found`, and the orchestrator swallowed this as a non-fatal warning, so the overall scan "succeeded" with no STIG document produced and no clear error surfaced. The Docker image now keeps an immutable build-time backup of `configuration/` at `/opt/epyon-defaults/configuration` (outside `/app`, so the bind mount can never shadow it), and `run-stig-scan.sh` self-heals by non-destructively restoring `.cklb`/`.xml` files into `STIGS_DIR` from that backup whenever it's found empty.

## [3.19.0] - 2026-09-19

### Added
- **Per-scan Jira Epic assignment** — clicking "Create Jira Tickets" on the Jira Review screen now opens a modal to pick a Jira Epic for that batch. The modal fetches the project's real, existing Epics (`jira_client.list_project_epics()`, `GET /api/scans/{scan_id}/jira-epics`) so users can reuse one instead of creating duplicates; it also offers one-click creation of "Epyon Critical/High/Medium/Low" Epics or a custom name (`jira_client.create_epic()`, `resolve_epic_selection()`). The chosen Epic is linked to every ticket in the batch (`link_issue_to_epic()`, supporting both classic "Epic Link" custom fields and team-managed "parent" linking) and stored per-ticket for later reference — there is no global/category-based Epic configuration.
- **Orphaned Jira ticket reassignment** — if a tracked Jira issue is deleted out-of-band, Epyon detects it (`jira_client.reassign_orphaned_tickets()`) and automatically recreates the ticket (re-linked to its original Epic) using a snapshot of the finding captured at creation time, preserving the same fingerprint and history. Runs automatically on every post-scan/manual sync, and on-demand via a new "Check for Deleted Tickets" button on the Jira Review screen or `POST /api/jira/reassign/{app_name}`.

## [3.18.0] - 2026-09-19

### Added
- **Scan database & 90-day retention** — `scans/` no longer grows unbounded. A new SQLite database (`web/data/epyon.db`, see `web/api/db.py` / `web/api/scan_store.py`) durably stores each scan's parsed summary (findings, STIG results, score card) via `parsers.load_scan_complete()`. A daily background sweep (`_retention_loop` in `web/api/main.py`) ingests new/changed scan folders, then compresses (tar+gzip, ~10x smaller) any folder older than `EPYON_SCAN_RETENTION_DAYS` (default 90) into the database and removes it from disk, freeing space while keeping full history available. `GET /api/scans/{id}` transparently falls back to the DB summary for archived scans; raw-file endpoints (SBOM, dashboard, STIG md/cklb, ZIP export) return `410` with a restore hint instead of `404`. `POST /api/scans/{id}/restore` re-extracts an archived scan's raw files to disk for `EPYON_SCAN_RESTORE_HOURS` (default 24). New admin endpoints `GET /api/retention/status` and `POST /api/retention/run`, plus a standalone CLI (`scripts/shell/scan-db-tool.py backfill|sweep|status|restore`) for one-time backfill of existing scans and manual/cron-driven operation. `DELETE /api/scans/{id}` now also purges the DB row/archive blob for archived scans.

## [3.17.1] - 2026-09-19

### Fixed
- **Docker-hosted Ollama configuration** — Docker Compose now passes the configured AI model and a Docker-specific endpoint through to the web container, and resolves `host.docker.internal` to the host gateway. This allows a locally running Ollama service to remain the primary AI provider while the native launcher continues to use `localhost`.

## [3.17.0] - 2026-09-18

### Added
- **Local-first AI provider with OpenAI fallback** — the AI Executive Summary primary endpoint can now point at a locally hosted, OpenAI-compatible LLM (e.g. [Ollama](https://ollama.com) at `http://localhost:11434/v1`), configurable via Settings → AI Executive Summary or the `OPENAI_BASE_URL`/`OPENAI_MODEL` env vars. An optional secondary OpenAI fallback (`fallback_enabled` + `fallback_model`, or `OPENAI_FALLBACK_MODEL`) automatically retries once against the public OpenAI API if the self-hosted primary fails or is unreachable and `OPENAI_API_KEY` is set. All AI summary/fix-suggestion call sites in `web/api/openai_summary.py` now route through a single `_chat_completion()` helper that implements this failover.

## [3.16.0] - 2026-09-18

### Added
- **Web UI Docker deployment** — added `web/Dockerfile`, root `docker-compose.yml`, and `scripts/deploy.sh` for containerized deployment of the Epyon dashboard to a local Docker engine or a remote host over SSH. The container bundles the Docker CLI and bind-mounts the host's container socket (docker-outside-of-docker) so scan layers still execute on the host engine; `scans/`, `configuration/`, and `web/data/` are bind-mounted for persistence. Defaults to port `8057` (override with `EPYON_PORT`).

## [3.15.0] - 2026-09-18

### Added
- **Manual Jira ticket review** — scan details now link to a review queue where users can filter and select vulnerability, misconfiguration, secret, and ML/AI findings before creating Jira tickets. The queue supports filter-aware and per-category bulk selection, finding details, duplicate status, chunked creation, and partial-failure retry.
- **Scan-scoped Jira APIs** — added candidate and fingerprint-only batch creation endpoints with server-side finding resolution, suppression enforcement, stable deduplication, and immediate persistence after each successful Jira issue creation.
- **Per-application Jira projects** — each application can set its own Jira project key from Jira Review while sharing global Jira credentials; the Settings key remains the backward-compatible fallback.

### Changed
- **Jira creation is always manual** — automatic creation has been removed from both web reconciliation and GitHub Actions. New tickets can only be created through Jira Review; automatic closure of remediated tickets and reopening of recurring findings remain enabled for tracked tickets across all finding categories.
- **Integration tokens are environment-only** — Jira, GitHub, OpenAI, and NVD credentials can no longer be entered in Settings or persisted in JSON files. Legacy file tokens are removed on read; deployments inject `JIRA_API_TOKEN`, `GITHUB_TOKEN`/`GH_PAT`, `OPENAI_API_KEY`, and `NVD_API_KEY` through the process environment.

## [3.14.4] - 2026-09-16

### Fixed
- **CI Phase 0 build evidence wiring** — the reusable GitHub Actions workflow now honors `BUILD_ENABLED`, `IMAGE_NAME`, `IMAGE_TAG`, and `COSIGN_KEY` by running the Phase 0 build, provenance, and signing scripts in `run-epyon-scan-ci.sh`, and it routes successful built images to downstream container scanners.

## [3.14.3] - 2026-09-15

### Fixed
- **Draft pull requests triggered security scans** — `scan-private-repo.yml`'s `pull_request` trigger had no `types:` filter, so GitHub's default event types (`opened`, `synchronize`, `reopened`) fired the `security-scan-pr` job on draft PRs too. The job now requires `github.event.pull_request.draft == false`, and the trigger explicitly lists `opened`, `synchronize`, `reopened`, and `ready_for_review` so the quick-gate scan runs automatically as soon as a draft is marked "Ready for review" (or on the next push), instead of scanning drafts that aren't ready for review.
- **Dashboard and suppression parity** — the Web UI and offline dashboard now share the same scan-data loader, preserve separate STIG `Not Applicable` and `Not Reviewed` counts, and apply package, wildcard CVE, and secret-pattern suppressions consistently.
- **Scan output validation** — CLI and CI scans now validate their core review artifacts before reporting completion, with optional checks for container-build evidence.

## [3.14.2] - 2026-09-11

### Fixed
- **Build Evidence Card showed false "Captured" status for missing artifacts** — `buildBuildEvidenceCard()` in `app.js` hardcoded `present: true` for all 10 rows of the "Release & Evidence Artifact Inventory" table (Image Digest, OCI Manifest, Dockerfile, Build Log, SLSA Provenance, Cosign Signature, SBOM, Vulnerability Scans, Scan Manifest, Suppression Audit), and always rendered the OCI Manifest / SLSA Provenance badges regardless of whether those files actually existed. Source-only scans (no `BUILD_ENABLED=true`) falsely showed all 10 artifacts as "✅ Captured" even when `build/`, `provenance.jsonl`, and `image.sig` were never generated. Rows now reflect the real `artifacts` flags returned by `parse_build_evidence()` in `web/api/parsers.py`, showing "⚠️ Not Captured" when a file is absent. Added a new `vuln_scans` flag (checks for `grype/`, `trivy/`, `clamav/` directories) to support the Vulnerability & Malware Scans row. Affects both the web UI and the static `security-dashboard.html` export, since both share `buildBuildEvidenceCard()`.

## [3.14.1] - 2026-09-11

### Fixed
- **Static Dashboard / Web UI Parity for ML Security Layers** — `generate-dashboard.py` (the self-contained `security-dashboard.html` generator) was missing Layer 18 (Model Provenance & Threat Intelligence), Layer 19 (Inference Environment Security), and Layer 20 (ML Runtime Behavioral Analysis) data, so the ML/AI Security card silently omitted these findings in the exported static dashboard while the web UI showed them. The static generator now calls `parse_model_provenance_dir()`, `parse_inference_security_dir()`, and `parse_ml_runtime_dir()` from `web/api/parsers.py` and includes their results in the embedded `window.__SCAN__` object, matching the `GET /api/scans/{scan_id}` response.

## [3.14.0] - 2026-09-10

### Added
- **Phase 0 Container Image Building & Supply Chain Attestation** (`BUILD_ENABLED=true` / `--build-image`) — Optional pre-scan pipeline phase that builds Docker/OCI container images using available container runtimes (`docker`, `podman`, `buildah`, `nerdctl`).
- **10-of-10 Release & Evidence Artifact Collection** — Extracts immutable SHA-256 image digests (`build/image-digest.txt`), OCI manifests (`build/oci-manifest.json`), and build execution logs (`build/build.log`).
- **SLSA v1.0 Provenance Attestation** (`generate-slsa-provenance.sh`) — Generates in-toto SLSA v1.0 build provenance predicates (`provenance.jsonl` and `provenance.json`) capturing builder identity, commit SHA, source repo URL, and subject image digest.
- **Cryptographic Image Signatures** (`sign-image-cosign.sh`) — Integrates Cosign image signing and generates signature metadata records (`image.sig`).
- **Web UI & Dashboard Build Evidence Card** — Displays Image Identifier, Immutable SHA-256 Digest, OCI Manifest status, SLSA Provenance status, and Cosign Signature status in both Web UI and HTML dashboard deliverables.
- **Scan Manifest Integration** — Hashes image build digests, SLSA provenance statements, and Cosign signature files into `scan-manifest.json`.
- **New Documentation Guide** (`documentation/CONTAINER_BUILD_AND_EVIDENCE_GUIDE.md`) — Comprehensive reference for container image building, 10-of-10 artifact tracking, SLSA provenance, and Cosign verification.

## [3.13.3] - 2026-09-09

### Fixed
- **Package-version suppressions** — correctly apply `package` rules to findings that also have a CVE or GHSA identifier, including vulnerability findings in the deduplicated severity-gate summary; filtering now also works with macOS's Bash 3.2.

## [3.13.2] - 2026-09-01

### Fixed
- **ML dependency fixtures** — upgraded the fixture packages used by direct dependency scanning to supported releases: PyTorch 2.8.0, Transformers 4.57.6, and NumPy 2.0.2.
- **Typosquatted fixture packages** — replaced `tensorflo`, `torh`, `troch`, and `transformres` with legitimate package names and supported releases. Dedicated mock scanner results continue to cover typosquatting detection.

## [3.13.1] - 2026-07-30

### Fixed
- **Critical: Workflow fails when GitHub Issues disabled** — added graceful degradation for repositories with Issues feature disabled
  - Root cause: Three workflow steps (`Comment on PR`, `Create Scan Notification Issues`, `Link Jira Tickets to GitHub Issue`) made unguarded GitHub Issues API calls that returned HTTP 410 when Issues were disabled, causing the entire workflow to fail even though the security scan succeeded
  - Added `continue-on-error: true` to all three steps to prevent workflow failure
  - Wrapped all `github.rest.issues.*` API calls in try-catch blocks with specific error handling for 410 (Issues disabled) and 403 (insufficient permissions)
  - Added informative console warnings explaining why issue creation was skipped
  - Impact: Repositories with Issues disabled (common for public repos, private repos, or organizations with restricted settings) would see the Epyon scan fail completely despite successful security scanning, blocking CI/CD pipelines
  - Now: Workflow continues successfully, all artifacts (dashboard, reports, Jira tickets) are still created, and clear warning messages explain which notification features were skipped

## [3.13.0] - 2026-07-30

### Added
- **Comprehensive ML/AI Security Suite** — Five integrated capabilities to detect AI supply chain attacks, malicious model exploits, and infrastructure misconfigurations
  - **Layer 14 Enhanced**: Comprehensive Model File Analysis — Multi-format scanner detects malicious code in pickle, PyTorch, ONNX, TensorFlow, and config files; identifies dangerous imports, JIT exploits, operator injection, and obfuscation patterns
  - **Layer 18 NEW**: Model Provenance & Threat Intelligence — Validates model authenticity via blocklist matching (SHA256 hashes, compromised authors/repos), typosquatting detection (Levenshtein distance < 3), GPG signature verification, and HuggingFace reputation checks
  - **Layer 19 NEW**: Inference Environment Security — Static analysis of Dockerfile, docker-compose, and Kubernetes manifests for 25+ misconfigurations (privileged mode, root user, dangerous capabilities, missing security contexts)
  - **Layer 20 NEW**: ML Runtime Behavioral Analysis — Opt-in sandboxed model loading with behavior monitoring (network attempts, file access, subprocess execution); isolates potentially malicious models in Docker/Podman containers with network disabled
  - **Layer 8.5 Enhanced**: ML-Aware Dependency Analysis — Extended pip-audit with ML framework recognition (40+ packages), typosquatting detection for ML packages, and high-severity ML CVE highlighting
  - **Layer 13 Enhanced**: ML STIG Compliance — 15 AI/ML security controls covering model security, supply chain, infrastructure, and runtime behavior; rule-based assessment using findings from Layers 14/18/19/20
- **ML Threat Intelligence Blocklist** (`configuration/ml-blocklist.json`) — Versioned threat feed with blocked model hashes, compromised authors, malicious repos, suspicious name patterns, and typosquat targets; supports remote threat feeds via URL
- **Web UI ML Security Integration** — New ML/AI Security card in scan detail view with findings from all 5 layers; 🧠 ML source badge for ML-specific findings; enhanced `buildModelSecurityCard()` supports dual schema (backward compatible)
- **97 New BATS Tests** — Comprehensive test coverage for all ML security layers: 20 tests for Layer 14, 19 for Layer 18, 21 for Layer 19, 20 for Layer 20, 17 for enhanced Layer 8.5; all passing
- **ML Security Guide** (`documentation/ML_SECURITY_GUIDE.md`) — 1000+ line comprehensive guide covering threat model, layer details, usage examples, best practices, threat intelligence maintenance, performance considerations, and troubleshooting

### Changed
- **Layer 14 (Pickle Safety)** — Rewritten from bash-only to Python-based scanner (`run-picklescan.py`) with multi-format support; backward-compatible JSON schema (array for enhanced, object for legacy); auto-detects and scans pickle, PyTorch JIT, ONNX, TensorFlow SavedModel, and config files
- **Layer count** — Updated from 17 layers to 20 layers across all documentation (README, SCAN_MATRIX, copilot-instructions)
- **Orchestration integration** — All ML layers integrated into `run-target-security-scan.sh` (local) and `run-epyon-scan-ci.sh` (CI/CD) with proper skip logic and scan mode awareness
- **API parsers** (`web/api/parsers.py`) — Added 4 new parsers for ML layers with schema normalization; updated `parse_scan_findings()` and `load_scan()` to include ML layer data
- **Frontend UI** (`web/static/app.js`) — Enhanced finding classification, added ML badge rendering, updated Model Security card to display 5 layers with proper status aggregation

### Fixed
- **Typosquatting false positives** — Exact matches (Levenshtein distance == 0) now excluded from typosquatting detection; prevents legitimate models from being flagged
- **HuggingFace metadata detection** — Removed early return in `_check_hf_metadata()`; always checks `config.json` regardless of `.huggingface/` directory presence

## [3.12.9] - 2026-07-09

### Fixed
- **Suppressed findings still showing in scan list dashboard** — scan overview counts were not filtering out suppressed findings
  - Root cause: `load_scan()` was reading counts directly from `security-findings-summary.json` (which includes all findings) without applying suppression filtering. The v3.12.6 filter was only applied in detail views (`load_enriched_findings()` and `parse_scan_findings()`), not in the scan list.
  - Changed `load_scan()` to call `load_enriched_findings()` (which applies filtering) instead of reading raw summary counts
  - Fallback to raw counts only if filtered findings cannot be loaded
  - Impact: Scan list dashboard (home page) showed inflated critical/high/medium/low counts including suppressed findings, while drill-down detail views showed correct filtered counts — creating confusing metric discrepancies
  - Now both scan list AND detail views exclude suppressed findings consistently

## [3.12.8] - 2026-07-07

### Fixed
- **Critical: Duplicate Jira tickets created on every scan** — strengthened duplicate prevention logic to ensure only one ticket per vulnerability
  - Root cause: The ticket map check was performed AFTER the previous scan check, creating a race condition where persistent findings could bypass the duplicate check if the previous scan comparison failed
  - Changed check order: ticket map is now checked FIRST (absolute source of truth), then previous scan (determines if "new")
  - Logic flow now guarantees:
    1. If open ticket exists for fingerprint → skip (prevents duplicates)
    2. If closed ticket exists → allow new ticket only if finding wasn't in previous scan (handles reappearances)
    3. If finding was in previous scan → skip (persistent finding, not new)
    4. Only create ticket if: no open ticket exists AND finding is genuinely new
  - Added detailed comments explaining the two-phase check and edge cases
  - Impact: Multiple tickets were being created for the same vulnerability across scans, causing Jira spam and inflated metrics
  - **Fingerprinting is stable**: Uses normalized paths and tool+id+package+target+app+project to ensure same finding = same fingerprint across scans

## [3.12.7] - 2026-07-07

### Fixed
- **Jira ticket creation not working from environment variables** — new findings were not creating tickets even when expected
  - Root cause: `create_on_new` setting was hardcoded to `False` when loading Jira config from environment variables. Only the web UI config file allowed enabling automatic ticket creation.
  - Added `JIRA_CREATE_ON_NEW` environment variable (accepts: true/false/1/0/yes/no/on/off, default: false)
  - Added `JIRA_AUTO_CLOSE` environment variable for consistency (was hardcoded to `true`, now configurable)
  - Updated module docstring to document all supported environment variables
  - Impact: CI/CD workflows and automated deployments could not enable automatic ticket creation without manually editing the web UI config file, blocking unattended operation
  - **To enable automatic ticket creation**: Set `JIRA_CREATE_ON_NEW=true` in your environment or workflow secrets
  - **Default behavior unchanged**: Auto-creation remains disabled by default to prevent Jira spam; auto-closure remains enabled by default

## [3.12.6] - 2026-07-07

### Fixed
- **Critical: Suppressed findings appearing in dashboard** — findings marked as suppressed via `.epyon-ignore.yml` rules were still showing up in the web UI dashboard and scan detail views
  - Root cause: `parse_scan_findings()` and `load_enriched_findings()` collected all findings from tool outputs but never filtered against the suppressed findings list from `suppressed-findings.md`
  - Added `_is_finding_suppressed()` to check if a finding matches any suppression rule (exact match, wildcard, or pattern match)
  - Added `_filter_suppressed_findings()` to remove suppressed findings from the critical/high/medium/low arrays and recalculate summary counts
  - Integrated filtering into both `parse_scan_findings()` (raw tool output parsing) and `load_enriched_findings()` (enriched summary file)
  - Suppressed findings remain available in the separate `suppressed_findings` array for audit/reporting purposes
  - Matching logic: CVE suppressions match on vulnerability ID; secret suppressions match on detector name; IaC suppressions match on check ID; wildcards (`*`) suppress all findings of that type
  - Impact: dashboards showed inflated vulnerability counts including findings that were intentionally suppressed with documented justifications, creating noise and reducing trust in metrics

## [3.12.5] - 2026-07-06

### Fixed
- **Critical: Web UI Jira ticket auto-closure not working** — tickets for remediated vulnerabilities were not being closed by the FastAPI-based reconciliation system
  - Root cause: `reconcile_app()` only checked findings from the immediate previous scan to determine what to close. If a vulnerability was remediated multiple scans ago, its fingerprint wouldn't appear in `previous_fps`, so the loop never attempted to close that ticket.
  - Changed logic to iterate over ALL open tickets in the ticket map and close any that are not present in the current scan, regardless of when they were remediated
  - Added app_name and project_key filtering to prevent closing tickets for other applications
  - Improved ticket creation logic to allow creating new tickets for previously-closed findings that reappear (e.g., reintroduced vulnerabilities)
  - Impact: tickets remained open indefinitely even after vulnerabilities were fixed, causing inflated security metrics and manual cleanup burden
  - Note: This fix is for the Python-based `web/api/jira_client.py` system used by the web UI. The shell-based `scripts/shell/create-jira-tickets.sh` used in GitHub Actions workflows was fixed separately in v3.12.4.

## [3.12.4] - 2026-07-02

### Fixed
- **Critical: Jira ticket auto-closure not working** — resolved CVEs were not closing tracked tickets
  - Root cause: CVE map persistence logic in `create-jira-tickets.sh` was failing to replace large/complex JSON maps stored in GitHub issue comments, causing old maps to be retained while new ones were appended. The read function always found the oldest/smallest map, so newly resolved CVEs were never detected for closure.
  - Changed `store_cve_map_in_github()` to remove ALL existing map markers before appending fresh one, preventing duplicate/stale markers
  - Changed regex pattern from attempting conditional replace to unconditional remove-then-append
  - Added closure loop summary logging: "✅ Closed N resolved CVE ticket(s)" or "ℹ️ No resolved CVEs to close"
  - Added debug verification when `EPYON_DEBUG=true` to confirm map round-trip persistence
  - Symptom: scans showing "11 previously tracked CVEs" when previous scan persisted 57 — 46 CVEs should have been closed but weren't
  - Impact: tickets for remediated vulnerabilities remained open indefinitely, inflating security debt metrics

## [3.12.3] - 2026-07-01

### Fixed
- **Backward Compatibility**: Restored `skip_stig` workflow input (deprecated) to prevent breaking existing repositories
  - v3.12.0 removed `skip_stig` in favor of `run_stig`, breaking production workflows
  - Repos using `skip_stig: true` in their workflows got error: "Invalid input, skip_stig is not defined"
  - Both `skip_stig` (old) and `run_stig` (new) now work during transition period
  - `skip_stig` is marked as DEPRECATED and will be removed in a future major version
  - SKIP_STIG logic now handles both inputs: `skip_stig: true` → skip, `run_stig: true` → enable
  - Existing repos can migrate at their own pace without immediate workflow failures

### Migration Guide
- **If using `skip_stig: true`**: Remove it entirely (STIG now skipped by default)
- **If using `skip_stig: false`**: Change to `run_stig: true` (explicit opt-in)
- **If not using skip_stig**: No action needed (already using new default behavior)

## [3.12.2] - 2026-07-01

### Fixed
- **Critical**: Corrected tool result file paths in `_get_layer_result_file()` causing webhook results to not be sent
  - SBOM: `filesystem.cyclonedx.json` (was looking for `filesystem-cyclonedx.json` with hyphen)
  - Grype: `grype-sbom-results.json` (was looking for `grype-results.json` without mode suffix)
  - Trivy: `trivy-filesystem-results.json` (was looking for `trivy-results.json`)
  - TruffleHog: `trufflehog-filesystem-results.json` (was looking for `trufflehog-results.json`)
  - Xeol: `xeol-filesystem-results.json` (was looking for `xeol-results.json`)
  - Each tool appends its scan mode to the filename - this was not accounted for in v3.12.1
  - Files didn't exist at expected paths, so webhook fell back to progress updates only
  - Barbatos received no actual findings data despite successful scans

## [3.12.1] - 2026-07-01

### Fixed
- **Critical Webhook Bug**: Tool scan results were not being sent to Barbatos, causing 0 findings to appear even when scans succeeded
  - Added `_get_layer_result_file()` function to map layer names to JSON output paths
  - Updated parallel layer completion to pass result file paths to webhook sender
  - SBOM, Grype, Trivy, TruffleHog, Checkov, and other tool results now sent to Barbatos
  - Added file size validation (warn >5MB, skip >10MB) to prevent oversized payloads
  - Added JSON validation before sending to catch malformed output files
  - Graceful fallback to progress updates if result files are missing or invalid
  - Barbatos will now show actual CVEs, secrets, IaC issues, API endpoints, and SBOM data

## [3.12.0] - 2026-07-01

### Changed
- **BREAKING**: STIG (Layer 13) is now **opt-in** by default instead of opt-out
  - Added `run_stig` workflow input (default: `false`)
  - Removed `skip_stig` workflow input
  - STIG now only runs when `run_stig: true` OR `scan_mode: stig`
  - **Full scans (`scan_mode: full`) no longer include STIG by default**
  - Rationale: STIG assessments are expensive (OpenAI API costs) and not needed for most CI pushes
  - Weekly Sunday scheduled scans still run STIG via explicit `run_stig: true`
  - To enable STIG on CI pushes to main: set `run_stig: true` in workflow inputs

### Migration Guide
- **If you want STIG on full scans**: Add `run_stig: true` to your workflow inputs
- **If you were using `skip_stig: true`**: Remove it (this is now the default behavior)
- **scan_mode: stig**: Still automatically enables STIG (no change needed)

## [3.11.9] - 2026-07-01

### Fixed
- **Webhook Integration**: Complete rewrite of webhook system to match official Barbatos Security Scan Webhook API v1.0 specification
  - Fixed HTTP 400 errors caused by payload structure mismatches
  - Implemented 5 distinct payload types per Barbatos API contract:
    1. Progress (layer): `{"progress": {"layer": 1, "name": "syft", "total": 16}}`
    2. Progress (step): `{"progress": {"step": "checkout-repo", "label": "message"}}`
    3. Tool results: `{"tool": "grype", "content": {...actual JSON...}}`
    4. Completion: `{"done": true}`
    5. Error: `{"error": "message"}`
  - Job ID now sent ONLY in `X-Epyon-Job-Id` header (removed from body)
  - Tool names standardized to lowercase: syft, grype, trivy, trufflehog, checkov, xeol
  - Added layer number tracking (1-16) for real-time progress indicators
  - Removed unnecessary fields from payload: jobId, appName, scanId, timestamp, eventType, status
  - Added `scan_start` and `scan_complete` webhook notifications
  - Added support for sending actual tool JSON output via `result_file` parameter
  - Tool name mapping: `layer-1---sbom` → `syft`, `layer-8---grype` → `grype`, etc.
## [3.11.8] - 2026-06-24

### Added
- **CVE Source Indicators** — Added colored source badges showing which vulnerability database each CVE comes from
  - Tracks source for Grype, Anchore, and Trivy findings (GHSA, NVD, Alpine, Debian, Ubuntu, RHEL, etc.)
  - Visual icons with tooltips: 🛡️ GHSA, 🏛️ NVD, 🏔️ Alpine, 🌀 Debian, 🟠 Ubuntu, 🎩 RHEL, 🔍 Trivy, 🦑 Grype
  - Helps security teams understand the provenance and reliability of vulnerability data
  - Displayed next to CVE IDs in scan finding details

## [3.11.7] - 2026-06-24

### Changed
- **Settings UI Cleanup** — Removed "Approved Base Images" section from Settings page
  - This configuration file is managed directly in `configuration/approved-base-images.conf`
  - Not a runtime setting, doesn't need to be in the UI

## [3.11.6] - 2026-06-24

### Fixed
- **Settings UI - NVD Key Display** — Fixed NVD API key not showing "Current: XXX" hint after saving
  - Removed `&& !nvdCfg.from_env` condition that was inconsistent with OpenAI config behavior
  - Added automatic settings view refresh after saving AI and NVD configs to display updated key hints
  - NVD and OpenAI API key hints now consistently show for all saved keys

## [3.11.5] - 2026-06-23

### Fixed
- **Web API Cache Invalidation Bug** — Fixed `AttributeError: 'NoneType' object has no attribute 'get'` in `/api/applications` and `/api/stats` endpoints
  - `_invalidate_scan_cache()` was setting `_dir_cache = None` instead of calling `_dir_cache.clear()`
  - Caused crashes when loading scan lists after cache invalidation
  - Removed obsolete `_dir_cache_ts` variable reference

## [3.11.4] - 2026-06-23

### Fixed
- **Web UI Shell Auto-Detection Logic** — Fixed bash version detection to work when shebang starts in bash 3.2
  - Previous logic only checked if BASH_VERSION was unset, but `#!/usr/bin/env bash` always sets it (even for 3.2)
  - Now checks if current bash version < 4 and searches for bash 4+ to re-exec regardless of whether already in bash
  - Added Homebrew paths to subprocess PATH environment to help script find bash 4+ installations
  - Works across macOS (Homebrew), Linux (Linuxbrew), and standard system paths

## [3.11.3] - 2026-06-23

### Fixed
- **Web UI Shell Compatibility** — Added shell auto-detection to `run-epyon-scan-ci.sh` (the script invoked by web UI)
  - Web API now lets script shebang and auto-detection handle shell selection instead of forcing bash interpreter
  - Removed explicit bash invocation in `web/api/jobs.py` that was bypassing shell detection logic
  - Previously, web UI forced a bash interpreter which could be bash 3.2 on macOS, causing syntax errors
  - Scripts now correctly detect and use bash 4+ regardless of parent process shell

## [3.11.2] - 2026-06-23

### Fixed
- **Web UI Shell Compatibility** — Added shell auto-detection to `run-target-security-scan.sh` (the main orchestrator)
  - Web UI was calling the orchestrator directly, bypassing the shell detection in `epyon.sh`
  - Individual scan scripts (TruffleHog, Trivy, Grype, pip-audit, safety, picklescan) now run in bash regardless of how they're invoked
  - Eliminates all remaining `bad substitution` and `unbound variable` errors in web UI scans

## [3.11.1] - 2026-06-23

### Added
- **Cross-Platform Shell Auto-Detection** — `epyon.sh` automatically detects the current shell and re-executes in bash if needed
  - Eliminates bash syntax errors when run from zsh, sh, or other shells
  - Works identically across Linux (bash), macOS (zsh/bash), and Windows (Git Bash/WSL)
  - Auto-detects bash version and requires 4.0+ with clear upgrade instructions
- **Windows Batch Launcher** — `epyon.bat` provides helpful guidance for Windows CMD/PowerShell users
  - Detects installed Git Bash and offers to launch it
  - Clear setup instructions for Git Bash and WSL
- **Platform Support Documentation** — Comprehensive platform compatibility matrix in README
  - Setup guides for macOS, Windows (Git Bash), Windows (WSL)
  - Shell compatibility details and requirements

### Fixed
- **Shell Compatibility Issues** — Scripts now work identically whether run from CLI or GitHub Actions
  - Fixed `bad substitution` errors in pip-audit, safety, picklescan when run from zsh
  - Fixed lowercase parameter expansion (`${var,,}`) failures in non-bash shells
  - Eliminated differences between GitHub Actions (bash) and macOS CLI (zsh) execution
- **macOS Scan Failures** — Layers 11.5, 11.6, and 14 now complete successfully on macOS

## [3.11.0] - 2026-06-23

### Added
- **Multi-Feed CVE Enrichment** — CVE findings now enriched from seven international vulnerability feeds
  - **OSV.dev** — Open source package vulnerabilities across all ecosystems
  - **GitHub Security Advisories (GHSA)** — OSS ecosystem advisories with CVSS scores and patch info
  - **JVN (Japan Vulnerability Notes)** — Japanese vulnerability database with international CVE coverage
  - **EUVD (ENISA)** — European Vulnerability Database (planned)
  - **GitLab Advisory Database** — Git-backed OSS advisories (planned)
  - Existing feeds: NVD (NIST), CISA KEV
- **New Scripts**:
  - `fetch-cve-feeds.py` — Python feed aggregator with caching (24-hour TTL)
  - `enrich-findings-multi-feed.sh` — Multi-feed enrichment wrapper integrated into scan pipeline
- **Feed-Specific Data** — Findings now include `feed_sources` field with:
  - List of feeds that returned data
  - Feed-specific summaries (OSV summary, GHSA severity/count)
  - Timestamp of enrichment
- **Comprehensive Documentation** — `documentation/MULTI_FEED_CVE_ENRICHMENT.md` with:
  - Feed capabilities and coverage comparison
  - Configuration guide (GitHub token, cache settings)
  - Manual enrichment instructions
  - Troubleshooting guide
  - Instructions for adding new feeds

### Changed
- Scan orchestration now runs multi-feed enrichment automatically after NVD/KEV enrichment
- Default limit: 50 CVEs per scan (configurable via `MAX_FEED_CVES` environment variable)
- Feed data cached locally for 24 hours to minimize API calls

## [3.10.2] - 2026-06-23

### Changed
- **Major performance improvement for scan history loading** — All API endpoints now load only the last 35 days of scans by default
  - Reduces scan directory traversal from 1,200+ scans to ~35-50 scans
  - Dramatically improves page load times for Stats, Metrics, Applications, and STIG History pages
  - Added `days` parameter to `find_scan_dirs()` function with date-based filtering at filesystem level
  - Scan directory cache now aware of days parameter for efficient repeated queries
  - Older scans remain accessible via direct URL but are excluded from aggregate views

## [3.10.1] - 2026-06-23

### Changed
- **STIG History date filter** — Reduced maximum time range from 90 days to 35 days to improve page load performance
  - Filter button options now: 7d, 14d, 30d, 35d, All (was: 7d, 14d, 30d, 90d, All)
  - Default remains 30 days
  - Reduces query time for large scan histories

## [3.10.0] - 2026-06-22

### Added
- **NVD API Key configuration in web UI** — Settings page now includes a dedicated section for NVD (National Vulnerability Database) API key configuration
  - New `/api/nvd/config` endpoint (GET/POST) for managing NVD API keys
  - Supports both environment variable (`NVD_API_KEY`) and UI-managed config (`web/data/nvd-config.json`)
  - Environment variable takes priority when set; UI shows notification when env var is active
  - Key validation enforces UUID format required by NVD API 2.0
  - `enrich-findings.sh` automatically loads key from config file if not set via environment
  - Increases CVSS enrichment rate from 5 requests/30s (unauthenticated) to 50 requests/30s (with key)
  - Dramatically speeds up enrichment for scans with 20+ CVEs (from 6+ minutes to <30 seconds)

### Changed
- NVD API key can now be configured through web UI Settings page in addition to environment variable
- Enrichment script reads from `web/data/nvd-config.json` as fallback when `NVD_API_KEY` env var not set

## [3.9.0] - 2026-06-22

### Added
- **Container-specific vulnerability tracking in dashboards** — Scan findings now include container image names for all Anchore/Grype vulnerabilities
  - Each container vulnerability shows which image it came from (e.g., `myapp:latest`, `postgres:15-alpine`)
  - Web UI displays container name in "Container Image" field in finding detail modal
  - Dashboard tables show container name in "Location" column with 📦 Container badge
  - New helper script `list-container-vulnerabilities.sh` shows per-container breakdown with severity counts
  - CSV export functionality documented for container-specific analysis
- **Anchore automatic image detection** — Scanner now automatically detects container characteristics before scanning, eliminating false positives without manual configuration
  - Auto-detects architecture (ARM64/AMD64) from `docker image inspect` and sets `--platform` flag
  - Auto-detects base OS (Alpine/Debian/Ubuntu) from image labels, names, and history layers
  - Auto-detects runtime (Node.js/Python/Go/Java) by probing environment variables and binaries
  - Auto-excludes build-stage dependencies when single runtime detected (e.g., Node.js-only → exclude Python/Go/Java/Ruby)
  - Works transparently in GitHub Actions workflows without user intervention
  - Logs all detection decisions: architecture, base OS, detected runtimes, and auto-configured exclusions
- **Anchore manual configuration overrides** — Platform detection, distro logging, and package filtering for advanced use cases
  - `ANCHORE_PLATFORM`: Override auto-detected platform (linux/amd64, linux/arm64, linux/aarch64)
  - `ANCHORE_EXCLUDE_TYPES`: Override auto-detected runtime exclusions (comma-separated: python,go,java,ruby)
  - `ANCHORE_SHOW_DISTRO`: Log detected OS/distro after each scan (default: true) for debugging false positives
  - Post-scan filtering removes excluded package types from results with count logging
- **ANCHORE_CONFIGURATION_GUIDE.md** — Comprehensive documentation for auto-detection behavior and manual override scenarios

### Changed
- Anchore scanner now inspects Docker images before scanning to auto-configure platform and exclusions (eliminates need for manual env vars in 90%+ of cases)
- Scan logs now show auto-detected architecture, base OS, runtimes, and exclusion decisions for all image scans
- Environment variables (`ANCHORE_PLATFORM`, `ANCHORE_EXCLUDE_TYPES`) are now **optional overrides** rather than required configuration

## [3.8.5] - 2026-06-18

### Fixed
- **pip-audit and safety findings not appearing in dashboards** — `generate-scan-findings-summary.sh` used `jq -r` flag on extraction filters, which output newline-delimited JSON (NDJSON) instead of proper JSON arrays. Downstream `jq` filters expecting arrays (`.[] | select(...)`) operated on raw text and silently produced no results. Fixed by removing `-r` flag and wrapping extraction filters in `[...]` to produce valid arrays, ensuring Python CVE findings from both pip-audit and safety layers now categorize correctly by severity and flow through to `security-findings-summary.json` and dashboard rendering.

## [3.8.4] - 2026-06-18

### Fixed
- **Dashboard HTML corruption from CVE descriptions** — `generate-dashboard.py` was embedding `window.__SCAN__` JSON directly into a `<script>` block without escaping `</script>` sequences. CVE descriptions (e.g. DOMPurify disclosures) that contained the literal string `</script>` would prematurely terminate the script tag, breaking dashboard rendering entirely. Fixed by escaping `</` → `<\/` in the serialized JSON before injection. The escaping is transparent to JSON.parse in the browser — values round-trip correctly.

## [3.8.3] - 2026-06-18

### Fixed
- **pip-audit CLI compatibility regression** — `run-pip-audit-scan.sh` used deprecated/invalid `--file` flag while CI installs `pip-audit 2.10.x`, causing scanner failures with empty fallback outputs and no findings in dashboards. Updated invocation to use supported flags (`-r`, `--locked`, and project-path mode) and OSV service (`-s osv`).
- **pip-audit consolidated schema mismatch** — scanner wrote `results` while parsers expected `scan_results`, which prevented findings from flowing into `security-findings-summary.json` and dashboard renderers. Normalized consolidated output to `scan_results`.
- **Transitive dependency visibility gap vs Athena** — added resolved environment audit path in `run-pip-audit-scan.sh` that creates an isolated venv, installs project dependencies (`.[dev]` fallback to core), runs `pip-audit -l`, and merges discovered vulnerabilities into consolidated output as `__resolved_environment__`.
- **CI Python runtime alignment** — workflow now provisions Python 3.13 before dependency scanners, matching target project requirements and improving resolver parity with Athena checks.

## [3.8.2] - 2026-06-18

### Fixed
- **Python dependency layers not executing in CI** — GitHub workflow dependency install step did not install `pip-audit` or `safety`, so Layers 11.5/11.6 could start but produce no scan outputs. Added explicit `pip3 install pip-audit safety` in `.github/workflows/epyon-scan.yml` and propagated `SKIP_PIP_AUDIT` / `SKIP_SAFETY` into `/tmp/epyon-env`.
- **Safety findings missing from summary/dashboard** — corrected invalid jq filtering logic in `generate-scan-findings-summary.sh` safety block so findings are appended and deduplicated by the existing global dedupe pass.
- **Safety output normalization across JSON schemas** — `run-safety-scan.sh` now normalizes safety JSON into a stable internal schema (`id`, `package`, `installed_version`, `safe_version`, `advisory`, `severity`) before consolidation, improving compatibility across safety output variants.
- **Lockfile detection bug in safety scanner** — fixed basename checks for `poetry.lock` and `Pipfile.lock` so path comparisons work correctly with absolute file paths.

## [3.8.1] - 2026-06-18

### Fixed
- **Safety artifact upload ELOOP** — `run-safety-scan.sh` was creating self-referential symlinks (`safety-*-results.json` -> itself), which caused GitHub Actions artifact upload to fail with `ELOOP: too many symbolic links encountered`. Removed self-link creation, added stale safety symlink cleanup at scan start, and fixed invalid `local` usage outside function scope in scan loop.

## [3.8.0] - 2026-06-18

### Added
- **Layer 11.6 (safety)** — Python-specific vulnerability scanner with NVD + PyPI advisory database coverage. Complements pip-audit (Layer 8.5) by catching CVEs in pip-audit's database gaps (e.g., GHSA-jm82-fx9c-mx94 for pypdf). Scans `requirements.txt`, `poetry.lock`, and `Pipfile.lock`. Runs in all scan modes (quick, nightly, full, stig) via `SKIP_SAFETY=true`. Requires `safety` to be installed (`pip install safety`).

### Changed
- Epyon now orchestrates **17 security tool layers** (was 16)

## [3.7.0] - 2026-06-16

### Added
- **Layer 8.5 (pip-audit)** — Direct Python dependency vulnerability scanner. Complements Grype (Layer 8) by scanning `requirements.txt`, `poetry.lock`, and `Pipfile.lock` directly, catching CVEs missed by SBOM-based scanners (Syft/Grype), especially recently published GitHub Security Advisories. Runs in all scan modes (quick, nightly, full, stig). Requires `pip-audit` to be installed (`pip install pip-audit`).

### Changed
- Epyon now orchestrates **16 security tool layers** (was 15)

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
