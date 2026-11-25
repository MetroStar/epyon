# Future Improvements — Planning Notes

Status: items 1, 2, 4, 5, 11, 12, 13 are **done**; item 3 is **partially done** (see its
entry); item 14 is **mostly done**, with Jira-key mapping and automatic control-to-role
mapping still open. Items 6–10 remain analysis-only questions, not yet started. File and
line references were checked against `main` at 3.73.0 (PR #282 in review).

## Contents

| # | Item | Type |
|---|------|------|
| 1 | Run STIG for selected control(s) | Feature (done in 3.84.0) |
| 2 | STIG Findings page UI tightening | UI (done in 3.85.0) |
| 3 | Hide tools that did not run (scan detail) | UI/data (partially done in 3.86.0 — see entry) |
| 4 | Run Scan page redesign (4a–4d) | UI (done in 3.87.0) |
| 5 | Move STIG History & MTTR to the Metrics page | UI (done in 3.88.0) |
| 6 | Web-UI cron for scheduled scans | Analysis |
| 7 | Where to debloat Epyon | Analysis |
| 8 | Smaller containers | Analysis |
| 9 | "Lite" deployment mode (+ quick vs full comparison) | Analysis |
| 10 | Review of the quartz-evaluator YAML | Analysis |
| 11 | Editable STIG drawer fields | Feature (done in 3.81.0) |
| 12 | Jira button on the STIG drawer | Bug (fixed in #291) |
| 13 | Optional justification that never overwrites evidence | Feature (done in 3.81.0) |
| 14 | Projects: pairing repos, repos in many projects, front-end/back-end STIG pairing | Feature (done in 3.79.0-3.82.0; Jira mapping open) |
| 15 | Shared evidence model across Epyon, ETK/Quartz and ATO Ready | Design (next priority) |
| 16 | Project third-party assets register | Plan (part of the Projects work) |

## Decisions so far (confirmed by product owner)

| Item | Decision |
|------|----------|
| 1 | Proceed with per-control Run STIG, but it must **not overwrite a scan**: it creates a new STIG scan that carries forward unchanged findings from the previous scan (see section 1). The rerun appears in Scan History as **its own entry** (labelled "STIG re-run"). Confirm-before-override for locked controls still applies. |
| 3 | Agreed: failed/skipped requested tools are shown in a marked "Failed / Did not run" state, not hidden. |
| 4d | Agreed: remove `nightly` from the UI only; keep it accepted by CLI/API/GitHub schedule. |
| 5 | The block to move is **History & MTTR** on the STIG page (`#/stig?view=history`). |
| 6 | Agreed: add web-UI cron alongside GitHub Actions (location in section 6). |
| 7, 8, 9 | Accepted as directional; each still needs measurement before removal (see sections). |
| 10 | quartz-evaluator is **not** in the `demo/quartz-evaluator` branch; treat as an external dependency (see section 10). |

## Reviewer direction (latest)

- **Keep going:** the third-party assets work and the accomplishment-metrics cleanup.
- **Hold:** major AI/STIG architecture changes (items 1, 11, 13 follow-ons, the
  checklist-assessment plan, and anything that changes how the AI assesses controls)
  until the other review comes back. Bug fixes and UI polish on shipped STIG features
  are not affected.
- **Next to nail down:** a shared evidence model across Epyon, ETK/Quartz and ATO Ready
  (item 15). Items 7–10 (debloat, smaller containers, lite mode, quartz-evaluator) stay
  analysis-only; item 10 feeds item 15.

## Remaining open questions

Items still need reviewer sign-off on viability. Open design work is in item 15.

---

## 1. Run STIG for selected control(s)

> **Shipped in 3.84.0** (script `--only`, `POST /api/scans/{id}/stig-run`, toolbar and drawer buttons). Not done: the collapsible group for re-run scans in history (they carry a "STIG re-run" label).

**Goal:** a "Run STIG" button in the STIG Findings toolbar (acts on checked rows) and in
the right-hand drawer (acts on that one control). It reassesses only those controls and
produces a new scan that carries forward all unchanged findings from the previous run.

**What exists:** `run-stig-assessment.py` always assesses the whole STIG; its CLI has
no per-control filter (`--target/--scan-dir/--app-name/--model/--base-url/--batch-size/--delay`).
Row selection already exists (`_stigJiraSel`, `stig.js:225`) and drives the Jira/Lock
buttons. The drawer is `components/drawers/stig.js`. Jobs run through `web/api/jobs.py`.

**Proposed shape**
- Script: add `--only V-222425,V-222426` (comma list). Reuse the existing batch/context
  code (`build_code_context_for_batch`); skip every other control and **merge** results
  onto a copy of the previous scan's results (written to the new scan directory).
- API: `POST /api/scans/{scan_id}/stig-run` with `{ "vuln_ids": [...] }`. Validate ids
  against the scan's own STIG data (boundary validation), cap the list size, return a job id.
- Job: reuse the jobs queue (same concurrency limit as scans), stream status to the UI.
- **No in-place mutation.** The rerun produces a **new scan record** (mode `stig`,
  `parent_scan_id` = the scan the user was viewing). It starts from the previous
  scan's `stig-results-{slug}.json`, reassesses only the selected controls, and
  **carries forward every other control unchanged**, marked `carried_forward_from:
  <scan_id>` with its original evidence/confidence. The earlier scan stays immutable, so
  history, MTTR, ETags and `_scan_cache` need no special handling.
- Carry-forward rule: a control is carried forward verbatim unless it was selected, or the
  existing freeze/invalidations apply (paths a human-reviewed entry lists have changed).
  The previous scan is the latest STIG-bearing scan for the app (not necessarily the
  one being viewed, if a newer one exists — warn and offer to use the newer one).
- On completion: regenerate `.md/.cklb/.json` for the new scan, invalidate only that
  scan's cache, and navigate to it. History & MTTR treat carried-forward rows as
  unchanged status (no false "remediated" events, no MTTR reset).
- UI: toolbar button next to *Add to Jira / Lock* ("Run STIG (n)"), disabled with no
  selection; drawer button "Re-run this control". Show running/queued state on the row.

**Rules to honour**
- Freeze logic: controls that are human-reviewed/locked, or `Not a Finding`/`Not Applicable`
  with confidence ≥ 85, must not be silently overwritten. Rerun should warn and require
  an explicit confirm ("Override locked control?").
- Needs the AI endpoint (now local by default) to be reachable; show a clear error if not.
- Record who/when/model and `parent_scan_id` on each rerun; show "carried forward from <scan>" per control in the drawer.

**Risks:** scan-history clutter from many single-control scans (mitigate with a
"STIG re-run" label and a collapsible group); two concurrent reruns for the same app
branching from the same parent (serialise per app); trend/score logic must treat
carried-forward controls as unchanged and, per existing rules, ignore STIG-only scans
for non-STIG score comparisons.

## 2. STIG Findings page UI

> **Shipped in 3.85.0.** Stat cards (Open / Not a Finding / N/A / Evidence needed / Total)
> are now clickable buttons that double as the status filter (`aria-pressed`), replacing
> the old duplicate status-chip row. Severity and STIG filters are a compact segmented
> control on one row alongside the search box. The three per-STIG downloads (.md/.cklb/.json)
> collapse into one "Export ▾" menu. Run STIG / Add to Jira / Lock now appear only as a
> bulk-action bar when rows are checked. Sticky header, badge styling, row height, and
> keyboard/screen-reader behavior are unchanged.

**Observed (screenshot):** status and severity chips are tightly stacked with uneven
label alignment; the search box is a lone row; "286 controls / Add to Jira / Lock" sit on a
fourth line; five stat boxes plus three download buttons make the top heavy; plain
header row, no sticky controls.

**Proposal** (reuse existing tokens/components; no new framework)
- Single compact filter bar: segmented Status control, segmented Severity control,
  search box, all on one row (wrap on narrow screens).
- Stat cards double as status filters (click "Open" to filter), removing the duplicate
  Status chip row.
- Downloads collapse into one "Export ▾" menu (md / cklb / json).
- Bulk-action bar appears only when rows are selected (Run STIG, Add to Jira, Lock, count).
- Sticky table header, consistent row height, confidence rendered as a small bar/pill,
  severity/status use the same badge components as the rest of the app.
- Keep keyboard and screen-reader behaviour (labels on controls, `aria-pressed` on segments).

## 3. Hide tools that did not run

> **Partially shipped in 3.86.0:** `layers_requested` is now recorded in `scan-metadata.json`
> for every web UI-triggered scan (standard, container-image, local-model, and STIG
> re-run), derived from the explicit Run Scan page layer picker or the scan mode's
> default set (`SCAN_MODE_LAYER_DEFAULTS` in `jobs.py`, mirroring
> `docs/scanning/SCAN_MATRIX.md`). The ML/AI Security card uses it: it no longer renders
> at all when none of layers 14/15/18/19/20 were requested, instead of always showing
> an empty shell. Not done: the same `not_requested` gating for SBOM/API
> discovery/network discovery/misconfigurations cards (they still rely on the
> "empty data → hide" heuristic, which doesn't distinguish "ran with zero findings"
> from "never requested"); the per-tool `ran`/`failed`/`skipped`/`not_requested` state
> in the parser and `tools_analyzed` filtering described below; CLI-triggered
> (`epyon.sh`/`run-target-security-scan.sh`) scans still don't record `layers_requested`
> at all, so they always fall back to the pre-existing heuristic.

**Data available:** `tools_analyzed` (what the page shows today), per-layer
`<layer>/status.json` (`status`: ok/failed/error/skipped + `reason`, already read by
`_layer_status_notes` in `parsers.py`), and `layer-timing.json`. Several cards (SBOM, API
discovery, network discovery, ML cards) render even when empty.

**Proposed rule**
- *Ran successfully* → shown (3-a for full runs, 3-b for partial runs).
- *Not requested for this scan* (not in the mode's layer set, or deselected on the Run
  Scan page) → **not shown anywhere** (tools list and empty cards).
- *Requested but failed or skipped* → recommend **showing it in a distinct
  "Failed / Did not run" state**, not hiding it. Hiding failures recreates the false-clean
  problem `_compute_scan_integrity` was built to catch. If you want them fully hidden, the
  existing warning banner (`_layer_status_notes`) should still list them.

**Implementation sketch:** record `layers_requested` in `scan-metadata.json` at scan
start (the mode matrix plus the user's layer selection), derive a per-tool state
(`ran` / `failed` / `skipped` / `not_requested`) in the parser, and filter in
`scan-detail.js`. Older scans without `layers_requested` fall back to "has output or
status.json".

## 4. Run Scan page

> **Shipped in 3.87.0.** The Target card now has a "Scanning" pill toggle
> (Project/Repository, Container Image, Local Model) separate from the
> What-to-run modal; Scan Types render as selectable pill chips (icon +
> title + tooltip description) with Full/Quick/STIG mutually exclusive;
> Scan Layers is expanded by default when Full or Quick is selected (Quick
> shows only the layers it actually honors); `nightly` and `baseline` are
> no longer offered as scan types in the UI (still accepted by CLI/API);
> redundant Select All/None controls were removed from Scan Types. See
> `web/src/pages/new-scan.js`.

- **4a Compact/grouped:** tighten vertical spacing; group into three clear cards —
  *Target* (source, app name, monitoring), *What to run* (scan types + layers),
  *Options* (AI, schedule/advanced). Reduce label/field gaps so related controls read as one unit.
- **4b Scan types:** keep checkbox semantics (multi-select) but render as selectable
  cards/chips with an icon, one-line description, and a visible checked state, instead of
  long sentence labels (`SCAN_TYPE_OPTIONS`, `new-scan.js:315`).
- **4c Scan layers always visible:** when a layer-capable type is selected (`full`,
  `baseline`; see `optInModes` at `new-scan.js:446`), show the layer grid expanded
  with all layers checked, plus Select all / none, so users see they can deselect. Keep it
  collapsible but expanded by default.
- **4d Remove nightly:** in `scripts/shell/run-epyon-scan-ci.sh` the only difference
  between `nightly` and `full` is Layer 13 (STIG) — nightly excludes it, full may run it —
  and STIG is opt-in in both. Remove from the UI picker; keep `nightly` accepted by the
  CLI/API for the GitHub schedule and historical scans (the "Full / Nightly" history tab
  already groups them). Update `SCAN_MATRIX.md` and the scan-type tooltips.

## 5. Move STIG History & MTTR to the Metrics page

> **Shipped in 3.88.0.** The "History & MTTR" view is now a collapsible "STIG Compliance"
> section on the Metrics page (`buildStigComplianceSection()` in
> `web/src/components/stig-compliance-section.js`, extracted from the old
> `web/src/pages/stig-history.js` so the render code moved rather than copied). It keeps
> its own app/STIG/range/status filters and sortable matrix — the Metrics page has no
> page-level app filter today, so the section follows the same self-contained-picker
> pattern already used by the MTTR panel's `#mttr-app-filter`, rather than a shared filter.
> The STIG page's tab bar was removed (nothing else used it) in favor of a direct
> "History & MTTR" link to the Metrics section. `#/stig?view=history` (with optional
> `app`/`slug` params) redirects to `#/metrics?section=stig-history&stigApp=...` so old
> links/bookmarks keep working; the target section auto-expands and scrolls into view.
> `/api/stig/history` was already ETag-cached like the other metrics endpoints, and its
> per-app computation cost matches what the dedicated page always paid, so no backend
> change was needed. The `stig_na`/`stig_nr` split is untouched.

**What exists:** the "History & MTTR" tab on the STIG page (`stig.js:114`, view
`#/stig?view=history`) rendered by `web/src/pages/stig-history.js` (summary cards incl.
Avg MTTR, per-control matrix with sortable MTTR column), backed by
`GET /api/stig/history` (`web/api/routers/stig.py`, MTTR computed ~line 495).

**Plan**
- Add a "STIG Compliance" section to `metrics.js`: summary cards (remediated, currently
  open, avg MTTR), status trend, and the per-control history/MTTR matrix. Extract the
  render code from `stig-history.js` into a shared component so it is moved, not copied.
- Keep the app selector behaviour (history is per app). Metrics page is aggregate today,
  so decide whether the section follows the page's app filter or has its own picker.
- Remove the "History & MTTR" tab from the STIG page; redirect `#/stig?view=history` to
  the Metrics section so existing links/bookmarks keep working.
- Keep the STIG split rules (`stig_na` vs `stig_nr` never merged).
- Performance: `/api/stig/history` scans every scan for the app; confirm it is cached/ETagged
  like the other metrics endpoints before putting it on a landing-style page.

---

## 6. Cron for nightly scans in the web UI (vs GitHub)

**What exists:** an async job runner with a configurable concurrency cap (default 2, max
16; `jobs.py`), a persisted scan config file, and a daily background loop pattern in the
FastAPI lifespan (retention sweep, `main.py`). GitHub schedules today: Mon–Sat 02:00 UTC
nightly, Sunday full (`scan-private-repo.yml`).

**What it would take (rough effort: 3–5 days including UI and tests)**
1. Schedule store: `web/data/schedules.json` (non-secret only) — id, app, mode, layers,
   cron expression, timezone, enabled, last/next run, last result.
2. Scheduler loop in the lifespan (asyncio): evaluate due schedules each minute, enqueue
   a normal scan job. A small dependency (`croniter`) or a restricted cron parser.
3. Policies: overlap guard (skip if the app's previous run is still going), missed-run
   handling after downtime (run once on startup vs skip), jitter, concurrency respect.
4. Single-instance safety: file lock or leader election, otherwise two replicas double-run.
5. API: CRUD under `/api/schedules`, audit-logged, same auth/validation as other config.
6. UI: Settings (or Applications) → "Schedules" table, create/edit/pause/run-now, last
   status; show "next run".
7. Notifications on failure (reuse webhook), and tests (time-mocked scheduler).

**Pros of web-UI cron**
- Runs where the local AI lives (`localhost:11434`); GitHub-hosted runners cannot reach it,
  which matters now that AI defaults to local (STIG scheduling in particular).
- Reuses warm image cache and the deployed host; no ~3–4 min image pull per run.
- Self-contained deployments (air-gapped/on-prem) need no GitHub Actions.
- One place to manage schedules per app, with run-now and visibility.
- Results land directly in the scan store (no GitHub sync step).

**Cons**
- Availability: schedules stop when the server is down; GitHub is an always-on scheduler.
- The server needs the container-runtime socket and CPU/disk for scans; contention with
  UI traffic (mitigate with the concurrency cap).
- Private-repo access needs a stored/loaded token on the host (env-only, as today).
- No PR/branch gating or per-repo secrets/OIDC that Actions provides.
- More code to own (scheduler correctness, DST/timezones, missed runs).

**Where it lives (UI):** **Settings → new "Scheduled Scans" section**, following the existing
collapsible sections (`settings.js`: AI Executive Summary, Jira, GitHub Actions, NVD,
Scan Concurrency). Settings owns global config and sits next to Scan Concurrency, which
the scheduler must respect. Two supporting touchpoints: a "Schedule…" shortcut on the
Run Scan page (prefills a schedule from the current form) and a small "Next scheduled
run / last result" line on each application's page. Schedule data itself is stored in
`web/data/schedules.json`, API under `/api/schedules`.

**Recommendation:** keep GitHub for PR/push-triggered quick/full scans; add web-UI cron
as an *additional* option, defaulting to a recommended "nightly" template, especially for
anything needing the local AI (STIG).

## 7. Where to debloat (redundancy candidates)

Verified from code/docs unless marked *(verify)*.

| Candidate | Overlaps with | Notes |
|---|---|---|
| Layer 10 Anchore | Layer 8 Grype (+ Layer 1 Syft) | `run-anchore-scan.sh` uses `anchore/grype` — same engine; value is mostly the extra config/baseline handling. Strongest removal candidate. |
| Safety (8.6) | pip-audit (8.5), Grype/Trivy on the SBOM | Three-to-four Python CVE sources; consider keeping pip-audit + Grype only. |
| npm audit (11.7) | Grype/Trivy on SBOM/lockfile | Keep only if lockfile-less resolution adds real finds *(verify with a diff on a few apps)*. |
| SonarQube (3) | Semgrep (11.8) SAST | Sonar is the heaviest image (2.2 GB + 1.4 GB scanner). Keep only if code-quality/coverage metrics are used. |
| Checkov (6) vs Layer 19 vs Trivy config | Dockerfile/K8s/IaC misconfig | Three overlapping IaC/config checks *(verify rule overlap)*. |
| Xeol (9) | endoflife.date fallback already in repo | Two EOL paths. |
| Layer 16 static network discovery | Layer 19 + Checkov | Mostly static config parsing. |
| ML layers 14/15/18/19/21 | none, but no-op without models | Auto-detect and don't run/show when no model files exist (ties to item 3). |
| Multiple tool tags/builds | — | Local image list has 3 ClamAV, 2 Trivy, 2 TruffleHog variants; standardise one. |

**Approach:** measure before deleting — diff findings per tool across a handful of apps
(unique findings per layer), then remove tools whose unique contribution is ~0. Also
confirm `docs/scanning/SCAN_MATRIX.md` (its quick-mode note disagrees with its own table).

## 8. Smaller containers

Measured locally: `epyon-web` is already 322 MB (Wolfi). The weight is in the tool
images pulled at scan time.

| Image | Size | Option |
|---|---|---|
| sonarqube:community + scanner-cli | 2.23 GB + 1.38 GB | Make optional/remote; or drop (Semgrep covers SAST). |
| semgrep/semgrep | 1.62 GB | `pip install semgrep` in a slim venv (~200–300 MB) or a pinned slim image. Note it runs even in quick mode. |
| checkov | 844 MB | pip-install in a slim venv; limit frameworks. |
| clamav | 393–803 MB | Signature DB (~300 MB) is inherent; share one volume, make opt-in. |
| trivy / grype / syft / xeol / trufflehog | 82–243 MB | Static Go binaries — run natively, no container. |
| alpine/helm | 130 MB | Already installed in the web image; remove duplicate pulls. |

General: pin tags + digests (no `:latest` churn), prune old tags (local Docker holds
76 GB of images, 80% reclaimable), one shared base, BuildKit cache mounts. Running Go
tools as native binaries removes both image size *and* the need to mount the Docker socket.

## 9. "Lite" deployment mode

**Suggestion:** a second deployment profile (`docker-compose.lite.yml` + a `Dockerfile.lite`)
that ships the web app plus native binaries for syft, grype, trivy, trufflehog and a
slim-venv semgrep/pip-audit — **no Docker socket, no tool containers**. Estimated
single image ~700 MB–1 GB (estimate, not measured). Local grype/syft preference already
exists in `run-anchore-scan.sh` (`command -v grype`).

### 9a. Quick vs full

Quick (`SCAN_MODE=quick`): layers 1, 2, 7, 8, 8.5, 8.6, 11.7, 11.8. Full adds 3, 4, 5, 6,
9, 10, 11, 14, 15, 16, 18, 19, 21 (+ STIG on request; 12 and 20 are always opt-in).

| | Quick | Full-only additions |
|---|---|---|
| Tools | Syft, TruffleHog, Trivy, Grype, pip-audit, safety, npm audit, Semgrep | SonarQube, ClamAV, Helm, Checkov, Xeol, Anchore, API discovery, network discovery, model/ML layers, compromised-source |
| Container images (approx.) | syft 82 MB, trufflehog 103 MB, trivy 243 MB, grype 102 MB, semgrep **1.62 GB** ≈ **2.2 GB** | sonarqube 2.23 GB + scanner 1.38 GB, clamav ~0.4–0.8 GB, checkov 0.84 GB, xeol 84 MB ≈ **+5 GB** (≈ 7 GB total) |
| Measured runtime | e.g. sapphire quick scan: 668 s total (Grype 448 s, Safety/Semgrep 483 s, Trivy 324 s) | longer; Sonar/ClamAV dominate |

**What a lite/quick-only profile loses:** code-quality and coverage metrics (Sonar),
malware detection (ClamAV), IaC/Helm findings (Checkov/Helm), end-of-life detection
(Xeol/fallback), Anchore baseline/container analysis, API and network discovery, ML/model
supply-chain layers, compromised-source detection, and STIG (AI) compliance.
**What it keeps:** SBOM, secrets, CVEs (container + dependencies), SAST, Python/Node
dependency audit — i.e. the findings that drive Security/Supply-Chain scoring.
Score Card dimensions that depend on missing layers (Compliance, Code Quality, MOSA) would
need a "not assessed" treatment rather than a score of zero.

## 10. quartz-evaluator YAML

**What it is:** the default configuration (`version: 1`, 97 checks) for
*quartz-evaluator*, a Go tool that evaluates a **delivered artifact** — an archive, source
tree, or container image — against a catalog of checks. Each check has an id, severity in
DISA terms (CAT-I ×11, CAT-II ×26, CAT-III ×39, INFO ×21), category, an
evaluation "Phase" (1 Understand requirements, 2 Characterize attack surface,
3 Cooperative vulnerability identification), NIST 800-53 / 800-218 / EO 14028 control
mappings, and remediation text.

**How it works**
- Check types: `builtin` (native Go analyzers, 66), `file` (presence by glob, 20),
  `content` (regex over text files, 9), `shell` (commands, 2 disabled examples).
- Custom configs `extends: default`; a check with an existing id overrides only the
  fields it sets (e.g. `{ id: SC-005, enabled: false }`).
- Settings bound extraction (20 GiB, 1 M files), exclude vendor/test paths, treat secrets
  in test paths as fixtures, and drop OS content from image text scans.
- Catalog groups: artifact integrity (hash, safe extraction), SBOM, detections
  (Dockerfile/Helm/Compose/OpenAPI, local AI models, LLM providers), source/supply chain,
  CI/CD, tests, 20 image checks (non-root, healthcheck, setuid, no creds in env/history,
  layer digests, signature/attestation, hardened base, FIPS Go binaries), 16 Kubernetes
  workload checks, Helm, Docker, licenses.
- Safety model: shell checks are **unsandboxed** and run with the caller's privileges;
  config is never read from the scanned directory (good, matches Epyon's trust rules).

**Fit with Epyon**
- *Overlap:* SBOM, secrets, Dockerfile/K8s/Helm posture (Checkov, Layer 19, Trivy
  config), CI detection, AI model detection (Layers 14/18). Overlapping checks would
  duplicate findings unless deduplicated.
- *Unique value:* chain-of-custody hash and archive integrity, image-layer/digest
  verification, setuid/world-writable/empty-password checks, hardened-base and
  signature evidence, FIPS Go binary inventory, test-evidence presence, CAT-mapped
  results with NIST citations — useful for ATO/ISSO evidence and the STIG layer.
- *Integration options:* (A) a new layer ("Artifact Evaluation") that runs the binary
  and writes `quartz/quartz-results.json`, parsed in `parsers.py` and shown as its own
  card; (B) map CAT-I/II/III to Epyon severities and feed results into STIG/ISSO evidence;
  (C) use the evaluator for image/artifact intake and keep Epyon for scanning.
- *Needed to decide:* the evaluator binary, its distribution/licensing and its output
  schema. Only the config has been provided, and the existing `demo/quartz-evaluator`
  branch does **not** contain it, so it must be treated as an external dependency
  (pinned version, checksum-verified download, no network at scan time).
  Run it only with a trusted, Epyon-owned config because of the shell check type.
- *Suggested next step if approved:* a spike that runs the evaluator against one app's
  image and source, then diffs its findings against Checkov/Layer 19/Trivy to measure
  unique value before committing to a layer.

---

## 11. Editable STIG drawer fields

- *Ask:* users can adjust a control's evidence from the drawer. Only Check Content
  and Remediation stay read-only (they come from the STIG itself).
- *Agreed direction:* store evidence, justification and status as separate fields.
  Persist edits in an Epyon-side store keyed by app and control (under `web/data`,
  which is the volume-mounted directory), and have scans read it as a human review.
  Today `PATCH /api/scans/{scan_id}/stig-override` writes only to that scan's
  `stig-results-{slug}.json`, so edits are not carried to later scans.
- *Done (3.81.0):* edits live in `web/data/stig-edits/{app}.json`
  (`{slug: {vuln_id: {status, evidence, justification, edited_by, edited_at}}}`, written by
  `scripts/shell/stig_edits.py`). Every scan reads them and **verifies** each against the code
  (the human-review verification prompt); a confirmed edit is locked and keeps the person's text,
  a contradicted one stays Open with a note and the edit is kept. An edit made against another
  release of the same STIG is not carried over: the control is re-assessed and says why.
- *Done (3.82.0):* an edit that a scan confirmed against the code is published to
  `docs/stig-reviews/` as an entry reviewed by the editor, so it locks on later scans and
  replaces the previous entry. Unverified or contradicted edits stay in the store only.

## 12. Jira button on the STIG drawer

- Drawers called `stopPropagation()` on click, so the delegated `data-act` handler never
  ran. Fixed in PR #291 (3.78.1). If the modal still reports "Jira is not configured",
  the server is missing the base URL, email or `JIRA_API_TOKEN`.

## 13. Optional justification that never overwrites evidence

- Justification is currently prepended to evidence as `[Human override] ...`, prefilled
  from the control title, and labelled "(required)".
- *Agreed direction:* keep it a separate optional field, drop the prefix and the prefill,
  and never require it to change a status. Done in 3.81.0 with item 11.

## 14. Projects: pairing repos and front-end/back-end STIGs

- *Meaning of project:* one system / ATO boundary containing several repos.
- *Today:* one application is one repo and is the unit of scans and STIG results. There
  is no Project entity. `registered-apps.json` holds repo URLs, and the Jira project key
  is stored per app.
- *Agreed direction:*
  - Add a Project entity with a membership list, many-to-many with repos, so a repo can
    belong to several projects.
  - Assess each repo on its own, then roll up per control. Any component Open makes the
    control Open; otherwise it passes. ETK records already carry `owner` and
    `component_statuses`, which can hold the per-repo results.
  - Front-end/back-end pairing in separate repos uses the same roll-up, with each repo
    tagged as a component of the project.
  - Roll-up refined: any Open gives Open; else any Undetermined gives Undetermined; else
    Not a Finding; Not Applicable only when every component is Not Applicable.
  - Each member repo carries a role tag (`frontend`, `backend`, `infra`). This also feeds
    inheritance in `docs/plans/STIG_CHECKLIST_ASSESSMENT.md`: a front-end criterion the
    repo cannot show resolves from the mapped control in the Project's backend repo.
- *Required parts (agreed):* every member role is required for every control; per-control
  overrides live in the policy file. A repo reports whether its own part is satisfied,
  partial or not addressed; the project control is Not a Finding only when all required
  parts are satisfied.
- *Phase 1 (done, 3.79.0):* Projects page and API: name, description, Jira key, repos with
  roles. *Phase 2 (done, 3.80.0):* per-project STIG roll-up page. *Per-control overrides (done, 3.82.0):* `configuration/stig-policy/project-roles.json`, `{"controls": {"V-222387": {"required_roles": ["backend"]}}}`; other roles show "not required".
- *Done:* per-project roll-up display ("Evidence needed" for Not Reviewed or missing parts,
  "not required" for roles excluded by the policy file); repository field is a dropdown of
  registered apps.
- *Still open:* how a project maps to Jira keys (proposed: a default key per project, with
  the per-app key as an override); automatic control-to-role mapping by CCI/SRG (today only
  the explicit override file).

## 15. Shared evidence model: Epyon, ETK/Quartz and ATO Ready

**Status:** design only. Do this before more AI/STIG architecture work, so that work
targets an agreed contract instead of Epyon-only fields.

**Goal:** one evidence record that all three tools can produce and consume, so a finding
or control assessment keeps its meaning as it moves between tools and up to the system.

**Starting point in Epyon:** ETK-format records (`scripts/shell/stig_records.py`) already
carry `owner`, `assessment_method`, `component_statuses` and `human_review`; project
roll-up (item 14) already defines a status rule. These are the candidate base, not the
final contract.

**Decisions needed**

| Area | Question | Epyon today |
|---|---|---|
| Provenance | Which fields say who or what produced a record: tool and version, scan id, commit SHA, input hashes (`scan-manifest.json`), model and prompt for AI output, and the citations that support it? | Partly: manifest hash, ETK citations; AI model not recorded per record |
| Common statuses | One status vocabulary and mapping. Epyon uses Not a Finding / Not Applicable / Open / Not Reviewed; the roll-up adds Undetermined. Quartz uses CAT-I/II/III and INFO severities. ATO Ready's terms are not yet mapped. | Four statuses plus Undetermined in roll-up only |
| Human review | What a review record holds (reviewer, time, scope, the evidence it covers), when it locks, and when it expires or is invalidated by a change. | `human_review` plus path-based locking; confidence >= 85 freeze |
| System roll-up | How component records combine into a system-level control, including inheritance, "not required" roles and partial satisfaction. | Item 14 rule and `project-roles.json`; per-repo only |
| Identity | Stable ids for controls, components and findings across tools (V-number, CCI, NIST control, fingerprint). | `finding_fingerprint()`, V-numbers |
| Versioning | Schema version, and what a consumer does with unknown fields or statuses. | None |

**Suggested approach**
1. Write the schema as a short spec (JSON Schema plus a status mapping table) in
   `docs/architecture/`, reviewed with the ETK/Quartz and ATO Ready owners.
2. Map existing Epyon outputs (`stig-results-{slug}.json`, ETK records,
   `security-findings-summary.json`) to it without changing behaviour.
3. Run the quartz-evaluator spike (item 10) and map its CAT/NIST output to the same schema.
4. Only then revisit item 14's open roll-up questions and any AI/STIG changes.

**Out of scope until the other review returns:** changing how the AI assesses controls
or the prompt and freeze logic.

## 16. Project third-party assets register

**Status:** plan. Part of the Projects work (item 14); not started.

**Problem:** SBOMs only cover what a repo itself builds (its own and dev dependencies).
They do not tell a project which third-party assets it consumes: external products,
vendored code, base images, models, charts, SaaS and services. Nobody can answer "what
third-party assets do we have, and where should we look when something goes wrong?"

**Meaning of "third-party asset":** anything the project uses but does not author and that
is not already tracked as a package in a member repo's SBOM. A CVE in third-party code that
is vendored into or built with our code base is already found, triaged and fixed by the
normal scans, so this register does not re-run vulnerability triage for it. Its extra value
is (a) an inventory, and (b) **trust evidence**: a periodic look at the asset's own
security posture.

**Decisions made**
- Include non-scannable assets (SaaS, external services, vendored code), so the register
  is complete even when no scanner applies.
- Refresh **monthly**, not every scan. Scans keep finding CVEs in code we build.
- Data is both **derived** (from scan outputs) and **stored** (per project, with history).

### 16a. Data model

Stored per project in `web/data/project-assets/{project}.json` (volume-mounted, same
pattern as `web/data/stig-edits/`). Non-secret fields only.

| Field | Notes |
|---|---|
| `id` | Stable slug, unique within the project |
| `name`, `version`, `vendor` | Version optional for services |
| `type` | `library`, `image`, `model`, `chart`, `vendored`, `saas`, `service`, `tool` |
| `source` | `declared` (entered by a person) or `discovered` (from a scan) |
| `purl` / `url` | Package URL or homepage, when known |
| `used_by` | List of `{repo, role}` (frontend, backend, infra) so issues can be traced to where it is used |
| `data_sensitivity`, `criticality` | Optional; helps decide where to look first |
| `owner` | Person or team who answers for it |
| `scannable` | Whether Epyon can scan it (an artifact, repo or image exists) |
| `trust` | Latest trust check: date, tool and scan id, summary, findings counts, and a status |
| `trust_history` | Previous checks, newest first |
| `provenance` | Who added it and when; for discovered entries, the scan id and commit |
| `notes` | Free text |

Use the status vocabulary and provenance fields agreed in item 15 once defined; until then
`trust.status` is one of `trusted`, `review`, `concern`, `not_assessed`.

### 16b. Where entries come from

1. **Declared:** a person adds them on the project page (name, type, used by, owner).
   This is the only route for SaaS and services.
2. **Discovered:** suggested from scans, accepted by a person. Candidates: base images
   (Trivy/Dockerfile `FROM`), Helm chart dependencies, models (layers 14/18), vendored
   directories, and third-party GitHub Actions. Discovered candidates are not added
   automatically; they appear in a "suggested" list to avoid noise.
3. Direct package dependencies stay in the SBOM and are **not** duplicated here, but each
   asset can link to the SBOM component when it is also one.

### 16c. Monthly trust check

- A scheduled job (the web-UI cron from item 6; a manual "Check now" button also works)
  runs once a month per project over assets with `scannable: true`.
- It reuses existing tools (Syft/Grype/Trivy for artifacts and images, the layer 18
  provenance check for models) against the asset's own artifact. It is not a full 21-layer scan.
- Results update `trust` and push the old value onto `trust_history`. Non-scannable
  assets are not checked; they show "not assessed" and an optional review-due date the
  owner confirms manually.
- Any failure to reach an asset is shown as "check failed", never as trusted.
- Cap work per run (number of assets, per-asset timeout), and use the SSRF guard for any
  user-supplied URL. No credentials are stored in the register.

**Not in this phase:** an "outdated" check (is a newer version available?). Deferred. It
needs registry lookups and per-ecosystem logic. Revisit if owners ask for it.

### 16d. API

All under `/api/projects/{name}/assets`, following the router pattern in `web/api/routers/`:
- `GET` list with filters (type, status, repo, owner, scannable); includes suggested entries.
- `POST` add; `PATCH /{id}` edit; `DELETE /{id}` remove (history kept).
- `POST /{id}/accept` turns a discovered suggestion into an entry.
- `POST /check` runs the trust check for the project or a selected asset (async job).
- `GET /export?format=csv|cyclonedx` for ATO packages.

Validate every body with Pydantic; reject path traversal in names; never accept tokens.

### 16e. UI

A "Third-party assets" tab on the project page, next to the STIG roll-up:
- Summary strip: total assets, by type, by trust status, not assessed, checks overdue, and
  new suggestions.
- Filterable table: name, version, type, used by (repo and role), owner, trust badge,
  last checked. Group by type, repo or status.
- Row click opens the right-hand drawer (same pattern as STIG) with details, trust
  history, linked SBOM component, and a Jira button.
- "Add asset" form and a "Suggested" panel with accept and dismiss.
- Reuse the existing badges; add a type icon per asset type.

### 16f. Build order

1. Data store and API (CRUD, filters, export). Declared assets only.
2. Project-page tab: table, drawer, add form, summary strip.
3. Discovery suggestions from existing scan outputs.
4. Monthly trust check job and history display.
5. Align field names and statuses with the shared evidence model (item 15).

**Tests:** API unit tests with the existing patching approach (`api.main`), BATS tests
for any new shell script, and `npm run build` plus `npm run check` for the SPA bundle.

**Decisions on the earlier open questions**
- An asset can be shared across projects (many-to-many, like repos in item 14). Its
  trust history lives once on the asset; `used_by` is recorded per project.
- The default owner is the system owner (the owner of the project's system / ATO boundary)
  when none is set.
- `trust.status` is `concern` when a check finds any high or critical finding; otherwise
  `trusted`, or `review` when a person has flagged it.
- An accepted suggestion keeps its link to the scan that suggested it. Store the scan id,
  commit and a snapshot of the discovering evidence in `provenance`, so the link
  still makes sense after the scan is pruned.

**Implication for the data model:** because assets are shared, store them in a
cross-project file (`web/data/project-assets/assets.json`) with each project holding
references (`asset_id`, `used_by`) instead of one file per project. Update 16a when building.
