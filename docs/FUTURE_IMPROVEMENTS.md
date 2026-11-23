# Future Improvements — Planning Notes

Status: **planning only, nothing here is implemented. Awaiting reviewer sign-off on viability before work starts.** Items 1–5 are product changes
to scope; items 6–10 are analysis questions. File and line references were checked
against `main` at 3.73.0 (PR #282 in review).

## Contents

| # | Item | Type |
|---|------|------|
| 1 | Run STIG for selected control(s) | Feature |
| 2 | STIG Findings page UI tightening | UI |
| 3 | Hide tools that did not run (scan detail) | UI/data |
| 4 | Run Scan page redesign (4a–4d) | UI |
| 5 | Move STIG History & MTTR to the Metrics page | UI |
| 6 | Web-UI cron for scheduled scans | Analysis |
| 7 | Where to debloat Epyon | Analysis |
| 8 | Smaller containers | Analysis |
| 9 | "Lite" deployment mode (+ quick vs full comparison) | Analysis |
| 10 | Review of the quartz-evaluator YAML | Analysis |
| 11 | Editable STIG drawer fields | Feature |
| 12 | Jira button on the STIG drawer | Bug (fixed in #291) |
| 13 | Optional justification that never overwrites evidence | Feature |
| 14 | Projects: pairing repos, repos in many projects, front-end/back-end STIG pairing | Design (phase 1 UI/API in 3.79.0) |

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

## Remaining open questions

None blocking. Items still need reviewer sign-off on viability.

---

## 1. Run STIG for selected control(s)

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
- *Open:* store format and location; whether edits also publish to `docs/stig-reviews/`.

## 12. Jira button on the STIG drawer

- Drawers called `stopPropagation()` on click, so the delegated `data-act` handler never
  ran. Fixed in PR #291 (3.78.1). If the modal still reports "Jira is not configured",
  the server is missing the base URL, email or `JIRA_API_TOKEN`.

## 13. Optional justification that never overwrites evidence

- Justification is currently prepended to evidence as `[Human override] ...`, prefilled
  from the control title, and labelled "(required)".
- *Agreed direction:* keep it a separate optional field, drop the prefix and the prefill,
  and never require it to change a status.

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
  roles. *Phase 2 (done, 3.80.0):* per-project STIG roll-up page. Per-control role overrides are still to do.
- *Open:* how a project maps to Jira keys (proposed: a default key per project, with the
  per-app key as an override); roll-up display in the UI; how a control maps to a role
  (proposed: CCI/SRG mapping plus an override file in `configuration/stig-policy/`).
