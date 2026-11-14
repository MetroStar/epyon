# Score Card Guide

How the Epyon Score Card is calculated, where each number comes from, and how a reviewer can verify it.

**Scoring version:** 2.0 (`SCORING_VERSION` in `scripts/shell/generate-trl-score.py`, `SCORECARD_SCORING_VERSION` in `web/api/main.py`)
**Engine:** `scripts/shell/generate-trl-score.py` · **API:** `web/api/main.py`, `web/api/scorecard.py` · **UI:** `web/static/app.js`

---

## 1. What the Score Card is

The Score Card rates an **application**, not one scan run. It produces:

- a **weighted score** (0–100),
- a **TRL level** (1–9) and a **letter grade** derived from it,
- six **dimension scores** (0–100 each),
- a list of **blockers**,
- an **evidence item** for every number that moved a score, each tied to a source file and its SHA-256.

It is meant to be defensible: any number can be traced to a tool output, and a named reviewer can sign off on it.

## 2. Design rules (read these first)

| Rule | Consequence |
|---|---|
| **Never scanned scores 0.** | A tool or dimension with no data contributes 0 and *keeps its weight*. Skipping a scan can never raise the score. |
| **Weights are never rescaled.** | If a dimension has no data, the other weights do not grow to compensate. |
| **No nulls.** | Every dimension has a numeric score. A dimension with no data has `applicable: false` and score 0. |
| **Scan type does not change the score.** | Quick, nightly, full and STIG scans all use the same weights. (`--weights` is an explicit manual override only.) |
| **Findings come from the latest scan only.** | A finding that an older scan reported and the latest scan does not is treated as *closed out*. Findings are not carried forward. |
| **STIG results come from the last STIG run.** | STIGs run on demand and may be days or weeks old, so the newest scan that has STIG results is used. |
| **Suppressed findings are counted but weigh 0.** | They appear as annotated evidence, never as deductions. |
| **Tests and fixtures are never scored.** | Findings under `tests*`, `test`, `__tests__`, `fixtures`, `spec` are shown as suppressed (test path). |

## 3. Where the data comes from

### 3.1 Scan history

`set_history()` builds a list of scans for the application: the scored scan first, then older scans of the same app, newest first (directories matching `scans/{app}_*`, older than the scored scan). `_HISTORY[0]` is always the scan being scored.

History is used for three different things, and it matters which:

| Input | Source |
|---|---|
| **Security findings (CVEs, secrets, SAST, IaC, malware inputs)** | **Latest scan with a consolidated `security-findings-summary.json` only.** |
| **ML layers 14 / 18 / 19 / 20** | Latest scan only (`load_layer`). |
| **STIG controls** | Newest scan with `stig-results-*.json`. |
| **API endpoints** | Maximum endpoint count across all scans (API discovery may not run every time). |
| **Other artifacts** (SBOM, Xeol, SonarQube, Checkov results, Helm, network, ClamAV, Garak, model card) | `locate()`: newest copy across history. Not carried-forward *findings*, but the most recent result of that tool. |
| **Trend** | Compares the latest findings with the next-older scan's findings. |

> **Why findings are latest-only.** An earlier design merged each tool's newest result across history. A quick scan that did not run Anchore then inherited weeks-old Anchore findings, which inflated counts against a different image. Findings that are gone are now closed out. History feeds only the trend, and a note listing tools that ran before but not in the latest scan (`sec-not-in-latest`, 0 weight).

### 3.2 Findings files

`security-findings-summary.json` is the raw consolidated output of all tools, deduplicated within a scan. `security-findings-filtered.json` is the same data with `.epyon-ignore.yml` suppressions removed. The Score Card scores the **filtered** file (the same one the UI and severity gate use) and reads the raw file to list what was suppressed.

### 3.3 Classifying a finding

A finding is routed by its `tool`:

| Class | Tools | Scored in |
|---|---|---|
| **Vulnerability (CVE)** | everything that is not SAST or misconfiguration (Grype, Trivy, Anchore, pip-audit, npm audit, Xeol, SonarQube…) | Security CVE lines, KEV, Supply Chain density and patchable debt, critical-CVE blocker |
| **Misconfiguration** | Checkov (IaC), TruffleHog (secrets) | Checkov: Security `sec-misconfig`. TruffleHog: Security secrets cap |
| **SAST** | Semgrep | Security `sec-sast` **and** Code Quality `cq-semgrep` |

`tool_family()` lowercases the tool name and keeps the part before the first `-`, so `Trivy-base-*` all count as "trivy".

## 4. Overall score, TRL and grade

```
weighted_score = Σ (dimension_score × weight)
```

| Dimension | Weight |
|---|---|
| Security & Safety | 30% |
| Supply Chain Integrity | 20% |
| Code Quality | 15% |
| Compliance & Documentation | 15% |
| Operational Readiness | 10% |
| MOSA | 10% |

Other weight profiles (`ml`, `stig`, `quick`) still exist in the script but are used only if `--weights` is passed explicitly.

| Weighted score | TRL | Grade |
|---|---|---|
| 90–100 | 9 | A+ |
| 80–89 | 8 | A |
| 70–79 | 7 | B+ |
| 60–69 | 6 | B |
| 50–59 | 5 | C+ |
| 40–49 | 4 | C |
| 30–39 | 3 | D |
| 0–29 | 2 / 1 | F |

The TRL is derived from the weighted score only. **Blockers do not change the number**; they are reported alongside it (section 11).

## 5. Security & Safety (30%)

Starts at 100 and subtracts. Floors at 0.

### 5.1 Deductions

| Evidence id | What | Points |
|---|---|---|
| `sec-cve-critical` | each critical CVE | −15 |
| `sec-cve-high` | each high CVE | −5 |
| `sec-cve-medium` | each medium CVE | −1 |
| `sec-cve-low` | each low CVE | −0.2 |
| `sec-misconfig` | Checkov IaC: critical/high/medium/low | −5 / −2 / −0.5 / −0.1 each, **max −25** |
| `sec-sast` | Semgrep: critical/high/medium/low | −3 / −1.5 / −0.5 / −0.1 each, **max −15** |
| `sec-kev` | each CISA Known Exploited Vulnerability (on top of its severity) | −10 each, **max −30** |
| `sec-ml-picklescan`, `sec-ml-provenance`, `sec-ml-inference`, `sec-ml-runtime` | per layer: 10×critical + 5×high + 1×medium | **max −25 per layer** |

CVE deductions are **uncapped**: a very large container scan can floor Security at 0 by itself. This is intentional, since volume is real risk, but it is why the unit of correct counting (section 9) matters.

### 5.2 Hard caps

Caps are applied after deductions; the lowest applicable cap wins.

| Evidence id | Condition | Security is capped at |
|---|---|---|
| `sec-cap-secrets` | any **critical or high** TruffleHog finding | 30 |
| `sec-cap-malware` | ClamAV `infected_files > 0` | 20 |
| `sec-cap-model` | dangerous imports or critical/high findings in Layer 14 | 40 |
| `sec-cap-provenance` | a critical Layer 18 provenance finding | 40 |
| `sec-cap-garak` | Garak pass rate below 80% | 50 |

TruffleHog findings below high do not deduct anywhere: secrets are not CVEs, and only Checkov feeds `sec-misconfig`.

### 5.3 Information lines (0 weight)

`sec-suppressed` (suppressed findings, by severity), `sec-coverage` (which scan each tool's findings came from), `sec-not-in-latest`, `sec-floor` (deductions exceeded 100) and `sec-clean` (nothing found).

## 6. Supply Chain Integrity (20%)

**Requires an SBOM** (CycloneDX, `sbom/filesystem.cyclonedx.json`). With no SBOM anywhere in the history the dimension is `applicable: false`, scores 0 and keeps its 20% weight (`sc-no-sbom`).

Starts at 100:

| Evidence id | What | Points |
|---|---|---|
| `sc-eol-critical` | each end-of-support component (Xeol: EOL **and** no support) | −20 |
| `sc-eol` | each EOL component | −5 |
| `sc-density` | (critical + high + medium CVEs) ÷ SBOM components, × 10 | −10 × ratio |
| `sc-patchable` | each critical/high CVE that already has a fixed version | −2, **max −20** |
| `sc-typosquat` | each possible typosquatted model (Layer 18) | −10, **max −30** |

An end-of-support component is counted under both `sc-eol-critical` and `sc-eol` (25 points total).

## 7. Code Quality (15%)

A **weighted average of the quality tools that have data**. Unlike dimensions, missing tools *inside* this dimension do not score 0; their weight is redistributed among the tools that did run. A dimension with none of the three is `applicable: false` (score 0).

| Component | Weight | Score |
|---|---|---|
| SonarQube quality gate (`cq-sonar`) | 40 | 100 if gate passed, else 50; minus 2 × technical-debt ratio %; clamped 0–100 |
| Checkov pass rate (`cq-checkov`) | 30 | passed ÷ (passed + failed) × 100 |
| Semgrep SAST (`cq-semgrep`) | 30 | 100 − 15×critical − 5×high − 1×medium − 0.2×low, floor 0 |

Missing tools appear as `cq-*-missing` evidence ("no evidence either way").

> Semgrep findings affect both Security (`sec-sast`, capped at −15) and Code Quality (`cq-semgrep`). The two use different scales on purpose: Security treats them as a bounded risk signal, Code Quality as the quality of the code.

## 8. Compliance & Documentation (15%)

A weighted average of up to three components. Only STIG is always present (it scores 0 with weight 70 if no STIG was ever run: `comp-no-stig`).

| Component | Weight | Present when |
|---|---|---|
| STIG | 70 | always |
| Model card completeness | 20 | a model card result exists |
| Documented API endpoints | 10 | any API endpoints were discovered (scores 100) |

### 8.1 STIG pass rate

From the newest scan that has `stig-results-*.json` (`get_latest_stig_results`). Every assessed control is placed in one bucket:

| Status | Treatment |
|---|---|
| **Not a Finding** | applicable, **passes** |
| **Open** | applicable, fails |
| **Not Reviewed** | applicable, fails (could not be confirmed statically, never silently passed or dropped) |
| **Not Applicable** | **excluded from the denominator** (does not help or hurt directly, but stops being counted against you) |

```
pass_rate = Not a Finding ÷ (Not a Finding + Open + Not Reviewed) × 100
```

Evidence label example: `STIG pass rate 21.7% (62 of 286 applicable controls; 40 Not Applicable excluded)`.

### 8.2 STIG adjustments (applied inside the 70-weight component)

| Evidence id | Effect |
|---|---|
| `comp-cat1` | CAT I (high severity) pass rate below 100% deducts `(100 − cat1_rate) × 0.15 ÷ 0.7` points. N/A is excluded here too. |
| `comp-unsupported` | "Not a Finding" controls with **under 20 characters of written evidence** (and not human-locked) deduct up to 10 points, proportional to their share of passes. |
| `comp-human` | info: controls reviewed and locked by a human (confidence ≥ 85 freeze logic). |
| `comp-lowconf` | info: passing/N-A controls with confidence below 50. |

The component is clamped to 0–100 before weighting.

## 9. Operational Readiness (10%)

Starts at 100.

| Evidence id | What | Points |
|---|---|---|
| `op-helm` | Helm chart failed to build | −30 |
| `op-ports` | each non-standard open port (only ports confirmed by an *active* scan; standard: 80, 443, 22, 3000, 8080, 8443) | −10 |
| `op-trend` | trend vs the previous scan | improving **+10**, degrading **−20**, stable 0 |

**Trend definition:** `critical × 5 + high` (vulnerabilities only) now, versus the same figure for the next-older scan that has findings. Lower is improving. The result is clamped 0–100. With no Helm, no network data and no earlier scan, the dimension is `applicable: false`.

## 10. MOSA (10%)

Modular Open Systems Approach. **Requires an SBOM** (otherwise not applicable, score 0). Starts at 100:

| Evidence id | Check | Penalty if absent |
|---|---|---|
| `mosa-sbom` | standard CycloneDX SBOM | −25 |
| `mosa-helm` | valid Helm chart (only judged if Helm ran) | −15 |
| `mosa-docker` | a Dockerfile in the scan history | −15 |
| `mosa-api` | documented API endpoints | −10 |
| `mosa-oss` | open-source license ratio of SBOM components | −20 if < 50%, −10 if < 80% |

## 11. Blockers

Reported with the score; they do not alter it. A blocker is a statement that the score should not be read alone.

| Level | Condition |
|---|---|
| CRITICAL | any secret leak (TruffleHog critical/high) |
| CRITICAL | malware detected |
| CRITICAL | any critical **CVE** (SAST and misconfigurations are excluded) |
| CRITICAL | any CISA KEV |
| CRITICAL | dangerous model-file content |
| HIGH | any end-of-support component |
| COMPLIANCE | STIG pass rate below 70% |
| COMPLIANCE | any "Not a Finding" control without written evidence |

## 12. Suppressed findings and test paths

- Findings matched by approved `.epyon-ignore.yml` rules are **counted and annotated**, with 0 weight (`sec-suppressed`). They are never silently dropped.
- Anything under a `tests*`, `test`, `__tests__`, `fixtures` or `spec` directory (any depth, judged relative to the scan target) is suppressed by a **built-in default rule**, labeled "(test path)". The Score Card applies the same rule as a backstop for ML layer items.
- Opt out with `include_tests: true` in `.epyon-ignore.yml`. The setting is recorded in the per-scan `ignore-rules.json` snapshot, which is what the Score Card reads.
- Checkov still scans test paths; its results there are filtered afterward by the UI and the Score Card.

See [IGNORE_RULES_GUIDE.md](IGNORE_RULES_GUIDE.md).

## 13. Evidence

Every score component is an **evidence item**:

| Field | Meaning |
|---|---|
| `id` | stable identifier (e.g. `sec-cve-high`) |
| `kind` | `deduction`, `cap`, `bonus`, `component`, `info`, `missing` |
| `label` | human-readable description |
| `measured` | the measured value (count, rate, …) |
| `impact` | points added or removed |
| `source`, `sha256` | artifact path (relative to `scans/`) and its SHA-256 |
| `refs`, `refs_total` | finding / control IDs behind the number (first 25 kept) |
| `note` | extra context, such as "from earlier scan …" |

The dimension drawer in the UI lists them. `evidence_manifest` in `trl-assessment.json` is the de-duplicated list of every source file with its hash.

### 13.1 Evidence package

`GET /api/scans/{id}/scorecard/evidence` downloads a zip containing `trl-assessment.json`, `signoff.json` (if any), `manifest.json`, and `artifacts/` with the source files. Sources are **re-hashed at download time**: a file that differs from the recorded hash is flagged `changed since scoring`, a missing one `missing`. Paths are confined to the scans directory; per-file (10 MB) and bundle (50 MB) limits apply and omissions are flagged.

### 13.2 Reviewer sign-off

`PUT /api/scans/{id}/scorecard/signoff` records a named reviewer (2–100 characters), an optional comment (max 2000) and a SHA-256 **digest of the score** (version, TRL, weighted score, weights, every dimension score). A later rescore that changes any of those makes the stored digest no longer match, and the sign-off shows as not matching the current score. `DELETE` revokes it. Sign-offs are stored in `web/data/scorecard-signoffs.json`.

## 14. Calculating, rescoring and versioning

- `POST /api/scans/{id}/scorecard` runs the engine on demand; the UI calls it when a scan page loads, so the card always reflects the current engine and current data. It needs at least one scan of the application with a `security-findings-summary.json` (otherwise HTTP 422), and the scan must be within the 35-day scan window.
- When the engine's `scoring_version` differs from the stored assessment, the old assessment is kept once as `trl-assessment.previous.json`, and the card shows before/after scores and per-dimension change.
- Evidence and sign-off endpoints refuse an assessment from an older scoring version (HTTP 409): rescore first.
- Output: `trl-assessment.json` in the scan directory.

## 15. Application trend on the Metrics page

Separate from the Score Card. The Metrics page shows an **Application Trend Status** per app (Improving / Declining / Stable / Not enough data):

- Risk index = 15×critical + 5×high + 1×medium + 0.2×low (the Score Card's CVE weights).
- One scan per day, same scan type as the latest scan only, last 30 points.
- Declining: risk up 10% or more, or more critical+high findings than the first point of the window. Improving: the opposite. Otherwise Stable.
- Implemented in `web/api/app_trends.py`, returned as `app_trends` by `GET /api/metrics`.

## 16. Reading a Score Card: a practical checklist

1. Check the **scored scan** and the `sec-coverage` evidence: which scan each tool's findings came from.
2. Check `sec-not-in-latest`: tools that ran before but not in the latest scan. Their absence is not counted as fixed or broken.
3. Expand Security: are scores dominated by one uncapped CVE line? A 0 usually means CVE volume, not a bug.
4. Check Compliance: when was the STIG run (`stig_latest_scan`)? How many controls are Open vs Not Applicable?
5. Look at dimensions marked **Not scanned**: they scored 0 and keep their weight.
6. Review blockers independently of the grade.
7. For audit, download the evidence package and confirm every artifact shows `ok`.

## 17. Troubleshooting

| Symptom | Likely cause |
|---|---|
| Counts higher than expected | CVE deductions are uncapped; check which tool and image the counts come from in `sec-coverage`. Tool findings from a different image/scan are not mixed any more, as only the latest scan counts. |
| A tool's findings disappeared | The latest scan did not run it. See `sec-not-in-latest`. |
| STIG pass rate very low | Open and Not Reviewed controls count against you; Not Applicable are excluded. Run a full STIG scan, then rescore. |
| Compliance seems stale | STIG results come from the last STIG run by design. |
| Semgrep not in CVE counts | By design: it has its own `sec-sast` line. |
| Test fixtures flagged | Confirm the path matches a default test-path rule and `include_tests` is not set. |
| HTTP 422 on the scorecard | No scan of this app has `security-findings-summary.json`. Re-run the scan. |
| Sign-off no longer valid | The score changed after sign-off. Rescore, review, and sign again. |

## 18. Related files

| File | Role |
|---|---|
| `scripts/shell/generate-trl-score.py` | Scoring engine |
| `scripts/shell/generate-scan-findings-summary.sh` | Builds `security-findings-summary.json` |
| `scripts/shell/parse-epyon-ignore.sh`, `scripts/shell/epyon_test_paths.py` | Suppression and test-path rules |
| `web/api/main.py` | Score Card API |
| `web/api/scorecard.py` | Sign-off and evidence package |
| `web/api/app_trends.py` | Metrics trend status |
| `tests/python/test_scorecard_evidence.py` | Score Card tests |
| `tests/shell/test-generate-trl-score.bats` | Engine BATS tests |
