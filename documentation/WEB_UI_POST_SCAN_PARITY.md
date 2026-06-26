# Potential Enhancement: Web UI Full Post-Scan Step Parity with CI

## Background

The CI workflow (`epyon-scan.yml`) runs a rich set of post-scan steps after the
orchestrator (`run-epyon-scan-ci.sh`) finishes. The Web UI (`web/api/jobs.py`)
currently only runs the orchestrator and then stops — the severity gate, findings
enrichment, metrics history, dashboard chart embedding, GitHub Issues, and JIRA
tickets are all CI-only today.

This document describes a plan to bring the Web UI to full parity.

---

## What the Web UI is Missing

| CI Post-Scan Step | Script / Mechanism | Web UI Today |
|-------------------|--------------------|--------------|
| Check Severity Gate | `check-severity-gate.sh` | ❌ Not run |
| Enrich Findings (NVD + CISA KEV) | `enrich-findings.sh` | ❌ Not run |
| Rebuild Metrics History | `get-scan-metrics.sh` | ❌ Not run |
| Embed Metrics Chart in Dashboard | `embed-metrics-in-dashboard.sh` | ❌ Not run |
| Create GitHub Issues | GitHub REST API (JS in workflow) | ❌ Not run |
| Create JIRA Tickets | `create-jira-tickets.sh` | ❌ Not run |
| Artifact Download | `actions/upload-artifact` | ✅ Already exists (`GET /api/scans/{id}/download`) |
| Fix Artifact Permissions | CI runner `chown` step | N/A (not needed for Web UI) |
| Generate Step Summary | `GITHUB_STEP_SUMMARY` | N/A (GitHub Actions only) |
| Comment on PR | `github.rest.issues.createComment` | N/A (no PR context from Web UI) |
| Fail on Critical | `exit 1` step | Equivalent: `gate_result` field on job |

---

## Implementation Plan

### Phase 1 — Post-Scan Subprocess Chain

**New helpers in `web/api/jobs.py`:**

- `_run_post_step(job, cmd, label, env, cwd, bash) -> int`
  Async subprocess wrapper; streams output to the job's output buffer via
  `_append_line`; returns exit code.

- `_read_findings_counts(scan_dir) -> dict`
  Reads `security-findings-summary.json` (falls back to the filtered variant).
  Returns `{critical, high, medium, low}` (all ints, default 0).

- `_run_post_scan_steps(job, scan_dir, scripts_dir, env, bash, epyon_root, clone_url, scan_mode)`
  Orchestrates the full post-scan chain. Called at the end of `run_scan_job()`
  after the orchestrator subprocess exits (skipped if job was cancelled or timed out).

**Extend `create_job()` return dict** with five new fields:

| Field | Type | Meaning |
|-------|------|---------|
| `gate_result` | `"pass"` / `"fail"` / `None` | Severity gate outcome |
| `findings_counts` | `{critical, high, medium, low}` / `None` | Parsed from findings JSON |
| `github_issue_url` | `str` / `None` | URL of the created/updated GitHub Issue |
| `jira_tickets_created` | `bool` / `None` | Whether JIRA step succeeded |
| `post_scan_status` | `"running"` / `"completed"` / `"skipped"` / `None` | Overall post-scan chain state |

**Post-scan execution order** (all steps are best-effort — each continues even if the prior one failed):

| # | Command | Fail behaviour |
|---|---------|----------------|
| 1 | `check-severity-gate.sh` | exit code -> `gate_result`; always continues |
| 2 | `enrich-findings.sh --scan-dir {scan_dir}` | gracefully exits 0 on no network |
| 3 | `get-scan-metrics.sh --scans-dir {scans} --output scan-history.json --quiet` | logged; skipped on error |
| 4 | `embed-metrics-in-dashboard.sh --metrics scan-history.json --dashboard {dashboard.html}` | skipped if dashboard HTML absent |
| 5 | GitHub Issues (Python module, Phase 2) | skipped if non-GitHub target or no token |
| 6 | `create-jira-tickets.sh` | skipped if JIRA not configured |

Env additions to all post-scan subprocesses (same defaults as CI):
- `FAIL_ON_CRITICAL` (default: `true`)
- `FAIL_ON_HIGH` (default: `true`)
- `HIGH_THRESHOLD` (default: `4`)
- `WARNING_ONLY` (default: `false`)
- `NVD_API_KEY` (optional; from `os.environ`)

All are read from `os.environ` — no new settings UI needed.

---

### Phase 2 — GitHub Issues Module

**New file: `web/api/github_config.py`** (~30 lines)

Extract `_read_github_config()` / `_write_github_config()` out of `main.py` into
a shared module. This avoids circular imports between `main.py` and `jobs.py`
when both need the GitHub token.

**New file: `web/api/github_issues.py`** (~150 lines)

```python
async def create_or_update_scan_issues(
    scan_dir: Path,
    github_token: str,
    github_repo: str,   # "owner/repo"
) -> dict:              # {"issue_url": str, "issue_number": int} | {}
```

Logic mirrors the CI `Create Scan Notification Issues` step:
1. Read findings from `scan_dir/security-findings-summary-filtered.json`
   (falls back to `security-findings-summary.json`).
2. For each severity level with findings (critical -> high -> medium -> low):
   - `GET /repos/{owner}/{repo}/issues?labels=security-scan,epyon,{sev}&state=open`
   - If open issue found -> `POST /repos/{owner}/{repo}/issues/{num}/comments`
   - Otherwise -> `POST /repos/{owner}/{repo}/issues` (creates with labels)
3. Returns `{issue_url, issue_number}` of the first issue created or updated.

Uses `httpx.AsyncClient` (already available as a FastAPI/Starlette transitive dep).
Auth: `Authorization: token {github_token}`.

**Target repo derivation in `jobs.py`:** `github_repo` is derived from `clone_url`
only when the URL matches `github.com/{owner}/{repo}`. Skipped for local path scans.
GitHub token is read from the existing `github-config.json` via the new
`github_config.read_github_config()`.

---

### Phase 3 — JIRA Configuration

**New file: `web/api/jira_config.py`** (~50 lines, mirrors `openai_summary.py` pattern)

- `JIRA_CONFIG_FILE = _HERE / ".." / "jira-config.json"`
- `read_jira_config() -> dict`
- `write_jira_config(cfg: dict) -> None`
- `get_jira_creds() -> dict | None` — returns `None` if any required field is missing

Fields stored in `jira-config.json`:
`jira_url`, `user_email`, `api_token`, `project_key`, `issue_type`

**New endpoints in `web/api/main.py`** (mirrors `/api/github/config` pattern):

- `GET /api/jira/config` -> `{configured, jira_url, project_key, issue_type}` (no secret)
- `POST /api/jira/config` -> validates HTTPS URL, writes config

**In `jobs.py`:** After the GitHub Issues step, if `jira_creds` is set and
`scan_mode == "full"` and findings exist, build the required env vars
and call `create-jira-tickets.sh` via `_run_post_step()`.

Required env vars for `create-jira-tickets.sh`:
`FINDINGS_FILE`, `JIRA_URL`, `PROJECT_KEY`, `ISSUE_TYPE`,
`AUTH` (base64-encoded `email:token`), `REPO_NAME`, `REPO_SLUG`,
`TODAY`, `RUN_URL` (web-ui placeholder), `CRITICAL_COUNT`, `HIGH_COUNT`,
`MEDIUM_COUNT`, `LOW_COUNT`, `GITHUB_ISSUE_URL` (from step 5 if available),
`GITHUB_ISSUE_NUMBER`, `GITHUB_TOKEN`

---

## Files to Change

| File | Change type | Summary |
|------|-------------|---------|
| `web/api/jobs.py` | Modify | Add helpers + post-scan chain |
| `web/api/main.py` | Modify | Add JIRA endpoints; update github_config import |
| `web/api/github_config.py` | **New** | Extracted from `main.py` |
| `web/api/github_issues.py` | **New** | ~150 lines; GitHub API via httpx |
| `web/api/jira_config.py` | **New** | ~50 lines; mirrors openai_summary.py |
| `scripts/shell/*.sh` | **No changes** | All called as subprocesses |

---

## Verification Steps

1. Start web UI; trigger a **full** scan against a GitHub URL target. Confirm job
   output log shows all six post-scan steps running in order.
2. **Gate:** scan with a known critical finding -> `GET /api/jobs/{id}` returns
   `gate_result: "fail"`.
3. **Findings counts:** `GET /api/jobs/{id}` includes a populated `findings_counts` dict.
4. **Enrich:** `security-findings-summary.json` contains `cvss_score` and `kev` fields.
5. **Dashboard:** `security-dashboard.html` contains the embedded metrics chart.
6. **GitHub Issues:** with GH token set in Settings and a GitHub URL target, confirm
   an issue is created in the target repo.
7. **JIRA:** with JIRA config set, confirm `create-jira-tickets.sh` is called with
   the correct env vars.
8. Run `bash run-tests.sh` — all 750 BATS tests still pass (no shell scripts modified).

---

## Key Decisions

- **GitHub Issues target:** created in the scanned repo (GitHub URL targets only).
  Skipped silently for local path scans.
- **Artifact download:** already exists at `GET /api/scans/{id}/download` — no changes.
- **Gate thresholds** (`FAIL_ON_CRITICAL` etc.) are read from `os.environ` only.
  No new settings UI. Advanced users set them via environment before starting the web server.
- **Post-scan failures are best-effort:** each step failure is logged to the job output
  but does not change `job["status"]`. The orchestrator exit code remains the source of
  truth for `status`; severity gate outcome is a separate `gate_result` field.
- **Circular import prevention:** `_read_github_config()` is moved to a new shared
  `github_config.py` module so both `main.py` and `jobs.py` can import it.
