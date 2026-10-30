"""
GitHub Metrics — CI health signals for the Metrics page.

Provides:
  - PR scan coverage rate  (derived from local ci-metadata.json, no API call)
  - Workflow success / failure rate (from GitHub Actions API)

Dependabot alerts and GitHub security issues were retired in 3.58.0; findings
are tracked in Jira.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any

import httpx


_GH_BASE = "https://api.github.com"


def _client(token: str) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        headers={
            "Authorization":        f"Bearer {token}",
            "Accept":               "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent":           "epyon-web/3.0.0",
        },
        follow_redirects=True,
        timeout=20.0,
    )


async def _get_all_pages(client: httpx.AsyncClient, path: str, per_page: int = 100) -> list:
    """Fetch all pages of a GitHub list endpoint."""
    results: list = []
    page = 1
    while True:
        try:
            resp = await client.get(
                f"{_GH_BASE}{path}",
                params={"per_page": per_page, "page": page},
            )
            if resp.status_code in (403, 404, 451):
                break  # no access or not found — skip silently
            resp.raise_for_status()
            data = resp.json()
            if not isinstance(data, list) or not data:
                break
            results.extend(data)
            if len(data) < per_page:
                break
            page += 1
        except (httpx.HTTPStatusError, httpx.RequestError):
            break
    return results


# ── Workflow success rate ─────────────────────────────────────

async def _workflow_runs_for_repo(client: httpx.AsyncClient, repo: str, since_days: int = 30) -> dict:
    """Return workflow run success/failure rate for security-related workflows."""
    # Only look at the last N days
    since_dt = datetime.now(timezone.utc)
    from datetime import timedelta
    cutoff = (since_dt - timedelta(days=since_days)).isoformat()

    runs = await _get_all_pages(client, f"/repos/{repo}/actions/runs")

    # Filter to security/epyon workflows and within date range
    security_keywords = {"security", "epyon", "scan", "sast", "cve"}
    relevant: list = []
    for run in runs:
        name = (run.get("name") or run.get("workflow_id") or "").lower()
        created = run.get("created_at") or ""
        if created < cutoff:
            continue
        if any(kw in name for kw in security_keywords):
            relevant.append(run)

    if not relevant:
        # Fall back to all workflow runs if no security-specific ones found
        relevant = [r for r in runs if (r.get("created_at") or "") >= cutoff]

    total    = len(relevant)
    success  = sum(1 for r in relevant if r.get("conclusion") == "success")
    failed   = sum(1 for r in relevant if r.get("conclusion") in ("failure", "timed_out"))
    skipped  = sum(1 for r in relevant if r.get("conclusion") == "skipped")
    in_progress = sum(1 for r in relevant if r.get("status") in ("in_progress", "queued"))

    success_rate = round((success / total) * 100, 1) if total > 0 else None

    return {
        "repo":         repo,
        "total_runs":   total,
        "success":      success,
        "failed":       failed,
        "skipped":      skipped,
        "in_progress":  in_progress,
        "success_rate": success_rate,
    }


# ── PR scan coverage (local data, no API call) ────────────────

def compute_pr_scan_coverage(all_scans: list[dict], monitored: set[str] | None = None) -> dict:
    """
    Derive PR scan coverage per app from existing ci_source metadata.
    Coverage = scans where event == pull_request / total scans (that have ci_source).
    When monitored is provided, only continuously-monitored apps are included.
    """
    by_target: dict[str, dict] = {}
    for s in all_scans:
        target = s.get("target") or ""
        if not target:
            continue
        if monitored and target not in monitored:
            continue
        ci = s.get("ci_source") or {}
        if not ci:
            continue
        entry = by_target.setdefault(target, {"total_ci": 0, "pr_scans": 0, "push_scans": 0, "other_scans": 0})
        entry["total_ci"] += 1
        event = ci.get("event") or ""
        if event == "pull_request":
            entry["pr_scans"] += 1
        elif event == "push":
            entry["push_scans"] += 1
        else:
            entry["other_scans"] += 1

    result = {}
    for target, counts in by_target.items():
        total = counts["total_ci"]
        prs   = counts["pr_scans"]
        result[target] = {
            "total_ci_scans": total,
            "pr_scans":       prs,
            "push_scans":     counts["push_scans"],
            "other_scans":    counts["other_scans"],
            "pr_coverage_pct": round((prs / total) * 100, 1) if total > 0 else 0,
        }
    return result


# ── Public entry point ────────────────────────────────────────

async def fetch_all(token: str, repos: list[str], all_scans: list[dict], monitored: set[str] | None = None) -> dict:
    """
    Fetch all GitHub metrics for the given repos.
    Returns a dict with keys: workflow_runs, pr_scan_coverage, error.
    """
    pr_coverage = compute_pr_scan_coverage(all_scans, monitored)

    if not token or not repos:
        return {
            "workflow_runs":    [],
            "pr_scan_coverage": pr_coverage,
            "error":            None if repos else "No repos configured",
        }

    async with _client(token) as client:
        run_results = await asyncio.gather(
            *[_workflow_runs_for_repo(client, r) for r in repos],
            return_exceptions=True,
        )

    runs = []
    for repo, r in zip(repos, run_results):
        runs.append({"repo": repo, "error": str(r)} if isinstance(r, Exception) else r)

    return {
        "workflow_runs":    runs,
        "pr_scan_coverage": pr_coverage,
        "error":            None,
    }
