"""
GitHub Metrics — fetches security signals from GitHub API.

Provides:
  - Dependabot alerts (open / fixed / dismissed counts + top packages)
  - Security issues (open count, avg days-to-close for closed security issues)
  - PR scan coverage rate  (derived from local ci-metadata.json, no API call)
  - Workflow success / failure rate (from GitHub Actions API)
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any

import httpx


_GH_BASE = "https://api.github.com"
_SECURITY_LABELS = {"security", "vulnerability", "cve", "critical", "high-severity"}


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


# ── Dependabot ────────────────────────────────────────────────

async def _dependabot_for_repo(client: httpx.AsyncClient, repo: str) -> dict:
    """Return dependabot alert summary for one repo."""
    alerts = await _get_all_pages(client, f"/repos/{repo}/dependabot/alerts")
    open_alerts    = [a for a in alerts if a.get("state") == "open"]
    fixed_alerts   = [a for a in alerts if a.get("state") == "fixed"]
    dismissed      = [a for a in alerts if a.get("state") == "dismissed"]

    # Severity breakdown of open alerts
    sev_counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    top_packages: dict[str, int] = {}
    for a in open_alerts:
        sev = (a.get("security_vulnerability") or {}).get("severity", "").lower()
        if sev in sev_counts:
            sev_counts[sev] += 1
        pkg = ((a.get("dependency") or {}).get("package") or {}).get("name", "")
        if pkg:
            top_packages[pkg] = top_packages.get(pkg, 0) + 1

    top_pkg_list = sorted(top_packages.items(), key=lambda x: -x[1])[:5]

    return {
        "repo":       repo,
        "open":       len(open_alerts),
        "fixed":      len(fixed_alerts),
        "dismissed":  len(dismissed),
        "by_severity": sev_counts,
        "top_packages": [{"package": p, "count": c} for p, c in top_pkg_list],
    }


# ── Security Issues ───────────────────────────────────────────

async def _security_issues_for_repo(client: httpx.AsyncClient, repo: str) -> dict:
    """Return security issue summary for one repo."""
    # Closed issues with security labels (for MTTR calc)
    closed: list = []
    for label in _SECURITY_LABELS:
        items = await _get_all_pages(client, f"/repos/{repo}/issues", per_page=100)
        for item in items:
            if item.get("pull_request"):
                continue  # skip PRs
            labels = {(l.get("name") or "").lower() for l in (item.get("labels") or [])}
            if labels & _SECURITY_LABELS:
                closed.append(item) if item.get("state") == "closed" else None

    # Open issues with security labels
    open_items = await _get_all_pages(client, f"/repos/{repo}/issues")
    open_sec = []
    for item in open_items:
        if item.get("pull_request"):
            continue
        labels = {(l.get("name") or "").lower() for l in (item.get("labels") or [])}
        if labels & _SECURITY_LABELS:
            open_sec.append(item)

    # Avg days to close
    close_durations: list[float] = []
    for issue in closed:
        created = issue.get("created_at")
        closed_at = issue.get("closed_at")
        if created and closed_at:
            try:
                t0 = datetime.fromisoformat(created.replace("Z", "+00:00"))
                t1 = datetime.fromisoformat(closed_at.replace("Z", "+00:00"))
                close_durations.append((t1 - t0).total_seconds() / 86400)
            except ValueError:
                pass

    avg_close_days = (
        round(sum(close_durations) / len(close_durations), 1)
        if close_durations else None
    )

    return {
        "repo":           repo,
        "open_security":  len(open_sec),
        "closed_security": len(closed),
        "avg_close_days": avg_close_days,
    }


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

def compute_pr_scan_coverage(all_scans: list[dict]) -> dict:
    """
    Derive PR scan coverage per app from existing ci_source metadata.
    Coverage = scans where event == pull_request / total scans (that have ci_source).
    """
    by_target: dict[str, dict] = {}
    for s in all_scans:
        target = s.get("target") or ""
        if not target:
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

async def fetch_all(token: str, repos: list[str], all_scans: list[dict]) -> dict:
    """
    Fetch all GitHub metrics for the given repos.
    Returns a dict with keys: dependabot, security_issues, workflow_runs, pr_scan_coverage.
    """
    pr_coverage = compute_pr_scan_coverage(all_scans)

    if not token or not repos:
        return {
            "dependabot":       [],
            "security_issues":  [],
            "workflow_runs":    [],
            "pr_scan_coverage": pr_coverage,
            "error":            None if repos else "No repos configured",
        }

    async with _client(token) as client:
        dep_tasks  = [_dependabot_for_repo(client, r) for r in repos]
        issue_tasks = [_security_issues_for_repo(client, r) for r in repos]
        run_tasks  = [_workflow_runs_for_repo(client, r) for r in repos]

        dep_results, issue_results, run_results = await asyncio.gather(
            asyncio.gather(*dep_tasks,   return_exceptions=True),
            asyncio.gather(*issue_tasks, return_exceptions=True),
            asyncio.gather(*run_tasks,   return_exceptions=True),
        )

    def _safe(results: list, repos: list[str]) -> list:
        out = []
        for repo, r in zip(repos, results):
            if isinstance(r, Exception):
                out.append({"repo": repo, "error": str(r)})
            else:
                out.append(r)
        return out

    return {
        "dependabot":       _safe(dep_results, repos),
        "security_issues":  _safe(issue_results, repos),
        "workflow_runs":    _safe(run_results, repos),
        "pr_scan_coverage": pr_coverage,
        "error":            None,
    }
