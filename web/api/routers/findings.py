"""Epyon Web — findings routes."""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter
from fastapi import HTTPException
from fastapi import Query
from fastapi import Response
from pydantic import BaseModel

from .. import finding_search
from .. import jira_client
from .. import openai_summary
from .. import parsers
from .. import main as api_main

router = APIRouter()

@router.get("/api/findings/search")
def findings_search(
    response: Response,
    q: str = Query(..., description="CVE/advisory id, or package name when field=package"),
    field: str = Query("id"),
    include_history: bool = Query(False),
):
    """Find every application affected by a CVE (or package) across the scan window."""
    api_main._sec_headers(response)
    try:
        needle = finding_search.validate_query(q).lower()
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    if field not in finding_search.FIELDS:
        raise HTTPException(400, "field must be 'id' or 'package'")

    hidden = api_main._load_hidden_apps()
    monitored = api_main._load_monitored_apps()
    all_dirs = api_main._cached_find_scan_dirs(days=35)
    candidates = finding_search.preselect_dirs(all_dirs, include_history, parsers.parse_dir_name)
    scans = [
        scan for scan in (api_main._cached_load_scan(d) for d in candidates)
        if scan["target"] not in hidden and (not monitored or scan["target"] in monitored)
    ]
    selected = finding_search.select_scans(scans, include_history)
    dirs_by_id = {d.name: d for d in candidates}
    ticket_map = jira_client.read_ticket_map()

    applications = []
    for scan in selected:
        scan_dir = dirs_by_id.get(scan["scan_id"])
        if not scan_dir:
            continue
        app_name = scan["target"]
        jira_cfg = jira_client.read_config(app_name)
        project_key = jira_cfg.get("project_key", "")
        index = api_main._scan_search_index(scan_dir, app_name, project_key)
        findings = finding_search.search_index(index, needle, field, ticket_map)
        if findings:
            applications.append({
                "app_name": app_name,
                "scan_id": scan["scan_id"],
                "timestamp": scan.get("timestamp", ""),
                "is_latest": scan["is_latest"],
                "project_key": project_key,
                "jira_base_url": (jira_cfg.get("base_url") or "").rstrip("/"),
                "jira_configured": all(
                    jira_cfg.get(key)
                    for key in ("base_url", "email", "api_token", "project_key")
                ),
                "findings": findings,
            })
    applications.sort(key=lambda a: (a["app_name"].lower(), a["timestamp"]), reverse=False)
    return {
        "query": needle,
        "field": field,
        "include_history": include_history,
        "total_applications": len({a["app_name"] for a in applications}),
        "total_findings": sum(len(a["findings"]) for a in applications),
        "applications": applications,
    }


# ── Per-finding fix suggestion ─────────────────────────────────

class _FindingFixRequest(BaseModel):
    id:            Optional[str] = None
    title:         Optional[str] = None
    description:   Optional[str] = None
    tool:          Optional[str] = None
    severity:      Optional[str] = None
    package:       Optional[str] = None
    version:       Optional[str] = None
    fixed_version: Optional[str] = None
    target:        Optional[str] = None
    references:    list[str]     = []


@router.post("/api/findings/fix")
async def finding_fix(body: _FindingFixRequest, response: Response):
    api_main._sec_headers(response)
    finding = {k: v for k, v in body.model_dump().items() if v}
    if not finding:
        raise HTTPException(400, "No finding data provided")
    try:
        fix = await openai_summary.generate_fix_suggestion(finding)
    except RuntimeError as exc:
        raise HTTPException(400, str(exc))
    except Exception as exc:
        raise HTTPException(502, f"OpenAI request failed: {exc}")
    return {"fix": fix}
