"""Epyon Web — jira routes."""
from __future__ import annotations

from datetime import datetime
from datetime import timezone
from typing import List
from typing import Optional
import re

from fastapi import APIRouter
from fastapi import HTTPException
from fastapi import Query
from fastapi import Request
from fastapi import Response
from pydantic import BaseModel

from .. import jira_client
from .. import parsers
from .. import main as api_main

router = APIRouter()

@router.get("/api/scans/{scan_id}/jira-candidates")
def scan_jira_candidates(scan_id: str, response: Response):
    """Return display-safe findings eligible for manual Jira ticket creation."""
    api_main._sec_headers(response)
    if not api_main._SAFE_ID_RE.match(scan_id):
        raise HTTPException(400, "Invalid scan_id")
    scan_dirs = parsers.find_scan_dirs(api_main.EPYON_ROOT, days=35)
    matched = next((directory for directory in scan_dirs if directory.name == scan_id), None)
    if not matched:
        raise HTTPException(404, "Scan not found")

    scan_data = parsers.load_scan_complete(matched, api_main.EPYON_ROOT)
    app_name = scan_data.get("target") or parsers.parse_dir_name(scan_id)["target"]
    cfg = jira_client.read_config(app_name)
    candidates = jira_client.build_ticket_candidates(
        scan_data,
        app_name,
        cfg.get("project_key", ""),
        jira_client.read_ticket_map(),
    )
    selectable = sum(candidate["selectable"] for candidate in candidates)
    return {
        "scan_id": scan_id,
        "app_name": app_name,
        "jira_configured": bool(
            cfg.get("base_url") and cfg.get("email") and cfg.get("api_token")
            and cfg.get("project_key")
        ),
        "credentials_configured": bool(
            cfg.get("base_url") and cfg.get("email") and cfg.get("api_token")
        ),
        "jira_base_url": cfg.get("base_url", "").rstrip("/"),
        "project_key": cfg.get("project_key", ""),
        "summary": {
            "total": len(candidates),
            "selectable": selectable,
            "suppressed": sum(
                candidate["selection_reason"] == "suppressed"
                for candidate in candidates
            ),
            "already_ticketed": sum(
                candidate["selection_reason"] == "already_ticketed"
                for candidate in candidates
            ),
        },
        "candidates": candidates,
    }


class JiraTicketCreateRequest(BaseModel):
    fingerprints: List[str]
    epic_key: Optional[str] = None
    epic_name: Optional[str] = None
    issue_type: Optional[str] = None
    triaged_by: Optional[str] = None


class JiraProjectKeyRequest(BaseModel):
    project_key: str


@router.post("/api/scans/{scan_id}/jira-project")
def scan_jira_project_update(
    scan_id: str,
    body: JiraProjectKeyRequest,
    request: Request,
    response: Response,
):
    """Set the Jira project key used by an application and all of its scans."""
    api_main._sec_headers(response)
    if not api_main._SAFE_ID_RE.match(scan_id):
        raise HTTPException(400, "Invalid scan_id")
    project_key = body.project_key.strip().upper()
    if not re.fullmatch(r"[A-Z][A-Z0-9]{0,9}", project_key):
        raise HTTPException(400, "project_key must be 1-10 uppercase alphanumeric characters")
    scan_dirs = parsers.find_scan_dirs(api_main.EPYON_ROOT, days=35)
    matched = next((directory for directory in scan_dirs if directory.name == scan_id), None)
    if not matched:
        raise HTTPException(404, "Scan not found")
    scan_data = parsers.load_scan_complete(matched, api_main.EPYON_ROOT)
    app_name = scan_data.get("target") or parsers.parse_dir_name(scan_id)["target"]
    jira_client.set_project_key(app_name, project_key)
    api_main._audit(request, "jira_project_key_changed", f"app={app_name} project={project_key}")
    return {"app_name": app_name, "project_key": project_key}


@router.post("/api/scans/{scan_id}/jira-tickets")
async def scan_jira_tickets_create(
    scan_id: str,
    body: JiraTicketCreateRequest,
    request: Request,
    response: Response,
):
    """Create Jira tickets for explicitly selected findings from one scan."""
    api_main._sec_headers(response)
    if not api_main._SAFE_ID_RE.match(scan_id):
        raise HTTPException(400, "Invalid scan_id")
    fingerprints = list(dict.fromkeys(body.fingerprints))
    if not fingerprints:
        raise HTTPException(400, "At least one fingerprint is required")
    if len(fingerprints) > 200:
        raise HTTPException(400, "A maximum of 200 findings can be submitted at once")
    if any(not api_main._JIRA_FP_RE.fullmatch(fingerprint) for fingerprint in fingerprints):
        raise HTTPException(400, "Invalid fingerprint")
    epic_key = (body.epic_key or "").strip().upper() or None
    if epic_key and not api_main._JIRA_EPIC_KEY_RE.fullmatch(epic_key):
        raise HTTPException(400, "epic_key must look like PROJECT-123")
    epic_name = (body.epic_name or "").strip() or None
    if epic_name and re.search(r"[<>\"';&|`$\n\r]", epic_name):
        raise HTTPException(400, "epic_name contains invalid characters")
    if epic_name and len(epic_name) > 200:
        raise HTTPException(400, "epic_name is too long")
    issue_type = (body.issue_type or "").strip() or None
    if issue_type and (re.search(r"[<>\"';&|`$\n\r]", issue_type) or len(issue_type) > 100):
        raise HTTPException(400, "issue_type is invalid")
    triaged_by = (body.triaged_by or "").strip() or None
    if triaged_by and (re.search(r"[<>`\x00-\x1f]", triaged_by) or len(triaged_by) > 200):
        raise HTTPException(400, "triaged_by is invalid")
    triage_note = (
        f"Triaged and added by: {triaged_by} on: {datetime.now(timezone.utc).date().isoformat()}"
        if triaged_by else None
    )

    scan_dirs = parsers.find_scan_dirs(api_main.EPYON_ROOT, days=35)
    matched = next((directory for directory in scan_dirs if directory.name == scan_id), None)
    if not matched:
        raise HTTPException(404, "Scan not found")

    scan_data = parsers.load_scan_complete(matched, api_main.EPYON_ROOT)
    app_name = scan_data.get("target") or parsers.parse_dir_name(scan_id)["target"]
    cfg = jira_client.read_config(app_name)
    required = ("base_url", "email", "api_token", "project_key")
    if any(not cfg.get(key) for key in required):
        raise HTTPException(400, "Jira is not fully configured")
    candidates = jira_client.build_ticket_candidates(
        scan_data, app_name, cfg["project_key"], jira_client.read_ticket_map()
    )
    findings_by_fingerprint = {
        candidate["fingerprint"]: candidate for candidate in candidates
    }
    resolved_epic_key = await jira_client.resolve_epic_selection(
        cfg, cfg["project_key"], epic_key, epic_name
    )
    if (epic_key or epic_name) and not resolved_epic_key:
        raise HTTPException(
            502,
            "Failed to resolve or create the selected Epic"
            + (f": {jira_client.last_epic_error(cfg, cfg['project_key'])}"
               if jira_client.last_epic_error(cfg, cfg["project_key"])
               else " — check server logs for the exact Jira API error"),
        )
    result = await jira_client.create_tickets_batch(
        app_name, findings_by_fingerprint, fingerprints, cfg, resolved_epic_key, issue_type, triage_note
    )
    api_main._audit(
        request,
        "jira_tickets_created",
        f"scan_id={scan_id} requested={len(fingerprints)} created={len(result['created'])}",
    )
    return result


# ── Jira integration ──────────────────────────────────────────

@router.get("/api/jira/config")
def jira_config_get(response: Response):
    api_main._sec_headers(response)
    cfg   = jira_client.read_config()
    token = cfg.get("api_token", "")
    return {
        "token_set":       bool(token),
        "base_url":        cfg.get("base_url", ""),
        "email":           cfg.get("email", ""),
        "project_key":     cfg.get("project_key", ""),
        "issue_type":      cfg.get("issue_type", "Bug"),
        "done_transition": cfg.get("done_transition", "Done"),
        "auto_close":      cfg.get("auto_close", False),
        "_from_env":       cfg.get("_from_env", False),
    }


@router.post("/api/jira/config")
async def jira_config_post(request: Request, response: Response):
    api_main._sec_headers(response)
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, "Invalid JSON")

    cfg = jira_client.read_config()

    base_url = (body.get("base_url") or "").strip()
    if base_url:
        if not base_url.startswith("https://"):
            raise HTTPException(400, "base_url must use HTTPS")
        if re.search(r"[;&|`$\(\)\n\r<>'\"\\]", base_url):
            raise HTTPException(400, "base_url contains invalid characters")
        cfg["base_url"] = base_url

    email = (body.get("email") or "").strip()
    if email:
        if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
            raise HTTPException(400, "Invalid email address")
        cfg["email"] = email

    if "api_token" in body:
        raise HTTPException(
            400,
            "Jira API tokens cannot be set in the UI; use JIRA_API_TOKEN",
        )

    if body.get("project_key") is not None:
        pk = (body["project_key"] or "").strip().upper()
        if pk and not re.match(r"^[A-Z][A-Z0-9]{0,9}$", pk):
            raise HTTPException(400, "project_key must be 1-10 uppercase alphanumeric characters")
        cfg["project_key"] = pk

    for str_field in ("issue_type", "done_transition"):
        if body.get(str_field) is not None:
            val = (body[str_field] or "").strip()
            if val and re.search(r"[<>\"';&|`$]", val):
                raise HTTPException(400, f"{str_field} contains invalid characters")
            cfg[str_field] = val

    if "auto_close" in body:
        cfg["auto_close"] = bool(body["auto_close"])
    cfg.pop("create_on_new", None)

    jira_client.write_config(cfg)
    api_main._audit(request, "jira_config_changed")
    return {"ok": True}


@router.post("/api/jira/test")
async def jira_test(response: Response):
    api_main._sec_headers(response)
    cfg = jira_client.read_config()
    result = await jira_client.test_connection(cfg)
    return result


@router.get("/api/scans/{scan_id}/jira-epics")
async def scan_jira_epics(scan_id: str, response: Response, project_key: Optional[str] = Query(None)):
    """List existing Jira Epics and issue types for this scan's
    application/project, plus Epyon's suggested severity-based Epic names.

    Powers the Epic + ticket-type pickers shown in the "Create Jira Tickets"
    modal — always offer real existing Epics/issue types so duplicates
    aren't created and invalid types aren't submitted.
    """
    api_main._sec_headers(response)
    if not api_main._SAFE_ID_RE.match(scan_id):
        raise HTTPException(400, "Invalid scan_id")
    scan_dirs = parsers.find_scan_dirs(api_main.EPYON_ROOT, days=35)
    matched = next((directory for directory in scan_dirs if directory.name == scan_id), None)
    if not matched:
        raise HTTPException(404, "Scan not found")
    scan_data = parsers.load_scan_complete(matched, api_main.EPYON_ROOT)
    app_name = scan_data.get("target") or parsers.parse_dir_name(scan_id)["target"]
    cfg = jira_client.read_config(app_name)
    override = (project_key or "").strip().upper()
    if override and not re.fullmatch(r"[A-Z][A-Z0-9]{0,9}", override):
        raise HTTPException(400, "project_key must be 1-10 uppercase alphanumeric characters")
    project_key = override or (cfg.get("project_key") or "").strip()

    existing: List[dict] = []
    issue_types: List[dict] = []
    if project_key and cfg.get("api_token"):
        existing = await jira_client.list_project_epics(cfg, project_key)
        issue_types = await jira_client.list_project_issue_types(cfg, project_key)

    return {
        "project_key": project_key,
        "existing": existing,
        "suggested": [
            {"label": label, "name": jira_client.suggested_epic_name(label)}
            for label in jira_client.SEVERITY_EPIC_LABELS
        ],
        "issue_types": issue_types,
        "default_issue_type": cfg.get("issue_type") or "Bug",
    }


@router.get("/api/jira/tickets")
def jira_tickets_list(response: Response):
    api_main._sec_headers(response)
    tmap = jira_client.read_ticket_map()
    # Return sorted list, newest created first
    entries = list(tmap.values())
    entries.sort(key=lambda e: e.get("created_at", ""), reverse=True)
    return {"total": len(entries), "tickets": entries}


@router.post("/api/jira/reassign/{app_name}")
async def jira_reassign_app(app_name: str, response: Response):
    """Check this application's tracked tickets for deleted Jira issues and
    reset any that were removed out-of-band back to an unsubmitted state,
    so they can be manually re-submitted. Never recreates a Jira issue
    automatically."""
    api_main._sec_headers(response)
    if not api_main._SAFE_ID_RE.match(app_name):
        raise HTTPException(400, "Invalid app_name")
    cfg = jira_client.read_config(app_name)
    if not cfg.get("api_token"):
        raise HTTPException(400, "Jira is not configured — set api_token first")
    return await jira_client.reassign_orphaned_and_save(app_name, cfg)


@router.post("/api/jira/sync/{app_name}")
async def jira_sync_app(app_name: str, response: Response):
    """Manually trigger Jira reconciliation for a specific application."""
    api_main._sec_headers(response)
    if not api_main._SAFE_ID_RE.match(app_name):
        raise HTTPException(400, "Invalid app_name")

    cfg = jira_client.read_config(app_name)
    if not cfg.get("api_token"):
        raise HTTPException(400, "Jira is not configured — set api_token first")

    all_dirs = parsers.find_scan_dirs(api_main.EPYON_ROOT, days=35)
    target_dirs = sorted(
        [d for d in all_dirs if parsers.parse_dir_name(d.name)["target"] == app_name],
        key=lambda d: d.name,
        reverse=True,
    )
    if len(target_dirs) < 2:
        raise HTTPException(400, "Need at least two scans for this application to compare findings")

    current_scan = parsers.load_scan_complete(target_dirs[0], api_main.EPYON_ROOT)
    previous_scan = parsers.load_scan_complete(target_dirs[1], api_main.EPYON_ROOT)

    result = await jira_client.reconcile_and_save(
        app_name,
        jira_client.flatten_ticketable_findings(current_scan),
        jira_client.flatten_ticketable_findings(previous_scan),
        cfg,
    )
    return result
