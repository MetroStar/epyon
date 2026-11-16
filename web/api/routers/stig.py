"""Epyon Web — stig routes."""
from __future__ import annotations

from collections import Counter
from datetime import datetime
from datetime import timezone
from typing import List
from typing import Optional
import json
import re

from fastapi import APIRouter
from fastapi import HTTPException
from fastapi import Query
from fastapi import Request
from fastapi import Response
from fastapi.responses import FileResponse
from pydantic import BaseModel

from .. import jira_client
from .. import parsers
from .. import main as api_main

router = APIRouter()

@router.get("/api/scans/{scan_id}/stig-findings-md")
def stig_findings_md(scan_id: str, response: Response):
    """Serve the primary STIG findings markdown for a given scan."""
    api_main._sec_headers(response)
    if not api_main._SAFE_ID_RE.match(scan_id):
        raise HTTPException(400, "Invalid scan_id")
    matched = api_main._require_scan_dir(scan_id)
    app_slug = re.sub(r"[^a-z0-9]+", "-", re.sub(r"_\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}$", "", scan_id).lower()).strip("-")
    report = matched / f"findings-{app_slug}.md"
    try:
        report.resolve().relative_to(api_main.EPYON_ROOT.resolve())
    except ValueError:
        raise HTTPException(403, "Access denied")
    if not report.exists():
        raise HTTPException(404, "STIG findings not generated for this scan")
    return FileResponse(str(report), media_type="text/markdown",
                        headers={"Content-Disposition": f'attachment; filename="findings-{scan_id}.md"'})


@router.get("/api/scans/{scan_id}/stig-findings-cklb")
def stig_findings_cklb(scan_id: str, response: Response):
    """Serve the primary STIG findings CKLB for a given scan."""
    api_main._sec_headers(response)
    if not api_main._SAFE_ID_RE.match(scan_id):
        raise HTTPException(400, "Invalid scan_id")
    matched = api_main._require_scan_dir(scan_id)
    app_slug = re.sub(r"[^a-z0-9]+", "-", re.sub(r"_\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}$", "", scan_id).lower()).strip("-")
    report = matched / f"findings-{app_slug}.cklb"
    try:
        report.resolve().relative_to(api_main.EPYON_ROOT.resolve())
    except ValueError:
        raise HTTPException(403, "Access denied")
    if not report.exists():
        raise HTTPException(404, "STIG findings CKLB not generated for this scan")
    return FileResponse(str(report), media_type="application/json",
                        headers={"Content-Disposition": f'attachment; filename="findings-{scan_id}.cklb"'})


@router.get("/api/scans/{scan_id}/stig-findings-json")
def stig_findings_json(scan_id: str, response: Response, slug: Optional[str] = None):
    """Download structured STIG findings (all STIGs, or one via ?slug=) as JSON."""
    api_main._sec_headers(response)
    if not api_main._SAFE_ID_RE.match(scan_id):
        raise HTTPException(400, "Invalid scan_id")
    if slug is not None and not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9_\-]*$", slug):
        raise HTTPException(400, "Invalid slug")
    matched = api_main._require_scan_dir(scan_id)
    stigs = api_main._build_stig_entries(scan_id, matched)
    if slug is not None:
        stigs = [s for s in stigs if s["slug"] == slug]
    if not stigs:
        raise HTTPException(404, "STIG findings not generated for this scan")
    app_name = re.sub(r"_\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}$", "", scan_id)
    payload = {
        "scan_id": scan_id,
        "application": app_name,
        "stigs": [
            {
                **{k: v for k, v in st.items() if k not in ("controls", "md_url", "cklb_url")},
                "summary": dict(Counter(c["status"] for c in st["controls"])),
                "controls": st["controls"],
            }
            for st in stigs
        ],
    }
    name = f"findings-{scan_id}{'-' + slug if slug else ''}.json"
    return Response(json.dumps(payload, indent=2), media_type="application/json",
                    headers={"Content-Disposition": f'attachment; filename="{name}"'})


@router.get("/api/scans/{scan_id}/stig-data")
def stig_data(scan_id: str, response: Response):
    """Return merged controls + assessment results for all STIGs in a scan as JSON."""
    api_main._sec_headers(response)
    if not api_main._SAFE_ID_RE.match(scan_id):
        raise HTTPException(400, "Invalid scan_id")
    scan_dirs = parsers.find_scan_dirs(api_main.EPYON_ROOT, days=35)
    matched = next((d for d in scan_dirs if d.name == scan_id), None)
    if not matched:
        raise HTTPException(404, "Scan not found")

    stigs = api_main._build_stig_entries(scan_id, matched)

    return {"scan_id": scan_id, "stigs": stigs}


_SAFE_SLUG_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_\-]*\.(md|cklb)$")


_VALID_STIG_STATUSES = {"Not a Finding", "Not Applicable", "Open", "Not Reviewed"}


class StigOverride(BaseModel):
    slug: str
    vuln_id: str
    status: str
    evidence: str = ""
    justification: str = ""  # human rationale stored alongside evidence
    clear_lock: bool = False  # when True, removes the human lock and resets to Open


@router.patch("/api/scans/{scan_id}/stig-override")
def stig_override(scan_id: str, body: StigOverride, response: Response):
    """Apply a human-reviewed override to a single STIG control.

    Sets status, updates evidence, marks locked_by_human=True and
    confidence=95 so the freeze logic carries this forward on subsequent scans.
    The justification is prepended to the evidence text so it is visible in
    the findings report.
    """
    api_main._sec_headers(response)
    if not api_main._SAFE_ID_RE.match(scan_id):
        raise HTTPException(400, "Invalid scan_id")
    # Validate slug to prevent path traversal
    if not re.match(r'^[a-z0-9][a-z0-9\-]*$', body.slug):
        raise HTTPException(400, "Invalid slug")
    if body.status not in _VALID_STIG_STATUSES:
        raise HTTPException(400, f"Invalid status. Must be one of: {sorted(_VALID_STIG_STATUSES)}")
    # Validate vuln_id format (e.g. APSC-DV-000070, TCAT-AS-000010)
    if not re.match(r'^[A-Z0-9]{2,}-[A-Z0-9]{2,}-[0-9]{4,}$', body.vuln_id):
        raise HTTPException(400, "Invalid vuln_id format")

    scan_dirs = parsers.find_scan_dirs(api_main.EPYON_ROOT, days=35)
    matched = next((d for d in scan_dirs if d.name == scan_id), None)
    if not matched:
        raise HTTPException(404, "Scan not found")

    results_file = matched / f"stig-results-{body.slug}.json"
    if not results_file.exists():
        raise HTTPException(404, f"STIG results file not found for slug: {body.slug}")

    # Resolve and verify the path is inside the scan directory (no traversal)
    try:
        results_file.resolve().relative_to(api_main.EPYON_ROOT.resolve())
    except ValueError:
        raise HTTPException(403, "Access denied")

    try:
        raw = json.loads(results_file.read_text(encoding="utf-8"))
    except Exception as exc:
        raise HTTPException(500, f"Could not read results file: {exc}") from exc

    assessments = raw.get("assessments", raw) if "assessments" in raw else raw

    # Build the updated evidence text — prepend justification if provided
    new_evidence = body.evidence
    if body.justification:
        prefix = f"[Human override] {body.justification}\n"
        if not new_evidence.startswith(prefix):
            new_evidence = prefix + new_evidence

    if body.clear_lock:
        # Remove the human lock; reset to Open with confidence 0 so AI re-assesses next scan
        assessments[body.vuln_id] = {
            **assessments.get(body.vuln_id, {}),
            "status":          "Open",
            "evidence":        "",
            "confidence":      0,
            "locked_by_human": False,
        }
    else:
        assessments[body.vuln_id] = {
            **assessments.get(body.vuln_id, {}),
            "status":          body.status,
            "evidence":        new_evidence,
            "confidence":      95,
            "locked_by_human": True,
        }

    # Write back in the wrapped format
    if "assessments" in raw:
        raw["assessments"] = assessments
    else:
        raw = {"assessments": assessments}

    results_file.write_text(json.dumps(raw, indent=2, ensure_ascii=False), encoding="utf-8")
    results_file.chmod(0o600)

    return {
        "scan_id":  scan_id,
        "slug":     body.slug,
        "vuln_id":  body.vuln_id,
        "status":   "Open" if body.clear_lock else body.status,
        "locked":   not body.clear_lock,
    }


@router.get("/api/scans/{scan_id}/stig-findings/{filename}")
def stig_findings_named(scan_id: str, filename: str, response: Response):
    """Serve a per-STIG named findings file (findings-{slug}.md or .cklb)."""
    api_main._sec_headers(response)
    if not api_main._SAFE_ID_RE.match(scan_id):
        raise HTTPException(400, "Invalid scan_id")
    if not _SAFE_SLUG_RE.match(filename):
        raise HTTPException(400, "Invalid filename")
    scan_dirs = parsers.find_scan_dirs(api_main.EPYON_ROOT, days=35)
    matched = next((d for d in scan_dirs if d.name == scan_id), None)
    if not matched:
        raise HTTPException(404, "Scan not found")
    report = matched / f"findings-{filename}"
    try:
        report.resolve().relative_to(api_main.EPYON_ROOT.resolve())
    except ValueError:
        raise HTTPException(403, "Access denied")
    if not report.exists():
        raise HTTPException(404, f"File not found: findings-{filename}")
    ext = filename.rsplit(".", 1)[-1]
    media = "text/markdown" if ext == "md" else "application/json"
    return FileResponse(str(report), media_type=media,
                        headers={"Content-Disposition": f'attachment; filename="findings-{filename}"'})


_STIG_JIRA_MAX = 100


class StigJiraControl(BaseModel):
    slug: str
    vuln_id: str


class StigJiraTicketRequest(BaseModel):
    controls: List[StigJiraControl]
    project_key: str
    epic_key: Optional[str] = None
    issue_type: Optional[str] = None
    tracker_key: Optional[str] = None
    triaged_by: Optional[str] = None


def _stig_jira_module():
    import sys
    shell_dir = str(api_main.EPYON_ROOT / "scripts" / "shell")
    if shell_dir not in sys.path:
        sys.path.insert(0, shell_dir)
    import stig_jira
    return stig_jira


@router.get("/api/scans/{scan_id}/stig-jira-context")
def scan_stig_jira_context(scan_id: str, response: Response):
    """Default Jira board for a scan's app plus the boards Epyon already knows."""
    api_main._sec_headers(response)
    if not api_main._SAFE_ID_RE.match(scan_id):
        raise HTTPException(400, "Invalid scan_id")
    app_name = parsers.parse_dir_name(scan_id)["target"]
    cfg = jira_client.read_config(app_name)
    known = {str(v).upper() for v in (cfg.get("project_keys") or {}).values() if isinstance(v, str)}
    if cfg.get("project_key"):
        known.add(cfg["project_key"].upper())
    return {
        "app_name": app_name,
        "jira_configured": bool(cfg.get("base_url") and cfg.get("email") and cfg.get("api_token")),
        "jira_base_url": (cfg.get("base_url") or "").rstrip("/"),
        "project_key": cfg.get("project_key", ""),
        "known_projects": sorted(known),
    }


@router.post("/api/scans/{scan_id}/stig-jira-tickets")
async def scan_stig_jira_tickets_create(
    scan_id: str,
    body: StigJiraTicketRequest,
    request: Request,
    response: Response,
):
    """Create Jira tickets for user-selected STIG controls in the chosen project.

    The project is taken from the request and is not persisted, so the user
    always sees and controls which board receives the tickets.
    """
    api_main._sec_headers(response)
    if not api_main._SAFE_ID_RE.match(scan_id):
        raise HTTPException(400, "Invalid scan_id")
    if not body.controls:
        raise HTTPException(400, "At least one control is required")
    if len(body.controls) > _STIG_JIRA_MAX:
        raise HTTPException(400, f"A maximum of {_STIG_JIRA_MAX} controls can be submitted at once")
    for c in body.controls:
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,80}", c.slug) or not re.fullmatch(r"[A-Za-z0-9._-]{1,80}", c.vuln_id):
            raise HTTPException(400, "Invalid control")
    project_key = body.project_key.strip().upper()
    if not re.fullmatch(r"[A-Z][A-Z0-9]{0,9}", project_key):
        raise HTTPException(400, "project_key must be 1-10 uppercase alphanumeric characters")
    epic_key = (body.epic_key or "").strip().upper() or None
    if epic_key and not api_main._JIRA_EPIC_KEY_RE.fullmatch(epic_key):
        raise HTTPException(400, "epic_key must look like PROJECT-123")
    tracker = (body.tracker_key or "").strip().upper()
    if tracker and not api_main._JIRA_EPIC_KEY_RE.fullmatch(tracker):
        raise HTTPException(400, "tracker_key must look like PROJECT-123")
    if tracker and not tracker.startswith(project_key + "-"):
        raise HTTPException(400, f"tracker_key {tracker} is not in project {project_key}")
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
    matched = next((d for d in scan_dirs if d.name == scan_id), None)
    if not matched:
        raise HTTPException(404, "Scan not found")
    app_name = parsers.parse_dir_name(scan_id)["target"]
    cfg = jira_client.read_config(app_name)
    if any(not cfg.get(k) for k in ("base_url", "email", "api_token")):
        raise HTTPException(400, "Jira is not fully configured")
    cfg = {**cfg, "project_key": project_key}
    stig_jira = _stig_jira_module()
    try:
        result = await stig_jira.create_manual(
            jira_client, cfg, app_name, matched,
            [(c.slug, c.vuln_id) for c in body.controls],
            tracker=tracker, epic_key=epic_key, issue_type=issue_type, triage_note=triage_note,
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    result["project_key"] = project_key
    api_main._audit(
        request, "stig_jira_tickets_created",
        f"scan_id={scan_id} project={project_key} requested={len(body.controls)} created={len(result['created'])}",
    )
    return result


# ── STIG History / MTTR ──────────────────────────────────────

@router.get("/api/stig/history")
def stig_history(
    response: Response,
    app: Optional[str] = Query(None),
    slug: Optional[str] = Query(None),
):
    """Return STIG control status history across all scans for an app, with MTTR."""
    api_main._sec_headers(response)
    scan_dirs = api_main._cached_find_scan_dirs()

    # Group scan dirs by app name, extract date/time from scan_id
    app_scans: dict[str, list[dict]] = {}
    for d in scan_dirs:
        m = api_main._APP_SCAN_RE.match(d.name)
        if not m:
            continue
        app_name, date_str, time_str = m.group(1), m.group(2), m.group(3)
        app_scans.setdefault(app_name, []).append(
            {"scan_id": d.name, "date": date_str, "time": time_str, "path": d}
        )

    # Apps that have at least one stig-results-*.json file
    stig_apps = sorted(
        a for a, scans in app_scans.items()
        if any(api_main._real_stig_files(s["path"]) for s in scans)
    )

    _empty_summary = {
        "total_controls": 0, "ever_open": 0,
        "remediated": 0, "avg_mttr_days": None, "currently_open": 0,
    }
    _base = {"apps": stig_apps, "app": None, "slugs": [], "slug": slug,
             "scans": [], "controls": [], "summary": _empty_summary}

    selected_app = app or (stig_apps[0] if stig_apps else None)
    if not selected_app:
        return _base

    # All slugs found for this app
    all_slugs: set[str] = set()
    for s in app_scans.get(selected_app, []):
        for f in api_main._real_stig_files(s["path"]):
            all_slugs.add(f.stem[len("stig-results-"):])

    selected_slugs = {slug} if (slug and slug in all_slugs) else all_slugs

    # Scans for this app that have STIG files, in chronological order
    stig_scans = sorted(
        [
            s for s in app_scans.get(selected_app, [])
            if any(
                api_main._is_real_stig_result(s["path"] / f"stig-results-{sl}.json")
                for sl in selected_slugs
            )
        ],
        key=lambda s: (s["date"], s["time"]),
    )

    # Deduplicate: keep only the latest STIG scan per calendar date
    _latest_per_date: dict[str, dict] = {}
    for s in stig_scans:
        _latest_per_date[s["date"]] = s
    stig_scans = list(_latest_per_date.values())

    if not stig_scans:
        return {**_base, "apps": stig_apps, "app": selected_app, "slugs": sorted(all_slugs)}

    # Build control metadata (title/severity) and the canonical vuln_id set per slug
    # (using the most-recent controls file per slug so the benchmark version is consistent)
    control_meta: dict[str, dict] = {}
    slug_control_ids: dict[str, set[str]] = {}
    for s in reversed(stig_scans):
        for sl in selected_slugs:
            cf = s["path"] / f"stig-controls-{sl}.json"
            if not cf.exists():
                continue
            try:
                cd = json.loads(cf.read_text(encoding="utf-8"))
                ids_for_slug: set[str] = set()
                for c in cd.get("controls", []):
                    vid = c.get("vuln_id", "")
                    if not vid:
                        continue
                    if vid not in control_meta:
                        control_meta[vid] = {
                            "title":     c.get("title", ""),
                            "severity":  c.get("severity", ""),
                            "stig_name": cd.get("stig_name", sl),
                            "check_content": c.get("check_content", ""),
                        }
                    ids_for_slug.add(vid)
                # Only use the first (most-recent) controls file per slug
                if sl not in slug_control_ids:
                    slug_control_ids[sl] = ids_for_slug
            except Exception:
                pass

    # Build per-vuln_id timeline, filling gaps with "Not Reviewed" for any
    # benchmark control that a scan ran but didn't explicitly produce a result for.
    # This guarantees every scan column is complete and the matrix is consistent.
    seen_entries: set[tuple] = set()
    vuln_timelines: dict[str, list[dict]] = {}
    latest_record: dict[str, dict] = {}
    for s in stig_scans:
        for sl in selected_slugs:
            rf = s["path"] / f"stig-results-{sl}.json"
            if not api_main._is_real_stig_result(rf):
                continue
            try:
                raw = json.loads(rf.read_text(encoding="utf-8"))
                results = raw.get("assessments", raw) if "assessments" in raw else raw
            except Exception:
                continue
            # Explicit assessment results
            for vid, data in results.items():
                key = (s["scan_id"], vid)
                if key not in seen_entries:
                    seen_entries.add(key)
                    vuln_timelines.setdefault(vid, []).append({
                        "scan_id": s["scan_id"],
                        "date":    s["date"],
                        "status":  data.get("status", "Not Reviewed"),
                        "evidence": data.get("evidence", ""),
                        "confidence": data.get("confidence", None),
                        "human_reviewed": bool(data.get("locked_by_human", False)),
                    })
                    latest_record[vid] = parsers.stig_record_fields(data, control_meta.get(vid, {}))
            # Fill any benchmark controls absent from this scan's results
            for vid in slug_control_ids.get(sl, set()):
                key = (s["scan_id"], vid)
                if key not in seen_entries:
                    seen_entries.add(key)
                    vuln_timelines.setdefault(vid, []).append({
                        "scan_id": s["scan_id"],
                        "date":    s["date"],
                        "status":  "Not Reviewed",
                        "evidence": "Control not assessed in this scan.",
                        "confidence": None,
                    })

    # Compute MTTR and assemble output
    controls_out: list[dict] = []
    total_mttr: list[int] = []
    currently_open = ever_open = remediated = currently_satisfied = 0

    for vid, timeline in sorted(vuln_timelines.items()):
        tl = sorted(timeline, key=lambda t: t["date"])
        first_open = None
        first_closed = None  # first "Not a Finding" AFTER first_open
        for entry in tl:
            if entry["status"] == "Open" and first_open is None:
                first_open = entry["date"]
            # Only count as remediated if it closed AFTER it was first opened
            if (entry["status"] == "Not a Finding"
                    and first_open is not None
                    and first_closed is None
                    and entry["date"] >= first_open):
                first_closed = entry["date"]

        mttr_days = None
        if first_open:
            ever_open += 1
        if first_open and first_closed:
            remediated += 1
            d1 = datetime.fromisoformat(first_open).date()
            d2 = datetime.fromisoformat(first_closed).date()
            mttr_days = (d2 - d1).days
            total_mttr.append(mttr_days)

        latest_status = tl[-1]["status"] if tl else "Not Reviewed"
        if latest_status == "Open":
            currently_open += 1
        if latest_status in ("Not a Finding", "Not Applicable"):
            currently_satisfied += 1

        meta = control_meta.get(vid, {})
        controls_out.append({
            "vuln_id":       vid,
            "title":         meta.get("title", ""),
            "severity":      meta.get("severity", ""),
            "stig_name":     meta.get("stig_name", ""),
            "timeline":      tl,
            "first_open":    first_open,
            "first_closed":  first_closed,
            "mttr_days":     mttr_days,
            "latest_status": latest_status,
            "record":        latest_record.get(vid),
        })

    avg_mttr = round(sum(total_mttr) / len(total_mttr), 1) if total_mttr else None
    scans_out = [
        {"scan_id": s["scan_id"], "date": s["date"], "label": s["date"][5:]}
        for s in stig_scans
    ]

    return {
        "apps":     stig_apps,
        "app":      selected_app,
        "slugs":    sorted(all_slugs),
        "slug":     slug,
        "scans":    scans_out,
        "controls": controls_out,
        "summary": {
            "total_controls":     len(controls_out),
            "ever_open":          ever_open,
            "remediated":         remediated,
            "avg_mttr_days":      avg_mttr,
            "currently_open":     currently_open,
            "currently_satisfied": currently_satisfied,
        },
    }
