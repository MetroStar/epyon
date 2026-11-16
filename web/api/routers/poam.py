"""Epyon Web — poam routes."""
from __future__ import annotations

from collections import Counter
from typing import Optional

from fastapi import APIRouter
from fastapi import HTTPException
from fastapi import Response
from pydantic import BaseModel

from .. import parsers
from .. import poam
from .. import main as api_main

router = APIRouter()

def _poam_rows(app_key_id: str, stig_scan_id: Optional[str], vuln_scan_id: Optional[str]) -> list[dict]:
    """Rows for one application: STIG items from one scan, CVEs from another (may be the same)."""
    sla, overrides = poam.get_sla_days(), poam.get_overrides(app_key_id)
    rows: list[dict] = []
    if stig_scan_id:
        stigs = api_main._build_stig_entries(stig_scan_id, api_main._require_scan_dir(stig_scan_id))
        rows += poam.build_rows(stig_scan_id, stigs, {}, sla_days=sla, overrides=overrides)
    if vuln_scan_id:
        data = parsers.load_scan_complete(api_main._require_scan_dir(vuln_scan_id), api_main.EPYON_ROOT)
        rows += poam.build_rows(vuln_scan_id, [], data.get("findings", {}), sla_days=sla, overrides=overrides)
    return poam.number_rows(rows)


def _scan_ref(scan: Optional[dict]) -> Optional[dict]:
    """The bits of a scan a POA&M reader needs to know which run the rows came from."""
    if not scan:
        return None
    return {"scan_id": scan["scan_id"], "scan_type": scan.get("scan_type", ""), "timestamp": scan.get("timestamp", "")}


def _poam_response(scan_ids_label: str, rows: list[dict], preview: bool, filename: str,
                   sources: Optional[dict] = None, notes: Optional[list[str]] = None):
    if preview:
        return {"scan_id": scan_ids_label, "columns": poam.COLUMNS, "total": len(rows),
                "sources": sources or {}, "notes": notes or [],
                "sla_days": poam.get_sla_days(),
                "by_severity": dict(Counter(r["Raw Severity"] for r in rows)),
                "by_source": dict(Counter("STIG" if r["Detection Source"].startswith("Epyon STIG") else "CVE" for r in rows)),
                "rows": rows}
    return Response(poam.to_csv(rows), media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="{filename}"'})


def _latest_poam_scans(app_name: str) -> tuple[Optional[dict], Optional[dict]]:
    """(latest scan with STIG results, latest full/nightly scan) for an application.

    CVEs only come from a full/nightly scan: quick scans skip tools, so falling back to one
    would silently report a partial picture as the application's POA&M."""
    scans = [api_main._cached_load_scan(d) for d in api_main._cached_find_scan_dirs()]
    scans = sorted((s for s in scans if s["target"] == app_name), key=lambda x: x.get("timestamp", ""), reverse=True)
    stig = next((s for s in scans if s.get("stig_total", 0) > 0), None)
    vuln = next((s for s in scans if s.get("scan_type") in api_main._COMPREHENSIVE_SCAN_TYPES), None)
    return stig, vuln


def _app_poam(name: str) -> tuple[list[dict], dict, list[str]]:
    """Rows, sources and notes for an application's POA&M."""
    stig, vuln = _latest_poam_scans(name)
    rows = _poam_rows(name, stig["scan_id"] if stig else "", vuln["scan_id"] if vuln else "")
    notes = []
    if not vuln:
        notes.append("No full or nightly scan yet, so CVEs are not included. Run a full scan to add them.")
    if not stig:
        notes.append("No scan with STIG results yet, so STIG items are not included.")
    return rows, {"stig": _scan_ref(stig), "vuln": _scan_ref(vuln)}, notes


@router.get("/api/scans/{scan_id}/poam")
def scan_poam(scan_id: str, response: Response, preview: bool = False):
    """POA&M of Open STIG controls plus unsuppressed Critical/High CVEs for one scan.

    Returns a CSV download, or JSON rows when ?preview=true."""
    api_main._sec_headers(response)
    if not api_main._SAFE_ID_RE.match(scan_id):
        raise HTTPException(400, "Invalid scan_id")
    rows = _poam_rows(scan_id, scan_id, scan_id)
    this = api_main._cached_load_scan(api_main._require_scan_dir(scan_id))
    sources = {"stig": _scan_ref(this) if this.get("stig_total", 0) > 0 else None, "vuln": _scan_ref(this)}
    notes: list[str] = []
    if this.get("scan_type") not in api_main._COMPREHENSIVE_SCAN_TYPES:
        _, latest_full = _latest_poam_scans(this["target"])
        sources["latest_full"] = _scan_ref(latest_full)
        notes.append(f"This is a {this.get('scan_type') or 'partial'} scan and does not run every tool, so its CVE list is incomplete. "
                     "The application POA&M uses the latest full scan.")
    return _poam_response(scan_id, rows, preview, f"poam-{scan_id}.csv", sources, notes)


@router.get("/api/applications/{name}/poam")
def app_poam(name: str, response: Response, preview: bool = False):
    """Application POA&M: Open STIG controls from its latest STIG scan plus Critical/High CVEs
    from its latest comprehensive scan."""
    api_main._sec_headers(response)
    if not api_main._SAFE_ID_RE.match(name):
        raise HTTPException(400, "Invalid application name")
    scans_exist = any(sc["target"] == name for sc in (api_main._cached_load_scan(d) for d in api_main._cached_find_scan_dirs()))
    if not scans_exist:
        raise HTTPException(404, "No scans found for this application")
    rows, sources, notes = _app_poam(name)
    return _poam_response(name, rows, preview, f"poam-{name}.csv", sources, notes)


@router.get("/api/poam/summary")
def poam_summary(response: Response):
    """Per-application POA&M roll-up for the POA&M overview page."""
    api_main._sec_headers(response)
    hidden = api_main._load_hidden_apps()
    names = sorted({s["target"] for s in (api_main._cached_load_scan(d) for d in api_main._cached_find_scan_dirs())} - hidden)
    apps_out: list[dict] = []
    for name in names:
        if not api_main._SAFE_ID_RE.match(name):
            continue
        stig, vuln = _latest_poam_scans(name)
        if not (stig or vuln):
            continue
        try:
            rows, sources, notes = _app_poam(name)
        except HTTPException:
            continue
        apps_out.append({"name": name, "stig_scan_id": (stig or {}).get("scan_id", ""),
                         "vuln_scan_id": (vuln or {}).get("scan_id", ""),
                         "sources": sources, "notes": notes, **poam.summarize(rows)})
    totals = {k: sum(a[k] for a in apps_out) for k in ("total", "stig", "cve", "overdue", "manual_dates")}
    totals["by_severity"] = {k: sum(a["by_severity"][k] for a in apps_out) for k in ("Critical", "High", "Medium", "Low")}
    return {"sla_days": poam.get_sla_days(), "totals": totals, "apps": apps_out}


class PoamSlaBody(BaseModel):
    sla_days: dict[str, int]


class PoamDueDateBody(BaseModel):
    key: str
    due_date: Optional[str] = None  # YYYY-MM-DD; null clears the override


@router.get("/api/poam/config")
def get_poam_config(response: Response):
    api_main._sec_headers(response)
    return {"sla_days": poam.get_sla_days(), "defaults": poam.SLA_DAYS}


@router.put("/api/poam/config")
def put_poam_config(body: PoamSlaBody, response: Response):
    """Set the days-to-complete per severity used for POA&M scheduled completion dates."""
    api_main._sec_headers(response)
    try:
        return {"sla_days": poam.set_sla_days(body.sla_days)}
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.put("/api/scans/{scan_id}/poam/due-date")
def put_poam_due_date(scan_id: str, body: PoamDueDateBody, response: Response):
    """Manually set (or clear) the completion date for one POA&M item; persists across rescans."""
    api_main._sec_headers(response)
    if not api_main._SAFE_ID_RE.match(scan_id):
        raise HTTPException(400, "Invalid scan_id")
    api_main._require_scan_dir(scan_id)
    try:
        poam.set_override(scan_id, body.key, body.due_date)
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {"key": body.key, "due_date": body.due_date}


@router.put("/api/applications/{name}/poam/due-date")
def put_app_poam_due_date(name: str, body: PoamDueDateBody, response: Response):
    api_main._sec_headers(response)
    if not api_main._SAFE_ID_RE.match(name):
        raise HTTPException(400, "Invalid application name")
    try:
        poam.set_override(name, body.key, body.due_date)
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {"key": body.key, "due_date": body.due_date}
