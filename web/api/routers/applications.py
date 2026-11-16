"""Epyon Web — applications routes."""
from __future__ import annotations

import json
import re
import shutil

from fastapi import APIRouter
from fastapi import HTTPException
from fastapi import Request
from fastapi import Response

from .. import parsers
from .. import cache_state
from .. import parse_cache
import time
from .. import main as api_main

router = APIRouter()

def _save_hidden_apps(hidden: set[str]) -> None:
    api_main.HIDDEN_APPS_FILE.parent.mkdir(parents=True, exist_ok=True)
    api_main.HIDDEN_APPS_FILE.write_text(json.dumps(sorted(hidden), indent=2))


def _save_monitored_apps(monitored: set[str]) -> None:
    api_main.MONITORED_APPS_FILE.parent.mkdir(parents=True, exist_ok=True)
    api_main.MONITORED_APPS_FILE.write_text(json.dumps(sorted(monitored), indent=2))


def _save_registered_apps(apps: list[dict]) -> None:
    api_main.REGISTERED_APPS_FILE.parent.mkdir(parents=True, exist_ok=True)
    api_main.REGISTERED_APPS_FILE.write_text(json.dumps(apps, indent=2), encoding="utf-8")


@router.post("/api/applications", status_code=201)
async def register_application(request: Request, response: Response):
    """Register a new application by name and URL (no scan triggered)."""
    api_main._sec_headers(response)
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, "Invalid JSON")
    name = (body.get("name") or "").strip()
    url  = (body.get("url")  or "").strip()
    if not name:
        raise HTTPException(400, "name is required")
    if not api_main._SAFE_ID_RE.match(name):
        raise HTTPException(400, "name must be alphanumeric with hyphens/underscores/dots only")
    valid_prefixes = ["https://", "http://", "git@"]
    if url and not any(url.startswith(p) for p in valid_prefixes):
        raise HTTPException(400, "url must be an HTTPS or SSH Git URL")
    if url and re.search(r"[;&|`$\(\)\n\r<>'\"]", url):
        raise HTTPException(400, "url contains invalid characters")
    apps = api_main._load_registered_apps()
    apps = [a for a in apps if a["name"] != name]
    apps.append({"name": name, "url": url, "added_at": api_main._now()})
    _save_registered_apps(apps)
    return {"registered": name, "url": url}


# ── Application action endpoints ─────────────────────────────────────────────
# Names are passed in the request body (POST) or as a ?name= query param
# (DELETE) to avoid Starlette normalising %2F → / in URL path parameters,
# which breaks routing when the application name is a full Git URL.

def _require_app_name(name: str | None) -> str:
    name = (name or "").strip()
    if not name:
        raise HTTPException(400, "name is required")
    return name


@router.post("/api/applications/hide")
async def hide_application(request: Request, response: Response):
    api_main._sec_headers(response)
    body = await request.json()
    name = _require_app_name(body.get("name"))
    hidden = api_main._load_hidden_apps()
    hidden.add(name)
    _save_hidden_apps(hidden)
    api_main._invalidate_scan_cache(reason="hidden_apps_changed", scan_id=name)
    return {"hidden": name}


@router.post("/api/applications/restore")
async def restore_application(request: Request, response: Response):
    api_main._sec_headers(response)
    body = await request.json()
    name = _require_app_name(body.get("name"))
    hidden = api_main._load_hidden_apps()
    hidden.discard(name)
    _save_hidden_apps(hidden)
    api_main._invalidate_scan_cache(reason="hidden_apps_changed", scan_id=name)
    return {"restored": name}


@router.post("/api/applications/monitored")
async def set_monitored(request: Request, response: Response):
    api_main._sec_headers(response)
    body = await request.json()
    name = _require_app_name(body.get("name"))
    monitored = api_main._load_monitored_apps()
    monitored.add(name)
    _save_monitored_apps(monitored)
    # /api/metrics and /api/applications both filter by this list, and both
    # cache their results independently — without busting those caches here,
    # the Metrics page kept showing the pre-toggle monitored-app set (and any
    # numbers derived from it) for up to 5 minutes after this change.
    api_main._invalidate_scan_cache(reason="monitored_apps_changed", scan_id=name)
    return {"monitored": name}


@router.delete("/api/applications/monitored")
def unset_monitored(name: str, response: Response):
    api_main._sec_headers(response)
    name = _require_app_name(name)
    monitored = api_main._load_monitored_apps()
    monitored.discard(name)
    _save_monitored_apps(monitored)
    api_main._invalidate_scan_cache(reason="monitored_apps_changed", scan_id=name)
    return {"unmonitored": name}


@router.delete("/api/applications/data")
def delete_application(name: str, request: Request, response: Response):
    """Permanently delete all scan directories for an application."""
    api_main._sec_headers(response)
    name = _require_app_name(name)
    api_main._audit(request, "delete_application", f"app={name}")
    scan_dirs = [
        d for d in parsers.find_scan_dirs(api_main.EPYON_ROOT, days=35)
        if parsers.parse_dir_name(d.name)["target"] == name
    ]
    deleted = []
    for d in scan_dirs:
        try:
            d.resolve().relative_to(api_main.EPYON_ROOT.resolve())
        except ValueError:
            raise HTTPException(403, "Access denied")
        shutil.rmtree(d)
        deleted.append(d.name)
    hidden = api_main._load_hidden_apps()
    if name in hidden:
        hidden.discard(name)
        _save_hidden_apps(hidden)
    return {"deleted": deleted}


@router.get("/api/applications-hidden")
def hidden_applications(response: Response):
    api_main._sec_headers(response)
    return sorted(api_main._load_hidden_apps())


@router.get("/api/applications/{name}/scans")
def app_scans(name: str, response: Response):
    api_main._sec_headers(response)
    if not api_main._SAFE_ID_RE.match(name):
        raise HTTPException(400, "Invalid application name")
    scans = [
        parsers.load_scan(d, api_main.EPYON_ROOT)
        for d in parsers.find_scan_dirs(api_main.EPYON_ROOT, days=35)
        if parsers.parse_dir_name(d.name)["target"] == name
    ]
    scans.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    return scans


def _load_registered_apps() -> list[dict]:
    try:
        if api_main.REGISTERED_APPS_FILE.exists():
            return json.loads(api_main.REGISTERED_APPS_FILE.read_text(encoding="utf-8"))
    except Exception:
        pass
    return []


@router.get("/api/applications")
def applications(response: Response):
    now = time.monotonic()
    
    # Return cached app list if available
    if cache_state.apps and (now - cache_state.apps[1]) < api_main._APPS_CACHE_TTL:
        age = now - cache_state.apps[1]
        api_main._cache_metrics["hits"]["apps"] += 1
        api_main._cache_metrics_logger.debug(f"cache_read source=memory endpoint=applications hit=true age_seconds={age:.1f}")
        response.headers["Cache-Control"] = "public, max-age=60"
        response.headers["X-Cache-Version"] = str(cache_state.version)
        return cache_state.apps[0]
    
    api_main._cache_metrics["misses"]["apps"] += 1
    api_main._cache_metrics_logger.debug("cache_read source=memory endpoint=applications hit=false")
    api_main._sec_headers(response)
    hidden   = api_main._load_hidden_apps()
    monitored = api_main._load_monitored_apps()
    scans = [api_main._cached_load_scan(d) for d in api_main._cached_find_scan_dirs()]
    parse_cache.flush()
    by_target: dict[str, list] = {}
    for s in scans:
        if s["target"] not in hidden:
            by_target.setdefault(s["target"], []).append(s)

    result = []
    for name, tscans in by_target.items():
        tscans.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        latest = tscans[0] if tscans else {}

        # For vulnerability counts, prefer the latest comprehensive scan (full/nightly)
        # so that quick/stig/local_model scans don't zero out the displayed counts.
        latest_comprehensive = next(
            (s for s in tscans if s.get("scan_type") in api_main._COMPREHENSIVE_SCAN_TYPES),
            latest,
        )

        # Find the latest scan that actually produced STIG output
        latest_stig = next((s for s in tscans if s.get("stig_total", 0) > 0), None)

        result.append({
            "name":                      name,
            "scan_count":                len(tscans),
            "last_scanned":              latest.get("timestamp", ""),
            "scan_type":                 latest.get("scan_type", ""),
            "critical":                  latest_comprehensive.get("critical", 0),
            "high":                      latest_comprehensive.get("high", 0),
            "medium":                    latest_comprehensive.get("medium", 0),
            "low":                       latest_comprehensive.get("low", 0),
            "status":                    parsers.get_status(latest_comprehensive),
            "gate_status":               latest_comprehensive.get("gate_status", "pass"),
            "latest_scan_id":            latest.get("scan_id", ""),
            "comprehensive_scan_id":     latest_comprehensive.get("scan_id", ""),
            "comprehensive_timestamp":   latest_comprehensive.get("timestamp", ""),
            "comprehensive_scan_type":   latest_comprehensive.get("scan_type", ""),
            "stig_total":                latest_stig.get("stig_total", 0)          if latest_stig else 0,
            "stig_open":           latest_stig.get("stig_open", 0)           if latest_stig else 0,
            "stig_pass":           latest_stig.get("stig_pass", 0)           if latest_stig else 0,
            "stig_na":             latest_stig.get("stig_na", 0)             if latest_stig else 0,
            "stig_nr":             latest_stig.get("stig_nr", 0)             if latest_stig else 0,
            "latest_stig_scan_id": latest_stig.get("scan_id", "")            if latest_stig else "",
            "has_stig_report":     latest_stig.get("has_stig_report", False) if latest_stig else False,
            "has_stig_cklb":       latest_stig.get("has_stig_cklb", False)   if latest_stig else False,
            "url":                 "",
            "monitored":           name in monitored,
        })

    # Merge in registered-but-unscanned apps
    scanned_names = {r["name"] for r in result}
    registered = _load_registered_apps()
    for reg in registered:
        rname = reg.get("name")
        if not rname:
            continue
        if rname in hidden or rname in scanned_names:
            # If it has been scanned, backfill the URL onto the existing entry
            for r in result:
                if r["name"] == rname and not r["url"]:
                    r["url"] = reg.get("url", "")
            continue
        result.append({
            "name":                rname,
            "scan_count":          0,
            "last_scanned":        "",
            "scan_type":           "",
            "critical":            0,
            "high":                0,
            "medium":              0,
            "low":                 0,
            "status":              "unknown",
            "latest_scan_id":      "",
            "stig_total":          0,
            "stig_open":           0,
            "stig_pass":           0,
            "stig_na":             0,
            "stig_nr":             0,
            "latest_stig_scan_id": "",
            "has_stig_report":     False,
            "has_stig_cklb":       False,
            "url":                 reg.get("url", ""),
            "added_at":            reg.get("added_at", ""),
            "monitored":           rname in monitored,
        })

    result.sort(key=lambda x: x.get("last_scanned", "") or x.get("added_at", ""), reverse=True)
    
    cache_state.apps = (result, now)
    api_main._cache_metrics["writes"]["apps"] += 1
    api_main._cache_metrics_logger.debug(f"cache_write endpoint=applications success=true count={len(result)}")
    response.headers["Cache-Control"] = "public, max-age=60"
    response.headers["X-Cache-Version"] = str(cache_state.version)
    return result
