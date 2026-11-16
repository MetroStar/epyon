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
