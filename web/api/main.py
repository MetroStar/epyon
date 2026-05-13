"""
Epyon Web — FastAPI backend
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from . import jobs as job_store
from . import parsers
from . import github_sync
from . import openai_summary

# ── Paths ─────────────────────────────────────────────────────
_HERE        = Path(__file__).parent
EPYON_ROOT   = (_HERE / ".." / "..").resolve()
SCRIPTS_DIR  = EPYON_ROOT / "scripts" / "shell"
APPROVED_IMAGES_FILE = EPYON_ROOT / "configuration" / "approved-base-images.conf"
GITHUB_CONFIG_FILE   = _HERE / ".." / "github-config.json"
HIDDEN_APPS_FILE     = EPYON_ROOT / "configuration" / "hidden-apps.json"
REGISTERED_APPS_FILE = EPYON_ROOT / "configuration" / "registered-apps.json"
STATIC_DIR           = (_HERE / ".." / "static").resolve()

# ── Validation ────────────────────────────────────────────────
_SAFE_ID_RE      = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_\-.]*$")
_JOB_ID_RE       = re.compile(r"^\d{14}$")
_VALID_SCAN_TYPES = {"quick", "full", "nightly", "baseline", "stig", "local_model"}
_TOKEN_RE        = re.compile(r"^(ghp_|github_pat_|ghs_|gho_)[a-zA-Z0-9_]+$")
_REPO_RE         = re.compile(r"^[a-zA-Z0-9_.\-]+/[a-zA-Z0-9_.\-]+$")
_KEY_RE          = re.compile(r"^sk-[A-Za-z0-9_\-]{20,}$")

# ── Metrics cache ─────────────────────────────────────────────
_metrics_cache:    dict  = {}
_metrics_cache_ts: float = 0.0
_METRICS_TTL:      float = 300.0


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _read_github_config() -> dict:
    try:
        return json.loads(GITHUB_CONFIG_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _write_github_config(cfg: dict) -> None:
    GITHUB_CONFIG_FILE.write_text(json.dumps(cfg, indent=2), encoding="utf-8")


# ── Lifespan ─────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(_: FastAPI):
    async def _auto_sync_loop() -> None:
        await asyncio.sleep(10)
        while True:
            cfg = _read_github_config()
            if cfg.get("token") and cfg.get("repos"):
                await github_sync.trigger_sync(
                    GITHUB_CONFIG_FILE, EPYON_ROOT, parsers.find_scan_dirs
                )
            await asyncio.sleep(3 * 60 * 60)

    asyncio.create_task(_auto_sync_loop())
    yield


# ── App ───────────────────────────────────────────────────────

app = FastAPI(title="Epyon Web", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def _sec_headers(response: Response) -> None:
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"]        = "SAMEORIGIN"


# ── Health ────────────────────────────────────────────────────

@app.get("/api/health")
def health(response: Response):
    _sec_headers(response)
    return {"status": "ok", "epyon_root": str(EPYON_ROOT)}


# ── Stats ─────────────────────────────────────────────────────

@app.get("/api/stats")
def stats(response: Response):
    _sec_headers(response)
    hidden = _load_hidden_apps()
    scans = [parsers.load_scan(d, EPYON_ROOT) for d in parsers.find_scan_dirs(EPYON_ROOT)]
    by_target: dict[str, dict] = {}
    for s in scans:
        t = s["target"]
        if t in hidden:
            continue
        if t not in by_target or s.get("timestamp", "") > by_target[t].get("timestamp", ""):
            by_target[t] = s
    latest = list(by_target.values())
    return {
        "total_applications": len(by_target),
        "total_scans":        len(scans),
        "critical": sum(s["critical"] for s in latest),
        "high":     sum(s["high"]     for s in latest),
        "medium":   sum(s["medium"]   for s in latest),
        "low":      sum(s["low"]      for s in latest),
    }


# ── Scan history ──────────────────────────────────────────────

@app.get("/api/scan-history")
def scan_history(response: Response):
    _sec_headers(response)
    hidden  = _load_hidden_apps()
    scans   = [parsers.load_scan(d, EPYON_ROOT) for d in parsers.find_scan_dirs(EPYON_ROOT)
               if parsers.parse_dir_name(d.name)["target"] not in hidden]
    targets = sorted({s["target"] for s in scans})
    users   = sorted({s["user"] for s in scans if s.get("user")})
    return {
        "generated_at": _now(),
        "total_scans":  len(scans),
        "targets":      targets,
        "users":        users,
    }


# ── Applications ──────────────────────────────────────────────

def _load_hidden_apps() -> set[str]:
    try:
        if HIDDEN_APPS_FILE.exists():
            return set(json.loads(HIDDEN_APPS_FILE.read_text()))
    except Exception:
        pass
    return set()


def _save_hidden_apps(hidden: set[str]) -> None:
    HIDDEN_APPS_FILE.parent.mkdir(parents=True, exist_ok=True)
    HIDDEN_APPS_FILE.write_text(json.dumps(sorted(hidden), indent=2))


def _load_registered_apps() -> list[dict]:
    try:
        if REGISTERED_APPS_FILE.exists():
            return json.loads(REGISTERED_APPS_FILE.read_text(encoding="utf-8"))
    except Exception:
        pass
    return []


def _save_registered_apps(apps: list[dict]) -> None:
    REGISTERED_APPS_FILE.parent.mkdir(parents=True, exist_ok=True)
    REGISTERED_APPS_FILE.write_text(json.dumps(apps, indent=2), encoding="utf-8")


@app.post("/api/applications", status_code=201)
async def register_application(request: Request, response: Response):
    """Register a new application by name and URL (no scan triggered)."""
    _sec_headers(response)
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, "Invalid JSON")
    name = (body.get("name") or "").strip()
    url  = (body.get("url")  or "").strip()
    if not name:
        raise HTTPException(400, "name is required")
    if not _SAFE_ID_RE.match(name):
        raise HTTPException(400, "name must be alphanumeric with hyphens/underscores/dots only")
    valid_prefixes = ["https://", "http://", "git@"]
    if url and not any(url.startswith(p) for p in valid_prefixes):
        raise HTTPException(400, "url must be an HTTPS or SSH Git URL")
    if url and re.search(r"[;&|`$\(\)\n\r<>'\"]", url):
        raise HTTPException(400, "url contains invalid characters")
    apps = _load_registered_apps()
    apps = [a for a in apps if a["name"] != name]
    apps.append({"name": name, "url": url, "added_at": _now()})
    _save_registered_apps(apps)
    return {"registered": name, "url": url}


@app.get("/api/applications")
def applications(response: Response):
    _sec_headers(response)
    hidden = _load_hidden_apps()
    scans = [parsers.load_scan(d, EPYON_ROOT) for d in parsers.find_scan_dirs(EPYON_ROOT)]
    by_target: dict[str, list] = {}
    for s in scans:
        if s["target"] not in hidden:
            by_target.setdefault(s["target"], []).append(s)

    result = []
    for name, tscans in by_target.items():
        tscans.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        latest = tscans[0] if tscans else {}

        # Find the latest scan that actually produced STIG output
        latest_stig = next((s for s in tscans if s.get("stig_total", 0) > 0), None)

        result.append({
            "name":                name,
            "scan_count":          len(tscans),
            "last_scanned":        latest.get("timestamp", ""),
            "scan_type":           latest.get("scan_type", ""),
            "critical":            latest.get("critical", 0),
            "high":                latest.get("high", 0),
            "medium":              latest.get("medium", 0),
            "low":                 latest.get("low", 0),
            "status":              parsers.get_status(latest),
            "latest_scan_id":      latest.get("scan_id", ""),
            "stig_total":          latest_stig.get("stig_total", 0)          if latest_stig else 0,
            "stig_open":           latest_stig.get("stig_open", 0)           if latest_stig else 0,
            "stig_pass":           latest_stig.get("stig_pass", 0)           if latest_stig else 0,
            "stig_na":             latest_stig.get("stig_na", 0)             if latest_stig else 0,
            "latest_stig_scan_id": latest_stig.get("scan_id", "")            if latest_stig else "",
            "has_stig_report":     latest_stig.get("has_stig_report", False) if latest_stig else False,
            "has_stig_cklb":       latest_stig.get("has_stig_cklb", False)   if latest_stig else False,
            "url":                 "",
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
            "latest_stig_scan_id": "",
            "has_stig_report":     False,
            "has_stig_cklb":       False,
            "url":                 reg.get("url", ""),
            "added_at":            reg.get("added_at", ""),
        })

    result.sort(key=lambda x: x.get("last_scanned", "") or x.get("added_at", ""), reverse=True)
    return result


@app.delete("/api/applications/{name}")
def hide_application(name: str, response: Response):
    _sec_headers(response)
    if not _SAFE_ID_RE.match(name):
        raise HTTPException(400, "Invalid application name")
    hidden = _load_hidden_apps()
    hidden.add(name)
    _save_hidden_apps(hidden)
    return {"hidden": name}


@app.post("/api/applications/{name}/restore")
def restore_application(name: str, response: Response):
    _sec_headers(response)
    if not _SAFE_ID_RE.match(name):
        raise HTTPException(400, "Invalid application name")
    hidden = _load_hidden_apps()
    hidden.discard(name)
    _save_hidden_apps(hidden)
    return {"restored": name}


@app.delete("/api/applications/{name}/data")
def delete_application(name: str, response: Response):
    """Permanently delete all scan directories for an application."""
    _sec_headers(response)
    if not _SAFE_ID_RE.match(name):
        raise HTTPException(400, "Invalid application name")
    scan_dirs = [
        d for d in parsers.find_scan_dirs(EPYON_ROOT)
        if parsers.parse_dir_name(d.name)["target"] == name
    ]
    deleted = []
    for d in scan_dirs:
        try:
            d.resolve().relative_to(EPYON_ROOT.resolve())
        except ValueError:
            raise HTTPException(403, "Access denied")
        shutil.rmtree(d)
        deleted.append(d.name)
    # Also remove from hidden list if present
    hidden = _load_hidden_apps()
    if name in hidden:
        hidden.discard(name)
        _save_hidden_apps(hidden)
    return {"deleted": deleted}


@app.delete("/api/scans/{scan_id}")
def delete_scan(scan_id: str, response: Response):
    """Permanently delete a single scan directory."""
    _sec_headers(response)
    if not _SAFE_ID_RE.match(scan_id):
        raise HTTPException(400, "Invalid scan_id")
    scan_dirs = parsers.find_scan_dirs(EPYON_ROOT)
    matched = next((d for d in scan_dirs if d.name == scan_id), None)
    if not matched:
        raise HTTPException(404, "Scan not found")
    try:
        matched.resolve().relative_to(EPYON_ROOT.resolve())
    except ValueError:
        raise HTTPException(403, "Access denied")
    shutil.rmtree(matched)
    return {"deleted": scan_id}


@app.get("/api/applications-hidden")
def hidden_applications(response: Response):
    _sec_headers(response)
    return sorted(_load_hidden_apps())


@app.get("/api/applications/{name}/scans")
def app_scans(name: str, response: Response):
    _sec_headers(response)
    if not _SAFE_ID_RE.match(name):
        raise HTTPException(400, "Invalid application name")
    scans = [
        parsers.load_scan(d, EPYON_ROOT)
        for d in parsers.find_scan_dirs(EPYON_ROOT)
        if parsers.parse_dir_name(d.name)["target"] == name
    ]
    scans.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    return scans


# ── Scan detail ───────────────────────────────────────────────

@app.get("/api/scans/{scan_id}/dashboard")
def scan_dashboard(scan_id: str, response: Response):
    if not _SAFE_ID_RE.match(scan_id):
        raise HTTPException(400, "Invalid scan_id")
    scan_dirs = parsers.find_scan_dirs(EPYON_ROOT)
    matched = next((d for d in scan_dirs if d.name == scan_id), None)
    if not matched:
        raise HTTPException(404, "Scan not found")
    dashboard = matched / "consolidated-reports" / "dashboards" / "security-dashboard.html"
    try:
        dashboard.resolve().relative_to(EPYON_ROOT.resolve())
    except ValueError:
        raise HTTPException(403, "Access denied")
    if not dashboard.exists():
        raise HTTPException(404, "Dashboard not generated for this scan")
    return FileResponse(str(dashboard), media_type="text/html")


@app.get("/api/scans/{scan_id}/stig-findings-md")
def stig_findings_md(scan_id: str, response: Response):
    """Serve the primary STIG findings markdown for a given scan."""
    _sec_headers(response)
    if not _SAFE_ID_RE.match(scan_id):
        raise HTTPException(400, "Invalid scan_id")
    scan_dirs = parsers.find_scan_dirs(EPYON_ROOT)
    matched = next((d for d in scan_dirs if d.name == scan_id), None)
    if not matched:
        raise HTTPException(404, "Scan not found")
    app_slug = re.sub(r"[^a-z0-9]+", "-", re.sub(r"_\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}$", "", scan_id).lower()).strip("-")
    report = matched / f"findings-{app_slug}.md"
    try:
        report.resolve().relative_to(EPYON_ROOT.resolve())
    except ValueError:
        raise HTTPException(403, "Access denied")
    if not report.exists():
        raise HTTPException(404, "STIG findings not generated for this scan")
    return FileResponse(str(report), media_type="text/markdown",
                        headers={"Content-Disposition": f'attachment; filename="findings-{scan_id}.md"'})


@app.get("/api/scans/{scan_id}/stig-findings-cklb")
def stig_findings_cklb(scan_id: str, response: Response):
    """Serve the primary STIG findings CKLB for a given scan."""
    _sec_headers(response)
    if not _SAFE_ID_RE.match(scan_id):
        raise HTTPException(400, "Invalid scan_id")
    scan_dirs = parsers.find_scan_dirs(EPYON_ROOT)
    matched = next((d for d in scan_dirs if d.name == scan_id), None)
    if not matched:
        raise HTTPException(404, "Scan not found")
    app_slug = re.sub(r"[^a-z0-9]+", "-", re.sub(r"_\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}$", "", scan_id).lower()).strip("-")
    report = matched / f"findings-{app_slug}.cklb"
    try:
        report.resolve().relative_to(EPYON_ROOT.resolve())
    except ValueError:
        raise HTTPException(403, "Access denied")
    if not report.exists():
        raise HTTPException(404, "STIG findings CKLB not generated for this scan")
    return FileResponse(str(report), media_type="application/json",
                        headers={"Content-Disposition": f'attachment; filename="findings-{scan_id}.cklb"'})


@app.get("/api/scans/{scan_id}/stig-data")
def stig_data(scan_id: str, response: Response):
    """Return merged controls + assessment results for all STIGs in a scan as JSON."""
    _sec_headers(response)
    if not _SAFE_ID_RE.match(scan_id):
        raise HTTPException(400, "Invalid scan_id")
    scan_dirs = parsers.find_scan_dirs(EPYON_ROOT)
    matched = next((d for d in scan_dirs if d.name == scan_id), None)
    if not matched:
        raise HTTPException(404, "Scan not found")

    stigs: list[dict] = []
    for results_file in sorted(matched.glob("stig-results-*.json")):
        slug = results_file.stem[len("stig-results-"):]
        controls_file = matched / f"stig-controls-{slug}.json"

        results: dict = {}
        try:
            raw = json.loads(results_file.read_text(encoding="utf-8"))
            # Support new wrapped format {assessments: {...}, token_usage: {...}}
            # and old flat format {vuln_id: {status, evidence}, ...}
            results = raw.get("assessments", raw) if "assessments" in raw else raw
        except Exception:
            pass

        controls_data: dict = {}
        try:
            controls_data = json.loads(controls_file.read_text(encoding="utf-8"))
        except Exception:
            pass

        controls_list = controls_data.get("controls", [])
        merged: list[dict] = []
        for c in controls_list:
            vid = c.get("vuln_id", "")
            assessed = results.get(vid, {})
            merged.append({
                "vuln_id":       vid,
                "group_id":      c.get("group_id", ""),
                "rule_id":       c.get("rule_id", ""),
                "number":        c.get("number"),
                "severity":      c.get("severity", ""),
                "title":         c.get("title", ""),
                "check_content": c.get("check_content", ""),
                "fix_text":      c.get("fix_text", ""),
                "discussion":    c.get("discussion", ""),
                "status":        assessed.get("status",     "Not Reviewed"),
                "evidence":      assessed.get("evidence",   ""),
                "confidence":    assessed.get("confidence", 0),
            })

        stigs.append({
            "slug":        slug,
            "stig_name":   controls_data.get("stig_name", slug),
            "release_info": controls_data.get("release_info", ""),
            "total":       len(merged),
            "controls":    merged,
        })

    return {"scan_id": scan_id, "stigs": stigs}


_SAFE_SLUG_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_\-]*\.(md|cklb)$")

@app.get("/api/scans/{scan_id}/stig-findings/{filename}")
def stig_findings_named(scan_id: str, filename: str, response: Response):
    """Serve a per-STIG named findings file (findings-{slug}.md or .cklb)."""
    _sec_headers(response)
    if not _SAFE_ID_RE.match(scan_id):
        raise HTTPException(400, "Invalid scan_id")
    if not _SAFE_SLUG_RE.match(filename):
        raise HTTPException(400, "Invalid filename")
    scan_dirs = parsers.find_scan_dirs(EPYON_ROOT)
    matched = next((d for d in scan_dirs if d.name == scan_id), None)
    if not matched:
        raise HTTPException(404, "Scan not found")
    report = matched / f"findings-{filename}"
    try:
        report.resolve().relative_to(EPYON_ROOT.resolve())
    except ValueError:
        raise HTTPException(403, "Access denied")
    if not report.exists():
        raise HTTPException(404, f"File not found: findings-{filename}")
    ext = filename.rsplit(".", 1)[-1]
    media = "text/markdown" if ext == "md" else "application/json"
    return FileResponse(str(report), media_type=media,
                        headers={"Content-Disposition": f'attachment; filename="findings-{filename}"'})


@app.get("/api/scans/{scan_id}")
def scan_detail(scan_id: str, response: Response):
    _sec_headers(response)
    if not _SAFE_ID_RE.match(scan_id):
        raise HTTPException(400, "Invalid scan_id")
    scan_dirs = parsers.find_scan_dirs(EPYON_ROOT)
    matched = next((d for d in scan_dirs if d.name == scan_id), None)
    if not matched:
        raise HTTPException(404, "Scan not found")
    data = parsers.load_scan(matched, EPYON_ROOT)
    data["findings"] = parsers.parse_scan_findings(matched)
    data["sbom"] = parsers.load_sbom_packages(matched)
    return data


@app.get("/api/scans/{scan_id}/sbom")
def scan_sbom(scan_id: str, response: Response):
    """Return SBOM package list for a scan (reads syft-json directly)."""
    _sec_headers(response)
    if not _SAFE_ID_RE.match(scan_id):
        raise HTTPException(400, "Invalid scan_id")
    scan_dirs = parsers.find_scan_dirs(EPYON_ROOT)
    matched = next((d for d in scan_dirs if d.name == scan_id), None)
    if not matched:
        raise HTTPException(404, "Scan not found")
    return parsers.load_sbom_packages(matched)


@app.get("/api/scans/{scan_id}/sbom/cyclonedx")
def scan_sbom_cyclonedx(scan_id: str, response: Response):
    """Download the CycloneDX SBOM JSON for a scan."""
    _sec_headers(response)
    if not _SAFE_ID_RE.match(scan_id):
        raise HTTPException(400, "Invalid scan_id")
    scan_dirs = parsers.find_scan_dirs(EPYON_ROOT)
    matched = next((d for d in scan_dirs if d.name == scan_id), None)
    if not matched:
        raise HTTPException(404, "Scan not found")
    sbom_dir = matched / "sbom"
    # Prefer the dedicated cyclonedx file, fall back to any *.cyclonedx.json
    candidates = [
        sbom_dir / "filesystem.cyclonedx.json",
        *sorted(sbom_dir.glob("*.cyclonedx.json")),
    ]
    cdx_file = next((f for f in candidates if f.exists()), None)
    if cdx_file is None:
        raise HTTPException(404, "CycloneDX SBOM not found for this scan")
    filename = f"sbom-{scan_id}.cyclonedx.json"
    return FileResponse(
        str(cdx_file),
        media_type="application/vnd.cyclonedx+json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ── Trigger scan ──────────────────────────────────────────────

@app.post("/api/scans", status_code=202)
async def trigger_scan(request: Request, response: Response):
    _sec_headers(response)
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, "Invalid JSON")

    target    = (body.get("target") or "").strip()
    scan_type = body.get("scan_type", "full")
    run_garak = bool(body.get("run_garak", False))

    if not target:
        raise HTTPException(400, "target is required")
    valid_prefixes = ["/", "./", "../", "https://", "http://", "git@"]
    if not any(target.startswith(p) for p in valid_prefixes):
        raise HTTPException(400, "target must be an absolute path, relative path, or Git URL")
    if re.search(r"[;&|`$\(\)\n\r<>]", target):
        raise HTTPException(400, "target contains invalid characters")
    if scan_type not in _VALID_SCAN_TYPES:
        raise HTTPException(400, f"scan_type must be one of: {sorted(_VALID_SCAN_TYPES)}")

    script_path = SCRIPTS_DIR / "run-epyon-scan-ci.sh"
    if not script_path.exists():
        raise HTTPException(500, "Scan script not found")

    job_id = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    job = job_store.create_job(job_id, target, scan_type)
    asyncio.create_task(
        job_store.run_scan_job(job_id, target, scan_type, script_path, EPYON_ROOT,
                               run_garak=run_garak)
    )
    return {"job_id": job_id, "status": "queued"}


# ── Jobs ──────────────────────────────────────────────────────

@app.get("/api/jobs")
def list_jobs(response: Response):
    _sec_headers(response)
    return sorted(job_store.jobs.values(), key=lambda j: j.get("started_at", ""), reverse=True)


@app.get("/api/jobs/{job_id}")
def get_job(job_id: str, response: Response):
    _sec_headers(response)
    if not _JOB_ID_RE.match(job_id):
        raise HTTPException(400, "Invalid job_id")
    job = job_store.jobs.get(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    return job


@app.post("/api/jobs/{job_id}/cancel")
def cancel_job(job_id: str, response: Response):
    _sec_headers(response)
    if not _JOB_ID_RE.match(job_id):
        raise HTTPException(400, "Invalid job_id")
    if job_id not in job_store.jobs:
        raise HTTPException(404, "Job not found")
    if job_store.jobs[job_id]["status"] not in ("queued", "running"):
        raise HTTPException(409, "Job is not running")
    job_store.cancel_job(job_id)
    return {"job_id": job_id, "status": "cancelled"}


# ── Metrics ───────────────────────────────────────────────────

@app.get("/api/metrics")
def get_metrics(response: Response):
    _sec_headers(response)
    global _metrics_cache, _metrics_cache_ts
    now = time.monotonic()
    if _metrics_cache and (now - _metrics_cache_ts) < _METRICS_TTL:
        return _metrics_cache

    scan_dirs = parsers.find_scan_dirs(EPYON_ROOT)
    all_scans = [parsers.load_scan(d, EPYON_ROOT) for d in scan_dirs]

    trend = sorted(
        [
            {
                "scan_id":   s["scan_id"],
                "target":    s["target"],
                "timestamp": s["timestamp"],
                "critical":  s["critical"],
                "high":      s["high"],
                "medium":    s["medium"],
                "low":       s["low"],
            }
            for s in all_scans if s.get("timestamp")
        ],
        key=lambda x: x["timestamp"],
    )[-60:]

    by_target: dict[str, list] = {}
    for s, d in zip(all_scans, scan_dirs):
        by_target.setdefault(s["target"], []).append((s, d))

    tool_counts:      dict[str, dict] = {}
    total_with_fix    = 0
    total_without_fix = 0
    cve_counts:       dict[str, dict] = {}

    for _target, scan_list in by_target.items():
        scan_list.sort(key=lambda x: x[0].get("timestamp", ""), reverse=True)
        _, latest_dir = scan_list[0]
        findings = parsers.parse_scan_findings(latest_dir)
        if not findings:
            continue
        for sev in ("critical", "high", "medium", "low"):
            for f in findings.get(f"{sev}_findings", []):
                tool = f.get("tool") or "Unknown"
                if tool not in tool_counts:
                    tool_counts[tool] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0}
                tool_counts[tool][sev]    += 1
                tool_counts[tool]["total"] += 1
                if f.get("fixed_version"):
                    total_with_fix += 1
                else:
                    total_without_fix += 1
                cve_id = f.get("id") or ""
                if cve_id.startswith("CVE-"):
                    if cve_id not in cve_counts:
                        cve_counts[cve_id] = {
                            "count":    0,
                            "severity": sev,
                            "title":    (f.get("title") or "")[:120],
                            "apps":     set(),
                        }
                    cve_counts[cve_id]["count"] += 1
                    cve_counts[cve_id]["apps"].add(_target)

    top_cves = sorted(cve_counts.items(), key=lambda x: x[1]["count"], reverse=True)[:20]

    scan_frequency = {
        target: {
            "total": len(scan_list),
            "dates": sorted(
                s.get("timestamp", "")[:10]
                for s, _ in scan_list if s.get("timestamp")
            ),
        }
        for target, scan_list in by_target.items()
    }

    result = {
        "trend": trend,
        "by_tool": sorted(
            [
                {
                    "tool":     k,
                    "critical": v["critical"],
                    "high":     v["high"],
                    "medium":   v["medium"],
                    "low":      v["low"],
                    "total":    v["total"],
                }
                for k, v in tool_counts.items()
            ],
            key=lambda x: -x["total"],
        ),
        "fix_rate": {"with_fix": total_with_fix, "without_fix": total_without_fix},
        "top_cves": [
            {
                "cve_id":   k,
                "count":    v["count"],
                "severity": v["severity"],
                "title":    v["title"],
                "apps":     sorted(v["apps"]),
            }
            for k, v in top_cves
        ],
        "scan_frequency": scan_frequency,
    }

    _metrics_cache    = result
    _metrics_cache_ts = now
    return result


# ── Settings ──────────────────────────────────────────────────

@app.get("/api/settings/approved-images")
def approved_images(response: Response):
    _sec_headers(response)
    try:
        content = APPROVED_IMAGES_FILE.read_text(encoding="utf-8")
    except OSError:
        content = ""
    return {"content": content}


# ── GitHub config ─────────────────────────────────────────────

@app.get("/api/github/config")
def github_config_get(response: Response):
    _sec_headers(response)
    cfg = _read_github_config()
    token = cfg.get("token", "")
    masked = re.sub(r"(?<=.{7}).(?=.{4})", "*", token) if token else ""
    return {
        "token_set":  bool(token),
        "token_hint": masked,
        "repos":      cfg.get("repos") or [],
        "last_sync":  cfg.get("last_sync"),
    }


@app.post("/api/github/config")
async def github_config_post(request: Request, response: Response):
    _sec_headers(response)
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, "Invalid JSON")

    cfg = _read_github_config()
    new_token = (body.get("token") or "").strip()
    if new_token and new_token != "KEEP_EXISTING":
        if not _TOKEN_RE.match(new_token):
            raise HTTPException(400, "Token does not look like a valid GitHub token")
        cfg["token"] = new_token

    if isinstance(body.get("repos"), list):
        cfg["repos"] = [
            r.strip() for r in body["repos"]
            if isinstance(r, str) and _REPO_RE.match(r.strip())
        ]
    _write_github_config(cfg)
    return {"ok": True}


# ── GitHub sync ───────────────────────────────────────────────

@app.post("/api/github/sync")
async def github_sync_post(response: Response):
    _sec_headers(response)
    state = github_sync.get_sync_state()
    if state["status"] == "running":
        return {"ok": False, "message": "Sync already in progress"}
    await github_sync.trigger_sync(GITHUB_CONFIG_FILE, EPYON_ROOT, parsers.find_scan_dirs)
    return {"ok": True, "message": "Sync started"}


@app.get("/api/github/sync")
def github_sync_status(response: Response):
    _sec_headers(response)
    return github_sync.get_sync_state()


# ── AI / OpenAI config ────────────────────────────────────────

@app.get("/api/ai/config")
def ai_config_get(response: Response):
    _sec_headers(response)
    cfg = openai_summary.read_ai_config()
    key = cfg.get("api_key", "")
    masked = re.sub(r"(?<=.{7}).(?=.{4})", "*", key) if key else ""
    return {
        "key_set":  bool(key),
        "key_hint": masked,
        "model":    cfg.get("model") or "gpt-4.1",
    }


@app.post("/api/ai/config")
async def ai_config_post(request: Request, response: Response):
    _sec_headers(response)
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, "Invalid JSON")

    cfg = openai_summary.read_ai_config()
    new_key = (body.get("api_key") or "").strip()
    if new_key and new_key != "KEEP_EXISTING":
        if not _KEY_RE.match(new_key):
            raise HTTPException(400, "api_key does not look like a valid OpenAI secret key")
        cfg["api_key"] = new_key

    allowed_models = {"gpt-4.1", "gpt-4o", "gpt-4o-mini", "gpt-4-turbo", "gpt-4", "gpt-3.5-turbo"}
    if body.get("model") in allowed_models:
        cfg["model"] = body["model"]

    openai_summary.write_ai_config(cfg)
    return {"ok": True}


# ── Executive summary ─────────────────────────────────────────

@app.post("/api/scans/{scan_id}/executive-summary")
async def exec_summary(scan_id: str, response: Response):
    _sec_headers(response)
    if not _SAFE_ID_RE.match(scan_id):
        raise HTTPException(400, "Invalid scan_id")

    scan_dirs = parsers.find_scan_dirs(EPYON_ROOT)
    matched = next((d for d in scan_dirs if d.name == scan_id), None)
    if not matched:
        raise HTTPException(404, "Scan not found")

    scan_meta = parsers.load_scan(matched, EPYON_ROOT)
    findings  = parsers.parse_scan_findings(matched)

    try:
        summary = await openai_summary.generate_summary(scan_id, scan_meta, findings)
    except RuntimeError as exc:
        raise HTTPException(400, str(exc))
    except Exception as exc:
        raise HTTPException(502, f"OpenAI request failed: {exc}")

    return {"scan_id": scan_id, "summary": summary}


@app.post("/api/scans/{scan_id}/technical-summary")
async def technical_summary(scan_id: str, response: Response):
    _sec_headers(response)
    if not _SAFE_ID_RE.match(scan_id):
        raise HTTPException(400, "Invalid scan_id")

    scan_dirs = parsers.find_scan_dirs(EPYON_ROOT)
    matched = next((d for d in scan_dirs if d.name == scan_id), None)
    if not matched:
        raise HTTPException(404, "Scan not found")

    scan_meta = parsers.load_scan(matched, EPYON_ROOT)
    findings  = parsers.parse_scan_findings(matched)

    try:
        summary = await openai_summary.generate_technical_summary(scan_id, scan_meta, findings)
    except RuntimeError as exc:
        raise HTTPException(400, str(exc))
    except Exception as exc:
        raise HTTPException(502, f"OpenAI request failed: {exc}")

    return {"scan_id": scan_id, "summary": summary}


@app.post("/api/executive-summary")
async def global_exec_summary(response: Response):
    _sec_headers(response)
    hidden = _load_hidden_apps()
    scan_dirs = parsers.find_scan_dirs(EPYON_ROOT)

    by_target: dict[str, tuple] = {}
    for d in scan_dirs:
        meta = parsers.parse_dir_name(d.name)
        target = meta["target"]
        if target in hidden:
            continue
        ts = meta["timestamp"]
        if target not in by_target or ts > by_target[target][1]:
            by_target[target] = (d, ts)

    if not by_target:
        raise HTTPException(404, "No scans found")

    apps = []
    for target, (scan_dir, _) in sorted(by_target.items()):
        scan_meta = parsers.load_scan(scan_dir, EPYON_ROOT)
        findings  = parsers.parse_scan_findings(scan_dir)
        apps.append({
            "name":           target,
            "critical":       scan_meta.get("critical", 0),
            "high":           scan_meta.get("high", 0),
            "medium":         scan_meta.get("medium", 0),
            "low":            scan_meta.get("low", 0),
            "tools_analyzed": scan_meta.get("tools_analyzed", []),
            "critical_sample": [
                {"tool": f.get("tool"), "id": f.get("id"), "package": f.get("package"), "title": f.get("title")}
                for f in findings.get("critical_findings", [])[:5]
            ],
        })

    try:
        summary = await openai_summary.generate_global_summary(apps)
    except RuntimeError as exc:
        raise HTTPException(400, str(exc))
    except Exception as exc:
        raise HTTPException(502, f"OpenAI request failed: {exc}")

    return {"summary": summary, "application_count": len(apps)}


@app.post("/api/technical-summary")
async def global_technical_summary(response: Response):
    _sec_headers(response)
    hidden = _load_hidden_apps()
    scan_dirs = parsers.find_scan_dirs(EPYON_ROOT)

    by_target: dict[str, tuple] = {}
    for d in scan_dirs:
        meta = parsers.parse_dir_name(d.name)
        target = meta["target"]
        if target in hidden:
            continue
        ts = meta["timestamp"]
        if target not in by_target or ts > by_target[target][1]:
            by_target[target] = (d, ts)

    if not by_target:
        raise HTTPException(404, "No scans found")

    apps = []
    for target, (scan_dir, _) in sorted(by_target.items()):
        scan_meta = parsers.load_scan(scan_dir, EPYON_ROOT)
        findings  = parsers.parse_scan_findings(scan_dir)
        apps.append({
            "name":           target,
            "critical":       scan_meta.get("critical", 0),
            "high":           scan_meta.get("high", 0),
            "medium":         scan_meta.get("medium", 0),
            "low":            scan_meta.get("low", 0),
            "tools_analyzed": scan_meta.get("tools_analyzed", []),
            "critical_sample": [
                {
                    "tool": f.get("tool"), "id": f.get("id"),
                    "package": f.get("package"), "version": f.get("version"),
                    "fixed_version": f.get("fixed_version"), "cvss": f.get("cvss"),
                    "title": f.get("title"),
                }
                for f in findings.get("critical_findings", [])[:15]
            ],
            "high_sample": [
                {
                    "tool": f.get("tool"), "id": f.get("id"),
                    "package": f.get("package"), "version": f.get("version"),
                    "fixed_version": f.get("fixed_version"), "cvss": f.get("cvss"),
                    "title": f.get("title"),
                }
                for f in findings.get("high_findings", [])[:10]
            ],
        })

    try:
        summary = await openai_summary.generate_global_technical_summary(apps)
    except RuntimeError as exc:
        raise HTTPException(400, str(exc))
    except Exception as exc:
        raise HTTPException(502, f"OpenAI request failed: {exc}")

    return {"summary": summary, "application_count": len(apps)}


# ── SPA / static file serving ─────────────────────────────────
# Serves web/static/ for JS, CSS, and other assets.

if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    @app.get("/{full_path:path}", include_in_schema=False)
    def spa_fallback(full_path: str):
        candidate = STATIC_DIR / full_path
        if candidate.is_file():
            return FileResponse(str(candidate))
        index = STATIC_DIR / "index.html"
        if index.exists():
            return FileResponse(str(index))
        return JSONResponse({"detail": "Frontend not found"}, status_code=503)
else:
    @app.get("/{full_path:path}", include_in_schema=False)
    def spa_not_found(full_path: str):
        return JSONResponse(
            {"detail": "Static directory not found"},
            status_code=503,
        )
