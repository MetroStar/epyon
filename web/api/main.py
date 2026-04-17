"""
Epyon Web — FastAPI backend
All routes match the Node.js server.js API exactly so the existing
React frontend (and future Comet frontend) can talk to either server.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
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

# ── Paths ─────────────────────────────────────────────────────
_HERE        = Path(__file__).parent
EPYON_ROOT   = (_HERE / ".." / "..").resolve()
SCRIPTS_DIR  = EPYON_ROOT / "scripts" / "shell"
APPROVED_IMAGES_FILE = EPYON_ROOT / "configuration" / "approved-base-images.conf"
GITHUB_CONFIG_FILE   = _HERE / ".." / "github-config.json"
HIDDEN_APPS_FILE     = EPYON_ROOT / "configuration" / "hidden-apps.json"

FRONTEND_DIST = EPYON_ROOT / "baseline" / "comet-starter" / "dist"

# ── Validation ────────────────────────────────────────────────
_SAFE_ID_RE      = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_\-.]*$")
_JOB_ID_RE       = re.compile(r"^\d{14}$")
_VALID_SCAN_TYPES = {"quick", "full", "images", "analysis"}
_TOKEN_RE        = re.compile(r"^(ghp_|github_pat_|ghs_|gho_)[a-zA-Z0-9_]+$")
_REPO_RE         = re.compile(r"^[a-zA-Z0-9_.\-]+/[a-zA-Z0-9_.\-]+$")

# ── Metrics cache ─────────────────────────────────────────────
_metrics_cache:    dict  = {}
_metrics_cache_ts: float = 0.0
_METRICS_TTL:      float = 300.0  # seconds


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _read_github_config() -> dict:
    try:
        return json.loads(GITHUB_CONFIG_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _write_github_config(cfg: dict) -> None:
    GITHUB_CONFIG_FILE.write_text(json.dumps(cfg, indent=2), encoding="utf-8")


# ── Lifespan (startup / shutdown) ────────────────────────────

@asynccontextmanager
async def lifespan(_: FastAPI):
    # Auto-sync on startup (+10s) then every 3 hours
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
    # Group by target, keep only the latest scan per application (exclude hidden)
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
        result.append({
            "name":           name,
            "scan_count":     len(tscans),
            "last_scanned":   latest.get("timestamp", ""),
            "scan_type":      latest.get("scan_type", ""),
            "critical":       latest.get("critical", 0),
            "high":           latest.get("high", 0),
            "medium":         latest.get("medium", 0),
            "low":            latest.get("low", 0),
            "status":         parsers.get_status(latest),
            "latest_scan_id": latest.get("scan_id", ""),
        })
    result.sort(key=lambda x: x.get("last_scanned", ""), reverse=True)
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


@app.get("/api/scans/{scan_id}/stig-report")
def scan_stig_report(scan_id: str, response: Response):
    _sec_headers(response)
    if not _SAFE_ID_RE.match(scan_id):
        raise HTTPException(400, "Invalid scan_id")
    scan_dirs = parsers.find_scan_dirs(EPYON_ROOT)
    matched = next((d for d in scan_dirs if d.name == scan_id), None)
    if not matched:
        raise HTTPException(404, "Scan not found")
    report = matched / "stig" / f"{scan_id}_stig-assessment.html"
    try:
        report.resolve().relative_to(EPYON_ROOT.resolve())
    except ValueError:
        raise HTTPException(403, "Access denied")
    if not report.exists():
        raise HTTPException(404, "STIG report not generated for this scan")
    return FileResponse(str(report), media_type="text/html")


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
    return data


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

    if not target:
        raise HTTPException(400, "target is required")
    valid_prefixes = ["/", "./", "../", "https://", "http://", "git@"]
    if not any(target.startswith(p) for p in valid_prefixes):
        raise HTTPException(400, "target must be an absolute path, relative path, or Git URL")
    if re.search(r"[;&|`$\(\)\n\r<>]", target):
        raise HTTPException(400, "target contains invalid characters")
    if scan_type not in _VALID_SCAN_TYPES:
        raise HTTPException(400, f"scan_type must be one of: {sorted(_VALID_SCAN_TYPES)}")

    script_path = SCRIPTS_DIR / "run-target-security-scan.sh"
    if not script_path.exists():
        raise HTTPException(500, "Scan script not found")

    job_id = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    job = job_store.create_job(job_id, target, scan_type)
    asyncio.create_task(
        job_store.run_scan_job(job_id, target, scan_type, script_path, EPYON_ROOT)
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

    # 1. Trend — all scans sorted by timestamp (cap at 60 for chart readability)
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

    # 2–4. By tool / fix rate / top CVEs — latest scan per app only
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

    # 5. Scan frequency
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


# ── SPA / static file serving ─────────────────────────────────
# Serves baseline/comet-starter/dist/ when built.
# Falls back gracefully when the dist hasn't been built yet.

if FRONTEND_DIST.exists():
    app.mount("/assets", StaticFiles(directory=str(FRONTEND_DIST / "assets")), name="assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    def spa_fallback(full_path: str):
        # Serve static files if they exist, otherwise serve index.html
        candidate = FRONTEND_DIST / full_path
        if candidate.is_file():
            return FileResponse(str(candidate))
        index = FRONTEND_DIST / "index.html"
        if index.exists():
            return FileResponse(str(index))
        return JSONResponse({"detail": "Frontend not built. Run: cd baseline/comet-starter && npm run build"}, 503)
else:
    @app.get("/{full_path:path}", include_in_schema=False)
    def spa_not_built(full_path: str):
        return JSONResponse(
            {"detail": "Frontend not built yet. Run: cd baseline/comet-starter && npm run build"},
            status_code=503,
        )
