#!/usr/bin/env python3
"""Epyon Web Interface — FastAPI Backend"""

import asyncio
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, field_validator

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
EPYON_ROOT = Path(__file__).parent.parent.resolve()
SCRIPTS_DIR = EPYON_ROOT / "scripts" / "shell"
CONFIGURATION_DIR = EPYON_ROOT / "configuration"
SCAN_HISTORY_FILE = EPYON_ROOT / "scan-history.json"
APPROVED_IMAGES_FILE = CONFIGURATION_DIR / "approved-base-images.conf"
STATIC_DIR = Path(__file__).parent / "static"

SCAN_SEARCH_PATHS = [
    EPYON_ROOT / "scans",
    EPYON_ROOT / "baseline" / "scans",
    EPYON_ROOT / "scripts" / "scans",
]

VALID_SCAN_TYPES = {"quick", "full", "images", "analysis"}

# Alphanumeric, underscores, hyphens, dots only
_SAFE_ID_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_\-\.]*$")
# Valid job IDs are 14-digit timestamps
_JOB_ID_RE = re.compile(r"^\d{14}$")

# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------
app = FastAPI(title="Epyon Web Interface", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8000", "http://127.0.0.1:8000"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# In-memory job store
# ---------------------------------------------------------------------------
_jobs: Dict[str, Dict[str, Any]] = {}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _validate_id(value: str, label: str = "id") -> str:
    if not _SAFE_ID_RE.match(value):
        raise HTTPException(status_code=400, detail=f"Invalid {label} format")
    return value


def _read_json(path: Path) -> Optional[Dict]:
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return None


def _find_scan_dirs() -> List[Path]:
    dirs: List[Path] = []
    epyon_root = EPYON_ROOT.resolve()
    for base in SCAN_SEARCH_PATHS:
        if not base.is_dir():
            continue
        for d in sorted(base.iterdir()):
            if not d.is_dir() or d.name.startswith("."):
                continue
            try:
                d.resolve().relative_to(epyon_root)
                dirs.append(d)
            except ValueError:
                pass  # skip anything outside the project root
    return dirs


def _parse_dir_name(name: str) -> Dict[str, str]:
    """Parse {target}_{user}_{YYYY-MM-DD}_{HH-MM-SS}."""
    parts = name.split("_")
    if len(parts) >= 4:
        time_p = parts[-1]
        date_p = parts[-2]
        user = parts[-3]
        target = "_".join(parts[:-3])
        return {
            "target": target,
            "user": user,
            "timestamp": f"{date_p}T{time_p.replace('-', ':')}",
        }
    return {"target": name, "user": "", "timestamp": ""}


def _load_scan(scan_dir: Path) -> Dict[str, Any]:
    scan_id = scan_dir.name
    parsed = _parse_dir_name(scan_id)
    data: Dict[str, Any] = {
        "scan_id": scan_id,
        "target": parsed["target"],
        "user": parsed["user"],
        "timestamp": parsed["timestamp"],
        "scan_type": "full",
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "total": 0,
        "tools_analyzed": [],
        "has_dashboard": False,
        "dashboard_url": None,
        "location": str(scan_dir.parent.relative_to(EPYON_ROOT)),
    }

    meta = _read_json(scan_dir / "scan-metadata.json")
    if meta:
        data["scan_type"] = meta.get("scan_type", "full")
        data["target"] = meta.get("target_name", parsed["target"])
        data["timestamp"] = meta.get("scan_timestamp", parsed["timestamp"])
        data["target_directory"] = meta.get("target_directory", "")
        data["file_statistics"] = meta.get("file_statistics", {})

    findings = _read_json(scan_dir / "security-findings-summary.json")
    if findings:
        summary = findings.get("summary", findings)
        data["critical"] = summary.get("total_critical", 0)
        data["high"] = summary.get("total_high", 0)
        data["medium"] = summary.get("total_medium", 0)
        data["low"] = summary.get("total_low", 0)
        data["total"] = data["critical"] + data["high"] + data["medium"] + data["low"]
        data["tools_analyzed"] = summary.get("tools_analyzed", [])

    dashboard = (
        scan_dir / "consolidated-reports" / "dashboards" / "security-dashboard.html"
    )
    if dashboard.exists():
        data["has_dashboard"] = True
        data["dashboard_url"] = f"/api/scans/{scan_id}/dashboard"

    return data


def _status(scan: Dict) -> str:
    if scan.get("critical", 0) > 0:
        return "critical"
    if scan.get("high", 0) > 0:
        return "high"
    if scan.get("medium", 0) > 0:
        return "medium"
    if scan.get("low", 0) > 0:
        return "low"
    if scan.get("scan_id"):
        return "clean"
    return "unknown"


# ---------------------------------------------------------------------------
# API — Health & Stats
# ---------------------------------------------------------------------------


@app.get("/api/health")
def health():
    return {"status": "ok", "epyon_root": str(EPYON_ROOT)}


@app.get("/api/stats")
def stats():
    scans = [_load_scan(d) for d in _find_scan_dirs()]
    targets = {s["target"] for s in scans}
    history = _read_json(SCAN_HISTORY_FILE)
    if history:
        targets |= set(history.get("targets", []))
    return {
        "total_applications": len(targets),
        "total_scans": len(scans),
        "critical": sum(s["critical"] for s in scans),
        "high": sum(s["high"] for s in scans),
        "medium": sum(s["medium"] for s in scans),
        "low": sum(s["low"] for s in scans),
    }


# ---------------------------------------------------------------------------
# API — Applications
# ---------------------------------------------------------------------------


@app.get("/api/applications")
def applications():
    scans = [_load_scan(d) for d in _find_scan_dirs()]
    by_target: Dict[str, List[Dict]] = {}
    for s in scans:
        by_target.setdefault(s["target"], []).append(s)

    # Include targets recorded in history that have no local scan dirs
    history = _read_json(SCAN_HISTORY_FILE)
    if history:
        for entry in history.get("trend", []):
            t = entry.get("target_name", "")
            if t and t not in by_target:
                by_target[t] = []

    result = []
    for target, tscans in by_target.items():
        tscans_sorted = sorted(tscans, key=lambda s: s["timestamp"], reverse=True)
        latest = tscans_sorted[0] if tscans_sorted else {}
        result.append(
            {
                "name": target,
                "scan_count": len(tscans),
                "last_scanned": latest.get("timestamp", ""),
                "scan_type": latest.get("scan_type", ""),
                "critical": latest.get("critical", 0),
                "high": latest.get("high", 0),
                "medium": latest.get("medium", 0),
                "low": latest.get("low", 0),
                "status": _status(latest),
                "latest_scan_id": latest.get("scan_id", ""),
            }
        )
    return sorted(result, key=lambda a: a["last_scanned"], reverse=True)


@app.get("/api/applications/{name}/scans")
def application_scans(name: str):
    name = _validate_id(name, "application name")
    scans = []
    for d in _find_scan_dirs():
        p = _parse_dir_name(d.name)
        if p["target"] == name:
            scans.append(_load_scan(d))
    return sorted(scans, key=lambda s: s["timestamp"], reverse=True)


# ---------------------------------------------------------------------------
# API — Scans
# ---------------------------------------------------------------------------


@app.get("/api/scans/{scan_id}")
def scan_detail(scan_id: str):
    scan_id = _validate_id(scan_id, "scan_id")
    for d in _find_scan_dirs():
        if d.name == scan_id:
            data = _load_scan(d)
            findings = _read_json(d / "security-findings-summary.json")
            if findings:
                data["findings"] = findings
            return data
    raise HTTPException(status_code=404, detail="Scan not found")


@app.get("/api/scans/{scan_id}/dashboard")
def scan_dashboard(scan_id: str):
    scan_id = _validate_id(scan_id, "scan_id")
    epyon_root = EPYON_ROOT.resolve()
    for d in _find_scan_dirs():
        if d.name == scan_id:
            dashboard = (
                d / "consolidated-reports" / "dashboards" / "security-dashboard.html"
            )
            try:
                dashboard.resolve().relative_to(epyon_root)
            except ValueError:
                raise HTTPException(status_code=403, detail="Access denied")
            if dashboard.exists():
                return FileResponse(str(dashboard), media_type="text/html")
            raise HTTPException(
                status_code=404, detail="Dashboard not generated for this scan"
            )
    raise HTTPException(status_code=404, detail="Scan not found")


@app.get("/api/scan-history")
def scan_history():
    data = _read_json(SCAN_HISTORY_FILE)
    if not data:
        return {"generated_at": "", "total_scans": 0, "targets": [], "trend": []}
    return data


# ---------------------------------------------------------------------------
# API — Settings
# ---------------------------------------------------------------------------


@app.get("/api/settings/approved-images")
def approved_images():
    try:
        return {"content": APPROVED_IMAGES_FILE.read_text()}
    except Exception:
        return {"content": ""}


# ---------------------------------------------------------------------------
# API — Jobs / Scan Trigger
# ---------------------------------------------------------------------------


class ScanRequest(BaseModel):
    target: str
    scan_type: str = "full"

    @field_validator("scan_type")
    @classmethod
    def validate_scan_type(cls, v: str) -> str:
        if v not in VALID_SCAN_TYPES:
            raise ValueError(
                f"scan_type must be one of: {', '.join(sorted(VALID_SCAN_TYPES))}"
            )
        return v

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("target cannot be empty")
        valid_prefixes = ("/", "./", "../", "https://", "http://", "git@")
        if not any(v.startswith(p) for p in valid_prefixes):
            raise ValueError(
                "target must be an absolute path, relative path, or Git URL"
            )
        # Reject shell metacharacters
        if re.search(r"[;&|`$\(\)\n\r<>]", v):
            raise ValueError("target contains invalid characters")
        return v


@app.post("/api/scans", status_code=202)
async def trigger_scan(req: ScanRequest, background_tasks: BackgroundTasks):
    scan_script = SCRIPTS_DIR / "run-target-security-scan.sh"
    if not scan_script.exists():
        raise HTTPException(status_code=500, detail="Scan script not found")

    job_id = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    _jobs[job_id] = {
        "job_id": job_id,
        "target": req.target,
        "scan_type": req.scan_type,
        "status": "queued",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "completed_at": None,
        "exit_code": None,
        "output": [],
        "error": None,
    }
    background_tasks.add_task(
        _run_scan_job, job_id, req.target, req.scan_type, str(scan_script)
    )
    return {"job_id": job_id, "status": "queued"}


async def _run_scan_job(
    job_id: str, target: str, scan_type: str, script_path: str
) -> None:
    _jobs[job_id]["status"] = "running"
    try:
        proc = await asyncio.create_subprocess_exec(
            "bash",
            script_path,
            target,
            scan_type,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            cwd=str(EPYON_ROOT),
        )
        assert proc.stdout is not None
        async for line_bytes in proc.stdout:
            line = line_bytes.decode("utf-8", errors="replace").rstrip()
            _jobs[job_id]["output"].append(line)
            if len(_jobs[job_id]["output"]) > 1000:
                _jobs[job_id]["output"] = _jobs[job_id]["output"][-1000:]
        await proc.wait()
        _jobs[job_id]["exit_code"] = proc.returncode
        _jobs[job_id]["status"] = "completed" if proc.returncode == 0 else "failed"
        _jobs[job_id]["completed_at"] = datetime.now(timezone.utc).isoformat()
    except Exception as exc:
        _jobs[job_id]["status"] = "error"
        _jobs[job_id]["error"] = str(exc)
        _jobs[job_id]["completed_at"] = datetime.now(timezone.utc).isoformat()


@app.get("/api/jobs")
def list_jobs():
    return sorted(_jobs.values(), key=lambda j: j["started_at"], reverse=True)


@app.get("/api/jobs/{job_id}")
def get_job(job_id: str):
    if not _JOB_ID_RE.match(job_id):
        raise HTTPException(status_code=400, detail="Invalid job_id format")
    if job_id not in _jobs:
        raise HTTPException(status_code=404, detail="Job not found")
    return _jobs[job_id]


# ---------------------------------------------------------------------------
# Static file serving — must come last
# ---------------------------------------------------------------------------

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/{full_path:path}")
def spa_fallback(full_path: str):
    # Serve static assets by name; everything else → index.html
    candidate = STATIC_DIR / full_path
    if candidate.exists() and candidate.is_file():
        try:
            candidate.resolve().relative_to(STATIC_DIR.resolve())
            return FileResponse(str(candidate))
        except ValueError:
            pass
    return FileResponse(str(STATIC_DIR / "index.html"))
