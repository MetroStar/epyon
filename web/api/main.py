"""
Epyon Web — FastAPI backend
"""
from __future__ import annotations

import asyncio
import io
import json
import logging
import os
import re
import shutil
import sys
import tarfile
import threading
import time
import zipfile
from collections import Counter, OrderedDict
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, List, Optional

from fastapi import FastAPI, File, Form, HTTPException, Query, Request, Response, UploadFile
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import jobs as job_store
from . import parsers
from .app_trends import app_trend
from . import poam
from . import scorecard as scorecard_store
from . import parse_cache
from . import finding_search
from . import github_sync
from . import github_metrics
from . import github_config
from . import openai_summary
from . import jira_client
from . import db as scan_db
from . import scan_store

# ── Paths ─────────────────────────────────────────────────────
_HERE        = Path(__file__).parent


def _load_env_local() -> None:
    """Load KEY=VALUE pairs from the repo's gitignored .env.local without overriding the shell."""
    path = _HERE.parent.parent / ".env.local"
    if not path.is_file():
        return
    for line in path.read_text(errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.removeprefix("export ").partition("=")
        key, val = key.strip(), val.strip().strip("'\"")
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key) and val:
            os.environ.setdefault(key, val)


_load_env_local()
EPYON_ROOT   = (_HERE / ".." / "..").resolve()
VERSION_FILE = EPYON_ROOT / "VERSION"
EPYON_VERSION = VERSION_FILE.read_text(encoding="utf-8").strip() if VERSION_FILE.exists() else "unknown"
SCRIPTS_DIR  = EPYON_ROOT / "scripts" / "shell"
APPROVED_IMAGES_FILE = EPYON_ROOT / "configuration" / "approved-base-images.conf"
GITHUB_CONFIG_FILE   = (_HERE / ".." / "data" / "github-config.json").resolve()
HIDDEN_APPS_FILE     = EPYON_ROOT / "configuration" / "hidden-apps.json"
JIRA_CONFIG_FILE     = (_HERE / ".." / "data" / "jira-config.json").resolve()
JIRA_TICKETS_FILE    = (_HERE / ".." / "data" / "jira-tickets.json").resolve()
SELF_ASSESSMENT_FILE = (_HERE / ".." / "data" / "self-assessment-latest.json").resolve()
REGISTERED_APPS_FILE = EPYON_ROOT / "configuration" / "registered-apps.json"
MONITORED_APPS_FILE  = EPYON_ROOT / "configuration" / "monitored-apps.json"
STATIC_DIR           = (_HERE / ".." / "static").resolve()

# Scan types that run the full tool suite (Anchore, Trivy, Checkov, etc.)
# Quick/stig/local_model scans do not produce complete vulnerability counts.
_COMPREHENSIVE_SCAN_TYPES = frozenset({"full", "nightly"})

# ── Scan database & retention ─────────────────────────────────
# Raw scan folders under scans/ are archived (compressed into the SQLite DB)
# and removed from disk once older than this many days. The parsed summary
# stays in the DB forever. See scan_store.py for the ingestion/archival logic.
_RETENTION_DAYS  = int(os.environ.get("EPYON_SCAN_RETENTION_DAYS", str(scan_store.DEFAULT_RETENTION_DAYS)))
_RESTORE_HOURS   = int(os.environ.get("EPYON_SCAN_RESTORE_HOURS", str(scan_store.DEFAULT_RESTORE_HOURS)))
_RETENTION_SWEEP_INTERVAL_SECONDS = 24 * 60 * 60

_scan_db_conn = scan_db.get_conn(EPYON_ROOT)


def _find_live_scan_dir(scan_id: str, days: int = 35):
    """Return the live (on-disk) scan directory Path, or None."""
    scan_dirs = parsers.find_scan_dirs(EPYON_ROOT, days=days)
    return next((d for d in scan_dirs if d.name == scan_id), None)


def _require_scan_dir(scan_id: str, days: int = 35) -> Path:
    """Resolve scan_id to a live directory. Raises 410 if the scan has been
    archived under the retention policy (with a restore hint), or 404 if the
    scan is unknown entirely."""
    matched = _find_live_scan_dir(scan_id, days=days)
    if matched:
        return matched
    if scan_store.is_archived(_scan_db_conn, scan_id):
        raise HTTPException(
            410,
            f"Scan '{scan_id}' was archived under the {_RETENTION_DAYS}-day retention policy. "
            f"POST /api/scans/{scan_id}/restore to temporarily restore its raw files.",
        )
    raise HTTPException(404, "Scan not found")


# ── Audit logging ────────────────────────────────────────────
_AUDIT_LOG_FILE = (_HERE / ".." / "data" / "audit.log").resolve()


def _setup_audit_logger() -> logging.Logger:
    logger = logging.getLogger("epyon.audit")
    if not logger.handlers:
        _AUDIT_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        handler = logging.FileHandler(str(_AUDIT_LOG_FILE), encoding="utf-8")
        handler.setFormatter(logging.Formatter(
            "%(asctime)s %(levelname)s %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%SZ",
        ))
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        logger.propagate = False
    return logger


_audit_logger = logging.getLogger("epyon.audit")


def _audit(request: Request, action: str, detail: str = "") -> None:
    """Write a single line to the audit log."""
    global _audit_logger
    if not _audit_logger.handlers:
        _audit_logger = _setup_audit_logger()
    client = getattr(request.client, "host", "unknown") if request.client else "unknown"
    _audit_logger.info("action=%s client=%s detail=%s", action, client, detail)

# ── Validation ────────────────────────────────────────────────
_SAFE_ID_RE      = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_\-.]*$")
_JIRA_FP_RE      = re.compile(r"^[a-f0-9]{16}\|[^\x00-\x1f]{1,40}$")
_JIRA_EPIC_KEY_RE = re.compile(r"^[A-Z][A-Z0-9]{0,9}-\d+$")
_JOB_ID_RE       = re.compile(r"^\d{14}(?:\d{2,})?$")
_APP_SCAN_RE     = re.compile(r"^(.+)_(\d{4}-\d{2}-\d{2})_(\d{2}-\d{2}-\d{2})$")
_VALID_SCAN_TYPES = {"quick", "full", "nightly", "baseline", "stig", "local_model", "container_image"}
_REPO_RE         = re.compile(r"^[a-zA-Z0-9_.\-]+/[a-zA-Z0-9_.\-]+$")
_UPLOAD_NAME_RE  = re.compile(r"[^a-zA-Z0-9_.\-]+")
MAX_UPLOAD_BYTES       = int(os.environ.get("EPYON_MAX_UPLOAD_MB", "500")) * 1024 * 1024
MAX_UPLOAD_UNZIPPED    = int(os.environ.get("EPYON_MAX_UPLOAD_UNZIPPED_MB", "2048")) * 1024 * 1024

# ── Metrics cache ─────────────────────────────────────────────
_metrics_cache:    dict  = {}
_metrics_cache_ts: float = 0.0
_METRICS_TTL:      float = 300.0
# History window for the Metrics page. 90 days matches GitHub's default artifact retention.
_METRICS_DAYS:     int   = max(7, int(os.environ.get("EPYON_METRICS_DAYS", "90") or 90))

# ── GitHub metrics cache ─────────────────────────────────────
_gh_metrics_cache:    dict  = {}
_gh_metrics_cache_ts: float = 0.0
_GH_METRICS_TTL:      float = 600.0  # 10 min — GH API is rate-limited
_GH_HISTORY_FILE = (_HERE / ".." / "data" / "github-signals-history.json").resolve()


def _load_gh_history() -> list[dict]:
    """Return the list of daily GitHub signals snapshots, or [] if none yet."""
    try:
        if _GH_HISTORY_FILE.exists():
            return json.loads(_GH_HISTORY_FILE.read_text(encoding="utf-8"))
    except Exception:
        pass
    return []


def _save_gh_snapshot(metrics: dict) -> None:
    """Append (or update) a daily aggregate snapshot of GitHub metrics to the history file."""
    try:
        runs  = metrics.get("workflow_runs", [])
        cov   = metrics.get("pr_scan_coverage", {})

        run_rates = [r["success_rate"] for r in runs if not r.get("error") and r.get("success_rate") is not None]
        workflow_success_rate = round(sum(run_rates) / len(run_rates)) if run_rates else None

        pr_scans  = sum(v.get("pr_scans", 0)     for v in cov.values())
        ci_scans  = sum(v.get("total_ci_scans", 0) for v in cov.values())
        pr_cov_pct = round(pr_scans / ci_scans * 100) if ci_scans > 0 else 0

        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        snapshot = {
            "date":                   today,
            "ts":                     datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "workflow_success_rate":  workflow_success_rate,
            "pr_coverage_pct":        pr_cov_pct,
        }

        history = _load_gh_history()
        # Replace the entry for today if it exists; otherwise append
        history = [e for e in history if e.get("date") != today]
        history.append(snapshot)
        # Keep at most 365 daily entries
        history = sorted(history, key=lambda e: e["date"])[-365:]

        _GH_HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)
        _GH_HISTORY_FILE.write_text(json.dumps(history, indent=2), encoding="utf-8")
    except Exception:
        pass  # never let history writes break the main metrics response

# ── Scan data cache ───────────────────────────────────────────
# Aggressive caching for filesystem-heavy operations.
# find_scan_dirs() is called on every list endpoint; load_scan() reads 8+ files
# per scan directory. With 40+ scans these dominate response time.
# Scans are immutable once written, so long TTLs are safe.
_scan_cache:      dict[str, tuple[dict, float]] = {}  # scan_id → (data, monotonic_ts)
_dir_cache:       dict[int, tuple[list, float]] = {}  # days → (dirs, monotonic_ts)
_stats_cache:     tuple[dict, float] | None = None    # (stats, monotonic_ts)
_apps_cache:      tuple[list, float] | None = None    # (apps, monotonic_ts)
# CVE search index: scan_id -> ((dir mtime_ns, project_key), per-scan lookup index).
# Scans are immutable, so the dir mtime only changes if a scan is rewritten.
_search_index:    "OrderedDict[str, tuple[tuple, dict]]" = OrderedDict()
_SEARCH_INDEX_MAX: int = 2000
_mobile_code_accuracy_cache: tuple[dict, float] | None = None  # (metrics, monotonic_ts)
_SCAN_CACHE_TTL:  float = 300.0  # 5 minutes — scans are immutable
_DIR_CACHE_TTL:   float = 60.0   # 1 minute — new scans appear less frequently
_STATS_CACHE_TTL: float = 120.0  # 2 minutes — aggregated stats
_APPS_CACHE_TTL:  float = 120.0  # 2 minutes — app list
_MOBILE_CODE_ACCURACY_CACHE_TTL: float = 300.0  # 5 minutes — fixture corpus is static
_DEFAULT_SCAN_DAYS: int = 35     # Only load last 35 days of scans by default
_CACHE_VERSION:   int = 0        # Increment on scan completion to bust frontend caches

# ── Cache metrics instrumentation ───────────────────────────
_cache_metrics = {
    "hits": {"scan": 0, "dir": 0, "stats": 0, "apps": 0, "search_index": 0},
    "misses": {"scan": 0, "dir": 0, "stats": 0, "apps": 0, "search_index": 0},
    "writes": {"scan": 0, "dir": 0, "stats": 0, "apps": 0, "search_index": 0},
    "invalidations": [],  # List of {timestamp, reason, version, scan_id}
    "staleness_seconds": [],  # List of staleness measurements for observability
}
_cache_metrics_logger = logging.getLogger("epyon.cache")

# uvicorn leaves the root logger at WARNING, which would hide the load-time timings.
for _name in ("epyon.perf", "epyon.parse_cache"):
    _lg = logging.getLogger(_name)
    _lg.setLevel(logging.INFO)
    if not _lg.handlers:
        _h = logging.StreamHandler()
        _h.setFormatter(logging.Formatter("%(levelname)s:     %(name)s: %(message)s"))
        _lg.addHandler(_h)


def _cached_find_scan_dirs(days: int = _DEFAULT_SCAN_DAYS) -> list:
    global _dir_cache
    now = time.monotonic()
    cached = _dir_cache.get(days)
    if cached and (now - cached[1]) < _DIR_CACHE_TTL:
        _cache_metrics["hits"]["dir"] += 1
        _cache_metrics_logger.debug(f"cache_read source=memory endpoint=scan_dirs hit=true days={days}")
        return cached[0]
    _cache_metrics["misses"]["dir"] += 1
    _cache_metrics_logger.debug(f"cache_read source=memory endpoint=scan_dirs hit=false days={days}")
    dirs = parsers.find_scan_dirs(EPYON_ROOT, days=days)
    _dir_cache[days] = (dirs, now)
    _cache_metrics["writes"]["dir"] += 1
    _cache_metrics_logger.debug(f"cache_write endpoint=scan_dirs success=true days={days} count={len(dirs)}")
    return dirs


def _memo_load_scan(scan_dir) -> dict:
    scan = parse_cache.get("scan", scan_dir, lambda: parsers.load_scan(scan_dir, EPYON_ROOT))
    if scan.get("gate_status") is not None:
        # Recompute from the stored counts so a gate policy change doesn't
        # need the whole parse cache rebuilt.
        scan["gate_status"] = parsers.compute_gate_status(
            scan.get("critical", 0), scan.get("high", 0), scan.get("misconfig_critical", 0),
        )
    return scan


def _scan_digest(scan_dir) -> dict:
    return parse_cache.get("digest", scan_dir, lambda: parse_cache.build_digest(scan_dir))


def _memo_suppressed(scan_dir) -> list:
    return parse_cache.get("suppressed", scan_dir, lambda: parsers.parse_suppressed_findings(scan_dir))


def _cached_load_scan(scan_dir) -> dict:
    scan_id = scan_dir.name
    now     = time.monotonic()
    cached  = _scan_cache.get(scan_id)
    if cached and (now - cached[1]) < _SCAN_CACHE_TTL:
        age = now - cached[1]
        _cache_metrics["hits"]["scan"] += 1
        _cache_metrics_logger.debug(f"cache_read source=memory endpoint=scan hit=true scan_id={scan_id} age_seconds={age:.1f}")
        return cached[0]
    _cache_metrics["misses"]["scan"] += 1
    _cache_metrics_logger.debug(f"cache_read source=memory endpoint=scan hit=false scan_id={scan_id}")
    data = _memo_load_scan(scan_dir)
    _scan_cache[scan_id] = (data, now)
    _cache_metrics["writes"]["scan"] += 1
    _cache_metrics_logger.debug(f"cache_write endpoint=scan success=true scan_id={scan_id}")
    return data


def _scan_search_index(scan_dir, app_name: str, project_key: str) -> dict:
    """Per-scan finding lookup index, rebuilt only when the scan directory changes."""
    key = (scan_dir.stat().st_mtime_ns, project_key)
    cached = _search_index.get(scan_dir.name)
    if cached and cached[0] == key:
        _search_index.move_to_end(scan_dir.name)
        _cache_metrics["hits"]["search_index"] += 1
        return cached[1]
    _cache_metrics["misses"]["search_index"] += 1
    scan_data = parsers.load_scan_complete(scan_dir, EPYON_ROOT)
    index = finding_search.build_scan_index(scan_data, app_name, project_key)
    _search_index[scan_dir.name] = (key, index)
    _cache_metrics["writes"]["search_index"] += 1
    while len(_search_index) > _SEARCH_INDEX_MAX:
        _search_index.popitem(last=False)
    return index


def _invalidate_scan_cache(reason: str = "scan_completion", scan_id: str = None) -> None:
    """Call after a scan completes so the next request sees fresh data."""
    global _dir_cache, _stats_cache, _apps_cache, _CACHE_VERSION
    global _metrics_cache, _metrics_cache_ts
    old_version = _CACHE_VERSION
    _scan_cache.clear()
    _dir_cache.clear()
    if reason in ("delete_scan", "restore_scan", "retention_sweep", "retention_sweep_manual"):
        _search_index.clear()
    _stats_cache = None
    _apps_cache = None
    # /api/metrics keeps its own 5-minute cache separate from the caches
    # above; without clearing it here the Metrics page kept serving
    # pre-scan data for up to 5 minutes after a scan completed.
    _metrics_cache    = {}
    _metrics_cache_ts = 0.0
    _CACHE_VERSION += 1  # Bust frontend caches
    
    # Record invalidation event
    invalidation_event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "reason": reason,
        "old_version": old_version,
        "new_version": _CACHE_VERSION,
        "scan_id": scan_id,
    }
    _cache_metrics["invalidations"].append(invalidation_event)
    # Keep only last 100 invalidation events
    _cache_metrics["invalidations"] = _cache_metrics["invalidations"][-100:]
    
    _cache_metrics_logger.info(
        f"cache_invalidation reason={reason} old_version={old_version} "
        f"new_version={_CACHE_VERSION} scan_id={scan_id or 'N/A'}"
    )


async def _jira_post_scan(target_name: str) -> None:
    """Auto-reconcile Jira tickets after a scan finishes for target_name."""
    try:
        cfg = jira_client.read_config(target_name)
        if not cfg.get("auto_close") or not cfg.get("api_token"):
            return

        all_dirs = parsers.find_scan_dirs(EPYON_ROOT, days=35)
        target_dirs = sorted(
            [d for d in all_dirs if parsers.parse_dir_name(d.name)["target"] == target_name],
            key=lambda d: d.name,
            reverse=True,
        )
        if len(target_dirs) < 2:
            return  # need at least two scans to compare

        current_scan = parsers.load_scan_complete(target_dirs[0], EPYON_ROOT)
        previous_scan = parsers.load_scan_complete(target_dirs[1], EPYON_ROOT)

        await jira_client.reconcile_and_save(
            target_name,
            jira_client.flatten_ticketable_findings(current_scan),
            jira_client.flatten_ticketable_findings(previous_scan),
            cfg,
        )
    except Exception:
        pass  # never let Jira errors break the scan pipeline


def _on_scan_complete(target_name: str = "", scan_name: str = "") -> None:
    """Callback invoked by jobs.py when a scan finishes."""
    _invalidate_scan_cache(reason="scan_completion", scan_id=scan_name)
    if scan_name:
        matched = _find_live_scan_dir(scan_name, days=0)
        if matched:
            try:
                scan_store.ingest_scan_dir(_scan_db_conn, matched, EPYON_ROOT)
            except Exception:
                logging.getLogger("epyon.scan_store").exception(
                    "failed to ingest completed scan %s", scan_name
                )
    if target_name:
        asyncio.create_task(_jira_post_scan(target_name))


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _read_github_config() -> dict:
    return github_config.read_config(GITHUB_CONFIG_FILE)


def _write_github_config(cfg: dict) -> None:
    github_config.write_config(GITHUB_CONFIG_FILE, cfg)


def _migrate_legacy_github_config() -> None:
    """One-time migration: GITHUB_CONFIG_FILE used to live directly under
    web/ (outside any docker-compose bind mount), so a container redeploy
    silently reset GitHub repo tracking to defaults on every restart even
    though scans/configuration/web-data all persisted correctly. It now
    lives under web/data/ (mounted), matching every other persisted config
    file — move an existing legacy file forward so on-disk/local installs
    don't lose their already-configured repo list."""
    legacy_path = (_HERE / ".." / "github-config.json").resolve()
    try:
        if legacy_path.exists() and not GITHUB_CONFIG_FILE.exists():
            GITHUB_CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
            legacy_path.replace(GITHUB_CONFIG_FILE)
    except Exception:
        pass  # never let a migration hiccup block startup


_migrate_legacy_github_config()


# ── Lifespan ─────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(_: FastAPI):
    async def _auto_sync_loop() -> None:
        await asyncio.sleep(10)
        while True:
            cfg = _read_github_config()
            if cfg.get("token") and cfg.get("repos"):
                await github_sync.trigger_sync(
                    GITHUB_CONFIG_FILE, EPYON_ROOT, parsers.find_scan_dirs,
                    on_complete=_invalidate_scan_cache,
                )
            await asyncio.sleep(15 * 60)  # re-check every 15 minutes

    async def _retention_loop() -> None:
        """Ingest new/changed scans and archive+prune folders older than the
        retention window (default 90 days). Runs once shortly after startup,
        then daily."""
        await asyncio.sleep(30)
        log = logging.getLogger("epyon.scan_store")
        while True:
            try:
                result = await asyncio.to_thread(
                    scan_store.run_retention_sweep, _scan_db_conn, EPYON_ROOT, _RETENTION_DAYS
                )
                if result["ingested"] or result["archived"]:
                    log.info(
                        "retention sweep: ingested=%d archived=%d bytes_freed=%d errors=%d",
                        result["ingested"], result["archived"], result["bytes_freed"], len(result["errors"]),
                    )
                    _invalidate_scan_cache(reason="retention_sweep")
            except Exception:
                log.exception("retention sweep failed")
            await asyncio.sleep(_RETENTION_SWEEP_INTERVAL_SECONDS)

    async def _warm_caches() -> None:
        """Parse scans in parallel worker processes and prebuild Metrics, in the
        background. Repeats so scans skipped while still settling (e.g. just
        synced from GitHub) are picked up without a request having to parse them."""
        log = logging.getLogger("epyon.perf")

        def _warm() -> int:
            t0 = time.monotonic()
            try:
                n = parse_cache.warm(_cached_find_scan_dirs(_METRICS_DAYS), EPYON_ROOT)
                log.info("parsed %d scans in %.1fs", n, time.monotonic() - t0)
                if n:
                    _invalidate_scan_cache(reason="cache_warm")
                if not _metrics_cache:
                    _compute_metrics()
                log.info("cache warm-up done in %.1fs", time.monotonic() - t0)
                return n
            except Exception:
                log.exception("cache warm-up failed")
                return 0

        while True:
            await asyncio.to_thread(_warm)
            await asyncio.sleep(5 * 60)

    async def _persist_jobs_loop() -> None:
        while True:
            await asyncio.sleep(5)
            await asyncio.to_thread(job_store.save_jobs)

    job_store.load_jobs()
    parse_cache.configure(_HERE.parent / "data" / "cache" / "parse-cache.json")
    asyncio.create_task(_persist_jobs_loop())
    asyncio.create_task(_auto_sync_loop())
    asyncio.create_task(_retention_loop())
    asyncio.create_task(_warm_caches())
    yield
    job_store.save_jobs()


# ── Security header constants ─────────────────────────────────
# CSP allows 'unsafe-inline' because app.js builds HTML via template literals
# with inline onclick handlers.  Removing it requires a full JS refactor and
# is tracked as a future hardening item (see APSC-DV-001600 evidence).
_CSP = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data: blob:; "
    "connect-src 'self'; "
    "font-src 'self'; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "form-action 'self';"
)
_PERMISSIONS_POLICY = "geolocation=(), microphone=(), camera=(), payment=(), usb=()"


# ── App ───────────────────────────────────────────────────────

app = FastAPI(title="Epyon Web", lifespan=lifespan)

# Restrict CORS to same-origin by default; override via EPYON_ALLOWED_ORIGINS
# (comma-separated list).  Never use wildcard in production deployments.
_ALLOWED_ORIGINS = [
    o.strip()
    for o in os.getenv(
        "EPYON_ALLOWED_ORIGINS",
        "http://localhost:8000,http://127.0.0.1:8000",
    ).split(",")
    if o.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_ALLOWED_ORIGINS,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-Requested-With"],
)


class _SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Apply security headers to every response (APSC-DV-001600 et al.)."""

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"]  = "nosniff"
        response.headers["X-Frame-Options"]         = "SAMEORIGIN"
        response.headers["X-XSS-Protection"]        = "0"
        response.headers["Referrer-Policy"]         = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"]      = _PERMISSIONS_POLICY
        response.headers["Content-Security-Policy"] = _CSP
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
            response.headers["Pragma"]        = "no-cache"
        return response


app.add_middleware(_SecurityHeadersMiddleware)


@app.exception_handler(Exception)
async def _unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Return a generic 500 without leaking internal details (APSC-DV-002390)."""
    _audit(request, "server_error", type(exc).__name__)
    return JSONResponse(status_code=500, content={"detail": "An internal error occurred."})


@app.exception_handler(RequestValidationError)
async def _request_validation_exception_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    if request.method == "GET" and request.url.path == "/api/findings/search":
        return JSONResponse(status_code=400, content={"detail": "Invalid search request"})
    return await request_validation_exception_handler(request, exc)


def _sec_headers(response: Response) -> None:
    response.headers["X-Content-Type-Options"]  = "nosniff"
    response.headers["X-Frame-Options"]         = "SAMEORIGIN"
    response.headers["X-XSS-Protection"]        = "0"
    response.headers["Referrer-Policy"]         = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"]      = _PERMISSIONS_POLICY
    response.headers["Content-Security-Policy"] = _CSP
    response.headers["Cache-Control"]           = "no-store, no-cache, must-revalidate, private"
    response.headers["Pragma"]                  = "no-cache"


# ── Stats ─────────────────────────────────────────────────────

@app.get("/api/stats")
def stats(response: Response):
    global _stats_cache
    now = time.monotonic()
    
    # Return cached stats if available
    if _stats_cache and (now - _stats_cache[1]) < _STATS_CACHE_TTL:
        age = now - _stats_cache[1]
        _cache_metrics["hits"]["stats"] += 1
        _cache_metrics_logger.debug(f"cache_read source=memory endpoint=stats hit=true age_seconds={age:.1f}")
        result = _stats_cache[0]
        # Allow browser caching for 60s
        response.headers["Cache-Control"] = "public, max-age=60"
        response.headers["X-Cache-Version"] = str(_CACHE_VERSION)
        return result
    
    _cache_metrics["misses"]["stats"] += 1
    _cache_metrics_logger.debug("cache_read source=memory endpoint=stats hit=false")
    _sec_headers(response)
    hidden = _load_hidden_apps()
    monitored = _load_monitored_apps()
    # Overview counts only continuously monitored apps; evaluation apps are excluded.
    scans = [s for s in (_cached_load_scan(d) for d in _cached_find_scan_dirs())
             if s["target"] in monitored and s["target"] not in hidden]
    by_target: dict[str, dict] = {}
    for s in scans:
        t = s["target"]
        if t not in by_target or s.get("timestamp", "") > by_target[t].get("timestamp", ""):
            by_target[t] = s
    latest = list(by_target.values())
    result = {
        "total_applications": len(by_target),
        "total_scans":        len(scans),
        "critical": sum(s["critical"] for s in latest),
        "high":     sum(s["high"]     for s in latest),
        "medium":   sum(s["medium"]   for s in latest),
        "low":      sum(s["low"]      for s in latest),
    }
    
    _stats_cache = (result, now)
    _cache_metrics["writes"]["stats"] += 1
    _cache_metrics_logger.debug("cache_write endpoint=stats success=true")
    response.headers["Cache-Control"] = "public, max-age=60"
    response.headers["X-Cache-Version"] = str(_CACHE_VERSION)
    return result


# ── Applications ──────────────────────────────────────────────

def _load_hidden_apps() -> set[str]:
    try:
        if HIDDEN_APPS_FILE.exists():
            return set(json.loads(HIDDEN_APPS_FILE.read_text()))
    except Exception:
        pass
    return set()


def _load_monitored_apps() -> set[str]:
    try:
        if MONITORED_APPS_FILE.exists():
            return set(json.loads(MONITORED_APPS_FILE.read_text()))
    except Exception:
        pass
    return set()


def _load_registered_apps() -> list[dict]:
    try:
        if REGISTERED_APPS_FILE.exists():
            return json.loads(REGISTERED_APPS_FILE.read_text(encoding="utf-8"))
    except Exception:
        pass
    return []


@app.get("/api/applications")
def applications(response: Response):
    global _apps_cache
    now = time.monotonic()
    
    # Return cached app list if available
    if _apps_cache and (now - _apps_cache[1]) < _APPS_CACHE_TTL:
        age = now - _apps_cache[1]
        _cache_metrics["hits"]["apps"] += 1
        _cache_metrics_logger.debug(f"cache_read source=memory endpoint=applications hit=true age_seconds={age:.1f}")
        response.headers["Cache-Control"] = "public, max-age=60"
        response.headers["X-Cache-Version"] = str(_CACHE_VERSION)
        return _apps_cache[0]
    
    _cache_metrics["misses"]["apps"] += 1
    _cache_metrics_logger.debug("cache_read source=memory endpoint=applications hit=false")
    _sec_headers(response)
    hidden   = _load_hidden_apps()
    monitored = _load_monitored_apps()
    scans = [_cached_load_scan(d) for d in _cached_find_scan_dirs()]
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
            (s for s in tscans if s.get("scan_type") in _COMPREHENSIVE_SCAN_TYPES),
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
    
    _apps_cache = (result, now)
    _cache_metrics["writes"]["apps"] += 1
    _cache_metrics_logger.debug(f"cache_write endpoint=applications success=true count={len(result)}")
    response.headers["Cache-Control"] = "public, max-age=60"
    response.headers["X-Cache-Version"] = str(_CACHE_VERSION)
    return result


def _build_stig_entries(scan_id: str, matched: Path) -> list[dict]:
    """Merge STIG controls with assessment results for every STIG in a scan directory."""
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
                "vuln_id":        vid,
                "group_id":       c.get("group_id", ""),
                "rule_id":        c.get("rule_id", ""),
                "number":         c.get("number"),
                "severity":       c.get("severity", ""),
                "title":          c.get("title", ""),
                "check_content":  c.get("check_content", ""),
                "fix_text":       c.get("fix_text", ""),
                "discussion":     c.get("discussion", ""),
                "status":         assessed.get("status",          "Not Reviewed"),
                "evidence":       assessed.get("evidence",         ""),
                "confidence":     assessed.get("confidence",       0),
                "locked_by_human": bool(assessed.get("locked_by_human", False)),
                "locked_by_stability": bool(assessed.get("locked_by_stability", False)),
                "stable_count":    assessed.get("stable_count", 0),
                **parsers.stig_record_fields(assessed, c),
            })

        app_slug  = re.sub(r"[^a-z0-9]+", "-", re.sub(r"_\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}$", "", scan_id).lower()).strip("-")
        md_file   = matched / f"findings-{app_slug}-{slug}.md"
        cklb_file = matched / f"findings-{app_slug}-{slug}.cklb"
        stigs.append({
            "slug":        slug,
            "stig_name":   controls_data.get("stig_name", slug),
            "release_info": controls_data.get("release_info", ""),
            "total":       len(merged),
            "controls":    merged,
            "md_url":      f"/api/scans/{scan_id}/stig-findings/{app_slug}-{slug}.md"   if md_file.exists()   else None,
            "cklb_url":    f"/api/scans/{scan_id}/stig-findings/{app_slug}-{slug}.cklb" if cklb_file.exists() else None,
        })

    return stigs


# ── Metrics ───────────────────────────────────────────────────

_metrics_lock = threading.Lock()


def _compute_metrics() -> dict:
    """Build the metrics payload. One build at a time; waiters reuse its result."""
    global _metrics_cache, _metrics_cache_ts
    with _metrics_lock:
        if _metrics_cache and (time.monotonic() - _metrics_cache_ts) < _METRICS_TTL:
            return _metrics_cache
        started = time.monotonic()
        result = _build_metrics()
        parse_cache.flush()
        _metrics_cache    = result
        _metrics_cache_ts = time.monotonic()
        logging.getLogger("epyon.perf").info("metrics built in %.1fs", _metrics_cache_ts - started)
        return result


def _freq_runs(scan_list: list) -> list[dict]:
    """Classify each scan as pr / nightly / other, and pass / fail by severity gate."""
    runs = []
    for s, _ in scan_list:
        ts = s.get("timestamp") or ""
        if not ts:
            continue
        ci = s.get("ci_source") or {}
        event = ci.get("event") or ""
        if event == "pull_request":
            kind = "pr"
        elif event == "schedule" or s.get("scan_type") == "nightly":
            kind = "nightly"
        else:
            kind = "other"
        result = {"fail": "fail", "pass": "pass"}.get(s.get("gate_status"), "unknown")
        runs.append({"date": ts[:10], "ts": ts, "kind": kind, "result": result})
    runs.sort(key=lambda r: r["ts"])
    return runs


def _build_metrics() -> dict:
    now = time.monotonic()
    scan_dirs = _cached_find_scan_dirs(days=_METRICS_DAYS)
    all_scans = [_memo_load_scan(d) for d in scan_dirs]

    scan_points = sorted(
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
    )

    by_target: dict[str, list] = {}
    for s, d in zip(all_scans, scan_dirs):
        by_target.setdefault(s["target"], []).append((s, d))

    # ── Monitored-app filter ──────────────────────────────────
    monitored = _load_monitored_apps()
    if monitored:
        by_target = {k: v for k, v in by_target.items() if k in monitored}
        scan_points = [t for t in scan_points if t["target"] in monitored]
    metrics_filtered = bool(monitored)
    monitored_count  = len(monitored)

    # One point per day: the latest scan of each app that day, summed across apps.
    # Many scans per day (PR/push runs) would otherwise crowd out older history.
    latest_per_day: dict[str, dict[str, dict]] = {}
    for pt in scan_points:
        latest_per_day.setdefault(pt["timestamp"][:10], {})[pt["target"]] = pt
    trend = [
        {
            "scan_id":   "",
            "target":    f"{len(apps)} app{'s' if len(apps) != 1 else ''}",
            "timestamp": f"{day}T00:00:00Z",
            **{sev: sum(a[sev] for a in apps.values()) for sev in ("critical", "high", "medium", "low")},
        }
        for day, apps in sorted(latest_per_day.items())
    ]

    tool_counts:      dict[str, dict] = {}
    tool_app_counts:  dict[str, dict[str, int]] = {}
    total_with_fix    = 0
    total_without_fix = 0
    total_suppressed_instances = 0
    cve_counts:       dict[str, dict] = {}

    for _target, scan_list in by_target.items():
        scan_list.sort(key=lambda x: x[0].get("timestamp", ""), reverse=True)
        _, latest_dir = scan_list[0]
        total_suppressed_instances += parsers.count_suppressed_instances(latest_dir)
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
                tool_app_counts.setdefault(tool, {})
                tool_app_counts[tool][_target] = tool_app_counts[tool].get(_target, 0) + 1
                if f.get("fixed_version"):
                    total_with_fix += 1
                else:
                    total_without_fix += 1
                cve_id = f.get("id") or ""
                if cve_id.startswith("CVE-"):
                    ftype = (f.get("type") or "").lower()
                    ftool = (f.get("tool") or "").lower()
                    if ftype == "container_vulnerability" or "anchore" in ftool:
                        cve_source = "container"
                    else:
                        cve_source = "code"
                    if cve_id not in cve_counts:
                        cve_counts[cve_id] = {
                            "count":    0,
                            "severity": sev,
                            "title":    (f.get("title") or "")[:120],
                            "apps":     set(),
                            "sources":  set(),
                        }
                    cve_counts[cve_id]["count"] += 1
                    cve_counts[cve_id]["apps"].add(_target)
                    cve_counts[cve_id]["sources"].add(cve_source)

    top_cves = sorted(cve_counts.items(), key=lambda x: x[1]["count"], reverse=True)[:20]

    app_trends = {
        target: app_trend([sc for sc, _ in scan_list])
        for target, scan_list in by_target.items()
    }

    scan_frequency = {
        target: {
            "total": len(scan_list),
            "dates": sorted(
                s.get("timestamp", "")[:10]
                for s, _ in scan_list if s.get("timestamp")
            ),
            "runs": _freq_runs(scan_list),
        }
        for target, scan_list in by_target.items()
    }

    # ── Merges to main ─────────────────────────────────────────
    merge_dates_by_target: dict[str, list[str]] = {}
    for _target, scan_list in by_target.items():
        for s, _ in scan_list:
            ci = s.get("ci_source", {})
            if ci.get("event") in ("push", "workflow_dispatch") and ci.get("branch") in ("main", "master", "dev"):
                date = (s.get("timestamp") or "")[:10]
                if date:
                    merge_dates_by_target.setdefault(_target, []).append(date)

    merges_to_main = {
        target: {
            "total": len(dates),
            "dates": sorted(dates),
        }
        for target, dates in merge_dates_by_target.items()
    }
    total_merges_to_main = sum(len(d) for d in merge_dates_by_target.values())

    # ── SLA Compliance Rate ────────────────────────────────────
    # SLA thresholds (days): critical=7, high=30, medium=90, low=180
    SLA_DAYS = {"critical": 7, "high": 30, "medium": 90, "low": 180}
    sla_within:  dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    sla_breached: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    # ── Secret Detection Trend ─────────────────────────────────
    # Per-target, per-scan: count of TruffleHog findings over time (last 60 scans)
    secret_trend: list[dict] = []
    secret_trend_by_target: dict[str, list[dict]] = {}

    # ── Weighted Risk Score Trend ──────────────────────────────
    # Score = critical*10 + high*7 + medium*4 + low*1, per scan
    RISK_WEIGHTS = {"critical": 10, "high": 7, "medium": 4, "low": 1}
    risk_trend: list[dict] = []

    # ── Suppression Rate ───────────────────────────────────────
    total_suppressed = 0
    suppressed_by_sev: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    suppressed_by_tool: dict[str, int] = {}
    suppressed_by_target: dict[str, list[dict]] = {}

    # ── Recurrence + First-Time Fix Rate ──────────────────────
    # recurrence: fingerprints that were resolved but reappeared
    # first_time_fix: fingerprints resolved within 1 scan cycle of first appearance
    recurrence_count   = 0
    first_time_fixed   = 0
    total_resolved     = 0

    for _target, scan_list in by_target.items():
        eligible = [
            (s, d) for s, d in scan_list
            if s.get("scan_type") not in ("stig",)
        ]
        if not eligible:
            continue
        eligible_sorted = sorted(eligible, key=lambda x: x[0].get("timestamp", ""))

        # Secret trend for this target
        t_secret_trend: list[dict] = []
        for scan_meta, scan_dir in eligible_sorted:
            ts = (scan_meta.get("timestamp") or "")[:10]
            if not ts:
                continue
            # Risk score uses only scan_meta — compute before attempting findings parse
            s = scan_meta
            risk_trend.append({
                "date":     ts,
                "target":   _target,
                "score":    (s.get("critical", 0) * RISK_WEIGHTS["critical"]
                             + s.get("high",     0) * RISK_WEIGHTS["high"]
                             + s.get("medium",   0) * RISK_WEIGHTS["medium"]
                             + s.get("low",      0) * RISK_WEIGHTS["low"]),
                "critical": s.get("critical", 0),
                "high":     s.get("high",     0),
                "medium":   s.get("medium",   0),
                "low":      s.get("low",      0),
            })
            try:
                dg = _scan_digest(scan_dir)
            except Exception:
                continue
            verified   = dg["verified"]
            unverified = dg["secrets"] - verified
            t_secret_trend.append({
                "date": ts, "target": _target,
                "verified": verified, "unverified": unverified,
                "total": dg["secrets"],
            })
        secret_trend.extend(t_secret_trend)
        if t_secret_trend:
            secret_trend_by_target[_target] = t_secret_trend

        # Suppression: union across all scans for target (latest scan may have empty file)
        seen_sup_keys: set[tuple] = set()
        target_suppressions: list[dict] = []
        for _, scan_dir in reversed(eligible_sorted):  # newest → oldest
            try:
                batch = _memo_suppressed(scan_dir)
            except Exception:
                continue
            for sup in batch:
                key = (sup.get("type", ""), sup.get("value", ""))
                if key not in seen_sup_keys:
                    seen_sup_keys.add(key)
                    target_suppressions.append(sup)
        total_suppressed += len(target_suppressions)
        if target_suppressions:
            suppressed_by_target[_target] = [
                {
                    "value":       sup.get("value", ""),
                    "tool":        sup.get("tool", "Unknown"),
                    "type":        sup.get("type", ""),
                    "severity":    sup.get("severity", ""),
                    "reason":      sup.get("reason", ""),
                    "approved_by": sup.get("approved_by", ""),
                }
                for sup in target_suppressions
            ]
        for sup in target_suppressions:
            raw_sev = (sup.get("severity") or "").lower()
            if raw_sev in suppressed_by_sev:
                suppressed_by_sev[raw_sev] += 1
            tool_key = (sup.get("tool") or "Unknown")
            suppressed_by_tool[tool_key] = suppressed_by_tool.get(tool_key, 0) + 1

        if len(eligible_sorted) < 2:
            continue

        # Build per-scan fingerprint sets for recurrence + SLA + first-time-fix
        fp_first_seen: dict[str, tuple[str, str]] = {}  # fp -> (timestamp, sev)
        fp_resolved_at: dict[str, str] = {}             # fp -> resolved_scan_ts
        fp_ever_resolved: set[str]     = set()
        # Pending-resolution: fp disappeared last scan but we require one more
        # consecutive absence before counting it as a genuine fix (filters scanner noise).
        fp_pending_resolution: dict[str, str] = {}      # fp -> scan_ts when it first disappeared
        fp_last_present: dict[str, str] = {}            # fp -> last scan_ts it was still present
        prev_fps: set[str]             = set()
        prev_ts_str: str               = ""

        for scan_meta, scan_dir in eligible_sorted:
            ts = scan_meta.get("timestamp", "")
            if not ts:
                continue
            try:
                dg = _scan_digest(scan_dir)
            except Exception:
                prev_fps = set()
                prev_ts_str = ts
                fp_pending_resolution.clear()
                continue
            curr_fps: set[str] = set()
            for fp, sev in dg["fps"].items():
                curr_fps.add(fp)
                if fp not in fp_first_seen:
                    fp_first_seen[fp] = (ts, sev)
                # Recurrence: was resolved before, now back
                if fp in fp_ever_resolved:
                    recurrence_count += 1
                    fp_ever_resolved.discard(fp)
                # Reappeared before confirmation — cancel the pending resolution
                fp_pending_resolution.pop(fp, None)

            # ── Two-scan confirmation: a finding must be absent from 2 consecutive
            # scans before it counts as resolved. Single-scan absences (scanner noise,
            # transient fetch failures, DB updates) are ignored. ──────────────────
            if prev_fps:
                disappeared_now = prev_fps - curr_fps

                # Confirm resolutions that were pending from the previous scan
                # (absent LAST scan AND still absent NOW → confirmed resolved)
                sla_seen_this_transition: set[str] = set()
                for fp, absent_since_ts in list(fp_pending_resolution.items()):
                    if fp not in curr_fps:  # still absent — confirmed
                        del fp_pending_resolution[fp]
                        if fp in fp_first_seen:
                            first_ts, sev = fp_first_seen[fp]
                            fp_ever_resolved.add(fp)
                            fp_resolved_at[fp] = absent_since_ts
                            total_resolved += 1
                            if fp_last_present.pop(fp, "") == first_ts:
                                first_time_fixed += 1
                            # SLA — deduplicate by CVE-ID::package (strip tool prefix)
                            fp_parts = fp.split('::', 2)
                            sla_key = f"{fp_parts[1]}::{fp_parts[2]}" if len(fp_parts) == 3 and fp_parts[1] else fp
                            if sla_key not in sla_seen_this_transition:
                                sla_seen_this_transition.add(sla_key)
                                try:
                                    first_dt = datetime.fromisoformat(first_ts.replace("Z", "+00:00"))
                                    res_dt   = datetime.fromisoformat(absent_since_ts.replace("Z", "+00:00"))
                                    if first_dt.tzinfo is None:
                                        first_dt = first_dt.replace(tzinfo=timezone.utc)
                                    if res_dt.tzinfo is None:
                                        res_dt = res_dt.replace(tzinfo=timezone.utc)
                                    days = (res_dt - first_dt).total_seconds() / 86400
                                    threshold = SLA_DAYS.get(sev, 180)
                                    if days <= threshold:
                                        sla_within[sev]   += 1
                                    else:
                                        sla_breached[sev] += 1
                                except ValueError:
                                    pass
                    # else: reappeared → already removed from pending_resolution above

                # Stage newly disappeared fingerprints as pending (not yet confirmed)
                for fp in disappeared_now:
                    if fp not in fp_ever_resolved and fp in fp_first_seen:
                        fp_pending_resolution[fp] = ts
                        fp_last_present[fp] = prev_ts_str

            prev_fps    = curr_fps
            prev_ts_str = ts

    # Aggregate SLA
    sla_by_sev = {}
    for sev in ("critical", "high", "medium", "low"):
        w = sla_within[sev]
        b = sla_breached[sev]
        total_sla = w + b
        sla_by_sev[sev] = {
            "within": w,
            "breached": b,
            "pct": round(w / total_sla * 100, 1) if total_sla > 0 else None,
            "sla_days": SLA_DAYS[sev],
        }
    sla_total_within  = sum(sla_within.values())
    sla_total_breached = sum(sla_breached.values())
    sla_total = sla_total_within + sla_total_breached
    sla_overall_pct = round(sla_total_within / sla_total * 100, 1) if sla_total > 0 else None

    # Aggregate risk trend (last 60 data points per target, sorted)
    by_target_trend: dict[str, list[dict]] = {}
    for pt in risk_trend:
        by_target_trend.setdefault(pt["target"], []).append(pt)

    risk_trend_sorted: list[dict] = []
    for target, pts in by_target_trend.items():
        pts_sorted = sorted(pts, key=lambda x: x["date"])[-60:]
        risk_trend_sorted.extend(pts_sorted)

    risk_trend_sorted.sort(key=lambda x: (x["target"], x["date"]))
    # Aggregate secret trend (last 60 total entries)
    secret_trend_sorted = sorted(secret_trend, key=lambda x: x["date"])[-60:]

    # Suppression rate vs fixed
    total_fixed_or_suppressed = total_resolved + total_suppressed
    suppression_rate_pct = (
        round(total_suppressed / total_fixed_or_suppressed * 100, 1)
        if total_fixed_or_suppressed > 0 else None
    )

    # Recurrence rate
    recurrence_rate_pct = (
        round(recurrence_count / total_resolved * 100, 1)
        if total_resolved > 0 else None
    )

    # First-time fix rate
    first_time_fix_pct = (
        round(first_time_fixed / total_resolved * 100, 1)
        if total_resolved > 0 else None
    )

    # ── MTTR (Mean Time to Remediate) + MTTD (Mean Time to Detect) ──────────────    # by_target lists are already sorted newest-first from the loop above
    all_remediation_days: list[float] = []
    all_remediation_days_by_sev: dict[str, list[float]] = {"critical": [], "high": [], "medium": [], "low": []}
    all_detection_days: list[float] = []
    all_detection_days_by_sev: dict[str, list[float]] = {"critical": [], "high": [], "medium": [], "low": []}
    target_mttr: dict[str, float] = {}
    # Per-target detailed metrics for app-level filtering
    metrics_by_target: dict[str, dict] = {}
    for _target, scan_list in by_target.items():
        # Only full and nightly scans carry consistent vulnerability data
        eligible = [
            (s, d) for s, d in scan_list
            if s.get("scan_type") not in ("stig",)
        ]
        if len(eligible) < 2:
            continue
        # eligible is newest-first; reverse to chronological order
        scans_to_check = list(reversed(eligible))  # oldest → newest

        # Build fingerprint -> first_seen_ts + severity mapping
        first_seen: dict[str, str] = {}
        first_seen_sev: dict[str, str] = {}
        known_fps: set[str] = set()
        prev_ts: str | None = None
        t_detection_days: list[float] = []
        t_detection_days_by_sev: dict[str, list[float]] = {"critical": [], "high": [], "medium": [], "low": []}
        for scan_meta, scan_dir in scans_to_check:
            ts = scan_meta.get("timestamp", "")
            if not ts:
                continue
            try:
                dg = _scan_digest(scan_dir)
            except Exception:
                prev_ts = ts
                continue
            current_fp_sev: dict[str, str] = dg["fps"]
            current_fps: set[str] = set(current_fp_sev)
            for fp, sev in current_fp_sev.items():
                if fp not in first_seen:
                    first_seen[fp] = ts
                    first_seen_sev[fp] = sev
            # MTTD: record detection window for newly-appearing findings
            if prev_ts:
                try:
                    prev_dt = datetime.fromisoformat(prev_ts.replace("Z", "+00:00"))
                    curr_dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                    if prev_dt.tzinfo is None:
                        prev_dt = prev_dt.replace(tzinfo=timezone.utc)
                    if curr_dt.tzinfo is None:
                        curr_dt = curr_dt.replace(tzinfo=timezone.utc)
                    detect_days = (curr_dt - prev_dt).total_seconds() / 86400
                    if detect_days >= 0:
                        for fp in (current_fps - known_fps):
                            sev = current_fp_sev.get(fp, "")
                            all_detection_days.append(detect_days)
                            t_detection_days.append(detect_days)
                            if sev in all_detection_days_by_sev:
                                all_detection_days_by_sev[sev].append(detect_days)
                            if sev in t_detection_days_by_sev:
                                t_detection_days_by_sev[sev].append(detect_days)
                except ValueError:
                    pass
            known_fps |= current_fps
            prev_ts = ts

        # Latest scan fingerprint set (scans_to_check[-1] is the newest)
        latest_meta, latest_dir = scans_to_check[-1]
        latest_ts = latest_meta.get("timestamp", "")
        if not latest_ts:
            continue
        latest_set: set[str] = set()
        try:
            latest_findings = parsers.parse_scan_findings(latest_dir)
        except Exception:
            continue
        for sev in ("critical", "high", "medium", "low"):
            for f in latest_findings.get(f"{sev}_findings", []):
                fp = f"{f.get('tool', '')}::{f.get('id', '')}::{f.get('package', '')}"
                if fp:
                    latest_set.add(fp)

        try:
            latest_dt = datetime.fromisoformat(latest_ts.replace("Z", "+00:00"))
            if latest_dt.tzinfo is None:
                latest_dt = latest_dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue

        target_days: list[float] = []
        t_remediation_days_by_sev: dict[str, list[float]] = {"critical": [], "high": [], "medium": [], "low": []}
        for fp, first_ts in first_seen.items():
            if fp not in latest_set:
                try:
                    first_dt = datetime.fromisoformat(first_ts.replace("Z", "+00:00"))
                    if first_dt.tzinfo is None:
                        first_dt = first_dt.replace(tzinfo=timezone.utc)
                    days = (latest_dt - first_dt).total_seconds() / 86400
                    if days >= 0:
                        all_remediation_days.append(days)
                        target_days.append(days)
                        sev = first_seen_sev.get(fp, "")
                        if sev in all_remediation_days_by_sev:
                            all_remediation_days_by_sev[sev].append(days)
                        if sev in t_remediation_days_by_sev:
                            t_remediation_days_by_sev[sev].append(days)
                except ValueError:
                    pass
        if target_days:
            target_mttr[_target] = round(sum(target_days) / len(target_days), 1)

        t_mttr = round(sum(target_days) / len(target_days), 1) if target_days else None
        t_mttd = round(sum(t_detection_days) / len(t_detection_days), 1) if t_detection_days else None
        metrics_by_target[_target] = {
            "mttr_days": t_mttr,
            "mttr_by_severity": {
                s: round(sum(v) / len(v), 1) if v else None
                for s, v in t_remediation_days_by_sev.items()
            },
            "mttd_days": t_mttd,
            "mttd_by_severity": {
                s: round(sum(v) / len(v), 1) if v else None
                for s, v in t_detection_days_by_sev.items()
            },
        }

    mttr_days = (
        round(sum(all_remediation_days) / len(all_remediation_days), 1)
        if all_remediation_days else None
    )
    mttr_by_severity = {
        sev: round(sum(days) / len(days), 1) if days else None
        for sev, days in all_remediation_days_by_sev.items()
    }
    mttd_days = (
        round(sum(all_detection_days) / len(all_detection_days), 1)
        if all_detection_days else None
    )
    mttd_by_severity = {
        sev: round(sum(days) / len(days), 1) if days else None
        for sev, days in all_detection_days_by_sev.items()
    }
    fastest_remediator = (
        min(target_mttr.items(), key=lambda x: x[1])
        if target_mttr else None
    )

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
                    "top_app":  max(tool_app_counts.get(k, {"":0}).items(), key=lambda x: x[1])[0],
                }
                for k, v in tool_counts.items()
            ],
            key=lambda x: -x["total"],
        ),
        "fix_rate": {"with_fix": total_with_fix, "without_fix": total_without_fix},
        "mttr_days": mttr_days,
        "mttr_by_severity": mttr_by_severity,
        "mttd_days": mttd_days,
        "mttd_by_severity": mttd_by_severity,
        "metrics_by_target": metrics_by_target,
        "fastest_remediator": {"target": fastest_remediator[0], "mttr_days": fastest_remediator[1]} if fastest_remediator else None,
        "top_cves": [
            {
                "cve_id":   k,
                "count":    v["count"],
                "severity": v["severity"],
                "title":    v["title"],
                "apps":     sorted(v["apps"]),
                "sources":  sorted(v["sources"]),
            }
            for k, v in top_cves
        ],
        "scan_frequency": scan_frequency,
        "app_trends": app_trends,
        "merges_to_main": merges_to_main,
        "window_days":         _METRICS_DAYS,
        "total_merges_to_main": total_merges_to_main,
        "metrics_filtered": metrics_filtered,
        "monitored_count":  monitored_count,
        # ── New metrics ──────────────────────────────────────
        "sla_compliance": {
            "overall_pct":     sla_overall_pct,
            "total_within":    sla_total_within,
            "total_breached":  sla_total_breached,
            "by_severity":     sla_by_sev,
        },
        "risk_trend":            risk_trend_sorted,
        "secret_trend":          secret_trend_sorted,
        "secret_trend_by_target": secret_trend_by_target,
        "suppression": {
            "total":       total_suppressed,
            "by_severity": suppressed_by_sev,
            "by_tool":     suppressed_by_tool,
            "by_target":   suppressed_by_target,
            "rate_pct":    suppression_rate_pct,
        },
        "accepted_risk_pct": (
            round(total_suppressed_instances /
                  (total_with_fix + total_without_fix + total_suppressed_instances) * 100, 1)
            if (total_with_fix + total_without_fix + total_suppressed_instances) > 0 else None
        ),
        "recurrence_rate_pct":    recurrence_rate_pct,
        "first_time_fix_pct":     first_time_fix_pct,
        "total_resolved":         total_resolved,
    }

    return result


# ── GitHub Metrics ────────────────────────────────────────────

@app.get("/api/github-metrics")
async def get_github_metrics(response: Response):
    _sec_headers(response)
    global _gh_metrics_cache, _gh_metrics_cache_ts
    now = time.monotonic()
    if _gh_metrics_cache and (now - _gh_metrics_cache_ts) < _GH_METRICS_TTL:
        return _gh_metrics_cache

    cfg   = _read_github_config()
    token = cfg.get("token", "")
    repos = cfg.get("repos") or []

    scan_dirs = parsers.find_scan_dirs(EPYON_ROOT, days=_METRICS_DAYS)
    all_scans = [parsers.load_scan(d, EPYON_ROOT) for d in scan_dirs]
    monitored_set = set(_load_monitored_apps()) or None

    result = await github_metrics.fetch_all(token, repos, all_scans, monitored_set, _METRICS_DAYS)

    _gh_metrics_cache    = result
    _gh_metrics_cache_ts = now
    _save_gh_snapshot(result)
    return result


_STIG_PLACEHOLDER_MARK = "STIG assessment skipped"


def _is_real_stig_result(path: Path) -> bool:
    """False for the all-"Not Reviewed" placeholder written when a scan reached the
    STIG layer without an AI endpoint. That scan never assessed anything, so it
    must not count as a STIG run or replace the last real results."""
    try:
        key = (str(path), path.stat().st_mtime_ns)
    except OSError:
        return False
    hit = _real_stig_cache.get(key)
    if hit is not None:
        return hit
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        res = raw.get("assessments", raw) if isinstance(raw, dict) and "assessments" in raw else raw
        real = any(
            not str((v or {}).get("evidence", "")).startswith(_STIG_PLACEHOLDER_MARK)
            for v in res.values()
        ) if isinstance(res, dict) and res else False
    except Exception:
        real = False
    _real_stig_cache[key] = real
    return real


_real_stig_cache: dict[tuple, bool] = {}


def _real_stig_files(scan_dir: Path) -> list[Path]:
    return [f for f in sorted(scan_dir.glob("stig-results-*.json")) if _is_real_stig_result(f)]


# ── NVD API config ────────────────────────────────────────────

NVD_CONFIG_FILE = (_HERE / ".." / "data" / "nvd-config.json").resolve()


def _load_mobile_code_validator():
    """Dynamically import tests/validate-mobile-code-scanner.py (hyphenated filename)."""
    import importlib.util
    script_path = EPYON_ROOT / "tests" / "validate-mobile-code-scanner.py"
    spec = importlib.util.spec_from_file_location("mobile_code_validator", script_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _cached_mobile_code_accuracy() -> dict:
    """Run the mobile code scanner against its labeled test corpus and return
    live precision/recall/F1 metrics, cached briefly since the fixture corpus
    never changes at runtime."""
    global _mobile_code_accuracy_cache
    now = time.monotonic()
    cached = _mobile_code_accuracy_cache
    if cached and (now - cached[1]) < _MOBILE_CODE_ACCURACY_CACHE_TTL:
        return cached[0]

    import tempfile
    validator = _load_mobile_code_validator()
    test_dir = EPYON_ROOT / "tests" / "fixtures" / "mobile-code"
    with tempfile.TemporaryDirectory(prefix="epyon-mobile-code-accuracy-") as tmp:
        metrics = validator.compute_accuracy_metrics(test_dir, Path(tmp))

    _mobile_code_accuracy_cache = (metrics, now)
    return metrics


def _compute_scan_integrity(scan_dirs: list, limit: int = 40, per_app_limit: int = 8) -> dict:
    """Flag scans that likely produced a false-clean result rather than a
    genuinely clean one — e.g. the class of bug where a tool scanned an
    empty/missing directory (empty bind mount, bad path translation, etc.)
    and silently reported zero findings instead of erroring.

    `scan-metadata.json`'s file_statistics.total_files is the most reliable
    signal available: it's a raw count of source files actually present in
    the target directory at scan time, generated independently of whatever
    any individual security tool did or didn't find — so it can't be fooled
    by a legitimately clean project (which still has files) the way a
    zero-findings count can.

    Scans are capped at `per_app_limit` most-recent-per-app (then an overall
    `limit`) rather than a single global most-recent-N — otherwise one
    frequently-scanned app (e.g. an hourly quick scan) fills the entire
    window and every other app's scans never get checked at all.
    """
    by_app: dict[str, list] = {}
    for scan_dir in sorted(scan_dirs, key=lambda d: d.name, reverse=True):
        app = parsers.parse_dir_name(scan_dir.name)["target"]
        bucket = by_app.setdefault(app, [])
        if len(bucket) < per_app_limit:
            bucket.append(scan_dir)

    scans = sorted(
        (d for bucket in by_app.values() for d in bucket),
        key=lambda d: d.name, reverse=True,
    )[:limit]
    results: list[dict] = []
    counts = {"healthy": 0, "suspicious": 0, "empty_target": 0, "unknown": 0}

    for scan_dir in scans:
        data = _cached_load_scan(scan_dir)
        scan_type = data.get("scan_type", "full")
        reasons: list[str] = []
        status = "healthy"

        if scan_type == "stig":
            # STIG-only runs don't collect file_statistics or run vuln tools.
            status = "unknown"
        else:
            file_stats = data.get("file_statistics") or {}
            total_files = file_stats.get("total_files")
            sbom = parsers.load_sbom_packages(scan_dir)

            if total_files is None:
                status = "unknown"
                reasons.append("scan predates file_statistics tracking")
            elif total_files == 0:
                status = "empty_target"
                reasons.append("0 source files scanned — target directory was likely empty or unreachable")
            elif total_files < 3:
                status = "suspicious"
                reasons.append(f"only {total_files} source file(s) scanned — verify the target path is correct")

            if status != "unknown" and (scan_dir / "sbom").is_dir() and sbom["total"] == 0:
                if status == "healthy":
                    status = "suspicious"
                reasons.append("SBOM layer ran but found 0 packages/components")

        counts[status] = counts.get(status, 0) + 1
        if status != "healthy":
            results.append({
                "scan_id":    data.get("scan_id"),
                "target":     data.get("target"),
                "timestamp":  data.get("timestamp"),
                "scan_type":  scan_type,
                "status":     status,
                "reasons":    reasons,
            })

    return {
        "summary": {"total": len(scans), **counts},
        "flagged": results,
    }

# ── Routers ───────────────────────────────────────────────────
from .routers.system import router as system_router  # noqa: E402
from .routers.applications import router as applications_router  # noqa: E402
from .routers.scans import router as scans_router  # noqa: E402
from .routers.reports import router as reports_router  # noqa: E402
from .routers.stig import router as stig_router  # noqa: E402
from .routers.poam import router as poam_router  # noqa: E402
from .routers.findings import router as findings_router  # noqa: E402
from .routers.jira import router as jira_router  # noqa: E402
from .routers.metrics import router as metrics_router  # noqa: E402
from .routers.github import router as github_router  # noqa: E402
for _router in (system_router, applications_router, scans_router, reports_router, stig_router, poam_router, findings_router, jira_router, metrics_router, github_router):
    app.include_router(_router)



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
