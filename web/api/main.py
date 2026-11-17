"""
Epyon Web — FastAPI backend
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
import time
from collections import OrderedDict
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from . import jobs as job_store
from . import parsers
from . import parse_cache
from . import finding_search
from . import github_sync
from . import github_config
from . import jira_client
from . import db as scan_db
from . import scan_store
from . import cache_state

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
_METRICS_TTL:      float = 300.0
# History window for the Metrics page. 90 days matches GitHub's default artifact retention.
_METRICS_DAYS:     int   = max(7, int(os.environ.get("EPYON_METRICS_DAYS", "90") or 90))

# ── GitHub metrics cache ─────────────────────────────────────
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
# CVE search index: scan_id -> ((dir mtime_ns, project_key), per-scan lookup index).
# Scans are immutable, so the dir mtime only changes if a scan is rewritten.
_search_index:    "OrderedDict[str, tuple[tuple, dict]]" = OrderedDict()
_SEARCH_INDEX_MAX: int = 2000
_SCAN_CACHE_TTL:  float = 300.0  # 5 minutes — scans are immutable
_DIR_CACHE_TTL:   float = 60.0   # 1 minute — new scans appear less frequently
_STATS_CACHE_TTL: float = 120.0  # 2 minutes — aggregated stats
_APPS_CACHE_TTL:  float = 120.0  # 2 minutes — app list
_MOBILE_CODE_ACCURACY_CACHE_TTL: float = 300.0  # 5 minutes — fixture corpus is static
_DEFAULT_SCAN_DAYS: int = 35     # Only load last 35 days of scans by default

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


_AGGREGATE_ONLY_REASONS = frozenset({"hidden_apps_changed", "monitored_apps_changed", "cache_warm"})


def _invalidate_scan_cache(reason: str = "scan_completion", scan_id: str = None) -> None:
    """Call after a scan completes so the next request sees fresh data."""
    old_version = cache_state.version
    # Scans are immutable once written, so a new scan only adds a directory; app visibility
    # and cache warming change no scan data. Anything that deletes or restores scans (or an
    # unknown reason) still drops everything.
    if reason == "scan_completion" and scan_id:
        _scan_cache.pop(scan_id, None)
        _dir_cache.clear()
    elif reason in _AGGREGATE_ONLY_REASONS:
        pass
    else:
        _scan_cache.clear()
        _dir_cache.clear()
    if reason in ("delete_scan", "restore_scan", "retention_sweep", "retention_sweep_manual"):
        _search_index.clear()
    cache_state.stats = None
    cache_state.apps = None
    # /api/metrics keeps its own 5-minute cache separate from the caches
    # above; without clearing it here the Metrics page kept serving
    # pre-scan data for up to 5 minutes after a scan completed.
    cache_state.metrics    = {}
    cache_state.metrics_ts = 0.0
    cache_state.version += 1  # Bust frontend caches
    
    # Record invalidation event
    invalidation_event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "reason": reason,
        "old_version": old_version,
        "new_version": cache_state.version,
        "scan_id": scan_id,
    }
    _cache_metrics["invalidations"].append(invalidation_event)
    # Keep only last 100 invalidation events
    _cache_metrics["invalidations"] = _cache_metrics["invalidations"][-100:]
    
    _cache_metrics_logger.info(
        f"cache_invalidation reason={reason} old_version={old_version} "
        f"new_version={cache_state.version} scan_id={scan_id or 'N/A'}"
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
                if not cache_state.metrics:
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
            if _etag_eligible(request, response):
                return await _with_etag(request, response)
        return response


# Read-only scan data the browser may keep and revalidate. Everything else (integration
# config, jobs, exports, auth-adjacent endpoints) stays no-store.
_ETAG_PREFIXES = (
    "/api/applications", "/api/scans", "/api/scan-history", "/api/metrics", "/api/stats", "/api/stig/history",
)
_ETAG_EXCLUDE = ("/download", "/dashboard", "/logs", "/stream", "/export", "/stig-findings", "/sbom", "/ssp-evidence")


def _etag_eligible(request: Request, response: Response) -> bool:
    path = request.url.path
    return (
        request.method == "GET"
        and response.status_code == 200
        and path.startswith(_ETAG_PREFIXES)
        and not any(x in path for x in _ETAG_EXCLUDE)
        and response.headers.get("content-type", "").startswith("application/json")
    )


async def _with_etag(request: Request, response: Response) -> Response:
    """Answer 304 when the client already holds this exact body; otherwise tag it."""
    body = b"".join([chunk async for chunk in response.body_iterator])
    etag = 'W/"%s"' % hashlib.sha1(body).hexdigest()
    headers = {k: v for k, v in response.headers.items() if k.lower() not in ("content-length", "cache-control", "pragma")}
    headers["ETag"] = etag
    headers["Cache-Control"] = "private, no-cache"
    if etag in [t.strip() for t in request.headers.get("if-none-match", "").split(",")]:
        return Response(status_code=304, headers=headers)
    return Response(content=body, status_code=200, headers=headers, media_type=response.media_type)


app.add_middleware(_SecurityHeadersMiddleware)
app.add_middleware(GZipMiddleware, minimum_size=1024)


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
    now = time.monotonic()
    cached = cache_state.mobile_code_accuracy
    if cached and (now - cached[1]) < _MOBILE_CODE_ACCURACY_CACHE_TTL:
        return cached[0]

    import tempfile
    validator = _load_mobile_code_validator()
    test_dir = EPYON_ROOT / "tests" / "fixtures" / "mobile-code"
    with tempfile.TemporaryDirectory(prefix="epyon-mobile-code-accuracy-") as tmp:
        metrics = validator.compute_accuracy_metrics(test_dir, Path(tmp))

    cache_state.mobile_code_accuracy = (metrics, now)
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
from .metrics_builder import _compute_metrics  # noqa: E402
from .stig_entries import _build_stig_entries  # noqa: E402,F401


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
