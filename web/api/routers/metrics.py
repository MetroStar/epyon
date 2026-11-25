"""Epyon Web — metrics routes."""
from __future__ import annotations

import json
import logging
import threading
import time

from fastapi import APIRouter
from fastapi import HTTPException
from fastapi import Response

from .. import cache_state
from .. import main as api_main

router = APIRouter()

@router.get("/api/metrics")
def get_metrics(response: Response):
    api_main._sec_headers(response)
    if cache_state.metrics:
        if (time.monotonic() - cache_state.metrics_ts) >= api_main._METRICS_TTL:
            try:
                _refresh_metrics_async()  # serve the stale copy while a fresh one builds
            except Exception:
                # Never let a background-refresh kick-off failure turn a cache hit into a 500.
                logging.getLogger("epyon.perf").exception("metrics background refresh kick-off failed")
        return cache_state.metrics
    try:
        return api_main._compute_metrics()
    except Exception:
        logging.getLogger("epyon.perf").exception("metrics computation failed")
        raise HTTPException(status_code=500, detail="Metrics computation failed; see server logs")


def _refresh_metrics_async() -> None:
    if api_main._metrics_lock.locked():
        return
    threading.Thread(target=api_main._compute_metrics, daemon=True).start()


# ── Cache Metrics ─────────────────────────────────────────────

@router.get("/api/metrics/cache")
def get_cache_metrics(response: Response):
    """Return cache performance metrics and observability data."""
    api_main._sec_headers(response)
    
    # Calculate hit rates
    def _hit_rate(cache_type: str) -> float | None:
        hits = api_main._cache_metrics["hits"][cache_type]
        misses = api_main._cache_metrics["misses"][cache_type]
        total = hits + misses
        return round(hits / total * 100, 1) if total > 0 else None
    
    # Calculate cache sizes
    cache_sizes = {
        "scan": len(api_main._scan_cache),
        "dir": len(api_main._dir_cache),
        "stats": 1 if cache_state.stats else 0,
        "apps": 1 if cache_state.apps else 0,
        "search_index": len(api_main._search_index),
    }
    
    # Recent invalidations (last 10)
    recent_invalidations = api_main._cache_metrics["invalidations"][-10:]
    
    return {
        "cache_version": cache_state.version,
        "hit_rates": {
            "scan": _hit_rate("scan"),
            "dir": _hit_rate("dir"),
            "stats": _hit_rate("stats"),
            "apps": _hit_rate("apps"),
            "search_index": _hit_rate("search_index"),
        },
        "hits": api_main._cache_metrics["hits"].copy(),
        "misses": api_main._cache_metrics["misses"].copy(),
        "writes": api_main._cache_metrics["writes"].copy(),
        "cache_sizes": cache_sizes,
        "recent_invalidations": recent_invalidations,
        "ttls": {
            "scan_seconds": api_main._SCAN_CACHE_TTL,
            "dir_seconds": api_main._DIR_CACHE_TTL,
            "stats_seconds": api_main._STATS_CACHE_TTL,
            "apps_seconds": api_main._APPS_CACHE_TTL,
        },
    }


@router.get("/api/metrics/mobile-code-accuracy")
async def get_mobile_code_accuracy(response: Response):
    """Live precision/recall/F1 for the mobile code scanner, computed by
    running it against its labeled test-fixture corpus (tests/fixtures/mobile-code)."""
    api_main._sec_headers(response)
    try:
        return api_main._cached_mobile_code_accuracy()
    except Exception as e:
        raise HTTPException(500, f"Failed to compute mobile code scanner accuracy: {e}")


@router.get("/api/metrics/scan-integrity")
def get_scan_integrity(response: Response, days: int = 35, limit: int = 40):
    """Validate that recent scans actually ran against real target content,
    to catch the false-clean-result bug class early instead of relying on
    someone noticing a suspiciously quiet dashboard."""
    api_main._sec_headers(response)
    scan_dirs = api_main._cached_find_scan_dirs(days=days)
    return api_main._compute_scan_integrity(scan_dirs, limit=limit)


@router.get("/api/metrics/self-assessment")
def get_self_assessment(response: Response):
    """Latest results from scripts/shell/run-self-assessment.sh — a real
    scan of the deliberately vulnerable fixture at
    tests/fixtures/self-assessment/, diffed against known-planted issues to
    verify every scanner layer is actually detecting what it should (not
    just running). Written by the harness to SELF_ASSESSMENT_FILE; absent
    until the harness has run at least once (e.g. via the scheduled
    self-assessment.yml workflow or a manual run)."""
    api_main._sec_headers(response)
    if not api_main.SELF_ASSESSMENT_FILE.exists():
        return {"available": False}
    try:
        data = json.loads(api_main.SELF_ASSESSMENT_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {"available": False}
    data["available"] = True
    return data
