"""/api/metrics must keep serving a stale cached payload while a background
refresh kicks off, instead of 500ing when the refresh helper errors."""
from __future__ import annotations

import sys
import time
from pathlib import Path

from fastapi.testclient import TestClient

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "web"))

from api import cache_state  # noqa: E402
from api import main as api_main  # noqa: E402
from api.routers import metrics as metrics_router  # noqa: E402


def test_api_main_exposes_metrics_lock():
    # Regression guard: _refresh_metrics_async() reads api_main._metrics_lock,
    # which only exists if main.py imports it from metrics_builder.
    assert hasattr(api_main, "_metrics_lock")


def test_stale_cache_served_even_if_refresh_kickoff_raises(monkeypatch):
    cache_state.metrics = {"ok": True}
    cache_state.metrics_ts = time.monotonic() - api_main._METRICS_TTL - 1

    def boom():
        raise AttributeError("module 'api.main' has no attribute '_metrics_lock'")

    monkeypatch.setattr(metrics_router, "_refresh_metrics_async", boom)
    resp = TestClient(api_main.app).get("/api/metrics")
    assert resp.status_code == 200
    assert resp.json() == {"ok": True}
