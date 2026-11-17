"""Application scan-history endpoint: cached loads, trimmed payload, gzip."""
from __future__ import annotations

import sys
from pathlib import Path

from fastapi.testclient import TestClient

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "web"))

from api import main as api_main  # noqa: E402
from api.routers import applications  # noqa: E402


def test_history_summary_drops_heavy_blocks_only():
    scan = {"scan_id": "a_1", "critical": 1, "tools_analyzed": ["grype"],
            "suppressed_findings": [{"id": "x"}] * 50, "build_evidence": {"k": 1}}
    out = applications._history_summary(scan)
    assert out == {"scan_id": "a_1", "critical": 1, "tools_analyzed": ["grype"]}
    assert "suppressed_findings" in scan  # cached scan is not mutated


def test_endpoint_uses_cached_loader_and_trims(monkeypatch, tmp_path):
    dirs = [tmp_path / "app-a_2026-11-16_10-00-00", tmp_path / "app-b_2026-11-16_11-00-00"]
    loaded = []

    def fake_load(d):
        loaded.append(d.name)
        return {"scan_id": d.name, "timestamp": d.name[-19:], "suppressed_findings": [{"id": 1}] * 500}

    monkeypatch.setattr(api_main, "_cached_find_scan_dirs", lambda *a, **k: dirs)
    monkeypatch.setattr(api_main, "_cached_load_scan", fake_load)
    resp = TestClient(api_main.app).get("/api/applications/app-a/scans", headers={"Accept-Encoding": "gzip"})
    assert resp.status_code == 200
    assert loaded == ["app-a_2026-11-16_10-00-00"]
    assert resp.json() == [{"scan_id": "app-a_2026-11-16_10-00-00", "timestamp": "2026-11-16_10-00-00"}]


def test_large_responses_are_gzipped():
    resp = TestClient(api_main.app).get("/static/app.js", headers={"Accept-Encoding": "gzip"})
    assert resp.status_code == 200
    assert resp.headers.get("content-encoding") == "gzip"
