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


def test_scan_data_gets_etag_and_304(monkeypatch):
    monkeypatch.setattr(api_main, "_cached_find_scan_dirs", lambda *a, **k: [])
    client = TestClient(api_main.app)
    first = client.get("/api/applications/app-a/scans")
    assert first.status_code == 200
    assert first.headers["cache-control"] == "private, no-cache"
    etag = first.headers["etag"]
    again = client.get("/api/applications/app-a/scans", headers={"If-None-Match": etag})
    assert again.status_code == 304 and again.content == b""
    stale = client.get("/api/applications/app-a/scans", headers={"If-None-Match": 'W/"other"'})
    assert stale.status_code == 200


def test_config_and_job_endpoints_stay_no_store():
    client = TestClient(api_main.app)
    for path in ("/api/jira/config", "/api/jobs"):
        resp = client.get(path)
        assert "no-store" in resp.headers.get("cache-control", ""), path
        assert "etag" not in resp.headers


def test_invalidation_is_narrow_for_completion_and_visibility():
    api_main._scan_cache.update({"a": ({}, 0.0), "b": ({}, 0.0)})
    api_main._dir_cache[35] = ([], 0.0)
    api_main._invalidate_scan_cache(reason="scan_completion", scan_id="a")
    assert "a" not in api_main._scan_cache and "b" in api_main._scan_cache and not api_main._dir_cache
    api_main._dir_cache[35] = ([], 0.0)
    api_main._invalidate_scan_cache(reason="hidden_apps_changed", scan_id="x")
    assert "b" in api_main._scan_cache and 35 in api_main._dir_cache
    api_main._invalidate_scan_cache(reason="delete_scan", scan_id="b")
    assert not api_main._scan_cache and not api_main._dir_cache


def test_scan_integrity_verdicts_are_memoized_per_scan(tmp_path, monkeypatch):
    scan = tmp_path / "app_2026-11-17_00-00-00"
    scan.mkdir()
    loads = []
    monkeypatch.setattr(api_main, "_cached_load_scan", lambda d: loads.append(d) or {
        "scan_id": d.name, "target": "app", "scan_type": "full", "file_statistics": {"total_files": 0}})
    api_main._integrity_cache.clear()
    first = api_main._compute_scan_integrity([scan])
    api_main._scan_cache.clear()
    second = api_main._compute_scan_integrity([scan])
    assert first == second and first["summary"]["empty_target"] == 1 and len(loads) == 1
    api_main._invalidate_scan_cache(reason="scan_completion", scan_id=scan.name)
    api_main._compute_scan_integrity([scan])
    assert len(loads) == 2
