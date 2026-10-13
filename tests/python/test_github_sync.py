"""GitHub Actions artifact sync — run-level caching.

run_github_sync() polls each configured repo's completed workflow runs on a
15-minute background loop. Listing a completed run's artifacts
("/actions/runs/{id}/artifacts") is a separate API call per run and the
dominant cost of a sync cycle; a completed run's artifact set never changes,
so a run already listed in a previous cycle must not be listed again.
"""
from __future__ import annotations

import asyncio
import importlib.util
import json
import sys
from pathlib import Path

import httpx
import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]


def _load_github_sync():
    """Load web/api/github_sync.py as the `api.github_sync` submodule so its
    `from . import github_config` relative import resolves correctly."""
    web_dir = REPO_ROOT / "web"
    if str(web_dir) not in sys.path:
        sys.path.insert(0, str(web_dir))
    import api  # noqa: F401  (ensures `api` package is registered first)
    spec = importlib.util.spec_from_file_location(
        "api.github_sync", web_dir / "api" / "github_sync.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules["api.github_sync"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def github_sync():
    return _load_github_sync()


def _runs_payload(run_ids: list[int]) -> dict:
    return {
        "workflow_runs": [
            {
                "id": rid,
                "name": "Epyon Security Scan",
                "event": "push",
                "head_branch": "main",
                "head_sha": "a" * 40,
                "created_at": "2026-01-01T00:00:00Z",
            }
            for rid in run_ids
        ]
    }


def _make_transport(run_ids: list[int], call_log: list[str]):
    """A MockTransport that serves the runs list and an empty artifacts list
    for any run, recording every request path for assertions."""

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        call_log.append(path)
        if path.endswith("/actions/runs"):
            return httpx.Response(200, json=_runs_payload(run_ids))
        if "/artifacts" in path:
            return httpx.Response(200, json={"artifacts": []})
        return httpx.Response(404, json={})

    return httpx.MockTransport(handler)


def test_already_synced_runs_are_not_relisted(github_sync, tmp_path, monkeypatch):
    config_path = tmp_path / "github-config.json"
    config_path.write_text(json.dumps({"repos": ["acme/widgets"]}))
    monkeypatch.setenv("GITHUB_TOKEN", "test-token")

    call_log: list[str] = []
    run_ids = [101, 102, 103]

    def fake_client(token):
        transport = _make_transport(run_ids, call_log)
        return httpx.AsyncClient(transport=transport, base_url="https://api.github.com")

    monkeypatch.setattr(github_sync, "_client", fake_client)

    # First sync: all 3 runs are new, so each must be listed for artifacts
    # (1 runs-list call + 3 artifacts-list calls = 4 total requests).
    asyncio.run(github_sync.run_github_sync(config_path, tmp_path, lambda _root: []))
    assert sum(1 for p in call_log if "/artifacts" in p) == 3

    # Second sync (e.g. the next 15-minute cycle): the same 3 runs are still
    # the most recent completed runs. None of them should be re-listed for
    # artifacts - only the cheap runs-list call should happen.
    call_log.clear()
    asyncio.run(github_sync.run_github_sync(config_path, tmp_path, lambda _root: []))
    assert sum(1 for p in call_log if "/artifacts" in p) == 0
    assert any(p.endswith("/actions/runs") for p in call_log)


def test_a_new_run_is_listed_while_previously_synced_runs_are_skipped(
    github_sync, tmp_path, monkeypatch
):
    config_path = tmp_path / "github-config.json"
    config_path.write_text(json.dumps({"repos": ["acme/widgets"]}))
    monkeypatch.setenv("GITHUB_TOKEN", "test-token")

    call_log: list[str] = []
    run_ids = [101, 102]

    def fake_client(token):
        return httpx.AsyncClient(
            transport=_make_transport(run_ids, call_log), base_url="https://api.github.com"
        )

    monkeypatch.setattr(github_sync, "_client", fake_client)
    asyncio.run(github_sync.run_github_sync(config_path, tmp_path, lambda _root: []))

    # A new run (103) appears on the next poll alongside the two known ones.
    call_log.clear()
    run_ids.append(103)
    asyncio.run(github_sync.run_github_sync(config_path, tmp_path, lambda _root: []))
    assert sum(1 for p in call_log if "/artifacts" in p) == 1
