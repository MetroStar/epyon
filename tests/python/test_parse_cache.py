"""Tests for the persistent per-scan parse cache."""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "web"))

from api import parse_cache  # noqa: E402


def _old_dir(tmp_path: Path, name: str = "app_2026-01-01_00-00-00") -> Path:
    d = tmp_path / name
    d.mkdir()
    old = time.time() - 3600
    os.utime(d, (old, old))
    return d


def _reset(path: Path) -> None:
    parse_cache.invalidate()
    parse_cache.configure(path)


def test_computes_once_and_survives_reload(tmp_path):
    cache_file = tmp_path / "cache" / "p.json"
    _reset(cache_file)
    scan = _old_dir(tmp_path)
    calls = []

    def compute():
        calls.append(1)
        return {"n": 1}

    assert parse_cache.get("k", scan, compute) == {"n": 1}
    assert parse_cache.get("k", scan, compute) == {"n": 1}
    assert len(calls) == 1

    parse_cache.flush()
    parse_cache.invalidate()
    parse_cache._dirty = False
    parse_cache.configure(cache_file)
    assert parse_cache.get("k", scan, compute) == {"n": 1}
    assert len(calls) == 1


def test_changed_mtime_recomputes(tmp_path):
    _reset(tmp_path / "p.json")
    scan = _old_dir(tmp_path)
    calls = []
    parse_cache.get("k", scan, lambda: calls.append(1) or 1)
    newer = time.time() - 1800
    os.utime(scan, (newer, newer))
    parse_cache.get("k", scan, lambda: calls.append(1) or 2)
    assert len(calls) == 2


def test_recent_scan_is_not_cached(tmp_path):
    _reset(tmp_path / "p.json")
    scan = tmp_path / "app_2026-01-02_00-00-00"
    scan.mkdir()
    calls = []
    parse_cache.get("k", scan, lambda: calls.append(1) or 1)
    parse_cache.get("k", scan, lambda: calls.append(1) or 1)
    assert len(calls) == 2
