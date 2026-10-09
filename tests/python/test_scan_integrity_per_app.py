"""Regression test: the Scan Integrity Check (Performance page) must sample
scans per-app, not from one global most-recent-N across every app combined.

Previously _compute_scan_integrity() took a flat top-`limit` most-recent scan
dirs sorted by name across the whole scans/ directory. An app scanned very
frequently (e.g. an hourly quick scan) would fill the entire window on its
own, so every other app's scans silently never got checked at all — making
the table look like it only covers one application.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]


def _load_main_module():
    # main.py uses package-relative imports (`from . import openai_summary`),
    # so it must be imported as `api.main` with web/ on sys.path — a bare
    # spec_from_file_location() load fails with "no known parent package".
    web_dir = str(REPO_ROOT / "web")
    if web_dir not in sys.path:
        sys.path.insert(0, web_dir)
    import importlib as _importlib
    return _importlib.import_module("api.main")


@pytest.fixture(scope="module")
def main_module():
    try:
        return _load_main_module()
    except Exception as e:  # pragma: no cover - environment-dependent
        pytest.skip(f"web/api/main.py could not be imported in this environment: {e}")


def _make_scan(root: Path, app: str, ts: str, total_files: int) -> Path:
    d = root / "scans" / f"{app}_{ts}"
    d.mkdir(parents=True)
    (d / "scan-metadata.json").write_text(json.dumps({
        "scan_id": d.name,
        "target_name": app,
        "scan_type": "full",
        "scan_timestamp": ts,
        "file_statistics": {"total_files": total_files},
    }))
    return d


def test_chatty_app_does_not_crowd_out_other_apps(tmp_path, main_module):
    # "chatty" scans 10 times; "quiet" scans once. Both must still be
    # represented after integrity checking, instead of "chatty" alone
    # filling the entire limit/window.
    dirs = []
    for i in range(10):
        dirs.append(_make_scan(tmp_path, "chatty", f"2026-10-{i + 1:02d}_12-00-00", 50))
    dirs.append(_make_scan(tmp_path, "quiet", "2026-09-30_12-00-00", 0))  # empty target

    result = main_module._compute_scan_integrity(dirs, limit=40, per_app_limit=8)

    flagged_apps = {f["target"] for f in result["flagged"]}
    assert "quiet" in flagged_apps, "quiet app's empty-target scan must still be checked"
    assert result["summary"]["empty_target"] == 1


def test_per_app_limit_caps_scans_checked_for_one_app(tmp_path, main_module):
    dirs = [
        _make_scan(tmp_path, "chatty", f"2026-10-{i:02d}_12-00-00", 50)
        for i in range(1, 21)  # 20 scans, well above per_app_limit
    ]

    result = main_module._compute_scan_integrity(dirs, limit=40, per_app_limit=8)

    assert result["summary"]["total"] == 8
