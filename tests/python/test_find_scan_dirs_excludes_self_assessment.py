"""Regression test: find_scan_dirs() must exclude self-assessment's transient
scan directories.

scripts/shell/run-self-assessment.sh runs a real full scan into
scans/self-assessment_<user>_<timestamp>/ to validate scanner layers against
a synthetic fixture, then deletes that directory once it's done comparing
results (unless invoked with --keep-scan). If that directory were surfaced
by find_scan_dirs() — and therefore in the Scan Integrity Check, Applications,
or Scans listings — a user could click into it while it's running or in the
post-completion cache window and hit a 404 "Scan not found" once the harness
deletes it. It must never be listed.
"""
from __future__ import annotations

from pathlib import Path


def _make_scan_dir(root: Path, name: str) -> Path:
    d = root / "scans" / name
    d.mkdir(parents=True)
    return d


def test_self_assessment_scan_dirs_are_excluded(tmp_path, parsers):
    epyon_root = tmp_path
    _make_scan_dir(epyon_root, "self-assessment_testuser_2026-09-28_12-00-00")
    real_scan = _make_scan_dir(epyon_root, "goldenapp_testuser_2026-09-28_12-00-00")

    dirs = parsers.find_scan_dirs(epyon_root, days=0)

    names = [d.name for d in dirs]
    assert "self-assessment_testuser_2026-09-28_12-00-00" not in names
    assert real_scan.name in names


def test_non_self_assessment_scans_still_listed(tmp_path, parsers):
    epyon_root = tmp_path
    # A real app that merely contains "self-assessment" as a substring
    # (not the exact reserved prefix) must still be listed.
    other = _make_scan_dir(epyon_root, "my-self-assessment-tool_testuser_2026-09-28_12-00-00")

    dirs = parsers.find_scan_dirs(epyon_root, days=0)

    assert other.name in [d.name for d in dirs]
