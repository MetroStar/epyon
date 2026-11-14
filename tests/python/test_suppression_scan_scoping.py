"""A scan's suppressions come only from that scan, never from Epyon's own files."""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


def _user_only(rules):
    """Rules written by the repo, without Epyon's built-in default test-path rules."""
    return [r for r in rules if not r.get("default") and r.get("approved_by") != "epyon-default"]


def _user_rules(parsers, scan):
    return _user_only(parsers.parse_suppressed_findings(scan))


def _make_scan(root: Path) -> Path:
    scan = root / "scans" / "app_user_2026-01-01_00-00-00"
    scan.mkdir(parents=True)
    return scan


def test_parent_ignore_file_is_not_read(tmp_path, parsers):
    scan = _make_scan(tmp_path)
    (tmp_path / ".epyon-ignore.yml").write_text(
        'ignores:\n  - type: path\n    value: "scans/**"\n    reason: epyon self-scan\n'
    )
    assert _user_rules(parsers, scan) == []


def test_shared_tmp_cache_is_not_read(tmp_path, monkeypatch, parsers):
    scan = _make_scan(tmp_path)
    cache = tmp_path / "stale-cache.json"
    cache.write_text(json.dumps({"ignores": [{"type": "tool", "value": "grype", "reason": "x"}]}))
    monkeypatch.setenv("IGNORE_CACHE", str(cache))
    assert _user_rules(parsers, scan) == []


def test_scan_snapshot_is_read(tmp_path, parsers):
    scan = _make_scan(tmp_path)
    (scan / "ignore-rules.json").write_text(
        json.dumps({"ignores": [{"type": "tool", "value": "grype", "reason": "x"}]})
    )
    assert [r["value"] for r in _user_rules(parsers, scan)] == ["grype"]


def test_parse_script_snapshots_rules_into_scan_dir(tmp_path):
    scan = _make_scan(tmp_path)
    ignore = tmp_path / ".epyon-ignore.yml"
    ignore.write_text(
        'ignores:\n  - type: cve\n    value: CVE-2024-1\n    reason: r\n    approved_by: me\n'
    )
    cache = tmp_path / "cache.json"
    subprocess.run(
        ["bash", "-c", f'source "{REPO}/scripts/shell/parse-epyon-ignore.sh"; parse_ignore_rules "{ignore}"'],
        env={"PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin", "SCAN_DIR": str(scan), "IGNORE_CACHE": str(cache)},
        check=True,
        capture_output=True,
    )
    assert json.loads((scan / "ignore-rules.json").read_text())["ignores"][0]["value"] == "CVE-2024-1"
