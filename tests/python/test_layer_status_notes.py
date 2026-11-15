import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "web"))
from api.parsers import parse_scan_environment_notes  # noqa: E402


def _status(scan_dir, tool, status, reason=""):
    d = scan_dir / tool
    d.mkdir()
    (d / "status.json").write_text(json.dumps({"tool": tool, "status": status, "reason": reason}))


def test_failed_and_skipped_layers_are_surfaced(tmp_path):
    _status(tmp_path, "xeol", "failed", "Xeol EOL database unavailable")
    _status(tmp_path, "npm-audit", "skipped", "npm not installed")
    _status(tmp_path, "semgrep", "success")
    notes = parse_scan_environment_notes(tmp_path)
    assert {n["layer"] for n in notes} == {"xeol", "npm-audit"}
    assert any("database unavailable" in n["message"] for n in notes)


def test_picklescan_threat_detection_is_not_reported_as_a_layer_gap(tmp_path):
    _status(tmp_path, "picklescan", "failed", "2 malicious file(s) detected")
    assert parse_scan_environment_notes(tmp_path) == []
