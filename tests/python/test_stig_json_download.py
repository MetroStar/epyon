"""STIG findings JSON download endpoint."""
from __future__ import annotations

import json

from fastapi.testclient import TestClient


def _scan_dir(tmp_path):
    scan = tmp_path / "myapp_2026-11-13_10-00-00"
    scan.mkdir()
    (scan / "stig-controls-asd.json").write_text(json.dumps({
        "stig_name": "ASD",
        "release_info": "v6r4",
        "controls": [
            {"vuln_id": "V-1", "rule_id": "SV-1", "severity": "high", "title": "t1"},
            {"vuln_id": "V-2", "rule_id": "SV-2", "severity": "low", "title": "t2"},
        ],
    }))
    (scan / "stig-results-asd.json").write_text(json.dumps({"assessments": {
        "V-1": {"status": "Not a Finding", "evidence": "e", "confidence": 90},
        "V-2": {"status": "Open", "evidence": "x", "confidence": 50},
    }}))
    return scan


def test_stig_json_download_is_structured(tmp_path, monkeypatch):
    from web.api import main as api_main

    scan = _scan_dir(tmp_path)
    monkeypatch.setattr(api_main.parsers, "find_scan_dirs", lambda root, days=35: [scan])
    client = TestClient(api_main.app)

    response = client.get(f"/api/scans/{scan.name}/stig-findings-json")

    assert response.status_code == 200
    assert "attachment" in response.headers["content-disposition"]
    body = response.json()
    assert body["application"] == "myapp"
    stig = body["stigs"][0]
    assert stig["summary"] == {"Not a Finding": 1, "Open": 1}
    assert [c["vuln_id"] for c in stig["controls"]] == ["V-1", "V-2"]
    assert stig["controls"][0]["status"] == "Not a Finding"


def test_stig_json_download_filters_and_validates_slug(tmp_path, monkeypatch):
    from web.api import main as api_main

    scan = _scan_dir(tmp_path)
    monkeypatch.setattr(api_main.parsers, "find_scan_dirs", lambda root, days=35: [scan])
    client = TestClient(api_main.app)

    assert client.get(f"/api/scans/{scan.name}/stig-findings-json?slug=asd").status_code == 200
    assert client.get(f"/api/scans/{scan.name}/stig-findings-json?slug=nope").status_code == 404
    assert client.get(f"/api/scans/{scan.name}/stig-findings-json?slug=../x").status_code == 400
