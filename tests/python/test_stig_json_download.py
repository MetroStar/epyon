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


def test_poam_csv_has_open_stigs_and_critical_high_cves(tmp_path, monkeypatch):
    import csv
    import io

    from web.api import main as api_main, poam

    monkeypatch.setattr(poam, "_CONFIG_FILE", tmp_path / "poam-config.json")
    scan = _scan_dir(tmp_path)
    findings = {
        "critical_findings": [{"tool": "Grype", "vulnerability_id": "CVE-1", "package_name": "lib",
                               "package_version": "1.0", "fix_versions": ["1.1"], "description": "=cmd()"}],
        "high_findings": [{"tool": "Trivy", "vulnerability_id": "CVE-2", "suppressed": True}],
        "medium_findings": [{"tool": "Trivy", "vulnerability_id": "CVE-3"}],
    }
    monkeypatch.setattr(api_main.parsers, "find_scan_dirs", lambda root, days=35: [scan])
    monkeypatch.setattr(api_main.parsers, "load_scan_complete", lambda d, r: {"findings": findings})

    response = TestClient(api_main.app).get(f"/api/scans/{scan.name}/poam")

    assert response.status_code == 200
    rows = list(csv.DictReader(io.StringIO(response.text)))
    ids = [r["Weakness Identifier"] for r in rows]
    assert ids == ["CVE-1", "V-2 / SV-2"]  # Open STIG only; suppressed and medium CVEs excluded
    assert rows[0]["Scheduled Completion Date"] == "2026-11-20"  # critical = 7 days
    assert rows[0]["Weakness Description"].startswith("'=")  # formula neutralised
    assert rows[0]["Remediation / Mitigation"] == "Upgrade to 1.1"

    preview = TestClient(api_main.app).get(f"/api/scans/{scan.name}/poam?preview=true").json()
    assert preview["total"] == 2
    assert preview["by_source"] == {"CVE": 1, "STIG": 1}
    assert preview["rows"][0]["POA&M ID"] == "POAM-0001"


def test_poam_sla_config_and_manual_due_date(tmp_path, monkeypatch):
    from web.api import main as api_main, poam

    scan = _scan_dir(tmp_path)
    monkeypatch.setattr(poam, "_CONFIG_FILE", tmp_path / "poam-config.json")
    monkeypatch.setattr(api_main.parsers, "find_scan_dirs", lambda root, days=35: [scan])
    monkeypatch.setattr(api_main.parsers, "load_scan_complete", lambda d, r: {"findings": {}})
    client = TestClient(api_main.app)
    url = f"/api/scans/{scan.name}/poam?preview=true"

    assert client.put("/api/poam/config", json={"sla_days": {"low": 10}}).status_code == 200
    assert client.put("/api/poam/config", json={"sla_days": {"low": 0}}).status_code == 400
    assert client.put("/api/poam/config", json={"sla_days": {"bogus": 5}}).status_code == 400
    row = client.get(url).json()["rows"][0]
    assert row["Scheduled Completion Date"] == "2026-11-23"  # low = 10 days from 2026-11-13
    assert row["Due Date Basis"] == "SLA (10d)"

    put = lambda d: client.put(f"/api/scans/{scan.name}/poam/due-date", json={"key": "stig:V-2", "due_date": d})
    assert put("2027-01-31").status_code == 200
    assert put("31/01/2027").status_code == 400
    row = client.get(url).json()["rows"][0]
    assert (row["Scheduled Completion Date"], row["Due Date Basis"]) == ("2027-01-31", "Manual")

    # override is keyed by app, so a later scan of the same app keeps it
    later = tmp_path / "myapp_2026-12-01_10-00-00"
    assert poam.get_overrides(later.name) == {"stig:V-2": "2027-01-31"}

    assert put(None).status_code == 200
    assert client.get(url).json()["rows"][0]["Due Date Basis"] == "SLA (10d)"


def test_poam_app_rollup_combines_latest_stig_and_vuln_scans(tmp_path, monkeypatch):
    from web.api import main as api_main, poam

    stig_scan = _scan_dir(tmp_path)  # myapp_2026-11-13_10-00-00 with one Open STIG
    vuln_scan = tmp_path / "myapp_2026-11-14_10-00-00"
    vuln_scan.mkdir()
    meta = {
        stig_scan.name: {"target": "myapp", "scan_id": stig_scan.name, "timestamp": "2026-11-13", "stig_total": 2, "scan_type": "stig"},
        vuln_scan.name: {"target": "myapp", "scan_id": vuln_scan.name, "timestamp": "2026-11-14", "stig_total": 0, "scan_type": "full"},
    }
    findings = {"critical_findings": [{"tool": "Grype", "vulnerability_id": "CVE-9", "package_name": "p"}]}
    dirs = [stig_scan, vuln_scan]
    monkeypatch.setattr(poam, "_CONFIG_FILE", tmp_path / "poam-config.json")
    monkeypatch.setattr(api_main, "_cached_find_scan_dirs", lambda days=35: dirs)
    monkeypatch.setattr(api_main, "_cached_load_scan", lambda d: meta[d.name])
    monkeypatch.setattr(api_main.parsers, "find_scan_dirs", lambda root, days=35: dirs)
    monkeypatch.setattr(api_main.parsers, "load_scan_complete", lambda d, r: {"findings": findings})
    monkeypatch.setattr(api_main, "_load_hidden_apps", lambda: set())
    client = TestClient(api_main.app)

    rows = client.get("/api/applications/myapp/poam?preview=true").json()["rows"]
    assert [r["Weakness Identifier"] for r in rows] == ["CVE-9", "V-2 / SV-2"]
    assert rows[0]["Scheduled Completion Date"] == "2026-11-21"  # CVE dated from the 14th: +7d

    client.put("/api/applications/myapp/poam/due-date", json={"key": "stig:V-2", "due_date": "2020-01-01"})
    summary = client.get("/api/poam/summary").json()
    app = summary["apps"][0]
    assert (app["name"], app["total"], app["stig"], app["cve"]) == ("myapp", 2, 1, 1)
    assert app["overdue"] == 1 and app["manual_dates"] == 1
    assert summary["totals"]["by_severity"]["Critical"] == 1
    assert client.get("/api/applications/nope/poam").status_code == 404
