"""Score Card: history-aware inputs, evidence records, sign-off and evidence package."""
import json
import subprocess
import sys
import zipfile
import io
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts" / "shell" / "generate-trl-score.py"
sys.path.insert(0, str(REPO / "web"))
from api import scorecard  # noqa: E402


def _finding(tool, vid, sev):
    return {"tool": tool, "vulnerability_id": vid, "package_name": "pkg", "severity": sev.upper()}


def _write_scan(root: Path, name: str, scan_type: str, findings: dict, tools: list):
    d = root / name
    d.mkdir(parents=True)
    body = {"summary": {"tools_analyzed": tools}, "critical_findings": [], "high_findings": [],
            "medium_findings": [], "low_findings": []}
    for sev, items in findings.items():
        body[f"{sev}_findings"] = items
    (d / "security-findings-summary.json").write_text(json.dumps(body))
    (d / "scan-metadata.json").write_text(json.dumps({"scan_id": name, "scan_type": scan_type}))
    return d


def _score(scan_dir: Path) -> dict:
    out = scan_dir / "out.json"
    subprocess.run([sys.executable, str(SCRIPT), "--scan-dir", str(scan_dir), "--output", str(out)],
                   check=True, capture_output=True)
    return json.loads(out.read_text())


@pytest.fixture
def scans(tmp_path):
    root = tmp_path / "scans"
    root.mkdir()
    _write_scan(root, "app_2026-01-01_00-00-00", "full",
                {"high": [_finding("Checkov", "CKV_1", "high"), _finding("Trivy-filesystem", "CVE-1", "high")]},
                ["Checkov", "Trivy-filesystem"])
    newest = _write_scan(root, "app_2026-01-02_00-00-00", "quick",
                         {"high": [_finding("Trivy-filesystem", "CVE-2", "high")]}, ["Trivy-filesystem"])
    return root, newest


def test_quick_scan_keeps_findings_from_tools_it_did_not_run(scans):
    _, newest = scans
    sec = _score(newest)["dimension_scores"]["security"]
    assert sec["details"]["high_cve"] == 1  # Checkov (misconfiguration) is not a vulnerability
    mis = next(e for e in sec["evidence"] if e["id"] == "sec-misconfig")
    assert mis["refs"] == ["Checkov:CKV_1:pkg"] and mis["impact"] == -2  # lighter weight than the 5 pt CVE
    coverage = next(e for e in sec["evidence"] if e["id"] == "sec-coverage")
    assert "checkov ← app_2026-01-01_00-00-00" in coverage["refs"]
    assert "trivy ← app_2026-01-02_00-00-00" in coverage["refs"]
    stale = [e for e in sec["evidence"] if e["id"] == "sec-cve-high"]
    assert stale and stale[0]["sha256"] and stale[0]["refs"] == ["Trivy-filesystem:CVE-2:pkg"]


def test_score_does_not_depend_on_scan_type(scans):
    _, newest = scans
    quick = _score(newest)
    (newest / "scan-metadata.json").write_text(json.dumps({"scan_id": newest.name, "scan_type": "stig"}))
    stig = _score(newest)
    assert quick["weights"] == stig["weights"]
    assert quick["weighted_score"] == stig["weighted_score"]
    assert quick["scoring_version"] == "2.0"


def test_signoff_is_invalidated_by_a_new_score(tmp_path, monkeypatch):
    monkeypatch.setattr(scorecard, "_FILE", tmp_path / "signoffs.json")
    trl = {"scoring_version": "2.0", "trl_level": 5, "weighted_score": 61.2, "weights": {"security": 1},
           "dimension_scores": {"security": {"score": 61.2}}}
    saved = scorecard.save_signoff("app_x", trl, "Ada Reviewer", "ok")
    assert saved["valid"] is True
    changed = {**trl, "weighted_score": 55.0, "dimension_scores": {"security": {"score": 55.0}}}
    assert scorecard.get_signoff("app_x", changed)["valid"] is False
    with pytest.raises(ValueError):
        scorecard.save_signoff("app_x", trl, "x", "")


def test_evidence_zip_confines_paths_and_flags_changed_files(tmp_path):
    root = tmp_path / "scans"
    (root / "app_1").mkdir(parents=True)
    (root / "app_1" / "a.json").write_text("{}")
    (tmp_path / "secret.txt").write_text("nope")
    trl = {"scoring_version": "2.0", "evidence_manifest": [
        {"path": "app_1/a.json", "sha256": "0" * 64},
        {"path": "../secret.txt", "sha256": "0" * 64}]}
    data = scorecard.build_evidence_zip(root, "app_1", trl, None)
    zf = zipfile.ZipFile(io.BytesIO(data))
    names = zf.namelist()
    assert "artifacts/app_1/a.json" in names and not any("secret" in n for n in names)
    statuses = {a["path"]: a["status"] for a in json.loads(zf.read("manifest.json"))["artifacts"]}
    assert statuses["app_1/a.json"] == "changed since scoring"
    assert statuses["../secret.txt"].startswith("rejected")


def _has_null(x):
    if x is None:
        return True
    if isinstance(x, dict):
        return any(_has_null(v) for v in x.values())
    if isinstance(x, list):
        return any(_has_null(v) for v in x)
    return False


def test_unscanned_data_lowers_score_and_nothing_is_null(scans):
    _, newest = scans
    out = _score(newest)
    assert not _has_null(out), [k for k, v in out.items() if _has_null(v)]
    dims = out["dimension_scores"]
    assert dims["supply_chain"]["applicable"] is False
    assert dims["supply_chain"]["score"] == 0
    assert abs(sum(out["weights"].values()) - 1.0) < 0.01  # weights are never rescaled
    assert out["weights"]["supply_chain"] > 0


def test_suppressed_findings_are_not_scored(scans):
    _, newest = scans
    crit = _finding("Anchore", "GHSA-x", "critical")
    summary = json.loads((newest / "security-findings-summary.json").read_text())
    summary["critical_findings"] = [crit]
    (newest / "security-findings-summary.json").write_text(json.dumps(summary))
    filtered = dict(summary, critical_findings=[])  # .epyon-ignore.yml suppressed it
    (newest / "security-findings-filtered.json").write_text(json.dumps(filtered))
    out = _score(newest)
    sec = out["dimension_scores"]["security"]
    assert sec["details"]["critical_cve"] == 0
    assert not any("critical CVE" in b for b in out["blockers"])
    sup = next(e for e in sec["evidence"] if e["id"] == "sec-suppressed")
    assert sup["refs"] == ["[suppressed] Anchore:GHSA-x:pkg"] and sup["impact"] == 0
    assert sup["measured"]["critical"] == 1 and sec["details"]["suppressed_findings"] == 1
