"""Human edits to STIG controls: the Epyon-side store, the override endpoint and verification outcome."""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "web"))
from api import main as api_main  # noqa: E402

_spec = importlib.util.spec_from_file_location("stig_edits_under_test", ROOT / "scripts" / "shell" / "stig_edits.py")
edits = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(edits)

SLUG = "u-asd-stig-v6r5-manual-xccdf"
CTRL = [{"vuln_id": "APSC-DV-000070"}]


@pytest.fixture(autouse=True)
def store(tmp_path, monkeypatch):
    monkeypatch.setenv("EPYON_STIG_EDITS_DIR", str(tmp_path / "edits"))
    return tmp_path / "edits"


def test_edit_keeps_status_evidence_and_justification_separate(store):
    edits.save_edit("midas-ui", SLUG, "APSC-DV-000070", "Not a Finding", "see config.ts", "", "ana")
    saved = edits.load("midas-ui")[SLUG]["APSC-DV-000070"]
    assert saved["evidence"] == "see config.ts" and saved["justification"] == "" and saved["edited_by"] == "ana"
    assert not any(p.name.endswith(".tmp") for p in store.iterdir())


def test_scan_gets_edit_as_prior_to_verify_and_other_release_is_reopened():
    edits.save_edit("midas-ui", SLUG, "APSC-DV-000070", "Not a Finding", "e", "j", "ana")
    prior, reasons = edits.edits_for_scan("midas-ui", SLUG, CTRL)
    assert prior["APSC-DV-000070"]["confidence"] == 0  # not frozen, so it is verified
    assert "e" in prior["APSC-DV-000070"]["human_review"]["entry"] and not reasons
    prior, reasons = edits.edits_for_scan("midas-ui", "u-asd-stig-v6r6-manual-xccdf", CTRL)
    assert prior == {} and "release changed" in reasons["APSC-DV-000070"]


def test_outcome_confirms_without_overwriting_and_flags_contradiction():
    edits.save_edit("midas-ui", SLUG, "APSC-DV-000070", "Not a Finding", "my text", "why", "ana")
    prior, _ = edits.edits_for_scan("midas-ui", SLUG, CTRL)
    p = prior["APSC-DV-000070"]
    ok = edits.apply_outcome(p, {"status": "Not a Finding", "evidence": "config.ts:12 sets it", "confidence": 90})
    assert ok["evidence"] == "my text" and ok["justification"] == "why" and ok["locked_by_human"]
    bad = edits.apply_outcome(p, {"status": "Open", "evidence": "value removed", "confidence": 80})
    assert bad["status"] == "Open" and bad["evidence"] == "value removed"
    assert bad["human_edit"]["evidence"] == "my text" and "could not be confirmed" in bad["verification_note"]


def test_override_endpoint_writes_store_and_stops_prepending(tmp_path, monkeypatch):
    scan = "midas-ui_2026-11-20_10-00-00"
    d = tmp_path / "scans" / scan
    d.mkdir(parents=True)
    (d / f"stig-results-{SLUG}.json").write_text(json.dumps({"assessments": {"APSC-DV-000070": {"status": "Open", "evidence": "old"}}}))
    monkeypatch.setattr(api_main, "EPYON_ROOT", tmp_path)
    from api import parsers
    monkeypatch.setattr(parsers, "find_scan_dirs", lambda *a, **k: [d])
    # the endpoint loads stig_edits.py relative to EPYON_ROOT
    (tmp_path / "scripts" / "shell").mkdir(parents=True)
    (tmp_path / "scripts" / "shell" / "stig_edits.py").write_text((ROOT / "scripts" / "shell" / "stig_edits.py").read_text())
    c = TestClient(api_main.app)
    r = c.patch(f"/api/scans/{scan}/stig-override", json={
        "slug": SLUG, "vuln_id": "APSC-DV-000070", "status": "Not a Finding", "evidence": "mine", "justification": ""})
    assert r.status_code == 200, r.text
    stored = json.loads((d / f"stig-results-{SLUG}.json").read_text())["assessments"]["APSC-DV-000070"]
    assert stored["evidence"] == "mine" and stored["justification"] == "" and stored["locked_by_human"]
    assert edits.load("midas-ui")[SLUG]["APSC-DV-000070"]["evidence"] == "mine"
    c.patch(f"/api/scans/{scan}/stig-override", json={
        "slug": SLUG, "vuln_id": "APSC-DV-000070", "status": "Open", "clear_lock": True})
    assert edits.load("midas-ui") == {}


def _engine_run(tmp_path, slug):
    spec = importlib.util.spec_from_file_location("epyon_run_stig_assessment_edits", ROOT / "scripts" / "shell" / "run-stig-assessment.py")
    assess = importlib.util.module_from_spec(spec)
    sys.modules["epyon_run_stig_assessment_edits"] = assess
    spec.loader.exec_module(assess)
    ctrl = {"number": 1, "vuln_id": "APSC-DV-000070", "group_id": "V-1", "rule_id": "SV-1r1", "severity": "high",
            "title": "t", "check_content": "c", "fix_text": "f"}
    scan = tmp_path / "scan"
    scan.mkdir()
    assess._assess_stig(
        stig_data={"stig_name": "ASD", "release_info": "V6R5", "controls": [ctrl], "source_format": "xccdf", "total_controls": 1},
        stig_path="x.xml", source_files=[], manual_docs=[], scan_dir=scan, app_name="midas-ui", model="m",
        batch_size=5, delay=0, api_key="", base_url="", scan_date="2026-11-23", slug=slug, is_primary=True,
        target_dir=str(tmp_path),
    )
    return json.loads((scan / f"stig-results-{slug}.json").read_text())["assessments"]["APSC-DV-000070"]


def test_scan_applies_stored_edit_and_reopens_for_new_release(tmp_path):
    edits.save_edit("midas-ui", SLUG, "APSC-DV-000070", "Not a Finding", "mine", "", "ana")
    a = _engine_run(tmp_path, SLUG)
    assert a["status"] == "Not a Finding" and a["evidence"] == "mine" and a["locked_by_human"]
    assert "Not verified" in a["verification_note"]
    b = _engine_run(tmp_path / "second", "u-asd-stig-v6r6-manual-xccdf") if (tmp_path / "second").mkdir() is None else None
    assert b["status"] != "Not a Finding" and "release changed" in b["reopened_reason"]
