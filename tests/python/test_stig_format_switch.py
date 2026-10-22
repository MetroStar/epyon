"""EPYON_STIG_FORMAT rollout switch and migration of locked controls (MID-4537)."""
from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SHELL = REPO_ROOT / "scripts" / "shell"


def _load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, SHELL / filename)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


assess = _load("epyon_run_stig_assessment_t5", "run-stig-assessment.py")

CONTROL = {
    "number": 1, "vuln_id": "APSC-DV-000160", "group_id": "V-222425", "rule_id": "SV-1r1", "severity": "high",
    "title": "Enforce authorizations", "check_content": "Verify access control.", "fix_text": "Fix it.",
}


def _scan(tmp_path: Path):
    stig = {"stig_name": "ASD STIG", "release_info": "V6R4", "controls": [CONTROL], "total_controls": 1}
    assess._assess_stig(
        stig_data=stig, stig_path="x.xml", source_files=[], manual_docs=[], scan_dir=tmp_path,
        app_name="myapp", model="gpt-4o", batch_size=5, delay=0, api_key="", base_url="",
        scan_date="2026-10-22", slug="asd", is_primary=True, target_dir=str(tmp_path),
    )


def test_default_and_unknown_values_are_legacy(monkeypatch):
    monkeypatch.delenv("EPYON_STIG_FORMAT", raising=False)
    assert assess.stig_format() == "legacy"
    monkeypatch.setenv("EPYON_STIG_FORMAT", "bogus")
    assert assess.stig_format() == "legacy"
    monkeypatch.setenv("EPYON_STIG_FORMAT", " ETK ")
    assert assess.stig_format() == "etk"


def test_legacy_writes_no_etk_artifacts(tmp_path, monkeypatch):
    monkeypatch.setenv("EPYON_STIG_FORMAT", "legacy")
    _scan(tmp_path)
    assert (tmp_path / "findings-myapp.md").exists() and (tmp_path / "stig-results-asd.json").exists()
    assert not (tmp_path / "stig-reviews-asd").exists()
    assert "vuln_map" not in json.loads((tmp_path / "stig-controls-asd.json").read_text())


def test_etk_writes_records(tmp_path, monkeypatch):
    monkeypatch.setenv("EPYON_STIG_FORMAT", "etk")
    _scan(tmp_path)
    assert (tmp_path / "stig-reviews-asd" / "v-222425.md").exists()


def test_legacy_prompt_is_the_original_four_field_prompt(monkeypatch):
    monkeypatch.setenv("EPYON_STIG_FORMAT", "legacy")
    prompt = assess.system_prompt()
    assert "these four fields" in prompt
    assert "changes_that_may_affect" not in prompt and "automation_recommendation" not in prompt
    assert "Return ONLY the JSON array." in prompt
    monkeypatch.setenv("EPYON_STIG_FORMAT", "etk")
    assert assess.system_prompt() == assess.SYSTEM_PROMPT


def test_locked_and_frozen_controls_survive_first_etk_scan(tmp_path, monkeypatch):
    """State written by the legacy engine (no record fields) keeps every human override."""
    monkeypatch.setenv("EPYON_STIG_FORMAT", "etk")
    legacy_state = {
        "assessments": {
            "APSC-DV-000001": {"status": "Not a Finding", "evidence": "Human: reviewed X.",
                               "confidence": 95, "locked_by_human": True},
            "APSC-DV-000002": {"status": "Open", "evidence": "Human: gap known.",
                               "confidence": 30, "locked_by_human": True},
            "APSC-DV-000003": {"status": "Not Applicable", "evidence": "No DB in repo.", "confidence": 88},
            "APSC-DV-000004": {"status": "Open", "evidence": "AI guess", "confidence": 40},
        },
        "token_usage": {},
    }
    prev_dir = tmp_path / "prev"
    prev_dir.mkdir()
    (prev_dir / "stig-results-asd.json").write_text(json.dumps(legacy_state))
    loaded = assess.load_previous_stig_results(prev_dir, "asd")
    for vid in ("APSC-DV-000001", "APSC-DV-000002", "APSC-DV-000003"):
        frozen = assess.compute_frozen_assessment(loaded[vid])
        assert frozen is not None
        for key in ("status", "evidence", "confidence"):
            assert frozen[key] == legacy_state["assessments"][vid][key], (vid, key)
    assert assess.compute_frozen_assessment(loaded["APSC-DV-000001"])["locked_by_human"] is True
    assert assess.compute_frozen_assessment(loaded["APSC-DV-000004"]) is None


def test_legacy_pr_script_dispatch(tmp_path):
    env = {k: v for k, v in os.environ.items() if k not in ("GITHUB_TOKEN", "GH_PAT")}
    env["EPYON_STIG_FORMAT"] = "legacy"
    out = subprocess.run(
        ["bash", str(SHELL / "create-stig-pr.sh"), "--target", str(tmp_path), "--scan-dir", str(tmp_path),
         "--app-name", "x"],
        capture_output=True, text=True, env=env,
    )
    assert "stig-reviews-*" not in out.stdout + out.stderr
    assert (SHELL / "create-stig-pr-legacy.sh").exists()


def test_compare_script_reports_counts_and_differences(tmp_path):
    cmp = _load("epyon_compare_stig_formats", "compare-stig-formats.py")
    legacy, etk = tmp_path / "l", tmp_path / "e"
    for d, status, ev in ((legacy, "Not a Finding", "ok"), (etk, "Open", "File: a.py:3 `x`")):
        d.mkdir()
        (d / "stig-results-asd.json").write_text(json.dumps(
            {"assessments": {"APSC-DV-000001": {"status": status, "evidence": ev, "confidence": 80}}}))
    out = cmp.render("demo", legacy, etk)
    assert "| Open | 0 | 1 |" in out and "| Evidence with a File: citation | 0 | 1 |" in out
    assert "asd:APSC-DV-000001: Not a Finding -> Open" in out
