"""ETK stig-review record rendering (MID-4532)."""
from __future__ import annotations

import importlib.util
import json
import re
import sys

import pytest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SHELL = REPO_ROOT / "scripts" / "shell"



@pytest.fixture(autouse=True)
def _etk_format(monkeypatch):
    monkeypatch.setenv("EPYON_STIG_FORMAT", "etk")


def _load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, SHELL / filename)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


rec = _load("epyon_stig_records_t", "stig_records.py")
assess = _load("epyon_run_stig_assessment_t", "run-stig-assessment.py")

CONTROL = {
    "number": 1, "vuln_id": "APSC-DV-000160", "group_id": "V-222425",
    "rule_id": "SV-222425r960792", "severity": "high",
    "title": "The application must enforce approved authorizations \u2014 per policy",
    "check_content": "Review the code. Verify access control is enforced. More text.",
    "fix_text": "Enforce access control in the application. Other detail.",
}


def _write(tmp_path, assessments, has_key=True):
    return rec.write_records(
        tmp_path / "out", [CONTROL], assessments, app_name="myapp", scan_date="2026-10-21",
        stig_name="ASD STIG", release_info="V6R4", model="gpt-4o", has_api_key=has_key,
    )


def test_v_number_and_vuln_map():
    assert rec.v_number(CONTROL) == "v-222425"
    assert rec.v_number({"vuln_id": "APSC-DV-000160"}) == "apsc-dv-000160"
    assert rec.vuln_map([CONTROL]) == {"APSC-DV-000160": "V-222425"}


def test_entry_follows_etk_layout_with_changes_table_and_automation(tmp_path):
    ev = "Access checks enforced.\n- File: src/auth.py - decorator @require_role\n- Requirement: SATISFIED"
    a = {
        "status": "Not a Finding", "evidence": ev, "confidence": 92,
        "changes_that_may_affect": [
            {"change": "Remove the role decorator", "where": "src/auth.py", "recheck": "Confirm routes still check roles"}
        ],
        "automation_recommendation": {
            "check": "grep routes for the decorator", "data_source": "source tree",
            "pass_fail_rule": "every route has it", "where_it_runs": "CI on each PR",
        },
    }
    paths = _write(tmp_path, {"APSC-DV-000160": a})
    entry = (tmp_path / "out" / "v-222425.md").read_text()
    assert entry.startswith("<!--") and "template-version: etk-stig-review-2026-10-21" in entry
    assert "# V-222425: The application must enforce approved authorizations - per policy (SV-222425r960792, APSC-DV-000160)" in entry
    assert "**Severity:** CAT I (SV-222425r960792)" in entry
    assert "| APSC-DV-000160 | Not a Finding |" in entry
    assert "| Remove the role decorator | src/auth.py | Confirm routes still check roles |" in entry
    assert "Check: grep routes for the decorator; Data source: source tree; Pass/fail rule: every route has it; Runs: CI on each PR" in entry
    assert "{{" not in entry
    index = (tmp_path / "out" / "README.md").read_text()
    assert "| V-222425 | [v-222425.md](v-222425.md) |" in index and "Not a Finding" in index
    assert {p.name for p in paths} == {"v-222425.md", "README.md"}


def test_fallback_rows_come_from_cited_files_when_fields_missing(tmp_path):
    a = {"status": "Open", "evidence": "Partial.\n- File: config/app.yml - timeout: 30", "confidence": 40}
    _write(tmp_path, {"APSC-DV-000160": a})
    entry = (tmp_path / "out" / "v-222425.md").read_text()
    assert "| Edit to config/app.yml | config/app.yml |" in entry
    assert "Check: automate the STIG check" in entry


def test_no_key_mode_writes_open_records_with_evidence_needed_and_no_zero_confidence(tmp_path):
    a = {"status": "Not Reviewed", "evidence": "STIG assessment skipped: OPENAI_API_KEY not configured.", "confidence": 0}
    _write(tmp_path, {"APSC-DV-000160": a}, has_key=False)
    entry = (tmp_path / "out" / "v-222425.md").read_text()
    assert "| APSC-DV-000160 | Open |" in entry
    assert "not confirmable from this repo. Evidence needed: Review the code." in entry
    assert "Confidence 1/100" in entry and "Confidence 0/" not in entry
    assert "no AI key was configured" in entry
    assert "Not Reviewed" not in entry


def test_records_are_ascii_and_redact_secrets_and_internal_hosts(tmp_path):
    ev = (
        "Uses \u201cquoted\u201d \u2014 text.\n- File: .env.example - password = hunter2hunter2\n"
        "- key sk-abcdefghijklmnopqrstuv and ghp_abcdefghijklmnopqrstuvwxyz1234\n"
        "- host db01.corp.internal and 10.2.3.4 and 8.8.8.8\n"
        "-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----"
    )
    _write(tmp_path, {"APSC-DV-000160": {"status": "Open", "evidence": ev, "confidence": 50}})
    for path in (tmp_path / "out").glob("*.md"):
        text = path.read_text(encoding="ascii")
        assert not re.search(r"hunter2hunter2|sk-abcdef|ghp_abcdef|MIIabc|db01\.corp|10\.2\.3\.4", text)
    entry = (tmp_path / "out" / "v-222425.md").read_text()
    assert "[REDACTED]" in entry and "[internal-host]" in entry and "8.8.8.8" in entry


def test_pipes_and_newlines_do_not_break_the_table(tmp_path):
    a = {"status": "Open", "evidence": "a | b\nsecond line", "confidence": 10}
    _write(tmp_path, {"APSC-DV-000160": a})
    row = next(l for l in (tmp_path / "out" / "v-222425.md").read_text().splitlines() if l.startswith("| APSC-DV-000160"))
    assert "a \\| b<br>second line" in row


def test_frozen_assessment_keeps_record_fields():
    prev = {
        "status": "Not a Finding", "evidence": "e", "confidence": 95,
        "changes_that_may_affect": [{"change": "c", "where": "w", "recheck": "r"}],
        "automation_recommendation": {"check": "x"},
    }
    frozen = assess.compute_frozen_assessment(prev)
    assert frozen["changes_that_may_affect"] == prev["changes_that_may_affect"]
    assert frozen["automation_recommendation"] == {"check": "x"}
    assert assess.compute_frozen_assessment({"status": "Open", "confidence": 40}) is None


def test_prompt_requests_the_new_fields():
    assert "changes_that_may_affect" in assess.SYSTEM_PROMPT
    assert "automation_recommendation" in assess.SYSTEM_PROMPT
    assert "these six fields" in assess.SYSTEM_PROMPT


def test_assess_stig_without_key_keeps_legacy_json_and_writes_records(tmp_path):
    stig = {
        "stig_name": "ASD STIG", "release_info": "V6R4", "controls": [CONTROL],
        "source_format": "xccdf", "total_controls": 1,
    }
    assess._assess_stig(
        stig_data=stig, stig_path="x.xml", source_files=[], manual_docs=[], scan_dir=tmp_path,
        app_name="myapp", model="gpt-4o", batch_size=5, delay=0, api_key="", base_url="",
        scan_date="2026-10-21", slug="asd", is_primary=True, target_dir=str(tmp_path),
    )
    results = json.loads((tmp_path / "stig-results-asd.json").read_text())
    entry = results["assessments"]["APSC-DV-000160"]
    assert {"status", "evidence", "confidence"} <= set(entry)
    controls = json.loads((tmp_path / "stig-controls-asd.json").read_text())
    assert controls["vuln_map"] == {"APSC-DV-000160": "V-222425"}
    assert (tmp_path / "findings-myapp.md").exists() and (tmp_path / "findings-myapp-asd.md").exists()
    assert (tmp_path / "stig-reviews-asd" / "v-222425.md").exists()
    assert (tmp_path / "stig-reviews-asd" / "README.md").exists()
