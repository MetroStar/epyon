"""Publishing STIG records and honouring human-reviewed entries (MID-4534)."""
from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys

import pytest
from pathlib import Path

SHELL = Path(__file__).resolve().parents[2] / "scripts" / "shell"



@pytest.fixture(autouse=True)
def _etk_format(monkeypatch):
    monkeypatch.setenv("EPYON_STIG_FORMAT", "etk")


def _load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, SHELL / filename)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


rec = _load("epyon_stig_records_t3", "stig_records.py")
assess = _load("epyon_run_stig_assessment_t3", "run-stig-assessment.py")

CONTROL = {"number": 1, "vuln_id": "APSC-DV-000160", "group_id": "V-222425", "rule_id": "SV-222425r960792",
           "severity": "high", "title": "Access control", "check_content": "Verify access control. More.",
           "fix_text": "Enforce it."}
STIG = {"stig_name": "ASD STIG", "release_info": "V6R4", "controls": [CONTROL], "source_format": "xccdf",
        "total_controls": 1}

HUMAN_ENTRY = """# V-222425: Access control (SV-222425r960792, APSC-DV-000160)

- **Reviewed:** 2026-01-05 by Jane Doe
- **Ticket:** ABC-1
- **Severity:** CAT I (SV-222425r960792)
- **Assessment method:** Manual review.

| Control ID | Status (Open / Not a Finding / Not Applicable) | Evidence | Notes |
|------------|------------------------------------------------|----------|-------|
| APSC-DV-000160 | Not a Finding | Roles enforced in src/auth.py:3 | Confidence 90/100. |

- **Findings:** None. Not a Finding.
- **Changes that may affect this STIG:** changes that would invalidate this
  assessment and need a re-review.

  | Change | Where (path, config, env var) | Re-check |
  |--------|-------------------------------|----------|
  | Edit the role check | src/auth.py | Confirm roles still enforced |

- **ATO Ready automation recommendation:** Check: grep; Data source: src; Pass/fail rule: present; Runs: CI
"""


def _git(repo, *args):
    env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t",
           "GIT_COMMITTER_EMAIL": "t@t"}
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, env=env)


def _repo(tmp_path, with_entry=True):
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "auth.py").write_text("import x\n\n@require_role\ndef v():\n    pass\n")
    if with_entry:
        (repo / "docs" / "stig-reviews").mkdir(parents=True)
        (repo / "docs" / "stig-reviews" / "v-222425.md").write_text(HUMAN_ENTRY)
    _git(repo, "init", "-q")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "init")
    return repo


def _run(tmp_path, repo, name="scan"):
    scan = tmp_path / name
    scan.mkdir()
    assess._assess_stig(
        stig_data=json.loads(json.dumps(STIG)), stig_path="x.xml", source_files=[], manual_docs=[],
        scan_dir=scan, app_name="myapp", model="gpt-4o", batch_size=5, delay=0, api_key="", base_url="",
        scan_date="2026-10-21", slug="asd", is_primary=True, target_dir=str(repo),
    )
    return scan


def test_parse_entry_reads_reviewer_status_evidence_and_paths():
    info = rec.parse_entry(HUMAN_ENTRY)
    assert info["reviewer"] == "Jane Doe" and info["reviewed"] == "2026-01-05"
    assert info["status"] == "Not a Finding" and "Roles enforced" in info["evidence"]
    assert info["confidence"] == 90 and info["paths"] == ["src/auth.py"]
    assert rec.is_human_reviewer("Jane Doe") and not rec.is_human_reviewer("Epyon AI assessment (gpt-4o)")


def test_human_entry_is_locked_and_not_reassessed(tmp_path):
    repo = _repo(tmp_path)
    locked, reasons, prior = assess._published_reviews([CONTROL], str(repo), "asd")
    assert "v-222425" in locked and not reasons
    frozen = assess.compute_frozen_assessment(prior["APSC-DV-000160"])
    assert frozen and frozen["locked_by_human"] and frozen["status"] == "Not a Finding"


def test_locked_entry_survives_a_scan_verbatim(tmp_path):
    repo = _repo(tmp_path)
    scan = _run(tmp_path, repo)
    kept = (scan / "stig-reviews-asd" / "v-222425.md").read_text()
    assert kept == HUMAN_ENTRY
    results = json.loads((scan / "stig-results-asd.json").read_text())["assessments"]["APSC-DV-000160"]
    assert results["status"] == "Not a Finding" and results["locked_by_human"] is True
    assert "Jane Doe" in (scan / "stig-reviews-asd" / "README.md").read_text()


def test_changed_listed_path_reopens_and_says_why(tmp_path):
    repo = _repo(tmp_path)
    (repo / "src" / "auth.py").write_text("changed\n")
    _git(repo, "commit", "-qam", "edit auth")
    locked, reasons, prior = assess._published_reviews([CONTROL], str(repo), "asd")
    assert not locked and "src/auth.py changed" in reasons["APSC-DV-000160"]
    assert assess.compute_frozen_assessment(prior["APSC-DV-000160"]) is None
    scan = _run(tmp_path, repo)
    entry = (scan / "stig-reviews-asd" / "v-222425.md").read_text()
    assert "Re-opened: src/auth.py changed since the 2026-01-05 review by Jane Doe." in entry


def test_unrelated_change_does_not_reopen(tmp_path):
    repo = _repo(tmp_path)
    (repo / "README.md").write_text("x\n")
    _git(repo, "add", "README.md")
    _git(repo, "commit", "-qm", "docs")
    _, reasons, _ = assess._published_reviews([CONTROL], str(repo), "asd")
    assert not reasons


def test_epyon_authored_entry_is_not_locked(tmp_path):
    repo = _repo(tmp_path, with_entry=False)
    (repo / "docs" / "stig-reviews").mkdir(parents=True)
    (repo / "docs" / "stig-reviews" / "v-222425.md").write_text(
        HUMAN_ENTRY.replace("Jane Doe", "Epyon AI assessment (gpt-4o)"))
    locked, reasons, prior = assess._published_reviews([CONTROL], str(repo), "asd")
    assert not locked and not reasons and not prior


def test_manual_stig_findings_doc_is_still_priority_context():
    files = [("docs/stig-findings.md", "x"), ("docs/stig-reviews/v-222425.md", "y"), ("src/a.py", "z")]
    manual, rest = assess.extract_manual_stig_docs(files)
    assert [m[0] for m in manual] == ["docs/stig-findings.md", "docs/stig-reviews/v-222425.md"]
    assert [r[0] for r in rest] == ["src/a.py"]


def test_publish_writes_docs_dir_sorted_index_and_no_stig_findings(tmp_path):
    repo = _repo(tmp_path, with_entry=False)
    (repo / "docs" / "stig-findings.md").parent.mkdir(parents=True, exist_ok=True)
    (repo / "docs" / "stig-findings.md").write_text("manual\n")
    scan = _run(tmp_path, repo)
    counts = rec.publish_records(scan, repo)
    assert counts["total"] == 1 and counts["open"] == 1
    assert (repo / "docs" / "stig-reviews" / "v-222425.md").exists()
    assert not (repo / "stig-findings.md").exists()
    assert (repo / "docs" / "stig-findings.md").read_text() == "manual\n"


def test_publish_does_not_overwrite_human_entry_and_sorts_rows(tmp_path):
    repo = _repo(tmp_path)
    scan = tmp_path / "scan2"
    d = scan / "stig-reviews-asd"
    d.mkdir(parents=True)
    (d / "v-222425.md").write_text(HUMAN_ENTRY.replace("Jane Doe", "Epyon AI assessment (gpt-4o)"))
    (d / "v-100000.md").write_text(HUMAN_ENTRY.replace("222425", "100000").replace("Jane Doe", "Epyon x"))
    (d / "README.md").write_text(
        "# STIG Review Record\n\n## Summary\n\n| STIG | Entry | Version/Release | Reviewed | Reviewer | Status | Findings | Automation recommendation |\n"
        "|------|-------|---|---|---|---|---|---|\n"
        "| V-222425 | [v-222425.md](v-222425.md) | V6R4 | 2026-10-21 | Epyon x | Open | open | - |\n"
        "| V-100000 | [v-100000.md](v-100000.md) | V6R4 | 2026-10-21 | Epyon x | Open | open | - |\n")
    rec.publish_records(scan, repo)
    assert (repo / "docs/stig-reviews/v-222425.md").read_text() == HUMAN_ENTRY
    index = (repo / "docs/stig-reviews/README.md").read_text()
    assert index.index("V-100000") < index.index("V-222425")
    assert "Jane Doe" in index


def test_publish_is_idempotent(tmp_path):
    repo = _repo(tmp_path, with_entry=False)
    scan = _run(tmp_path, repo)
    rec.publish_records(scan, repo)
    first = {p.name: p.read_text() for p in (repo / "docs/stig-reviews").iterdir()}
    rec.publish_records(scan, repo)
    assert first == {p.name: p.read_text() for p in (repo / "docs/stig-reviews").iterdir()}
