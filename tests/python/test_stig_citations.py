"""STIG evidence citation verification (MID-4533)."""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

SHELL = Path(__file__).resolve().parents[2] / "scripts" / "shell"


def _load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, SHELL / filename)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


cit = _load("epyon_stig_citations_t", "stig_citations.py")
rec = _load("epyon_stig_records_t2", "stig_records.py")
assess = _load("epyon_run_stig_assessment_t2", "run-stig-assessment.py")

CONTROL = {"vuln_id": "APSC-DV-000160", "group_id": "V-222425", "rule_id": "SV-1r1", "severity": "high",
           "title": "t", "check_content": "Verify access control is enforced. More."}


def _repo(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "auth.py").write_text("import x\n\n@require_role('admin')\ndef view():\n    pass\n")
    (tmp_path / ".env").write_text("SECRET=1\n")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "m.js").write_text("x\n")
    return tmp_path


def _a(evidence, status="Not a Finding", conf=95):
    return {"status": status, "evidence": evidence, "confidence": conf}


def test_matching_citation_keeps_status_and_confidence(tmp_path):
    repo = _repo(tmp_path)
    a = _a('Enforced.\n- File: src/auth.py:3 - "@require_role(\'admin\')"\n- Requirement: SATISFIED')
    out = cit.verify_assessment(a, repo, CONTROL)
    assert out["status"] == "Not a Finding" and out["confidence"] == 95
    assert "citation_failures" not in out and "verification_note" not in out


def test_citation_without_line_or_quote_only_needs_the_file(tmp_path):
    repo = _repo(tmp_path)
    assert cit.verify_assessment(_a("- File: src/auth.py - decorator present"), repo)["status"] == "Not a Finding"


def test_missing_file_downgrades_and_lists_failure(tmp_path):
    repo = _repo(tmp_path)
    out = cit.verify_assessment(_a("- File: src/nope.py:3 - \"x\""), repo, CONTROL)
    assert out["status"] == "Open" and out["confidence"] < 85
    assert out["downgraded_from"] == "Not a Finding"
    assert out["citation_failures"] == ["src/nope.py:3: file not found"]
    assert "Evidence needed: Verify access control is enforced." in out["verification_note"]


def test_line_beyond_end_and_mismatched_text_fail(tmp_path):
    repo = _repo(tmp_path)
    far = cit.verify_assessment(_a("- File: src/auth.py:99 - \"x\""), repo)
    assert far["status"] == "Open" and "line does not exist" in far["citation_failures"][0]
    bad = cit.verify_assessment(_a('- File: src/auth.py:3 - "@require_admin_only"'), repo)
    assert bad["status"] == "Open" and "not found" in bad["citation_failures"][0]


def test_excluded_and_traversal_paths_fail(tmp_path):
    repo = _repo(tmp_path)
    for path in (".env", "node_modules/m.js", "../outside.py"):
        out = cit.verify_assessment(_a(f"- File: {path}:1 - ok"), repo)
        assert out["status"] == "Open", path


def test_not_applicable_needs_absence_statement(tmp_path):
    repo = _repo(tmp_path)
    no = cit.verify_assessment(_a("The app is simple.", "Not Applicable"), repo)
    assert no["status"] == "Open" and no["downgraded_from"] == "Not Applicable"
    yes = cit.verify_assessment(_a("Searched src/ for LDAP and SAML usage; no match found.", "Not Applicable"), repo)
    assert yes["status"] == "Not Applicable"


def test_external_owner_needs_confirmation(tmp_path):
    repo = _repo(tmp_path)
    out = cit.verify_assessment(_a("MFA is handled by the identity provider."), repo)
    assert out["status"] == "Open" and out["needs_owner_confirmation"] is True
    assert "needs owner confirmation" in out["verification_note"]


def test_open_and_not_reviewed_are_not_raised(tmp_path):
    repo = _repo(tmp_path)
    assert cit.verify_assessment(_a("none", "Not Reviewed", 0), repo)["status"] == "Not Reviewed"
    assert cit.verify_assessment(_a("Missing.", "Open", 30), repo)["confidence"] == 30


def test_downgraded_control_is_not_frozen(tmp_path):
    repo = _repo(tmp_path)
    out = cit.verify_assessment(_a("- File: src/nope.py:1 - ok"), repo)
    assert assess.compute_frozen_assessment(out) is None


def test_record_lists_failed_citation(tmp_path):
    repo = _repo(tmp_path)
    out = cit.verify_assessment(_a("- File: src/nope.py:3 - ok"), repo, CONTROL)
    entry = rec.render_entry(CONTROL, out, scan_date="2026-10-21", reviewer="Epyon", method="m")
    assert "| APSC-DV-000160 | Open |" in entry
    assert "Failed citation: src/nope.py:3: file not found." in entry
    assert "Downgraded from Not a Finding" in entry


def test_verification_makes_no_model_calls(tmp_path, monkeypatch):
    repo = _repo(tmp_path)
    monkeypatch.setattr(assess, "_call_ai", lambda *a, **k: (_ for _ in ()).throw(AssertionError("model call")), raising=False)
    cit.verify_assessment(_a("- File: src/auth.py:3 - \"@require_role\""), repo)
