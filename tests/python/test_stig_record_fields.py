"""MID-4535: record fields served to the UI keep Not Reviewed separate and old scans safe."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "web"))

from api.parsers import stig_record_fields  # noqa: E402


def test_old_scan_has_safe_defaults():
    f = stig_record_fields({"status": "Open", "evidence": "x"}, {})
    assert f["changes_that_may_affect"] == []
    assert f["automation_recommendation"] is None
    assert f["citation_failures"] == []
    assert f["human_reviewed"] is False
    assert f["evidence_needed"] == ""


def test_not_reviewed_gets_evidence_needed_from_check_content():
    f = stig_record_fields(
        {"status": "Not Reviewed"},
        {"check_content": "Verify the TLS config. Then check logs."},
    )
    assert f["evidence_needed"] == "Verify the TLS config."


def test_record_fields_pass_through_and_human_flag():
    f = stig_record_fields(
        {
            "status": "Not a Finding",
            "locked_by_human": True,
            "changes_that_may_affect": [{"change": "c", "where": "w", "recheck": "r"}],
            "automation_recommendation": {"check": "a", "data_source": "d"},
            "citation_failures": ["bad cite"],
        },
        {},
    )
    assert f["human_reviewed"] is True
    assert f["changes_that_may_affect"][0]["where"] == "w"
    assert f["automation_recommendation"]["check"] == "a"
    assert f["citation_failures"] == ["bad cite"]
    assert f["evidence_needed"] == ""


def test_malformed_fields_are_ignored():
    f = stig_record_fields(
        {"changes_that_may_affect": "oops", "automation_recommendation": 5, "citation_failures": "x"}, {}
    )
    assert f["changes_that_may_affect"] == []
    assert f["automation_recommendation"] is None
    assert f["citation_failures"] == []
