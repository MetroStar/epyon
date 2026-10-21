"""Cross-application CVE/package search (MID-4485)."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "web"))

from api import finding_search  # noqa: E402


def _finding(tool, fid, sev="high", pkg="libfoo", **extra):
    return {"tool": tool, "id": fid, "severity": sev, "package": pkg,
            "version": "1.0", "target": "app/requirements.txt", **extra}


def _scan(vulns=(), misconfigs=(), ml=()):
    def bucket(items):
        out = {f"{s}_findings": [] for s in ("critical", "high", "medium", "low")}
        for item in items:
            out[f"{item['severity']}_findings"].append(item)
        return out
    return {"findings": bucket(vulns), "misconfigurations": bucket(misconfigs),
            "ml_findings": bucket(ml)}


def _search(scan, needle="cve-2024-0001", field="id", tickets=None):
    return finding_search.search_scan(scan, "app-a", needle, field, "MID", tickets)


def test_exact_match_returns_public_fields():
    scan = _scan([_finding("grype", "CVE-2024-0001", fixed_version="1.1"),
                  _finding("grype", "CVE-2024-9999")])
    found = _search(scan)
    assert len(found) == 1
    assert found[0]["id"] == "CVE-2024-0001"
    assert found[0]["fixed_version"] == "1.1"
    assert found[0]["package"] == "libfoo"


def test_same_cve_from_two_tools_is_deduplicated_with_both_tools():
    scan = _scan([_finding("grype", "CVE-2024-0001", sev="medium"),
                  _finding("trivy", "CVE-2024-0001", sev="critical", fixed_version="2.0")])
    found = _search(scan)
    assert len(found) == 1
    assert sorted(found[0]["tools"]) == ["grype", "trivy"]
    assert found[0]["severity"] == "critical"
    assert found[0]["fixed_version"] == "2.0"


def test_package_field_matches_package_not_id():
    scan = _scan([_finding("grype", "CVE-2024-0001", pkg="golang.org/x/text")])
    assert len(_search(scan, "golang.org/x/text", "package")) == 1
    assert _search(scan, "golang.org/x/text", "id") == []


def test_suppressed_and_ticketed_are_marked():
    finding = _finding("grype", "CVE-2024-0001", suppressed=True)
    scan = _scan([finding])
    fingerprint = finding_search.jira_client.finding_fingerprint(finding, "app-a", "MID")
    found = _search(scan, tickets={fingerprint: {"issue_key": "MID-1"}})
    assert found[0]["suppressed"] is True
    assert found[0]["jira_issue_key"] == "MID-1"


def test_misconfigurations_are_searchable_by_id():
    scan = _scan(misconfigs=[_finding("checkov", "CKV_AWS_20", sev="medium")])
    assert _search(scan, "ckv_aws_20")[0]["category"] == "misconfiguration"


@pytest.mark.parametrize("bad", ["", "ab", "x" * 101, "CVE-2024-1;rm", "<script>", "a b c"])
def test_invalid_queries_rejected_without_echo(bad):
    with pytest.raises(ValueError) as exc:
        finding_search.validate_query(bad)
    assert bad.strip() == "" or bad not in str(exc.value)


def test_valid_queries_accepted():
    assert finding_search.validate_query(" CVE-2024-0001 ") == "CVE-2024-0001"
    assert finding_search.validate_query("GHSA-abcd-1234-wxyz")
    assert finding_search.validate_query("golang.org/x/text")


def test_select_scans_latest_only_vs_history():
    scans = [
        {"target": "a", "timestamp": "2026-10-01T00:00:00", "scan_id": "a1"},
        {"target": "a", "timestamp": "2026-10-10T00:00:00", "scan_id": "a2"},
        {"target": "b", "timestamp": "2026-10-05T00:00:00", "scan_id": "b1"},
    ]
    latest = finding_search.select_scans(scans, include_history=False)
    assert {s["scan_id"] for s in latest} == {"a2", "b1"}
    history = finding_search.select_scans(scans, include_history=True)
    assert {s["scan_id"]: s["is_latest"] for s in history} == {"a1": False, "a2": True, "b1": True}
