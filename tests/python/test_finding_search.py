"""Cross-application CVE/package search (MID-4485)."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "web"))

from api import finding_search  # noqa: E402
from api import main as api_main  # noqa: E402


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


@pytest.mark.parametrize("params", [{}, {"q": "CVE-2024-0001", "include_history": "invalid"}])
def test_search_request_validation_returns_generic_400(params):
    response = TestClient(api_main.app).get("/api/findings/search", params=params)

    assert response.status_code == 400
    assert response.json() == {"detail": "Invalid search request"}


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


# ── MID-4487: per-scan index and endpoint caching ─────────────

def test_index_does_not_freeze_jira_ticket_state():
    finding = _finding("grype", "CVE-2024-0001")
    index = finding_search.build_scan_index(_scan([finding]), "app-a", "MID")
    assert finding_search.search_index(index, "cve-2024-0001", "id")[0]["jira_issue_key"] == ""
    fingerprint = finding_search.jira_client.finding_fingerprint(finding, "app-a", "MID")
    found = finding_search.search_index(index, "cve-2024-0001", "id", {fingerprint: {"issue_key": "MID-9"}})
    assert found[0]["jira_issue_key"] == "MID-9"


def test_search_index_results_are_not_mutated_between_queries():
    scan = _scan([_finding("grype", "CVE-2024-0001"), _finding("trivy", "CVE-2024-0001")])
    index = finding_search.build_scan_index(scan, "app-a", "MID")
    first = finding_search.search_index(index, "cve-2024-0001", "id")
    first[0]["tools"].append("tampered")
    second = finding_search.search_index(index, "cve-2024-0001", "id")
    assert "tampered" not in second[0]["tools"]


def test_preselect_dirs_keeps_newest_per_target_without_parsing_scans():
    names = ["a_u_2026-10-01_00-00-00", "a_u_2026-10-10_00-00-00", "b_u_2026-10-05_00-00-00"]
    dirs = [Path(n) for n in names]
    parse = lambda n: {"target": n.split("_")[0], "timestamp": n.split("_", 2)[2]}
    assert {d.name for d in finding_search.preselect_dirs(dirs, False, parse)} == {names[1], names[2]}
    assert len(finding_search.preselect_dirs(dirs, True, parse)) == 3


@pytest.fixture
def api_client(tmp_path, monkeypatch):
    import shutil
    from fastapi.testclient import TestClient
    from api import main

    golden = REPO_ROOT / "tests/fixtures/golden-scan/goldenapp_testuser_2026-09-16_12-00-00"
    (tmp_path / "scans").mkdir()
    shutil.copytree(golden, tmp_path / "scans" / golden.name)
    monkeypatch.setattr(main, "EPYON_ROOT", tmp_path)
    monkeypatch.setattr(main, "_load_monitored_apps", lambda: set())
    hidden: set = set()
    monkeypatch.setattr(main, "_load_hidden_apps", lambda: hidden)
    main._search_index.clear()
    main._invalidate_scan_cache(reason="test")
    return TestClient(main.app), main, tmp_path, hidden


def test_endpoint_reuses_index_and_reports_hits(api_client):
    client, main, _, _ = api_client
    before = dict(main._cache_metrics["misses"])["search_index"]
    assert client.get("/api/findings/search", params={"q": "CVE-2024-00001"}).json()["total_findings"] == 1
    assert client.get("/api/findings/search", params={"q": "CVE-2024-00001"}).json()["total_findings"] == 1
    assert main._cache_metrics["misses"]["search_index"] - before == 1
    assert main._cache_metrics["hits"]["search_index"] >= 1
    stats = client.get("/api/metrics/cache").json()
    assert stats["hits"]["search_index"] >= 1 and stats["cache_sizes"]["search_index"] == 1


def test_hide_and_unhide_are_reflected_without_rebuilding(api_client):
    client, main, _, hidden = api_client
    query = {"q": "CVE-2024-00001"}
    assert client.get("/api/findings/search", params=query).json()["total_applications"] == 1
    hidden.add("goldenapp")
    main._invalidate_scan_cache(reason="hidden_apps_changed")
    assert client.get("/api/findings/search", params=query).json()["total_applications"] == 0
    hidden.clear()
    main._invalidate_scan_cache(reason="hidden_apps_changed")
    assert client.get("/api/findings/search", params=query).json()["total_applications"] == 1


def test_new_scan_is_found_after_invalidation(api_client):
    import shutil
    client, main, root, _ = api_client
    query = {"q": "CVE-2024-00001", "include_history": "true"}
    assert client.get("/api/findings/search", params=query).json()["total_applications"] == 1
    golden = REPO_ROOT / "tests/fixtures/golden-scan/goldenapp_testuser_2026-09-16_12-00-00"
    shutil.copytree(golden, root / "scans" / "goldenapp_testuser_2026-09-17_12-00-00")
    main._invalidate_scan_cache(reason="scan_completion")
    result = client.get("/api/findings/search", params=query).json()
    assert {a["scan_id"] for a in result["applications"]} == {
        "goldenapp_testuser_2026-09-16_12-00-00", "goldenapp_testuser_2026-09-17_12-00-00"}


def test_deleting_scans_drops_index_entries(api_client):
    client, main, _, _ = api_client
    client.get("/api/findings/search", params={"q": "CVE-2024-00001"})
    assert len(main._search_index) == 1
    main._invalidate_scan_cache(reason="delete_scan")
    assert len(main._search_index) == 0
