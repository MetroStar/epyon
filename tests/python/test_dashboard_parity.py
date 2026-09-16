"""Dashboard parity: the offline HTML and the live web UI must report identical data.

Both paths must resolve to ``parsers.load_scan_complete``. Any field that differs here
is a bug the user would see as "the dashboard shows different numbers than the web UI".
"""
from __future__ import annotations

# Fields that legitimately differ between the two delivery mechanisms.
#   scorecard      - embedded offline, fetched lazily over HTTP in the web UI
#   has_dashboard  - the offline file *is* the dashboard, so it never links to itself
#   dashboard_url  - ditto
_DELIVERY_ONLY_FIELDS = {"scorecard", "has_dashboard", "dashboard_url"}


def test_static_and_web_scan_objects_match(parsers, dashboard, golden_scan_dir, repo_root):
    """build_scan_object() must equal load_scan_complete() on every shared field."""
    web = parsers.load_scan_complete(golden_scan_dir, repo_root)
    static = dashboard.build_scan_object(golden_scan_dir, repo_root)

    shared_keys = (set(web) | set(static)) - _DELIVERY_ONLY_FIELDS
    mismatched = {
        key: {"web_ui": web.get(key), "static_html": static.get(key)}
        for key in shared_keys
        if web.get(key) != static.get(key)
    }
    assert not mismatched, f"dashboard parity drift: {sorted(mismatched)}"


def test_severity_counts_match(parsers, dashboard, golden_scan_dir, repo_root):
    web = parsers.load_scan_complete(golden_scan_dir, repo_root)
    static = dashboard.build_scan_object(golden_scan_dir, repo_root)

    for sev in ("critical", "high", "medium", "low", "total"):
        assert web[sev] == static[sev], f"{sev} count differs"


def test_stig_not_reviewed_is_not_folded_into_not_applicable(
    parsers, dashboard, golden_scan_dir, repo_root
):
    """Regression: the static generator used to merge Not Reviewed into stig_na.

    The fixture has 1 Not Applicable and 2 Not Reviewed, so conflation is detectable.
    """
    web = parsers.load_scan_complete(golden_scan_dir, repo_root)
    static = dashboard.build_scan_object(golden_scan_dir, repo_root)

    assert web["stig_na"] == 1
    assert web["stig_nr"] == 2
    assert static["stig_na"] == 1, "static dashboard folded Not Reviewed into stig_na"
    assert static["stig_nr"] == 2, "static dashboard dropped the stig_nr field"

    for field in ("stig_open", "stig_pass", "stig_na", "stig_nr", "stig_total"):
        assert web[field] == static[field], f"{field} differs between dashboards"


def test_suppressed_findings_are_flagged_in_both_paths(
    parsers, dashboard, golden_scan_dir, repo_root
):
    """Regression: the static generator never marked findings as suppressed.

    The fixture suppresses netty-handler@4.1.136.Final via .epyon-ignore.yml.
    """
    web = parsers.load_scan_complete(golden_scan_dir, repo_root)
    static = dashboard.build_scan_object(golden_scan_dir, repo_root)

    def suppressed_ids(scan):
        findings = scan.get("findings") or {}
        return {
            f.get("id")
            for sev in ("critical", "high", "medium", "low")
            for f in findings.get(f"{sev}_findings", [])
            if f.get("suppressed") is True
        }

    assert "GHSA-c4c3-7fpv-j4q5" in suppressed_ids(web)
    assert "GHSA-c4c3-7fpv-j4q5" in suppressed_ids(static), (
        "static dashboard did not mark the .epyon-ignore.yml suppression"
    )
    assert suppressed_ids(web) == suppressed_ids(static)


def test_misconfigurations_excluded_from_vulnerability_counts(
    parsers, golden_scan_dir, repo_root
):
    """Checkov and TruffleHog belong in misconfigurations, never in the CVE counts."""
    web = parsers.load_scan_complete(golden_scan_dir, repo_root)

    vuln_tools = {
        (f.get("tool") or "").lower()
        for sev in ("critical", "high", "medium", "low")
        for f in web["findings"].get(f"{sev}_findings", [])
    }
    assert "checkov" not in vuln_tools
    assert "trufflehog" not in vuln_tools

    misconfig = web["misconfigurations"]["summary"]
    total_misconfig = sum(
        misconfig[f"total_{sev}"] for sev in ("critical", "high", "medium", "low")
    )
    assert total_misconfig >= 2, "expected the Checkov and TruffleHog fixture findings"
