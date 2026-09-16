"""Suppression parity: the bash and Python matchers must agree on every rule type.

The bash matcher runs during scans (gating, suppressed-findings.md) while the Python
matcher runs when rendering dashboards. If they disagree, a rule appears to work in one
surface and silently fail in the other.
"""
from __future__ import annotations

import json
import subprocess

import pytest

BASH_FN = {
    "tool": 'is_tool_ignored "{tool}"',
    "cve": 'is_cve_ignored "{id}" "{tool}"',
    "package": 'is_package_ignored "{package}" "{version}" "{tool}"',
    "path": 'is_path_ignored "{target}" "{tool}"',
    "secret": 'is_secret_ignored "{id}" "{target}" "{tool}"',
}

# (case id, ignore rule, finding, bash entry point, expected suppressed)
CASES = [
    (
        "tool-exact",
        {"type": "tool", "value": "grype"},
        {"tool": "Grype", "id": "CVE-2024-1111", "package": "p", "version": "1", "target": "a.txt"},
        "tool",
        True,
    ),
    (
        "cve-exact",
        {"type": "cve", "value": "CVE-2024-1111"},
        {"tool": "Grype", "id": "CVE-2024-1111", "package": "p", "version": "1", "target": "a.txt"},
        "cve",
        True,
    ),
    (
        "cve-wildcard",
        {"type": "cve", "value": "CVE-2024-*"},
        {"tool": "Grype", "id": "CVE-2024-9999", "package": "p", "version": "1", "target": "a.txt"},
        "cve",
        True,
    ),
    (
        "cve-no-match",
        {"type": "cve", "value": "CVE-2024-1111"},
        {"tool": "Grype", "id": "CVE-2999-0000", "package": "p", "version": "1", "target": "a.txt"},
        "cve",
        False,
    ),
    (
        "cve-no-fallthrough-to-package",
        {"type": "cve", "value": "p"},
        {"tool": "Grype", "id": "CVE-2999-0000", "package": "p", "version": "1", "target": "a.txt"},
        "cve",
        False,
    ),
    (
        "package-with-version",
        {"type": "package", "value": "netty-handler@4.1.136.Final"},
        {
            "tool": "Anchore",
            "id": "GHSA-c4c3-7fpv-j4q5",
            "package": "netty-handler",
            "version": "4.1.136.Final",
            "target": "img",
        },
        "package",
        True,
    ),
    (
        "package-any-version",
        {"type": "package", "value": "netty-handler"},
        {
            "tool": "Anchore",
            "id": "GHSA-c4c3-7fpv-j4q5",
            "package": "netty-handler",
            "version": "9.9.9",
            "target": "img",
        },
        "package",
        True,
    ),
    (
        "package-version-mismatch",
        {"type": "package", "value": "netty-handler@4.1.136.Final"},
        {
            "tool": "Anchore",
            "id": "GHSA-c4c3-7fpv-j4q5",
            "package": "netty-handler",
            "version": "4.1.137.Final",
            "target": "img",
        },
        "package",
        False,
    ),
    (
        "secret-detector",
        {"type": "secret-detector", "value": "Gitlab"},
        {"tool": "TruffleHog", "id": "Gitlab", "package": "Gitlab", "version": "", "target": "a.py"},
        "secret",
        True,
    ),
    (
        "secret-pattern-regex",
        {"type": "secret-pattern", "value": "^Gitlab$"},
        {"tool": "TruffleHog", "id": "Gitlab", "package": "Gitlab", "version": "", "target": "a.py"},
        "secret",
        True,
    ),
]


def _write_cache(tmp_path, rule: dict):
    """Emit an ignore cache in the shape parse-epyon-ignore.sh produces."""
    entry = {
        "type": rule["type"],
        "value": rule["value"],
        "reason": "parity test",
        "expires": "",
        "approved_by": "tester",
        "paths": rule.get("paths", []),
        "expired": False,
    }
    cache = tmp_path / "ignore-cache.json"
    cache.write_text(json.dumps({"ignores": [entry]}), encoding="utf-8")
    return cache


def _bash_says_suppressed(repo_root, cache, tmp_path, entry: str, finding: dict) -> bool:
    script = repo_root / "scripts" / "shell" / "filter-ignored-findings.sh"
    invocation = BASH_FN[entry].format(
        tool=finding["tool"].lower(),
        id=finding["id"],
        package=finding["package"],
        version=finding["version"],
        target=finding["target"],
    )
    result = subprocess.run(
        ["bash", "-c", f'source "{script}" && {invocation}'],
        env={
            "PATH": "/usr/local/bin:/usr/bin:/bin:/opt/homebrew/bin",
            "IGNORE_CACHE": str(cache),
            "SUPPRESSED_LOG": str(tmp_path / "suppressed.md"),
        },
        capture_output=True,
        text=True,
    )
    return result.returncode == 0


@pytest.mark.parametrize(
    "case_id,rule,finding,bash_entry,expected",
    CASES,
    ids=[c[0] for c in CASES],
)
def test_bash_and_python_matchers_agree(
    case_id, rule, finding, bash_entry, expected, parsers, repo_root, tmp_path
):
    if not (repo_root / "scripts" / "shell" / "filter-ignored-findings.sh").exists():
        pytest.skip("filter-ignored-findings.sh not found")

    cache = _write_cache(tmp_path, rule)

    python_result = parsers._is_finding_suppressed(finding, [rule])
    bash_result = _bash_says_suppressed(repo_root, cache, tmp_path, bash_entry, finding)

    assert python_result == expected, f"python matcher wrong for {case_id}"
    assert bash_result == expected, f"bash matcher wrong for {case_id}"
    assert python_result == bash_result, f"bash/python disagree on {case_id}"


def test_expired_rules_are_ignored(parsers, tmp_path, monkeypatch):
    """An expired rule must not suppress anything."""
    cache = tmp_path / "expired-cache.json"
    cache.write_text(
        json.dumps(
            {
                "ignores": [
                    {
                        "type": "cve",
                        "value": "CVE-2020-0001",
                        "reason": "old",
                        "approved_by": "tester",
                        "expires": "2020-01-01",
                        "expired": False,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("IGNORE_CACHE", str(cache))

    rules = parsers.parse_suppressed_findings(tmp_path)
    assert rules == [], "expired rule should not be loaded"
