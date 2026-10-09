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


def test_markdown_suppression_extracts_matched_pattern(parsers, tmp_path):
    """suppressed-findings.md logs path/cve rules as '<finding> (matched: <pattern>)'.

    The reusable glob pattern (e.g. "reg.mini.dev:keycloak-fips/*") must be extracted
    as the rule value — not the one-off matched-finding text — or future findings
    against the same rule will never match.
    """
    md = tmp_path / "suppressed-findings.md"
    md.write_text(
        "# Suppressed Security Findings Report\n\n"
        "## Suppressed: reg.mini.dev:keycloak-fips/v26.7.4-dev "
        "(matched: reg.mini.dev:keycloak-fips/*)\n"
        "- **Tool**: Anchore\n"
        "- **Type**: path\n"
        "- **Value**: reg.mini.dev:keycloak-fips/v26.7.4-dev "
        "(matched: reg.mini.dev:keycloak-fips/*)\n"
        "- **Reason**: Accepted risk pending upstream remediation\n"
        "- **Approved By**: rnelson\n"
        "- **Severity**: Varies\n",
        encoding="utf-8",
    )

    rules = parsers.parse_suppressed_findings(tmp_path)
    path_rules = [r for r in rules if r.get("type") == "path"]
    assert len(path_rules) == 1
    assert path_rules[0]["value"] == "reg.mini.dev:keycloak-fips/*"

    other_finding = {
        "tool": "anchore",
        "id": "GHSA-9pwp-9qqc-pr26",
        "package": "bc-fips",
        "version": "2.1.2",
        "target": "reg.mini.dev:keycloak-fips/v27.0.0-dev",
    }
    assert parsers._is_finding_suppressed(other_finding, rules) is True


def test_filter_suppressed_findings_excludes_suppressed_from_totals(parsers):
    """total_<sev> counts feed the top-level summary cards and must reflect only
    active findings — suppressed findings must not inflate the headline counts."""
    findings_dict = {
        "critical_findings": [
            {"tool": "anchore", "id": "GHSA-1", "package": "bc-fips", "version": "2.1.2"},
            {"tool": "anchore", "id": "GHSA-2", "package": "netty-handler", "version": "4.1.136.Final"},
        ],
        "high_findings": [],
        "medium_findings": [],
        "low_findings": [],
    }
    suppressions = [{"type": "package", "value": "netty-handler@4.1.136.Final"}]

    result = parsers._filter_suppressed_findings(findings_dict, suppressions)

    assert result["summary"]["total_critical"] == 1
    assert result["summary"]["suppressed_critical"] == 1
    assert result["critical_findings"][0]["suppressed"] is False
    assert result["critical_findings"][1]["suppressed"] is True


def test_tool_name_used_as_type_is_normalized_python(parsers, tmp_path):
    """`type: anchore` (a tool name used where the rule type belongs) is a common
    authoring mistake — the correct form is `type: tool, value: anchore`. Without
    normalization this silently matches nothing (no branch in
    _is_finding_suppressed checks `type == "anchore"`), so every Anchore finding
    keeps appearing despite the "suppress everything" intent. It must be
    normalized to a real `tool` rule instead of silently dropped."""
    ignore_yml = tmp_path / ".epyon-ignore.yml"
    ignore_yml.write_text(
        "version: \"1.0\"\n"
        "ignores:\n"
        "  - type: anchore\n"
        "    value: \"*\"\n"
        "    reason: \"Swarm false positives\"\n"
        "    approved_by: tester\n",
        encoding="utf-8",
    )

    rules = parsers.parse_suppressed_findings(tmp_path)
    assert len(rules) == 1
    assert rules[0]["type"] == "tool"
    assert rules[0]["value"] == "anchore"

    finding = {
        "tool": "Anchore",
        "id": "CVE-2026-99999",
        "package": "keycloak",
        "version": "26.7.4",
        "target": "reg.mini.dev:keycloak-fips",
    }
    assert parsers._is_finding_suppressed(finding, rules) is True


_MISINDENTED_IGNORE_YML = """version: "1.0"

ignores:
  - type: cve
    value: "CKV_GHA_7"
    reason: "pre-existing, correctly indented"
    approved_by: "rlnelson"

- type: cve
  value: "GHSA-98qh-xjc8-98pq"
  reason: "newly pasted at the wrong indentation"
  approved_by: "rlnelson"
"""


def test_misindented_ignore_entry_is_autofixed_python(parsers, tmp_path):
    """A recurring hand-edit mistake: pasting a new '- type: ...' entry under
    'ignores:' at a different indentation than its siblings. YAML requires one
    consistent indentation level per block sequence, so this silently breaks
    parsing of the *entire* list, not just the new entry — every previously
    working suppression stops applying with no obvious cause. The parser must
    auto-repair this specific shape (and keep loading the rest of the file)
    rather than silently returning zero rules."""
    ignore_yml = tmp_path / ".epyon-ignore.yml"
    ignore_yml.write_text(_MISINDENTED_IGNORE_YML, encoding="utf-8")

    rules = parsers.parse_suppressed_findings(tmp_path)
    values = {r["value"] for r in rules}
    assert values == {"CKV_GHA_7", "GHSA-98qh-xjc8-98pq"}


def test_misindented_ignore_entry_is_autofixed_bash(repo_root, tmp_path):
    """Bash-side parity for the same mis-indentation autofix: the ignore cache
    parse-epyon-ignore.sh produces must contain both entries, not silently drop
    every rule in the file."""
    script = repo_root / "scripts" / "shell" / "parse-epyon-ignore.sh"
    if not script.exists():
        pytest.skip("parse-epyon-ignore.sh not found")

    ignore_yml = tmp_path / ".epyon-ignore.yml"
    ignore_yml.write_text(_MISINDENTED_IGNORE_YML, encoding="utf-8")
    cache = tmp_path / "ignore-cache.json"

    result = subprocess.run(
        ["bash", "-c", f'source "{script}" && parse_ignore_rules "{ignore_yml}"'],
        env={
            "PATH": "/usr/local/bin:/usr/bin:/bin:/opt/homebrew/bin",
            "IGNORE_CACHE": str(cache),
        },
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr

    cache_data = json.loads(cache.read_text(encoding="utf-8"))
    values = {entry["value"] for entry in cache_data["ignores"]}
    assert values == {"CKV_GHA_7", "GHSA-98qh-xjc8-98pq"}
    assert len(cache_data.get("warnings", [])) > 0


def test_tool_name_used_as_type_is_normalized_bash(repo_root, tmp_path):
    """Bash-side parity for the same `type: anchore` normalization: the ignore
    cache parse-epyon-ignore.sh produces must rewrite it to `type: tool,
    value: anchore` so is_tool_ignored (used by check-severity-gate.sh and the
    legacy dashboard generator) actually suppresses it too."""
    script = repo_root / "scripts" / "shell" / "parse-epyon-ignore.sh"
    if not script.exists():
        pytest.skip("parse-epyon-ignore.sh not found")

    ignore_yml = tmp_path / ".epyon-ignore.yml"
    ignore_yml.write_text(
        "version: \"1.0\"\n"
        "ignores:\n"
        "  - type: anchore\n"
        "    value: \"*\"\n"
        "    reason: \"Swarm false positives\"\n"
        "    approved_by: tester\n",
        encoding="utf-8",
    )
    cache = tmp_path / "ignore-cache.json"

    result = subprocess.run(
        ["bash", "-c", f'source "{script}" && parse_ignore_rules "{ignore_yml}"'],
        env={
            "PATH": "/usr/local/bin:/usr/bin:/bin:/opt/homebrew/bin",
            "IGNORE_CACHE": str(cache),
        },
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr

    cache_data = json.loads(cache.read_text(encoding="utf-8"))
    assert len(cache_data["ignores"]) == 1
    assert cache_data["ignores"][0]["type"] == "tool"
    assert cache_data["ignores"][0]["value"] == "anchore"

    check = subprocess.run(
        ["bash", "-c", f'source "{repo_root / "scripts" / "shell" / "filter-ignored-findings.sh"}" && is_tool_ignored "anchore"'],
        env={
            "PATH": "/usr/local/bin:/usr/bin:/bin:/opt/homebrew/bin",
            "IGNORE_CACHE": str(cache),
            "SUPPRESSED_LOG": str(tmp_path / "suppressed.md"),
        },
        capture_output=True,
        text=True,
    )
    assert check.returncode == 0, "is_tool_ignored should suppress the normalized 'anchore' tool rule"
