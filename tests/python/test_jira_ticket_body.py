"""Tests for MID-4187: Jira tickets include CVE information, acceptance
criteria, and a definition of done, so a reviewer never has to go back to
the raw scan output to triage, fix, or verify a finding."""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest


def _load_jira_client(repo_root: Path):
    module_name = "epyon_jira_client_ticket_body_tests"
    spec = importlib.util.spec_from_file_location(
        module_name, repo_root / "web" / "api" / "jira_client.py"
    )
    if spec is None or spec.loader is None:
        raise ImportError("Unable to load jira_client")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def _flatten_text(adf_node) -> str:
    """Concatenate all text nodes in an ADF document for substring assertions."""
    out: list[str] = []

    def walk(node):
        if isinstance(node, dict):
            if node.get("type") == "text":
                out.append(node.get("text", ""))
            for child in node.get("content", []) or []:
                walk(child)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(adf_node)
    return "".join(out)


def _headings(adf_doc: dict) -> list[str]:
    return [
        _flatten_text(block)
        for block in adf_doc["content"]
        if block.get("type") == "heading"
    ]


@pytest.fixture
def jira_client(repo_root):
    return _load_jira_client(repo_root)


def test_cve_finding_includes_cve_details_ac_and_dod(jira_client):
    finding = {
        "tool": "Grype",
        "id": "CVE-2026-42198",
        "severity": "high",
        "package": "pgjdbc",
        "version": "42.5.5",
        "fixed_version": "42.7.11",
        "title": "pgjdbc: Unbounded PBKDF2 iterations",
        "references": ["https://github.com/pgjdbc/pgjdbc/security/advisories/GHSA-98qh-xjc8-98pq"],
        "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2026-42198",
        "cvss_score": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "cisa_kev": False,
    }
    adf = jira_client.build_finding_description(finding, "myapp")

    assert _headings(adf) == ["CVE Details", "Acceptance Criteria", "Definition of Done"]

    text = _flatten_text(adf)
    assert "CVE-2026-42198" in text
    assert "7.5" in text and "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" in text
    assert "pgjdbc" in text and "42.5.5" in text
    assert "42.7.11" in text
    assert "https://nvd.nist.gov/vuln/detail/CVE-2026-42198" in text
    # Acceptance criteria reference the CVE id and the fix target.
    assert "CVE-2026-42198" in text and "42.7.11" in text
    # Definition of done checklist items.
    assert "merged" in text.lower()
    assert "re-scan" in text.lower() or "rescan" in text.lower()
    assert "pull request" in text.lower()

    # CVE/advisory id should be rendered as a link, not plain text.
    cve_para = adf["content"][2]
    cve_text_node = next(n for n in cve_para["content"] if n["text"] == "CVE-2026-42198")
    assert any(m["type"] == "link" for m in cve_text_node.get("marks", []))


def test_non_cve_finding_states_no_cve_explicitly(jira_client):
    finding = {
        "tool": "Checkov",
        "id": "CKV_AWS_123",
        "severity": "medium",
        "package": "main.tf",
        "title": "S3 bucket should have versioning enabled",
    }
    adf = jira_client.build_finding_description(finding, "myapp")
    text = _flatten_text(adf)
    assert "No CVE/advisory identifier" in text
    assert "CKV_AWS_123" in text
    assert "Checkov" in text
    # Still gets acceptance criteria / definition of done even without a CVE.
    assert "Acceptance Criteria" in [h for h in _headings(adf)]
    assert "Definition of Done" in [h for h in _headings(adf)]


def test_missing_cvss_renders_not_available(jira_client):
    finding = {"tool": "TruffleHog", "id": "AWS", "severity": "critical", "package": "AWS"}
    adf = jira_client.build_finding_description(finding, "myapp")
    text = _flatten_text(adf)
    assert "Not available" in text


def test_kev_finding_adds_kev_callout_and_due_date_criterion(jira_client):
    finding = {
        "tool": "Grype",
        "id": "CVE-2026-00001",
        "severity": "critical",
        "package": "foo",
        "version": "1.0",
        "fixed_version": "1.1",
        "cisa_kev": True,
        "cisa_due_date": "2026-11-01",
    }
    adf = jira_client.build_finding_description(finding, "myapp")
    text = _flatten_text(adf)
    assert "Known Exploited Vulnerability" in text
    assert "2026-11-01" in text


def test_ghsa_id_is_recognized_as_cve_like(jira_client):
    finding = {
        "tool": "Grype",
        "id": "GHSA-98qh-xjc8-98pq",
        "severity": "high",
        "package": "pgjdbc",
        "references": ["https://github.com/advisories/GHSA-98qh-xjc8-98pq"],
    }
    adf = jira_client.build_finding_description(finding, "myapp")
    text = _flatten_text(adf)
    assert "No CVE/advisory identifier" not in text
    assert "GHSA-98qh-xjc8-98pq" in text


def test_create_ticket_uses_build_finding_description(jira_client, monkeypatch):
    """create_ticket() must delegate to build_finding_description() rather than
    reconstructing its own body, keeping both behaviors in lockstep."""
    captured: dict = {}

    class FakeResponse:
        status_code = 201
        text = ""

        def json(self):
            return {"key": "SEC-1"}

    class FakeClient:
        def __init__(self, *a, **kw):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, url, auth=None, headers=None, json=None):
            captured["payload"] = json
            return FakeResponse()

    async def fake_resolve_issue_type(cfg, project_key, requested):
        return requested

    monkeypatch.setattr(jira_client.httpx, "AsyncClient", FakeClient)
    monkeypatch.setattr(jira_client, "_resolve_issue_type", fake_resolve_issue_type)

    import asyncio

    finding = {
        "tool": "Grype", "id": "CVE-2026-42198", "severity": "high",
        "package": "pgjdbc", "version": "42.5.5", "fixed_version": "42.7.11",
    }
    cfg = {"project_key": "SEC", "email": "a@b.com", "api_token": "tok", "base_url": "https://x.atlassian.net"}
    key = asyncio.run(jira_client.create_ticket(cfg, finding, "myapp"))

    assert key == "SEC-1"
    expected = jira_client.build_finding_description(finding, "myapp")
    assert captured["payload"]["fields"]["description"] == expected
