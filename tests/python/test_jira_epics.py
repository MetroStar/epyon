"""Tests for Jira Epic assignment and orphaned-ticket reassignment."""
from __future__ import annotations

import asyncio
import importlib.util
import sys
from pathlib import Path


def _load_jira_client(repo_root: Path):
    module_name = "epyon_jira_client_epic_tests"
    spec = importlib.util.spec_from_file_location(
        module_name, repo_root / "web" / "api" / "jira_client.py"
    )
    if spec is None or spec.loader is None:
        raise ImportError("Unable to load Jira client")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def test_get_epics_returns_defaults_when_unassigned(repo_root, tmp_path, monkeypatch):
    jira_client = _load_jira_client(repo_root)
    monkeypatch.setattr(jira_client, "_CONFIG_FILE", tmp_path / "jira-config.json")

    epics = jira_client.get_epics("SEC")

    assert set(epics) == set(jira_client.EPIC_CATEGORIES)
    for category, record in epics.items():
        assert record["epic_key"] is None
        assert record["color"]
        assert record["name"]


def test_assign_epic_creates_issue_and_persists_color(repo_root, tmp_path, monkeypatch):
    jira_client = _load_jira_client(repo_root)
    monkeypatch.setattr(jira_client, "_CONFIG_FILE", tmp_path / "jira-config.json")

    async def fake_create_epic_issue(cfg, project_key, name):
        return "SEC-500"

    monkeypatch.setattr(jira_client, "_create_epic_issue", fake_create_epic_issue)

    record = asyncio.run(
        jira_client.assign_epic({}, "SEC", "vulnerability", "#123456")
    )

    assert record["epic_key"] == "SEC-500"
    assert record["color"] == "#123456"

    # Persisted — a second read (fresh call) sees the same assignment and does
    # not attempt to recreate the epic.
    epics = jira_client.get_epics("SEC")
    assert epics["vulnerability"]["epic_key"] == "SEC-500"
    assert epics["vulnerability"]["color"] == "#123456"


def test_assign_epic_updates_color_without_recreating_existing_epic(
    repo_root, tmp_path, monkeypatch
):
    jira_client = _load_jira_client(repo_root)
    monkeypatch.setattr(jira_client, "_CONFIG_FILE", tmp_path / "jira-config.json")

    calls = []

    async def fake_create_epic_issue(cfg, project_key, name):
        calls.append(name)
        return "SEC-501"

    monkeypatch.setattr(jira_client, "_create_epic_issue", fake_create_epic_issue)

    asyncio.run(jira_client.assign_epic({}, "SEC", "ml", "#111111"))
    asyncio.run(jira_client.assign_epic({}, "SEC", "ml", "#222222"))

    assert len(calls) == 1  # Epic only created once
    epics = jira_client.get_epics("SEC")
    assert epics["ml"]["epic_key"] == "SEC-501"
    assert epics["ml"]["color"] == "#222222"


def test_assign_epic_rejects_invalid_color(repo_root, tmp_path, monkeypatch):
    jira_client = _load_jira_client(repo_root)
    monkeypatch.setattr(jira_client, "_CONFIG_FILE", tmp_path / "jira-config.json")

    try:
        asyncio.run(jira_client.assign_epic({}, "SEC", "vulnerability", "red"))
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_create_ticket_links_to_epic_when_provided(repo_root, monkeypatch):
    jira_client = _load_jira_client(repo_root)

    linked = {}

    async def fake_link(cfg, issue_key, epic_key):
        linked["issue_key"] = issue_key
        linked["epic_key"] = epic_key
        return True

    class FakeResponse:
        status_code = 201

        def json(self):
            return {"key": "SEC-42"}

    class FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def post(self, *args, **kwargs):
            return FakeResponse()

    monkeypatch.setattr(jira_client.httpx, "AsyncClient", lambda **kwargs: FakeClient())
    monkeypatch.setattr(jira_client, "link_issue_to_epic", fake_link)

    cfg = {"project_key": "SEC", "email": "a@b.com", "api_token": "x", "base_url": "https://x.atlassian.net"}
    finding = {"id": "CVE-9", "tool": "Grype", "severity": "high"}

    key = asyncio.run(jira_client.create_ticket(cfg, finding, "example", "SEC-101"))

    assert key == "SEC-42"
    assert linked == {"issue_key": "SEC-42", "epic_key": "SEC-101"}


def test_reassign_orphaned_tickets_recreates_deleted_issue(repo_root, monkeypatch):
    jira_client = _load_jira_client(repo_root)

    async def fake_issue_exists(cfg, issue_key):
        return issue_key != "SEC-1"  # SEC-1 was deleted

    async def fake_create_ticket(cfg, finding, app_name, epic_key=None):
        assert finding["id"] == "CVE-1"  # rebuilt from finding_snapshot
        assert epic_key == "SEC-999"
        return "SEC-2"

    monkeypatch.setattr(jira_client, "_issue_exists", fake_issue_exists)
    monkeypatch.setattr(jira_client, "create_ticket", fake_create_ticket)
    monkeypatch.setattr(
        jira_client, "get_epics",
        lambda project_key: {"vulnerability": {"epic_key": "SEC-999", "color": "#fff", "name": "Vulns"}},
    )

    ticket_map = {
        "fp-1": {
            "issue_key": "SEC-1",
            "app": "example",
            "project_key": "SEC",
            "category": "vulnerability",
            "epic_key": "SEC-999",
            "finding_id": "CVE-1",
            "closed_at": None,
            "finding_snapshot": {"id": "CVE-1", "tool": "Grype", "severity": "high"},
            "previous_issue_keys": [],
        },
        "fp-2": {
            "issue_key": "SEC-3",  # still exists — should be untouched
            "app": "example",
            "project_key": "SEC",
            "category": "vulnerability",
            "closed_at": None,
        },
    }
    cfg = {"project_key": "SEC"}

    result = asyncio.run(
        jira_client.reassign_orphaned_tickets("example", cfg, ticket_map)
    )

    assert result["checked"] == 2
    assert result["orphaned"] == ["SEC-1"]
    assert result["reassigned"] == [{"old": "SEC-1", "new": "SEC-2"}]
    assert ticket_map["fp-1"]["issue_key"] == "SEC-2"
    assert ticket_map["fp-1"]["previous_issue_keys"] == ["SEC-1"]
    assert ticket_map["fp-1"]["reassigned_at"]
    assert ticket_map["fp-2"]["issue_key"] == "SEC-3"


def test_reassign_orphaned_tickets_skips_other_apps_and_projects(repo_root, monkeypatch):
    jira_client = _load_jira_client(repo_root)

    async def fake_issue_exists(cfg, issue_key):
        return False  # would be "deleted" if checked

    monkeypatch.setattr(jira_client, "_issue_exists", fake_issue_exists)

    ticket_map = {
        "fp-other-app": {
            "issue_key": "SEC-9",
            "app": "other-app",
            "project_key": "SEC",
            "closed_at": None,
        },
        "fp-other-project": {
            "issue_key": "OPS-9",
            "app": "example",
            "project_key": "OPS",
            "closed_at": None,
        },
    }
    cfg = {"project_key": "SEC"}

    result = asyncio.run(
        jira_client.reassign_orphaned_tickets("example", cfg, ticket_map)
    )

    assert result["checked"] == 0
    assert result["orphaned"] == []
    assert ticket_map["fp-other-app"]["issue_key"] == "SEC-9"
    assert ticket_map["fp-other-project"]["issue_key"] == "OPS-9"
