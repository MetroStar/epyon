"""Tests for Jira Epic selection (per-scan) and orphaned-ticket reassignment."""
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


def test_suggested_epic_names_cover_all_severities(repo_root):
    jira_client = _load_jira_client(repo_root)
    names = [jira_client.suggested_epic_name(label) for label in jira_client.SEVERITY_EPIC_LABELS]
    assert names == ["Epyon Critical", "Epyon High", "Epyon Medium", "Epyon Low"]


def test_list_project_epics_returns_existing_epics(repo_root, monkeypatch):
    jira_client = _load_jira_client(repo_root)

    class FakeResponse:
        status_code = 200

        def json(self):
            return {
                "issues": [
                    {"key": "IRIS-2603", "fields": {"summary": "Epyon Critical Security Findings - iris"}},
                    {"key": "IRIS-2579", "fields": {"summary": "Epyon High Security Findings - iris"}},
                ]
            }

    class FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def get(self, url, **kwargs):
            assert "search" in url
            assert kwargs["params"]["jql"].startswith('project = "IRIS"')
            return FakeResponse()

    monkeypatch.setattr(jira_client.httpx, "AsyncClient", lambda **kwargs: FakeClient())

    epics = asyncio.run(jira_client.list_project_epics(
        {"base_url": "https://x.atlassian.net", "email": "a@b.com", "api_token": "t"}, "IRIS"
    ))

    assert epics == [
        {"key": "IRIS-2603", "summary": "Epyon Critical Security Findings - iris"},
        {"key": "IRIS-2579", "summary": "Epyon High Security Findings - iris"},
    ]


def test_list_project_epics_returns_empty_without_project_key(repo_root):
    jira_client = _load_jira_client(repo_root)
    assert asyncio.run(jira_client.list_project_epics({}, "")) == []


def test_resolve_epic_selection_prefers_existing_key(repo_root, monkeypatch):
    jira_client = _load_jira_client(repo_root)

    async def fail_if_called(cfg, project_key, name):
        raise AssertionError("should not create a new epic when epic_key is given")

    monkeypatch.setattr(jira_client, "create_epic", fail_if_called)

    result = asyncio.run(
        jira_client.resolve_epic_selection({}, "SEC", "SEC-101", "Epyon Critical")
    )
    assert result == "SEC-101"


def test_resolve_epic_selection_creates_when_only_name_given(repo_root, monkeypatch):
    jira_client = _load_jira_client(repo_root)

    async def fake_create_epic(cfg, project_key, name):
        assert project_key == "SEC"
        assert name == "Epyon Critical"
        return "SEC-900"

    monkeypatch.setattr(jira_client, "create_epic", fake_create_epic)

    result = asyncio.run(
        jira_client.resolve_epic_selection({}, "SEC", None, "Epyon Critical")
    )
    assert result == "SEC-900"


def test_resolve_epic_selection_reuses_existing_epic_matching_name(repo_root, monkeypatch):
    """Re-submitting a quick-create name that already exists in Jira must reuse
    the existing Epic instead of creating a duplicate."""
    jira_client = _load_jira_client(repo_root)

    async def fake_list_project_epics(cfg, project_key):
        return [
            {"key": "IRIS-2579", "summary": "Epyon High Security Findings - iris"},
            {"key": "IRIS-2603", "summary": "Epyon Critical Security Findings - iris"},
        ]

    async def fail_if_called(cfg, project_key, name):
        raise AssertionError("should not create a duplicate epic when a name match exists")

    monkeypatch.setattr(jira_client, "list_project_epics", fake_list_project_epics)
    monkeypatch.setattr(jira_client, "create_epic", fail_if_called)

    result = asyncio.run(
        jira_client.resolve_epic_selection({}, "IRIS", None, "Epyon High")
    )
    assert result == "IRIS-2579"


def test_resolve_epic_selection_returns_none_when_nothing_chosen(repo_root):
    jira_client = _load_jira_client(repo_root)
    result = asyncio.run(jira_client.resolve_epic_selection({}, "SEC", None, None))
    assert result is None


def test_list_project_issue_types_excludes_subtasks(repo_root, monkeypatch):
    jira_client = _load_jira_client(repo_root)

    class FakeResponse:
        status_code = 200
        def json(self):
            return {
                "issueTypes": [
                    {"id": "1", "name": "Task", "subtask": False},
                    {"id": "2", "name": "Bug", "subtask": False},
                    {"id": "3", "name": "Sub-task", "subtask": True},
                ]
            }

    class FakeClient:
        async def __aenter__(self): return self
        async def __aexit__(self, *args): return False
        async def get(self, url, **kwargs):
            assert url.endswith("/issue/createmeta/MID/issuetypes")
            return FakeResponse()

    monkeypatch.setattr(jira_client.httpx, "AsyncClient", lambda **kwargs: FakeClient())
    cfg = {"base_url": "https://x.atlassian.net", "email": "a@b.com", "api_token": "t"}
    types = asyncio.run(jira_client.list_project_issue_types(cfg, "MID"))
    assert types == [{"id": "1", "name": "Task"}, {"id": "2", "name": "Bug"}]


def test_resolve_issue_type_falls_back_when_configured_type_invalid(repo_root, monkeypatch):
    """Reproduces the real failure: a project whose issue type scheme has no
    "Bug" type rejects every ticket with 400 'Specify a valid issue type'."""
    jira_client = _load_jira_client(repo_root)

    async def fake_list_types(cfg, project_key):
        return [{"id": "1", "name": "Task"}, {"id": "2", "name": "Story"}]

    monkeypatch.setattr(jira_client, "list_project_issue_types", fake_list_types)
    cfg = {"base_url": "https://x.atlassian.net", "email": "a@b.com", "api_token": "t"}
    result = asyncio.run(jira_client._resolve_issue_type(cfg, "MID", "Bug"))
    assert result == "Task"  # falls back to the project's first valid type


def test_resolve_issue_type_keeps_valid_configured_type(repo_root, monkeypatch):
    jira_client = _load_jira_client(repo_root)

    async def fake_list_types(cfg, project_key):
        return [{"id": "1", "name": "Task"}, {"id": "2", "name": "Bug"}]

    monkeypatch.setattr(jira_client, "list_project_issue_types", fake_list_types)
    cfg = {"base_url": "https://x.atlassian.net", "email": "a@b.com", "api_token": "t"}
    result = asyncio.run(jira_client._resolve_issue_type(cfg, "MID", "bug"))  # case-insensitive
    assert result == "bug"


def test_create_tickets_batch_passes_issue_type_through(repo_root, tmp_path, monkeypatch):
    jira_client = _load_jira_client(repo_root)
    monkeypatch.setattr(jira_client, "_TICKETS_FILE", tmp_path / "jira-tickets.json")
    monkeypatch.setattr(jira_client, "_RECONCILE_LOCK", None)

    seen = []

    async def fake_create_ticket(cfg, finding, app_name, epic_key=None, issue_type=None):
        seen.append(issue_type)
        return f"SEC-{finding['id']}"

    monkeypatch.setattr(jira_client, "create_ticket", fake_create_ticket)
    findings = {"one": {"id": "CVE-1", "tool": "Grype", "severity": "high"}}
    cfg = {"project_key": "SEC"}

    result = asyncio.run(
        jira_client.create_tickets_batch("example", findings, ["one"], cfg, None, "Task")
    )
    assert seen == ["Task"]
    assert jira_client.read_ticket_map()["one"]["issue_type"] == "Task"


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


def test_create_tickets_batch_links_every_ticket_to_the_same_epic(
    repo_root, tmp_path, monkeypatch
):
    jira_client = _load_jira_client(repo_root)
    monkeypatch.setattr(jira_client, "_TICKETS_FILE", tmp_path / "jira-tickets.json")
    monkeypatch.setattr(jira_client, "_RECONCILE_LOCK", None)

    seen_epic_keys = []

    async def fake_create_ticket(cfg, finding, app_name, epic_key=None, issue_type=None):
        seen_epic_keys.append(epic_key)
        return f"SEC-{finding['id']}"

    monkeypatch.setattr(jira_client, "create_ticket", fake_create_ticket)

    findings = {
        "one": {"id": "CVE-1", "tool": "Grype", "severity": "high"},
        "two": {"id": "CVE-2", "tool": "Trivy", "severity": "critical"},
    }
    cfg = {"project_key": "SEC"}

    result = asyncio.run(
        jira_client.create_tickets_batch("example", findings, ["one", "two"], cfg, "SEC-777")
    )

    assert seen_epic_keys == ["SEC-777", "SEC-777"]
    assert {c["issue_key"] for c in result["created"]} == {"SEC-CVE-1", "SEC-CVE-2"}
    saved = jira_client.read_ticket_map()
    assert saved["one"]["epic_key"] == "SEC-777"
    assert saved["two"]["epic_key"] == "SEC-777"


def test_issue_exists_true_for_live_issue_via_search(repo_root, monkeypatch):
    jira_client = _load_jira_client(repo_root)

    class FakeResponse:
        status_code = 200
        def json(self):
            return {"issues": [{"key": "MID-3078"}]}

    class FakeClient:
        async def __aenter__(self): return self
        async def __aexit__(self, *args): return False
        async def get(self, url, **kwargs):
            assert kwargs["params"]["jql"] == 'project = "MID" AND key = "MID-3078"'
            return FakeResponse()

    monkeypatch.setattr(jira_client.httpx, "AsyncClient", lambda **kwargs: FakeClient())
    assert asyncio.run(jira_client._issue_exists({"base_url": "https://x.atlassian.net", "email": "a@b.com", "api_token": "t"}, "MID-3078")) is True


def test_issue_exists_false_for_trashed_issue_excluded_from_search(repo_root, monkeypatch):
    """Jira Cloud's trash keeps a "deleted" issue retrievable via direct GET
    for ~60 days, but JQL search excludes it immediately — this is why
    `_issue_exists` uses search rather than a direct issue GET."""
    jira_client = _load_jira_client(repo_root)

    class FakeResponse:
        status_code = 200
        def json(self):
            return {"issues": []}  # trashed: excluded from search results

    class FakeClient:
        async def __aenter__(self): return self
        async def __aexit__(self, *args): return False
        async def get(self, url, **kwargs):
            return FakeResponse()

    monkeypatch.setattr(jira_client.httpx, "AsyncClient", lambda **kwargs: FakeClient())
    assert asyncio.run(jira_client._issue_exists({"base_url": "https://x.atlassian.net", "email": "a@b.com", "api_token": "t"}, "MID-3078")) is False


def test_issue_exists_true_on_error_response(repo_root, monkeypatch):
    jira_client = _load_jira_client(repo_root)

    class FakeResponse:
        status_code = 500
        def json(self):
            return {}

    class FakeClient:
        async def __aenter__(self): return self
        async def __aexit__(self, *args): return False
        async def get(self, url, **kwargs):
            return FakeResponse()

    monkeypatch.setattr(jira_client.httpx, "AsyncClient", lambda **kwargs: FakeClient())
    assert asyncio.run(jira_client._issue_exists({"base_url": "https://x.atlassian.net", "email": "a@b.com", "api_token": "t"}, "MID-3078")) is True


def test_reassign_orphaned_tickets_resets_deleted_issue_to_unsubmitted(repo_root, monkeypatch):
    jira_client = _load_jira_client(repo_root)

    async def fake_issue_exists(cfg, issue_key):
        return issue_key != "SEC-1"  # SEC-1 was deleted

    def fail_create_ticket(*args, **kwargs):
        raise AssertionError("orphan detection must never auto-recreate a Jira issue")

    monkeypatch.setattr(jira_client, "_issue_exists", fake_issue_exists)
    monkeypatch.setattr(jira_client, "create_ticket", fail_create_ticket)

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
    assert result["reassigned"] == [{"old": "SEC-1", "new": None}]
    # The orphaned fingerprint's ticket-map entry is removed entirely — the
    # finding goes back to its original, unsubmitted state.
    assert "fp-1" not in ticket_map
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
