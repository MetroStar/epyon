"""Tests for the manual Jira ticket review workflow."""
from __future__ import annotations

import asyncio
import importlib.util
import sys
from pathlib import Path

from fastapi.testclient import TestClient


def _load_jira_client(repo_root: Path):
    module_name = "epyon_jira_client_manual_tests"
    spec = importlib.util.spec_from_file_location(
        module_name, repo_root / "web" / "api" / "jira_client.py"
    )
    if spec is None or spec.loader is None:
        raise ImportError("Unable to load Jira client")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def test_ticket_candidates_cover_all_finding_categories(
    repo_root, parsers, golden_scan_dir
):
    jira_client = _load_jira_client(repo_root)
    scan_data = parsers.load_scan_complete(golden_scan_dir, repo_root)

    candidates = jira_client.build_ticket_candidates(
        scan_data, "goldenapp_testuser", "SEC"
    )

    expected_counts = {
        "vulnerability": len(jira_client.flatten_findings(scan_data["findings"])),
        "misconfiguration": len(
            jira_client.flatten_findings(scan_data["misconfigurations"])
        ),
        "ml": len(jira_client.flatten_findings(scan_data["ml_findings"])),
    }
    actual_counts = {
        category: sum(c["category"] == category for c in candidates)
        for category in expected_counts
    }

    assert actual_counts == expected_counts
    assert all(candidate["fingerprint"] for candidate in candidates)


def test_read_config_resolves_per_application_project_key(
    repo_root, tmp_path, monkeypatch
):
    jira_client = _load_jira_client(repo_root)
    config_file = tmp_path / "jira-config.json"
    config_file.write_text(
        '{"project_key":"DEFAULT","project_keys":{"app-one":"ONE"}}',
        encoding="utf-8",
    )
    monkeypatch.setattr(jira_client, "_CONFIG_FILE", config_file)

    assert jira_client.read_config()["project_key"] == "DEFAULT"
    assert jira_client.read_config("app-one")["project_key"] == "ONE"
    assert jira_client.read_config("app-two")["project_key"] == "DEFAULT"


def test_set_project_key_does_not_persist_environment_credentials(
    repo_root, tmp_path, monkeypatch
):
    jira_client = _load_jira_client(repo_root)
    config_file = tmp_path / "jira-config.json"
    monkeypatch.setattr(jira_client, "_CONFIG_FILE", config_file)
    monkeypatch.setenv("JIRA_API_TOKEN", "environment-secret")
    monkeypatch.setenv("JIRA_BASE_URL", "https://example.atlassian.net")
    monkeypatch.setenv("JIRA_USER_EMAIL", "security@example.com")

    jira_client.set_project_key("app-one", "one")

    saved = config_file.read_text(encoding="utf-8")
    assert "environment-secret" not in saved
    assert jira_client.read_config("app-one")["project_key"] == "ONE"


def test_set_project_key_rejects_invalid_values(repo_root, tmp_path, monkeypatch):
    jira_client = _load_jira_client(repo_root)
    monkeypatch.setattr(jira_client, "_CONFIG_FILE", tmp_path / "jira-config.json")

    try:
        jira_client.set_project_key("app-one", "not valid")
    except ValueError as error:
        assert str(error) == "Invalid Jira project key"
    else:
        raise AssertionError("Invalid project key was accepted")


def test_global_jira_config_endpoint_remains_writable(tmp_path, monkeypatch):
    from web.api import main as api_main

    config_file = tmp_path / "jira-config.json"
    monkeypatch.setattr(api_main.jira_client, "_CONFIG_FILE", config_file)
    monkeypatch.setattr(api_main, "_audit", lambda *args, **kwargs: None)

    response = TestClient(api_main.app).post(
        "/api/jira/config",
        json={"project_key": "DEFAULT"},
    )

    assert response.status_code == 200
    assert api_main.jira_client.read_config()["project_key"] == "DEFAULT"


def test_ticketable_findings_cover_all_categories_and_exclude_suppressed(repo_root):
    jira_client = _load_jira_client(repo_root)
    scan_data = {
        "findings": {"high_findings": [{"id": "CVE-1"}]},
        "misconfigurations": {
            "critical_findings": [{"id": "SECRET-1", "suppressed": True}],
            "medium_findings": [{"id": "CKV-1"}],
        },
        "ml_findings": {"low_findings": [{"id": "ML-1"}]},
    }

    findings = jira_client.flatten_ticketable_findings(scan_data)

    assert [finding["id"] for finding in findings] == ["CVE-1", "CKV-1", "ML-1"]


def test_ticket_candidates_disable_suppressed_and_existing_findings(repo_root):
    jira_client = _load_jira_client(repo_root)
    finding = {
        "tool": "Grype",
        "id": "CVE-2026-1000",
        "severity": "high",
        "package": "example",
        "target": "requirements.txt",
    }
    suppressed = {**finding, "id": "CVE-2026-1001", "suppressed": True}
    scan_data = {
        "findings": {"high_findings": [finding, suppressed]},
        "misconfigurations": {},
        "ml_findings": {},
    }
    fingerprint = jira_client.finding_fingerprint(finding, "example-app", "SEC")

    candidates = jira_client.build_ticket_candidates(
        scan_data,
        "example-app",
        "SEC",
        {fingerprint: {"issue_key": "SEC-42", "closed_at": None}},
    )

    assert candidates[0]["selectable"] is False
    assert candidates[0]["selection_reason"] == "already_ticketed"
    assert candidates[0]["jira_ticket"]["issue_key"] == "SEC-42"
    assert candidates[1]["selectable"] is False
    assert candidates[1]["selection_reason"] == "suppressed"


def test_ticket_candidates_exclude_unapproved_source_fields(repo_root):
    jira_client = _load_jira_client(repo_root)
    scan_data = {
        "findings": {},
        "misconfigurations": {
            "critical_findings": [{
                "tool": "TruffleHog",
                "id": "PrivateKey",
                "severity": "critical",
                "title": "Verified secret: PrivateKey",
                "target": "config.env",
                "raw": "do-not-return",
                "secret": "do-not-return",
                "extra_data": {"token": "do-not-return"},
            }],
        },
        "ml_findings": {},
    }

    candidate = jira_client.build_ticket_candidates(scan_data, "example-app", "SEC")[0]

    assert candidate["tool"] == "TruffleHog"
    assert "raw" not in candidate
    assert "secret" not in candidate
    assert "extra_data" not in candidate


def test_create_tickets_batch_persists_successes_and_is_idempotent(
    repo_root, tmp_path, monkeypatch
):
    jira_client = _load_jira_client(repo_root)
    tickets_file = tmp_path / "jira-tickets.json"
    monkeypatch.setattr(jira_client, "_TICKETS_FILE", tickets_file)
    monkeypatch.setattr(jira_client, "_RECONCILE_LOCK", None)
    findings = {
        "one": {"id": "CVE-1", "tool": "Grype", "severity": "high"},
        "two": {"id": "CVE-2", "tool": "Trivy", "severity": "critical"},
    }
    calls = []

    async def fake_create_ticket(cfg, finding, app_name, epic_key=None, issue_type=None):
        calls.append(finding["id"])
        return "SEC-1" if finding["id"] == "CVE-1" else None

    monkeypatch.setattr(jira_client, "create_ticket", fake_create_ticket)
    cfg = {"project_key": "SEC"}

    first = asyncio.run(
        jira_client.create_tickets_batch("example", findings, ["one", "two"], cfg)
    )
    second = asyncio.run(
        jira_client.create_tickets_batch("example", findings, ["one"], cfg)
    )

    saved = jira_client.read_ticket_map()
    assert first["created"] == [{"fingerprint": "one", "issue_key": "SEC-1"}]
    assert first["failed"] == [
        {"fingerprint": "two", "reason": "jira_creation_failed"}
    ]
    assert second["already_exists"] == [
        {"fingerprint": "one", "issue_key": "SEC-1"}
    ]
    assert calls == ["CVE-1", "CVE-2"]
    assert saved["one"]["creation_source"] == "manual"


def test_reconcile_reopens_when_automatic_creation_is_disabled(repo_root, monkeypatch):
    jira_client = _load_jira_client(repo_root)
    finding = {"id": "CVE-1", "tool": "Grype", "severity": "high"}
    fingerprint = jira_client.finding_fingerprint(finding, "example", "SEC")
    ticket_map = {
        fingerprint: {
            "issue_key": "SEC-1",
            "app": "example",
            "project_key": "SEC",
            "closed_at": "2026-09-17T00:00:00+00:00",
        }
    }

    async def fake_reopen_ticket(cfg, issue_key):
        return True

    monkeypatch.setattr(jira_client, "reopen_ticket", fake_reopen_ticket)
    result = asyncio.run(
        jira_client.reconcile_app(
            "example",
            [finding],
            [],
            {"project_key": "SEC", "create_on_new": False},
            ticket_map,
        )
    )

    assert result["reopened"] == ["SEC-1"]
    assert result["opened"] == []
    assert ticket_map[fingerprint]["closed_at"] is None


def test_reconcile_never_creates_tickets_even_with_legacy_flag(repo_root, monkeypatch):
    jira_client = _load_jira_client(repo_root)
    finding = {"id": "CVE-1", "tool": "Grype", "severity": "critical"}

    async def fail_if_called(cfg, finding, app_name):
        raise AssertionError("Automatic Jira creation must remain disabled")

    monkeypatch.setattr(jira_client, "create_ticket", fail_if_called)
    result = asyncio.run(
        jira_client.reconcile_app(
            "example",
            [finding],
            [],
            {"project_key": "SEC", "create_on_new": True},
            {},
        )
    )

    assert result == {"closed": [], "opened": [], "reopened": [], "errors": []}


def test_jira_candidates_endpoint_returns_scan_findings(
    golden_scan_dir, monkeypatch
):
    from web.api import main as api_main

    monkeypatch.setattr(
        api_main.parsers, "find_scan_dirs", lambda root, days=35: [golden_scan_dir]
    )
    monkeypatch.setattr(
        api_main.jira_client,
        "read_config",
        lambda app_name=None: {"project_key": "SEC"},
    )
    monkeypatch.setattr(api_main.jira_client, "read_ticket_map", lambda: {})

    response = TestClient(api_main.app).get(
        f"/api/scans/{golden_scan_dir.name}/jira-candidates"
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["scan_id"] == golden_scan_dir.name
    assert payload["summary"]["total"] == len(payload["candidates"])
    assert {candidate["category"] for candidate in payload["candidates"]} >= {
        "vulnerability",
        "misconfiguration",
    }


def test_jira_project_endpoint_sets_key_for_scan_application(
    golden_scan_dir, tmp_path, monkeypatch
):
    from web.api import main as api_main

    config_file = tmp_path / "jira-config.json"
    monkeypatch.setattr(api_main.jira_client, "_CONFIG_FILE", config_file)
    monkeypatch.setattr(api_main, "_audit", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        api_main.parsers, "find_scan_dirs", lambda root, days=35: [golden_scan_dir]
    )

    client = TestClient(api_main.app)
    saved = client.post(
        f"/api/scans/{golden_scan_dir.name}/jira-project",
        json={"project_key": "gold"},
    )
    candidates = client.get(
        f"/api/scans/{golden_scan_dir.name}/jira-candidates"
    )

    assert saved.status_code == 200
    assert saved.json()["project_key"] == "GOLD"
    assert candidates.status_code == 200
    assert candidates.json()["project_key"] == "GOLD"


def test_jira_ticket_endpoint_rejects_forged_fingerprint_without_jira_call(
    golden_scan_dir, monkeypatch
):
    from web.api import main as api_main

    monkeypatch.setattr(api_main, "_audit", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        api_main.parsers, "find_scan_dirs", lambda root, days=35: [golden_scan_dir]
    )
    monkeypatch.setattr(
        api_main.jira_client,
        "read_config",
        lambda app_name=None: {
            "base_url": "https://example.atlassian.net",
            "email": "security@example.com",
            "api_token": "test-token",
            "project_key": "SEC",
        },
    )
    monkeypatch.setattr(api_main.jira_client, "read_ticket_map", lambda: {})

    async def fail_if_called(cfg, finding, app_name):
        raise AssertionError("Jira must not be called for an unknown fingerprint")

    monkeypatch.setattr(api_main.jira_client, "create_ticket", fail_if_called)
    response = TestClient(api_main.app).post(
        f"/api/scans/{golden_scan_dir.name}/jira-tickets",
        json={"fingerprints": ["0123456789abcdef|forged"]},
    )

    assert response.status_code == 200
    assert response.json()["ineligible"] == [{
        "fingerprint": "0123456789abcdef|forged",
        "reason": "unknown_fingerprint",
    }]


def test_jira_ticket_endpoint_limits_batch_size(golden_scan_dir):
    from web.api import main as api_main

    response = TestClient(api_main.app).post(
        f"/api/scans/{golden_scan_dir.name}/jira-tickets",
        json={
            "fingerprints": [
                f"{index:016x}|CVE-{index}" for index in range(201)
            ]
        },
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "A maximum of 200 findings can be submitted at once"