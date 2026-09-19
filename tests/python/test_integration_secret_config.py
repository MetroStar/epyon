"""Security tests for environment-only integration credentials."""
from __future__ import annotations

import json

from fastapi.testclient import TestClient


def test_jira_ignores_and_scrubs_file_token(repo_root, tmp_path, monkeypatch):
    from web.api import jira_client

    config_file = tmp_path / "jira-config.json"
    config_file.write_text(json.dumps({
        "base_url": "https://jira.example.com",
        "email": "security@example.com",
        "api_token": "legacy-file-token",
        "project_key": "SEC",
    }), encoding="utf-8")
    monkeypatch.setattr(jira_client, "_CONFIG_FILE", config_file)
    monkeypatch.delenv("JIRA_API_TOKEN", raising=False)

    config = jira_client.read_config()
    persisted = json.loads(config_file.read_text(encoding="utf-8"))

    assert config["api_token"] == ""
    assert "api_token" not in persisted
    assert config_file.stat().st_mode & 0o777 == 0o600


def test_jira_uses_environment_token_without_persisting_it(tmp_path, monkeypatch):
    from web.api import jira_client

    config_file = tmp_path / "jira-config.json"
    config_file.write_text('{"project_key":"SEC"}', encoding="utf-8")
    monkeypatch.setattr(jira_client, "_CONFIG_FILE", config_file)
    monkeypatch.setenv("JIRA_API_TOKEN", "environment-jira-token")

    config = jira_client.read_config()
    jira_client.write_config(config)

    assert config["api_token"] == "environment-jira-token"
    assert "environment-jira-token" not in config_file.read_text(encoding="utf-8")


def test_github_uses_environment_token_and_scrubs_legacy_tokens(tmp_path, monkeypatch):
    from web.api import github_config

    config_file = tmp_path / "github-config.json"
    config_file.write_text(json.dumps({
        "token": "legacy-default-token",
        "repos": ["MetroStar/epyon"],
        "extra_tokens": [{"repos": ["other/repo"], "token": "legacy-extra-token"}],
    }), encoding="utf-8")
    monkeypatch.setenv("GITHUB_TOKEN", "environment-github-token")
    monkeypatch.setenv("GH_PAT", "lower-priority-token")

    config = github_config.read_config(config_file)
    persisted = json.loads(config_file.read_text(encoding="utf-8"))

    assert config["token"] == "environment-github-token"
    assert config["_from_env"] is True
    assert persisted == {"repos": ["MetroStar/epyon"]}
    assert config_file.stat().st_mode & 0o777 == 0o600


def test_github_falls_back_to_gh_pat(tmp_path, monkeypatch):
    from web.api import github_config

    config_file = tmp_path / "github-config.json"
    config_file.write_text('{"repos":[]}', encoding="utf-8")
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.setenv("GH_PAT", "environment-gh-pat")

    assert github_config.read_config(config_file)["token"] == "environment-gh-pat"


def test_openai_uses_environment_key_and_scrubs_legacy_file(tmp_path, monkeypatch):
    from web.api import openai_summary

    config_file = tmp_path / "ai-config.json"
    config_file.write_text(
        '{"api_key":"legacy-openai-key","model":"gpt-4o-mini"}',
        encoding="utf-8",
    )
    monkeypatch.setattr(openai_summary, "AI_CONFIG_FILE", config_file)
    monkeypatch.setenv("OPENAI_API_KEY", "environment-openai-key")

    config = openai_summary.read_ai_config()

    assert openai_summary.get_api_key() == "environment-openai-key"
    assert "api_key" not in config
    assert "legacy-openai-key" not in config_file.read_text(encoding="utf-8")
    assert config_file.stat().st_mode & 0o777 == 0o600


def test_nvd_scrubs_legacy_file_and_reports_environment_status(tmp_path, monkeypatch):
    from web.api import main as api_main

    config_file = tmp_path / "nvd-config.json"
    config_file.write_text('{"api_key":"legacy-nvd-key"}', encoding="utf-8")
    monkeypatch.setattr(api_main, "NVD_CONFIG_FILE", config_file)
    monkeypatch.setenv("NVD_API_KEY", "environment-nvd-key")

    response = TestClient(api_main.app).get("/api/nvd/config")

    assert response.status_code == 200
    assert response.json() == {"key_set": True, "from_env": True}
    assert "legacy-nvd-key" not in config_file.read_text(encoding="utf-8")
    assert config_file.stat().st_mode & 0o777 == 0o600


def test_config_apis_reject_secret_fields(tmp_path, monkeypatch):
    from web.api import main as api_main

    monkeypatch.setattr(api_main, "GITHUB_CONFIG_FILE", tmp_path / "github-config.json")
    monkeypatch.setattr(api_main.jira_client, "_CONFIG_FILE", tmp_path / "jira-config.json")
    monkeypatch.setattr(api_main, "_audit", lambda *args, **kwargs: None)
    client = TestClient(api_main.app)

    github_response = client.post("/api/github/config", json={"token": "github-secret"})
    jira_response = client.post("/api/jira/config", json={"api_token": "jira-secret"})
    ai_response = client.post("/api/ai/config", json={"api_key": "openai-secret"})
    nvd_response = client.post("/api/nvd/config", json={"api_key": "nvd-secret"})

    assert github_response.status_code == 400
    assert jira_response.status_code == 400
    assert ai_response.status_code == 400
    assert nvd_response.status_code == 400
    assert "github-secret" not in github_response.text
    assert "jira-secret" not in jira_response.text
    assert "openai-secret" not in ai_response.text
    assert "nvd-secret" not in nvd_response.text


def test_config_responses_never_return_secret_values(tmp_path, monkeypatch):
    from web.api import main as api_main

    monkeypatch.setattr(api_main, "GITHUB_CONFIG_FILE", tmp_path / "github-config.json")
    monkeypatch.setattr(api_main.jira_client, "_CONFIG_FILE", tmp_path / "jira-config.json")
    monkeypatch.setenv("GITHUB_TOKEN", "environment-github-token")
    monkeypatch.setenv("JIRA_API_TOKEN", "environment-jira-token")
    monkeypatch.setenv("OPENAI_API_KEY", "environment-openai-token")
    monkeypatch.setenv("NVD_API_KEY", "environment-nvd-token")
    client = TestClient(api_main.app)

    github_payload = client.get("/api/github/config").json()
    jira_payload = client.get("/api/jira/config").json()
    ai_payload = client.get("/api/ai/config").json()
    nvd_payload = client.get("/api/nvd/config").json()

    assert github_payload["token_set"] is True
    assert "token" not in github_payload
    assert "token_hint" not in github_payload
    assert jira_payload["token_set"] is True
    assert "api_token" not in jira_payload
    assert "token_hint" not in jira_payload
    assert ai_payload["key_set"] is True
    assert "api_key" not in ai_payload
    assert "key_hint" not in ai_payload
    assert nvd_payload == {"key_set": True, "from_env": True}


def test_settings_ui_has_no_jira_or_github_token_inputs(repo_root):
    source = (repo_root / "web" / "static" / "app.js").read_text(encoding="utf-8")

    assert 'id="gh-token"' not in source
    assert 'class="field-input gh-extra-token"' not in source
    assert 'id="jira-token"' not in source
    assert 'id="ai-key"' not in source
    assert 'id="nvd-key"' not in source


def test_scan_state_file_never_receives_integration_secrets(repo_root):
    source = (repo_root / "web" / "api" / "jobs.py").read_text(encoding="utf-8")

    for variable in ("JIRA_API_TOKEN", "GITHUB_TOKEN", "GH_PAT"):
        assert f'env_lines.append(f"{variable}=' not in source
        assert f'env_lines.append("{variable}=' not in source