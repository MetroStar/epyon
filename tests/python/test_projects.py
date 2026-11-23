"""Projects API: create, edit, delete; a repo can belong to several projects."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "web"))

from api import main as api_main  # noqa: E402
from api import projects_store  # noqa: E402


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(projects_store, "PROJECTS_FILE", tmp_path / "projects.json")
    return TestClient(api_main.app)


def _body(**over):
    body = {"name": "ATO Ready", "jira_project_key": "ato",
            "repos": [{"app": "midas", "role": "backend"}, {"app": "midas-ui", "role": "frontend"}]}
    body.update(over)
    return body


def test_create_and_list(client):
    r = client.post("/api/projects", json=_body())
    assert r.status_code == 201
    project = r.json()
    assert project["id"] == "ato-ready"
    assert project["jira_project_key"] == "ATO"
    listed = client.get("/api/projects").json()
    assert [p["id"] for p in listed["projects"]] == ["ato-ready"]
    assert "frontend" in listed["roles"]


def test_repo_can_belong_to_several_projects(client):
    client.post("/api/projects", json=_body())
    r = client.post("/api/projects", json=_body(name="Platform", repos=[{"app": "midas-ui", "role": "frontend"}]))
    assert r.status_code == 201
    assert len(client.get("/api/projects").json()["projects"]) == 2


@pytest.mark.parametrize("bad", [
    {"name": ""},
    {"jira_project_key": "1bad"},
    {"repos": [{"app": "../etc", "role": "backend"}]},
    {"repos": [{"app": "midas", "role": "wizard"}]},
    {"repos": [{"app": "midas", "role": "backend"}, {"app": "midas", "role": "frontend"}]},
])
def test_rejects_invalid_input(client, bad):
    assert client.post("/api/projects", json=_body(**bad)).status_code == 400


def test_duplicate_name_rejected(client):
    client.post("/api/projects", json=_body())
    assert client.post("/api/projects", json=_body()).status_code == 400


def test_update_and_delete(client):
    client.post("/api/projects", json=_body())
    r = client.put("/api/projects/ato-ready", json=_body(repos=[{"app": "midas", "role": "backend"}]))
    assert r.status_code == 200
    assert r.json()["repos"] == [{"app": "midas", "role": "backend"}]
    assert client.put("/api/projects/missing", json=_body()).status_code == 404
    assert client.delete("/api/projects/ato-ready").status_code == 200
    assert client.delete("/api/projects/ato-ready").status_code == 404
