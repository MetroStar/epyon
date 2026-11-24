"""Projects: a system / ATO boundary made of one or more applications (repos).

A project lists member applications, each tagged with a role. An application can
belong to several projects. Projects are stored in ``web/data/projects.json``
(the persisted data volume); the file holds no secrets.
"""
from __future__ import annotations

import json
import re
import threading
from datetime import datetime, timezone
from pathlib import Path

PROJECTS_FILE = (Path(__file__).resolve().parent / ".." / "data" / "projects.json").resolve()

ROLES = ("frontend", "backend", "infra", "other")
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
_APP_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_\-.]*$")
_JIRA_KEY_RE = re.compile(r"^[A-Z][A-Z0-9]{1,9}$")

_lock = threading.Lock()


class ProjectError(ValueError):
    """Invalid project input or a missing project."""


def slugify(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:63]


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_projects() -> list[dict]:
    try:
        data = json.loads(PROJECTS_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    return data if isinstance(data, list) else []


def _save(projects: list[dict]) -> None:
    PROJECTS_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = PROJECTS_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(projects, indent=2), encoding="utf-8")
    tmp.replace(PROJECTS_FILE)


def _clean(body: dict) -> dict:
    name = str(body.get("name") or "").strip()
    if not name or len(name) > 80:
        raise ProjectError("name is required (80 characters or fewer)")
    description = str(body.get("description") or "").strip()[:500]
    jira_key = str(body.get("jira_project_key") or "").strip().upper()
    if jira_key and not _JIRA_KEY_RE.match(jira_key):
        raise ProjectError("jira_project_key must be 2-10 letters or digits, starting with a letter")
    repos, seen = [], set()
    for item in body.get("repos") or []:
        if not isinstance(item, dict):
            raise ProjectError("each repo must be an object with app and role")
        app = str(item.get("app") or "").strip()
        role = str(item.get("role") or "other").strip().lower()
        if not _APP_RE.match(app):
            raise ProjectError(f"invalid application name: {app!r}")
        if role not in ROLES:
            raise ProjectError(f"role must be one of: {', '.join(ROLES)}")
        if app in seen:
            raise ProjectError(f"application listed twice: {app}")
        seen.add(app)
        repos.append({"app": app, "role": role})
    return {"name": name, "description": description, "jira_project_key": jira_key, "repos": repos}


def create_project(body: dict) -> dict:
    fields = _clean(body)
    pid = slugify(fields["name"])
    if not _ID_RE.match(pid):
        raise ProjectError("name must contain letters or digits")
    with _lock:
        projects = load_projects()
        if any(p.get("id") == pid for p in projects):
            raise ProjectError(f"a project named {fields['name']!r} already exists")
        now = _now()
        project = {"id": pid, **fields, "created_at": now, "updated_at": now}
        _save(projects + [project])
    return project


def update_project(pid: str, body: dict) -> dict:
    fields = _clean(body)
    with _lock:
        projects = load_projects()
        for p in projects:
            if p.get("id") == pid:
                p.update(fields)
                p["updated_at"] = _now()
                _save(projects)
                return p
    raise ProjectError(f"project not found: {pid}")


def delete_project(pid: str) -> None:
    with _lock:
        projects = load_projects()
        kept = [p for p in projects if p.get("id") != pid]
        if len(kept) == len(projects):
            raise ProjectError(f"project not found: {pid}")
        _save(kept)
