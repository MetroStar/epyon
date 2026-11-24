"""Epyon Web — project routes (systems made of several applications)."""
from __future__ import annotations

from fastapi import APIRouter
from fastapi import HTTPException
from fastapi import Request
from fastapi import Response

from .. import projects_rollup
from .. import projects_store as store
from .poam import _latest_poam_scans
from .. import main as api_main

router = APIRouter()


async def _body(request: Request) -> dict:
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, "Invalid JSON")
    if not isinstance(body, dict):
        raise HTTPException(400, "Body must be a JSON object")
    return body


@router.get("/api/projects")
def list_projects(response: Response):
    api_main._sec_headers(response)
    return {"projects": store.load_projects(), "roles": list(store.ROLES)}


@router.post("/api/projects", status_code=201)
async def create_project(request: Request, response: Response):
    api_main._sec_headers(response)
    try:
        return store.create_project(await _body(request))
    except store.ProjectError as e:
        raise HTTPException(400, str(e))


@router.put("/api/projects/{project_id}")
async def update_project(project_id: str, request: Request, response: Response):
    api_main._sec_headers(response)
    try:
        return store.update_project(project_id, await _body(request))
    except store.ProjectError as e:
        raise HTTPException(404 if "not found" in str(e) else 400, str(e))


@router.delete("/api/projects/{project_id}")
def delete_project(project_id: str, response: Response):
    api_main._sec_headers(response)
    try:
        store.delete_project(project_id)
    except store.ProjectError as e:
        raise HTTPException(404, str(e))
    return {"deleted": project_id}


@router.get("/api/projects/{project_id}/stig-rollup")
def project_stig_rollup(project_id: str, response: Response):
    """Per-control STIG status for a project, combining the latest STIG scan of each member repo."""
    api_main._sec_headers(response)
    project = next((p for p in store.load_projects() if p["id"] == project_id), None)
    if not project:
        raise HTTPException(404, "Project not found")
    components, sources = [], []
    for repo in project["repos"]:
        stig_scan, _ = _latest_poam_scans(repo["app"])
        stigs = None
        if stig_scan:
            stigs = api_main._build_stig_entries(stig_scan["scan_id"], api_main._require_scan_dir(stig_scan["scan_id"]))
        components.append({"app": repo["app"], "role": repo["role"], "stigs": stigs})
        sources.append({"app": repo["app"], "role": repo["role"],
                        "scan_id": stig_scan["scan_id"] if stig_scan else None,
                        "timestamp": stig_scan.get("timestamp", "") if stig_scan else None})
    policy, policy_error = projects_rollup.load_policy(
        api_main.EPYON_ROOT / "configuration" / "stig-policy" / "project-roles.json")
    return {"project": {"id": project["id"], "name": project["name"]},
            "components": sources, "policy_error": policy_error,
            "stigs": projects_rollup.rollup(components, policy)}
