"""Epyon Web — project routes (systems made of several applications)."""
from __future__ import annotations

from fastapi import APIRouter
from fastapi import HTTPException
from fastapi import Request
from fastapi import Response

from .. import projects_store as store
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
