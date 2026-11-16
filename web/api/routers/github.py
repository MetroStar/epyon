"""Epyon Web — github routes."""
from __future__ import annotations

from fastapi import APIRouter
from fastapi import HTTPException
from fastapi import Request
from fastapi import Response

from .. import github_sync
from .. import parsers
from .. import main as api_main

router = APIRouter()

@router.get("/api/github-signals-history")
def get_github_signals_history(response: Response):
    api_main._sec_headers(response)
    return api_main._load_gh_history()


# ── GitHub config ─────────────────────────────────────────────

@router.get("/api/github/config")
def github_config_get(response: Response):
    api_main._sec_headers(response)
    cfg = api_main._read_github_config()
    token = cfg.get("token", "")
    return {
        "token_set":    bool(token),
        "from_env":     bool(cfg.get("_from_env")),
        "repos":        cfg.get("repos") or [],
        "last_sync":    cfg.get("last_sync"),
    }


@router.post("/api/github/config")
async def github_config_post(request: Request, response: Response):
    api_main._sec_headers(response)
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, "Invalid JSON")

    if "token" in body or "extra_tokens" in body:
        raise HTTPException(
            400,
            "GitHub tokens cannot be set in the UI; use GITHUB_TOKEN or GH_PAT",
        )

    cfg = api_main._read_github_config()
    if isinstance(body.get("repos"), list):
        cfg["repos"] = [
            r.strip() for r in body["repos"]
            if isinstance(r, str) and api_main._REPO_RE.match(r.strip())
        ]

    api_main._write_github_config(cfg)
    return {"ok": True}


# ── GitHub sync ───────────────────────────────────────────────

@router.post("/api/github/sync")
async def github_sync_post(response: Response):
    api_main._sec_headers(response)
    state = github_sync.get_sync_state()
    if state["status"] == "running":
        return {"ok": False, "message": "Sync already in progress"}
    await github_sync.trigger_sync(
        api_main.GITHUB_CONFIG_FILE, api_main.EPYON_ROOT, parsers.find_scan_dirs,
        on_complete=api_main._invalidate_scan_cache,
    )
    return {"ok": True, "message": "Sync started"}


@router.get("/api/github/sync")
def github_sync_status(response: Response):
    api_main._sec_headers(response)
    return github_sync.get_sync_state()
