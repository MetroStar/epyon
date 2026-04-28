"""
GitHub Actions artifact sync for Epyon Web.
Downloads scan artifacts from configured GitHub repositories.
"""
from __future__ import annotations

import asyncio
import json
import re
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

SCAN_ID_RE = re.compile(
    r"^[a-zA-Z0-9][a-zA-Z0-9_-]*_\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}$"
)

_sync_state: dict[str, Any] = {
    "status": "idle", "started_at": None, "result": None, "error": None
}


def get_sync_state() -> dict:
    return dict(_sync_state)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _client(token: str) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        headers={
            "Authorization":        f"Bearer {token}",
            "Accept":               "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent":           "epyon-web/3.0.0",
        },
        follow_redirects=False,
        timeout=60.0,
    )


async def _github_get(client: httpx.AsyncClient, path: str) -> dict:
    resp = await client.get(f"https://api.github.com{path}")
    resp.raise_for_status()
    return resp.json()


async def _download_artifact(url: str, token: str, dest: Path) -> None:
    async with httpx.AsyncClient(follow_redirects=False, timeout=120.0) as plain_client:
        remaining_url = url
        for _ in range(10):
            parsed = httpx.URL(remaining_url)
            is_github_api = parsed.host == "api.github.com"
            headers = {
                "User-Agent": "epyon-web/3.0.0",
                **({"Authorization": f"Bearer {token}",
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28"}
                   if is_github_api else {}),
            }
            resp = await plain_client.get(remaining_url, headers=headers)
            if resp.status_code in (301, 302, 307, 308):
                remaining_url = resp.headers["location"]
                continue
            resp.raise_for_status()
            dest.write_bytes(resp.content)
            return
    raise RuntimeError("Too many redirects downloading artifact")


async def run_github_sync(
    config_path: Path,
    epyon_root: Path,
    find_scan_dirs_fn: Any,
) -> dict:
    global _sync_state

    cfg = _read_config(config_path)
    token = cfg.get("token")
    if not token:
        raise ValueError("GitHub token not configured")
    repos = [r.strip() for r in (cfg.get("repos") or []) if r and "/" in r]
    if not repos:
        raise ValueError("No repositories configured")

    result: dict = {"synced": [], "skipped": [], "failed": []}
    existing_ids = {d.name for d in find_scan_dirs_fn(epyon_root)}

    async with _client(token) as gh:
        for repo_spec in repos:
            owner, repo = repo_spec.split("/", 1)
            try:
                runs_data = await _github_get(
                    gh, f"/repos/{owner}/{repo}/actions/runs?status=completed&per_page=30"
                )
                for run in runs_data.get("workflow_runs") or []:
                    arts_data = await _github_get(
                        gh,
                        f"/repos/{owner}/{repo}/actions/runs/{run['id']}/artifacts?per_page=50",
                    )
                    for artifact in arts_data.get("artifacts") or []:
                        name = artifact.get("name", "")
                        if not SCAN_ID_RE.match(name):
                            continue
                        if name.startswith("metrics-"):
                            continue
                        if artifact.get("expired"):
                            continue
                        if name in existing_ids:
                            result["skipped"].append(name)
                            continue

                        tmp_zip = Path(tempfile.mktemp(suffix=".zip", prefix="epyon-gh-"))
                        try:
                            await _download_artifact(
                                f"https://api.github.com/repos/{owner}/{repo}"
                                f"/actions/artifacts/{artifact['id']}/zip",
                                token, tmp_zip,
                            )
                            dest_dir = epyon_root / "scans" / name
                            dest_dir.mkdir(parents=True, exist_ok=True)
                            with zipfile.ZipFile(tmp_zip) as zf:
                                zf.extractall(dest_dir)

                            ci_meta = {
                                "source":      "github",
                                "repo":        f"{owner}/{repo}",
                                "run_id":      run["id"],
                                "artifact_id": artifact["id"],
                                "workflow":    run.get("name", ""),
                                "event":       run.get("event", ""),
                                "branch":      run.get("head_branch", ""),
                                "commit":      (run.get("head_sha") or "")[:7],
                                "synced_at":   _now(),
                            }
                            (dest_dir / "ci-metadata.json").write_text(
                                json.dumps(ci_meta, indent=2)
                            )
                            result["synced"].append(name)
                            existing_ids.add(name)
                        except Exception as exc:
                            result["failed"].append({"scan_id": name, "error": str(exc)})
                        finally:
                            try:
                                tmp_zip.unlink()
                            except OSError:
                                pass
            except Exception as exc:
                result["failed"].append({"repo": f"{owner}/{repo}", "error": str(exc)})

    cfg["last_sync"] = _now()
    _write_config(config_path, cfg)
    return result


async def trigger_sync(
    config_path: Path,
    epyon_root: Path,
    find_scan_dirs_fn: Any,
) -> None:
    global _sync_state
    if _sync_state["status"] == "running":
        return
    _sync_state = {"status": "running", "started_at": _now(), "result": None, "error": None}

    async def _run() -> None:
        global _sync_state
        try:
            r = await run_github_sync(config_path, epyon_root, find_scan_dirs_fn)
            _sync_state = {"status": "done", "started_at": _sync_state["started_at"],
                           "result": r, "error": None}
        except Exception as exc:
            _sync_state = {"status": "error", "started_at": _sync_state["started_at"],
                           "result": None, "error": str(exc)}

    asyncio.create_task(_run())


def _read_config(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _write_config(path: Path, cfg: dict) -> None:
    path.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
