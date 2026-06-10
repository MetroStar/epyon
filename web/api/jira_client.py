"""Jira integration for Epyon — auto-close tickets when findings are remediated.

Config is stored in  web/data/jira-config.json.
Ticket map           web/data/jira-tickets.json  (fingerprint → issue metadata)

Credentials are resolved in priority order:
  1. web/data/jira-config.json  (saved via Settings UI)
  2. Environment variables      (JIRA_BASE_URL, JIRA_USER_EMAIL, JIRA_API_TOKEN,
                                 JIRA_PROJECT_KEY) — same names used by the
                                 GitHub Actions workflow so repo secrets work
                                 without any manual configuration.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

# Prevents concurrent reconcile calls (auto post-scan + manual sync) from
# reading the same stale ticket map and creating duplicate Jira tickets.
_RECONCILE_LOCK: asyncio.Lock | None = None


def _get_lock() -> asyncio.Lock:
    """Return (or lazily create) the module-level reconcile lock.

    Deferring creation to first use avoids 'no current event loop' errors
    that occur if the lock is instantiated at import time in some test
    environments.
    """
    global _RECONCILE_LOCK
    if _RECONCILE_LOCK is None:
        _RECONCILE_LOCK = asyncio.Lock()
    return _RECONCILE_LOCK

# ── Paths (set once at import time, same convention as openai_summary.py) ────
_HERE         = Path(__file__).parent
_DATA_DIR     = (_HERE / ".." / "data").resolve()
_CONFIG_FILE  = _DATA_DIR / "jira-config.json"
_TICKETS_FILE = _DATA_DIR / "jira-tickets.json"


# ── Config helpers ────────────────────────────────────────────

def _env_config() -> dict:
    """Build a config dict from environment variables (same names as the
    GitHub Actions workflow so repo secrets require zero extra setup)."""
    base_url  = os.environ.get("JIRA_BASE_URL", "").strip()
    email     = os.environ.get("JIRA_USER_EMAIL", "").strip()
    token     = os.environ.get("JIRA_API_TOKEN", "").strip()
    project   = os.environ.get("JIRA_PROJECT_KEY", "").strip()
    if not (base_url and email and token):
        return {}
    return {
        "base_url":        base_url,
        "email":           email,
        "api_token":       token,
        "project_key":     project,
        "issue_type":      os.environ.get("JIRA_ISSUE_TYPE", "Bug").strip(),
        "done_transition":  os.environ.get("JIRA_DONE_TRANSITION", "Done").strip(),
        "min_severity":    os.environ.get("JIRA_MIN_SEVERITY", "high").strip(),
        "auto_close":      True,
        "create_on_new":   False,
        "_from_env":       True,   # marker so the UI can show "from environment"
    }


def read_config() -> dict:
    """Return merged config: file values take precedence over env vars."""
    file_cfg: dict = {}
    try:
        if _CONFIG_FILE.exists():
            file_cfg = json.loads(_CONFIG_FILE.read_text(encoding="utf-8"))
    except Exception:
        pass
    if file_cfg:
        # If the file has credentials, use it as-is
        if file_cfg.get("api_token"):
            return file_cfg
        # File exists but is incomplete — merge env vars as fallback for missing keys
        merged = {**_env_config(), **file_cfg}
        return merged
    return _env_config()


def write_config(cfg: dict) -> None:
    _CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    _CONFIG_FILE.write_text(json.dumps(cfg, indent=2), encoding="utf-8")


# ── Ticket map helpers ────────────────────────────────────────

def read_ticket_map() -> dict:
    """Return dict of fingerprint → {issue_key, app, created_at, closed_at, ...}."""
    try:
        if _TICKETS_FILE.exists():
            return json.loads(_TICKETS_FILE.read_text(encoding="utf-8"))
    except Exception:
        pass
    return {}


def write_ticket_map(tmap: dict) -> None:
    _TICKETS_FILE.parent.mkdir(parents=True, exist_ok=True)
    _TICKETS_FILE.write_text(json.dumps(tmap, indent=2), encoding="utf-8")


# ── Finding fingerprint ───────────────────────────────────────

def _norm_path(v: str) -> str:
    """Reduce absolute paths to their last two components for fingerprint stability.

    Tools like Checkov, ClamAV, and TruffleHog report absolute paths that
    include the temp clone directory (e.g. /tmp/clone-abc123/src/app.py).
    That prefix changes every scan, so including it raw in the fingerprint
    produces a new key — and a new Jira ticket — for the same finding on
    every run.  Normalising to the last two path components (src/app.py)
    keeps the fingerprint stable while still distinguishing different files.
    Non-absolute values are returned unchanged.
    """
    if not v or not v.startswith("/"):
        return v
    parts = [p for p in Path(v).parts if p != "/"]
    return "/".join(parts[-2:]) if len(parts) >= 2 else (parts[-1] if parts else v)


def finding_fingerprint(finding: dict, app_name: str) -> str:
    """Stable key for a finding that is consistent across scans.

    Identity is: tool + CVE/check id + package + target + app_name.
    Absolute paths in package/target are normalised to their last two
    components so that temp-clone prefixes do not break stability.
    Returns a short SHA-256 hex prefix combined with the id for readability.
    """
    parts = "|".join([
        (finding.get("tool")    or "").strip(),
        (finding.get("id")      or "").strip(),
        _norm_path((finding.get("package") or "").strip()),
        _norm_path((finding.get("target")  or "").strip()),
        app_name.strip(),
    ])
    h   = hashlib.sha256(parts.encode()).hexdigest()[:16]
    fid = (finding.get("id") or "unknown")[:40]
    return f"{h}|{fid}"


def flatten_findings(findings_dict: dict) -> list[dict]:
    """Flatten a parse_scan_findings() / load_enriched_findings() result."""
    out: list[dict] = []
    for sev in ("critical", "high", "medium", "low"):
        out.extend(findings_dict.get(f"{sev}_findings", []))
    return out


# ── Jira REST API helpers ─────────────────────────────────────

def _auth(cfg: dict) -> httpx.BasicAuth:
    return httpx.BasicAuth(cfg["email"], cfg["api_token"])


def _base(cfg: dict) -> str:
    return cfg["base_url"].rstrip("/")


async def test_connection(cfg: dict) -> dict:
    """Ping Jira and return {ok, message}."""
    for k in ("base_url", "email", "api_token"):
        if not cfg.get(k):
            return {"ok": False, "message": f"Missing required field: {k}"}
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(
                f"{_base(cfg)}/rest/api/3/myself",
                auth=_auth(cfg),
                headers={"Accept": "application/json"},
            )
        if r.status_code == 200:
            display = r.json().get("displayName", cfg["email"])
            return {"ok": True, "message": f"Connected as {display}"}
        return {"ok": False, "message": f"HTTP {r.status_code}: {r.text[:300]}"}
    except Exception as exc:
        return {"ok": False, "message": str(exc)}


async def create_ticket(cfg: dict, finding: dict, app_name: str) -> str | None:
    """Create a Jira issue for a finding. Returns the issue key or None."""
    project_key = (cfg.get("project_key") or "").strip()
    if not project_key:
        return None

    sev   = (finding.get("severity") or "unknown").upper()
    tool  = finding.get("tool")  or "Unknown"
    fid   = finding.get("id")    or "Unknown"
    pkg   = finding.get("package") or ""
    ver   = finding.get("version") or ""
    fixed = finding.get("fixed_version") or ""
    title = finding.get("title") or fid
    refs  = finding.get("references") or []

    summary = f"[{sev}][{tool}] {fid} in {pkg or app_name}"[:254]

    body_lines = [
        f"Detected by Epyon scanner in application *{app_name}*.",
        f"",
        f"*Severity:* {sev}",
        f"*Finding ID:* {fid}",
        f"*Title:* {title}",
    ]
    if pkg:
        body_lines.append(f"*Package:* {pkg}@{ver}" if ver else f"*Package:* {pkg}")
    if fixed:
        body_lines.append(f"*Fix available in:* {fixed}")
    if refs:
        body_lines.append("*References:*")
        body_lines.extend(f"  - {r}" for r in refs[:3])

    description: dict[str, Any] = {
        "version": 1,
        "type": "doc",
        "content": [
            {
                "type": "paragraph",
                "content": [{"type": "text", "text": "\n".join(body_lines)}],
            }
        ],
    }

    issue_type = (cfg.get("issue_type") or "Bug").strip()
    labels = ["epyon", "security", tool.lower().replace(" ", "-"),
              sev.lower(), app_name.lower().replace(" ", "-")]

    payload: dict[str, Any] = {
        "fields": {
            "project":     {"key": project_key},
            "summary":     summary,
            "description": description,
            "issuetype":   {"name": issue_type},
            "labels":      labels,
        }
    }

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.post(
                f"{_base(cfg)}/rest/api/3/issue",
                auth=_auth(cfg),
                headers={"Accept": "application/json", "Content-Type": "application/json"},
                json=payload,
            )
        if r.status_code == 201:
            return r.json().get("key")
        return None
    except Exception:
        return None


async def _find_done_transition_id(cfg: dict, issue_key: str, done_name: str) -> str | None:
    """Return the transition ID whose name matches done_name (case-insensitive).
    Falls back through common 'closed' state names if exact match is not found.
    """
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(
                f"{_base(cfg)}/rest/api/3/issue/{issue_key}/transitions",
                auth=_auth(cfg),
                headers={"Accept": "application/json"},
            )
        if r.status_code != 200:
            return None
        transitions = r.json().get("transitions", [])
        # Exact match first
        for t in transitions:
            if t.get("name", "").lower() == done_name.lower():
                return t["id"]
        # Fallbacks
        for fallback in ("done", "close issue", "closed", "resolved"):
            for t in transitions:
                if t.get("name", "").lower() == fallback:
                    return t["id"]
    except Exception:
        pass
    return None


async def close_ticket(cfg: dict, issue_key: str) -> bool:
    """Transition a Jira issue to its 'Done' state. Returns True on success."""
    done_name = (cfg.get("done_transition") or "Done").strip()
    tid = await _find_done_transition_id(cfg, issue_key, done_name)
    if not tid:
        return False
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.post(
                f"{_base(cfg)}/rest/api/3/issue/{issue_key}/transitions",
                auth=_auth(cfg),
                headers={"Accept": "application/json", "Content-Type": "application/json"},
                json={"transition": {"id": tid}},
            )
        return r.status_code == 204
    except Exception:
        return False


# ── Reconciliation ────────────────────────────────────────────

_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


async def reconcile_app(
    app_name: str,
    current_findings: list[dict],
    previous_findings: list[dict],
    cfg: dict,
    ticket_map: dict,
) -> dict:
    """Compare current vs previous scan findings for one application.

    Remediated (in previous but absent in current):
        → close the tracked Jira ticket if one exists and is still open.

    New (in current but absent in previous) — only when cfg.create_on_new is True:
        → create a new Jira ticket if severity meets cfg.min_severity.

    Mutates *ticket_map* in-place and returns a summary dict.
    """
    result: dict = {"closed": [], "opened": [], "errors": []}

    create_on_new = bool(cfg.get("create_on_new", False))
    min_sev       = (cfg.get("min_severity") or "high").lower()
    min_rank      = _SEV_RANK.get(min_sev, 1)

    now_ts = datetime.now(timezone.utc).isoformat()

    current_fps  = {finding_fingerprint(f, app_name): f for f in current_findings}
    previous_fps = {finding_fingerprint(f, app_name): f for f in previous_findings}

    # ── Remediated findings ──────────────────────────────────
    for fp, finding in previous_fps.items():
        if fp in current_fps:
            continue
        entry = ticket_map.get(fp)
        if not entry:
            continue
        issue_key = entry.get("issue_key", "")
        if not issue_key or entry.get("closed_at"):
            continue  # already closed or never tracked
        ok = await close_ticket(cfg, issue_key)
        if ok:
            ticket_map[fp]["closed_at"] = now_ts
            result["closed"].append(issue_key)
        else:
            result["errors"].append(f"Failed to close {issue_key}")

    # ── New findings (opt-in) ────────────────────────────────
    if create_on_new:
        for fp, finding in current_fps.items():
            if fp in previous_fps:
                continue
            if fp in ticket_map:
                continue
            sev_rank = _SEV_RANK.get((finding.get("severity") or "low").lower(), 3)
            if sev_rank > min_rank:
                continue
            issue_key = await create_ticket(cfg, finding, app_name)
            if issue_key:
                ticket_map[fp] = {
                    "issue_key":  issue_key,
                    "app":        app_name,
                    "finding_id": finding.get("id", ""),
                    "severity":   finding.get("severity", ""),
                    "tool":       finding.get("tool", ""),
                    "created_at": now_ts,
                    "closed_at":  None,
                }
                result["opened"].append(issue_key)
            else:
                result["errors"].append(
                    f"Failed to create ticket for {finding.get('id', fp[:12])}"
                )

    return result


async def reconcile_and_save(
    app_name: str,
    current_findings: list[dict],
    previous_findings: list[dict],
    cfg: dict,
) -> dict:
    """Atomically read → reconcile → write the ticket map under a shared lock.

    Both the automatic post-scan hook and the manual /api/jira/sync endpoint
    call this function.  The lock prevents the race condition where both paths
    read the same stale ticket map concurrently, each create tickets for the
    same new findings, and the second write silently discards the first's
    entries — resulting in duplicate Jira issues.
    """
    async with _get_lock():
        ticket_map = read_ticket_map()
        result = await reconcile_app(
            app_name, current_findings, previous_findings, cfg, ticket_map
        )
        write_ticket_map(ticket_map)
    return result
