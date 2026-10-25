"""Jira integration for Epyon — auto-close tickets when findings are remediated.

Config is stored in  web/data/jira-config.json.
Ticket map           web/data/jira-tickets.json  (fingerprint → issue metadata)

Credentials are resolved in priority order:
  1. web/data/jira-config.json  (saved via Settings UI)
  2. Environment variables      (JIRA_BASE_URL, JIRA_USER_EMAIL, JIRA_API_TOKEN,
                                 JIRA_PROJECT_KEY) — same names used by the
                                 GitHub Actions workflow so repo secrets work
                                 without any manual configuration.

Environment variables (all optional except credentials):
  JIRA_BASE_URL           — Jira Cloud base URL (required, e.g., https://org.atlassian.net)
  JIRA_USER_EMAIL         — Jira user email (required)
  JIRA_API_TOKEN          — Jira API token (required)
  JIRA_PROJECT_KEY        — Jira project key (e.g., SEC)
  JIRA_ISSUE_TYPE         — Issue type for new tickets (default: Bug)
  JIRA_DONE_TRANSITION    — Transition name to close tickets (default: Done)

Note: Tickets are ALWAYS automatically closed when findings are remediated.
      This behavior is not configurable to ensure proper ticket lifecycle management.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

logger = logging.getLogger(__name__)

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
    """Build environment overrides; the API token is never read from disk."""
    fields = {
        "base_url": os.environ.get("JIRA_BASE_URL", "").strip(),
        "email": os.environ.get("JIRA_USER_EMAIL", "").strip(),
        "api_token": os.environ.get("JIRA_API_TOKEN", "").strip(),
        "project_key": os.environ.get("JIRA_PROJECT_KEY", "").strip(),
        "issue_type": os.environ.get("JIRA_ISSUE_TYPE", "").strip(),
        "done_transition": os.environ.get("JIRA_DONE_TRANSITION", "").strip(),
    }
    return {key: value for key, value in fields.items() if value}


def read_config(app_name: str | None = None) -> dict:
    """Return non-secret file settings with environment credential overrides."""
    file_cfg: dict = {}
    had_legacy_token = False
    try:
        if _CONFIG_FILE.exists():
            file_cfg = json.loads(_CONFIG_FILE.read_text(encoding="utf-8"))
            had_legacy_token = "api_token" in file_cfg
    except Exception:
        pass
    file_cfg.pop("api_token", None)
    if had_legacy_token:
        write_config(file_cfg)
    config = {**file_cfg, **_env_config()}
    config["api_token"] = os.environ.get("JIRA_API_TOKEN", "").strip()
    config["_from_env"] = bool(config["api_token"])

    if app_name:
        project_keys = config.get("project_keys") or {}
        override = project_keys.get(app_name)
        if isinstance(override, str) and override.strip():
            config = {**config, "project_key": override.strip().upper()}
    return config


def write_config(cfg: dict) -> None:
    safe_config = {
        key: value for key, value in cfg.items()
        if key not in {"api_token", "_from_env"}
    }
    _CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    _CONFIG_FILE.write_text(json.dumps(safe_config, indent=2), encoding="utf-8")
    _CONFIG_FILE.chmod(0o600)


def set_project_key(app_name: str, project_key: str) -> None:
    """Persist an app project override without copying environment credentials."""
    normalized_key = project_key.strip().upper()
    if not re.fullmatch(r"[A-Z][A-Z0-9]{0,9}", normalized_key):
        raise ValueError("Invalid Jira project key")
    file_cfg: dict = {}
    try:
        if _CONFIG_FILE.exists():
            loaded = json.loads(_CONFIG_FILE.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                file_cfg = loaded
    except Exception:
        pass
    project_keys = file_cfg.get("project_keys")
    if not isinstance(project_keys, dict):
        project_keys = {}
    project_keys[app_name] = normalized_key
    file_cfg["project_keys"] = project_keys
    write_config(file_cfg)


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
    temporary = _TICKETS_FILE.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(tmap, indent=2), encoding="utf-8")
    temporary.replace(_TICKETS_FILE)


# ── Epic lookup & linking ─────────────────────────────────────
# Epic assignment is chosen per ticket-creation batch (i.e. per scan, when
# the user clicks "Create Jira Tickets") rather than persisted globally.
# The severity-based Epics below are just suggested names for a "create new"
# option — Epyon always lets the user pick from Jira's real existing Epics
# first so duplicates aren't created.

SEVERITY_EPIC_LABELS = ("Critical", "High", "Medium", "Low")


def suggested_epic_name(severity_label: str) -> str:
    """Default name offered when the user chooses to create a new Epic."""
    return f"Epyon {severity_label}"


async def list_project_epics(cfg: dict, project_key: str) -> list[dict]:
    """Return existing Epic issues in a Jira project as [{key, summary}, ...],
    newest first. Used to populate the Epic picker so users can reuse an
    existing Epic instead of creating a duplicate.
    """
    if not project_key:
        return []
    jql = f'project = "{project_key}" AND issuetype = Epic ORDER BY created DESC'
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(
                # NOTE: the legacy `/rest/api/3/search` endpoint was removed by
                # Atlassian on 2025-08-01; `/rest/api/3/search/jql` is its
                # replacement (same JQL semantics, `nextPageToken` pagination).
                f"{_base(cfg)}/rest/api/3/search/jql",
                auth=_auth(cfg),
                headers={"Accept": "application/json"},
                params={"jql": jql, "fields": "summary", "maxResults": 100},
            )
        if r.status_code != 200:
            return []
        return [
            {"key": issue.get("key"), "summary": (issue.get("fields") or {}).get("summary", "")}
            for issue in r.json().get("issues", [])
        ]
    except Exception:
        return []


_ISSUE_TYPE_CACHE: dict[tuple[str, str], list[dict]] = {}  # (base_url, project_key) → issue types


async def list_project_issue_types(cfg: dict, project_key: str) -> list[dict]:
    """Return creatable, non-subtask issue types for a project as
    [{id, name}, ...]. Used to validate/repair the configured issue type
    before ticket creation.
    """
    if not project_key:
        return []
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(
                f"{_base(cfg)}/rest/api/3/issue/createmeta/{project_key}/issuetypes",
                auth=_auth(cfg),
                headers={"Accept": "application/json"},
            )
        if r.status_code != 200:
            return []
        return [
            {"id": t.get("id"), "name": t.get("name")}
            for t in r.json().get("issueTypes", [])
            if not t.get("subtask")
        ]
    except Exception:
        return []


async def _resolve_issue_type(cfg: dict, project_key: str, requested: str) -> str:
    """Return an issue type name valid for creation in this project.

    Falls back to the project's first non-subtask issue type if the
    configured name (default "Bug") isn't part of this project's issue type
    scheme — a common misconfiguration that otherwise makes every ticket
    creation fail with a 400 ("Specify a valid issue type") and no way to
    recover without a manual Settings change.
    """
    cache_key = (_base(cfg), project_key)
    types = _ISSUE_TYPE_CACHE.get(cache_key)
    if types is None:
        types = await list_project_issue_types(cfg, project_key)
        _ISSUE_TYPE_CACHE[cache_key] = types
    if not types:
        return requested  # couldn't look it up — try the configured value as-is
    if any((t.get("name") or "").strip().lower() == requested.strip().lower() for t in types):
        return requested
    fallback = types[0].get("name") or requested
    logger.warning(
        "Configured Jira issue type %r is not valid for project %s; falling back to %r. "
        "Available issue types: %s",
        requested, project_key, fallback, [t.get("name") for t in types],
    )
    return fallback


_FIELD_CACHE: dict[str, dict] = {}  # base_url → {"epic_link": id|None, "epic_name": id|None}


async def _discover_epic_fields(cfg: dict) -> dict:
    """Look up the custom field IDs Jira uses for 'Epic Link' / 'Epic Name'.

    Company-managed (classic) projects expose these as custom fields whose
    IDs vary per Jira instance. Team-managed projects have no such fields and
    use the standard 'parent' field instead — callers fall back accordingly.
    """
    base = _base(cfg)
    if base in _FIELD_CACHE:
        return _FIELD_CACHE[base]
    result = {"epic_link": None, "epic_name": None}
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(
                f"{base}/rest/api/3/field",
                auth=_auth(cfg),
                headers={"Accept": "application/json"},
            )
        if r.status_code == 200:
            for field in r.json():
                name = (field.get("name") or "").strip().lower()
                if name == "epic link":
                    result["epic_link"] = field.get("id")
                elif name == "epic name":
                    result["epic_name"] = field.get("id")
    except Exception:
        pass
    _FIELD_CACHE[base] = result
    return result


async def _resolve_epic_issue_type(cfg: dict, project_key: str) -> str:
    """Return the issue type name this project actually uses for Epics.

    Most projects call it exactly "Epic", but the createmeta list is the
    source of truth — some instances rename/relabel it (Atlassian has also
    renamed the "Epic" hierarchy level to "Parent" in some team-managed
    projects), and using an invalid name makes Jira reject the create call
    with 400 ("Specify a valid issue type"), which previously surfaced only
    as an opaque 502 in the UI.
    """
    cache_key = (_base(cfg), project_key)
    types = _ISSUE_TYPE_CACHE.get(cache_key)
    if types is None:
        types = await list_project_issue_types(cfg, project_key)
        _ISSUE_TYPE_CACHE[cache_key] = types
    if not types:
        return "Epic"  # couldn't look it up — try the standard name as-is
    names = [(t.get("name") or "").strip() for t in types]
    for candidate in ("epic", "parent"):
        for name in names:
            if name.lower() == candidate:
                return name
    for candidate in ("epic", "parent"):
        for name in names:
            if candidate in name.lower():
                return name
    logger.warning(
        "Project %s has no 'Epic'/'Parent' issue type in its scheme; Epic "
        "creation will likely fail. Available issue types: %s",
        project_key, names,
    )
    return "Epic"


_LAST_EPIC_ERROR: dict[tuple[str, str], str] = {}


def last_epic_error(cfg: dict, project_key: str) -> str:
    """Jira's reason for the most recent failed Epic creation, or ''."""
    return _LAST_EPIC_ERROR.get((_base(cfg), project_key), "")


def _jira_error_text(r: "httpx.Response") -> str:
    try:
        body = r.json()
    except Exception:
        return f"HTTP {r.status_code}: {r.text[:200]}"
    parts = list(body.get("errorMessages") or [])
    parts += [f"{k}: {v}" for k, v in (body.get("errors") or {}).items()]
    return f"HTTP {r.status_code}: " + ("; ".join(parts) or r.text[:200])


async def create_epic(cfg: dict, project_key: str, name: str) -> str | None:
    """Create a new Epic issue in Jira and return its issue key, or None on failure.

    The reason for a failure is kept for last_epic_error(). When Jira rejects the
    legacy 'Epic Name' field because it is not on the project's create screen
    (common in newer projects), the request is retried without it.
    """
    key = (_base(cfg), project_key)
    _LAST_EPIC_ERROR.pop(key, None)
    issue_type = await _resolve_epic_issue_type(cfg, project_key)
    fields: dict[str, Any] = {
        "project": {"key": project_key},
        "summary": name,
        "issuetype": {"name": issue_type},
    }
    epic_name_field = (await _discover_epic_fields(cfg)).get("epic_name")
    if epic_name_field:
        fields[epic_name_field] = name
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            for _attempt in range(2):
                r = await client.post(
                    f"{_base(cfg)}/rest/api/3/issue",
                    auth=_auth(cfg),
                    headers={"Accept": "application/json", "Content-Type": "application/json"},
                    json={"fields": fields},
                )
                if r.status_code == 201:
                    return r.json().get("key")
                detail = _jira_error_text(r)
                if epic_name_field in fields and epic_name_field in detail:
                    del fields[epic_name_field]
                    continue
                break
        _LAST_EPIC_ERROR[key] = detail
        logger.warning("Jira Epic creation failed for %s (%r): %s", project_key, name, detail)
    except Exception as exc:
        _LAST_EPIC_ERROR[key] = f"{type(exc).__name__}: {exc}"
        logger.warning("Jira Epic creation raised an exception for %s (%r)", project_key, name, exc_info=True)
    return None


async def link_issue_to_epic(cfg: dict, issue_key: str, epic_key: str) -> bool:
    """Attach an existing issue to an Epic. Best-effort — tries the classic
    'Epic Link' custom field first, then falls back to 'parent' (team-managed
    projects). Failure never blocks ticket creation/reassignment.
    """
    if not issue_key or not epic_key:
        return False
    epic_fields = await _discover_epic_fields(cfg)
    attempts: list[dict] = []
    if epic_fields.get("epic_link"):
        attempts.append({epic_fields["epic_link"]: epic_key})
    attempts.append({"parent": {"key": epic_key}})
    for fields in attempts:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.put(
                    f"{_base(cfg)}/rest/api/3/issue/{issue_key}",
                    auth=_auth(cfg),
                    headers={"Accept": "application/json", "Content-Type": "application/json"},
                    json={"fields": fields},
                )
            if r.status_code == 204:
                return True
        except Exception:
            continue
    return False


async def resolve_epic_selection(
    cfg: dict,
    project_key: str,
    epic_key: str | None,
    epic_name: str | None,
) -> str | None:
    """Resolve a ticket-creation request's Epic choice to a concrete key.

    - epic_key given → use it directly (user picked an existing Epic).
    - epic_name given (no epic_key) → reuse an existing Epic whose summary
      starts with that name (case-insensitive), else create a new one. This
      guards against duplicate Epics if a client resubmits a "create" choice
      for a name that already exists (e.g. re-clicking a quick-create button).
    - neither given → no Epic (tickets created unassigned).
    """
    if epic_key:
        return epic_key
    name = (epic_name or "").strip()
    if name:
        needle = name.lower()
        for epic in await list_project_epics(cfg, project_key):
            if (epic.get("summary") or "").strip().lower().startswith(needle):
                return epic.get("key")
        return await create_epic(cfg, project_key, name)
    return None


# ── Finding fingerprint ───────────────────────────────────────


def _norm_path(v: str) -> str:
    """Reduce absolute paths to their last components for fingerprint stability.

    Tools like Checkov, ClamAV, and TruffleHog report absolute paths that
    include the temp clone directory (e.g. /tmp/clone-abc123/src/app.py).
    That prefix changes every scan, so including it raw in the fingerprint
    produces a new key — and a new Jira ticket — for the same finding on
    every run.  Normalising to the last components (src/subdir/app.py)
    keeps the fingerprint stable while still distinguishing different files.
    Non-absolute values are returned unchanged.
    """
    if not v:
        return ""
    # Convert Windows paths to Unix-style for consistency
    v = v.replace("\\", "/")
    if not v.startswith("/"):
        return v  # Relative path, use as-is
    parts = [p for p in Path(v).parts if p not in ("/", "\\")]
    # Use last 3 components for better uniqueness while removing temp prefixes
    if len(parts) >= 3:
        return "/".join(parts[-3:])
    return "/".join(parts) if parts else v


def finding_fingerprint(finding: dict, app_name: str, project_key: str = "") -> str:
    """Stable key for a finding that is consistent across scans within a project.

    Identity is: tool + CVE/check id + package + target + app_name + project_key.
    Absolute paths in package/target are normalised to their last components
    so that temp-clone prefixes do not break stability.
    Including project_key prevents duplicates when the same app is tracked
    across multiple Jira projects.
    Returns a short SHA-256 hex prefix combined with the id for readability.
    """
    parts = "|".join([
        (finding.get("tool")    or "").strip(),
        (finding.get("id")      or "").strip(),
        _norm_path((finding.get("package") or "").strip()),
        _norm_path((finding.get("target")  or "").strip()),
        app_name.strip().lower().replace(" ", "-"),  # Normalize app name
        project_key.strip().upper(),  # Normalize project key
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


def flatten_ticketable_findings(scan_data: dict) -> list[dict]:
    """Flatten all finding categories that can be manually ticketed."""
    findings: list[dict] = []
    for key in ("findings", "misconfigurations", "ml_findings"):
        findings.extend(flatten_findings(scan_data.get(key, {})))
    return [finding for finding in findings if not finding.get("suppressed")]


def build_ticket_candidates(
    scan_data: dict,
    app_name: str,
    project_key: str = "",
    ticket_map: dict | None = None,
) -> list[dict]:
    """Build categorized, fingerprinted Jira candidates from parsed scan data."""
    tickets = ticket_map or {}
    candidates: list[dict] = []
    display_fields = (
        "tool", "type", "id", "severity", "package", "version",
        "fixed_version", "title", "description", "target", "location",
        "line", "references", "cisa_kev", "nvd_cvss_v3_score",
        "nvd_cvss_v3_severity", "cvss_score", "cvss_vector", "nvd_url",
        "suppressed", "suppression_reason",
    )
    categories = (
        ("vulnerability", scan_data.get("findings", {})),
        ("misconfiguration", scan_data.get("misconfigurations", {})),
        ("ml", scan_data.get("ml_findings", {})),
    )

    for category, findings in categories:
        for finding in flatten_findings(findings):
            fingerprint = finding_fingerprint(finding, app_name, project_key)
            ticket = tickets.get(fingerprint)
            suppressed = bool(finding.get("suppressed"))
            candidate = {key: finding[key] for key in display_fields if key in finding}
            candidate.update({
                "category": category,
                "fingerprint": fingerprint,
                "selectable": not suppressed and ticket is None,
                "selection_reason": (
                    "suppressed" if suppressed else "already_ticketed" if ticket else None
                ),
                "jira_ticket": ticket,
            })
            candidates.append(candidate)

    return candidates


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


async def add_comment(cfg: dict, issue_key: str, comment_text: str) -> bool:
    """Post a plain-text comment on an existing Jira issue. Returns True on success.

    Used for the triage note ("Triaged and added by: X on: YYYY-MM-DD") a user
    attaches when submitting a ticket from the "Create Jira Tickets" modal — a
    best-effort operation that never fails ticket creation itself.
    """
    body: dict[str, Any] = {
        "body": {
            "version": 1,
            "type": "doc",
            "content": [
                {
                    "type": "paragraph",
                    "content": [{"type": "text", "text": comment_text}],
                }
            ],
        }
    }
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.post(
                f"{_base(cfg)}/rest/api/3/issue/{issue_key}/comment",
                auth=_auth(cfg),
                headers={"Accept": "application/json", "Content-Type": "application/json"},
                json=body,
            )
        if r.status_code == 201:
            return True
        logger.warning(
            "Jira comment failed for %s: HTTP %s — %s", issue_key, r.status_code, r.text[:500],
        )
        return False
    except Exception:
        logger.warning("Jira comment raised an exception for %s", issue_key, exc_info=True)
        return False


_CVE_ID_RE = re.compile(r"^(CVE-\d{4}-\d{4,}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})$", re.IGNORECASE)


def _text(value: str, *, bold: bool = False, link: str | None = None, code: bool = False) -> dict:
    node: dict[str, Any] = {"type": "text", "text": value}
    marks = []
    if bold:
        marks.append({"type": "strong"})
    if code:
        marks.append({"type": "code"})
    if link:
        marks.append({"type": "link", "attrs": {"href": link}})
    if marks:
        node["marks"] = marks
    return node


def _para(*inline: dict) -> dict:
    return {"type": "paragraph", "content": list(inline)}


def _heading(text: str, level: int = 3) -> dict:
    return {"type": "heading", "attrs": {"level": level}, "content": [_text(text)]}


def _bullets(items: list[list[dict]]) -> dict:
    return {
        "type": "bulletList",
        "content": [
            {"type": "listItem", "content": [_para(*item)]} for item in items
        ],
    }


def build_stig_description(finding: dict, app_name: str) -> dict[str, Any]:
    """ADF ticket body for a STIG control gap (tool == "stig")."""
    sev = (finding.get("severity") or "unknown").upper()
    fid = finding.get("id") or "Unknown"
    content: list[dict] = [
        _para(_text("STIG control assessed by Epyon in application "), _text(app_name, bold=True), _text(".")),
        _heading("Control"),
        _para(_text("Control: ", bold=True), _text(f"{fid} {finding.get('title') or ''}".strip())),
        _para(_text("Severity: ", bold=True), _text(sev)),
    ]
    for label, key in (("STIG", "stig_name"), ("Status", "status")):
        if finding.get(key):
            content.append(_para(_text(f"{label}: ", bold=True), _text(str(finding[key])[:300])))
    for heading, key in (("Evidence", "description"), ("Check", "check_content"), ("Fix", "fix_text")):
        if finding.get(key):
            content.append(_heading(heading))
            content.append(_para(_text(str(finding[key])[:1500])))
    content.append(_heading("Acceptance Criteria"))
    content.append(_bullets([[_text(
        f"Given {fid} is reported Open for {app_name}, when the control is satisfied and the "
        "evidence is recorded in the STIG review record, then a follow-up Epyon STIG scan "
        "reports it as Not a Finding."
    )]]))
    content.append(_heading("Definition of Done"))
    content.append(_bullets([
        [_text("The fix or documented justification is merged to the default branch.")],
        [_text("The review record for this control is updated with the evidence.")],
    ]))
    return {"version": 1, "type": "doc", "content": content}


def build_finding_description(finding: dict, app_name: str) -> dict[str, Any]:
    """Build the ADF ticket body for a finding: CVE Details, Acceptance Criteria,
    and Definition of Done — so a reviewer can triage, fix, and verify the
    finding entirely from the ticket without going back to the scan output.
    """
    sev   = (finding.get("severity") or "unknown").upper()
    tool  = finding.get("tool")  or "Unknown"
    fid   = finding.get("id")    or "Unknown"
    pkg   = finding.get("package") or ""
    ver   = finding.get("version") or ""
    fixed = finding.get("fixed_version") or ""
    title = finding.get("title") or fid
    refs  = finding.get("references") or []
    nvd_url = finding.get("nvd_url") or ""
    cvss_score  = finding.get("cvss_score")
    cvss_vector = finding.get("cvss_vector") or ""
    is_cve = bool(_CVE_ID_RE.match(fid.strip())) if fid else False
    advisory_url = nvd_url or (refs[0] if refs else "")
    is_kev = bool(finding.get("cisa_kev"))

    content: list[dict] = [
        _para(_text(f"Detected by Epyon scanner in application "), _text(app_name, bold=True), _text(".")),
        _heading("CVE Details"),
    ]

    if is_cve:
        content.append(
            _para(_text("CVE/Advisory: ", bold=True),
                  _text(fid, link=advisory_url) if advisory_url else _text(fid))
        )
    else:
        content.append(_para(_text(
            f"No CVE/advisory identifier is associated with this finding "
            f"(tool: {tool}, check ID: {fid})."
        )))

    content.append(_para(_text("Severity: ", bold=True), _text(sev)))

    if cvss_score is not None:
        cvss_text = f"{cvss_score}" + (f" ({cvss_vector})" if cvss_vector else "")
    else:
        cvss_text = "Not available"
    content.append(_para(_text("CVSS score/vector: ", bold=True), _text(cvss_text)))

    if pkg:
        content.append(_para(_text("Affected package: ", bold=True),
                              _text(f"{pkg}@{ver}" if ver else pkg, code=True)))

    content.append(_para(
        _text("Fixed version: ", bold=True),
        _text(fixed, code=True) if fixed else _text("No fix currently available"),
    ))

    if title and title != fid:
        content.append(_para(_text("Title: ", bold=True), _text(title[:500])))

    if advisory_url:
        content.append(_para(_text("Advisory: ", bold=True), _text(advisory_url, link=advisory_url)))

    if is_kev:
        content.append(_para(_text(
            "\U0001f525 This is a CISA Known Exploited Vulnerability (KEV).", bold=True
        )))

    # ── Acceptance Criteria ────────────────────────────────────
    fix_target = f"updated to {fixed}" if fixed else "updated to a non-vulnerable version or otherwise remediated"
    ac_items = [
        [_text(
            f"Given {fid} is currently reported in {app_name}, "
            f"when the affected package is {fix_target}, "
            f"then a follow-up Epyon scan no longer reports {fid} at {sev} severity."
        )],
    ]
    if is_kev:
        due = finding.get("cisa_due_date") or "the CISA-mandated due date"
        ac_items.append([_text(f"Given this finding is a CISA KEV, when remediation is tracked, then it is resolved by {due}.")])
    content.append(_heading("Acceptance Criteria"))
    content.append(_bullets(ac_items))

    # ── Definition of Done ─────────────────────────────────────
    content.append(_heading("Definition of Done"))
    content.append(_bullets([
        [_text("Fix is merged to the default branch.")],
        [_text(f"A re-scan of {app_name} is clean for {fid}, or the finding is formally risk-accepted "
               f"in .epyon-ignore.yml with a documented reason and expiration date.")],
        [_text("This ticket is linked to the pull request that resolved the finding.")],
    ]))

    return {"version": 1, "type": "doc", "content": content}


async def create_ticket(
    cfg: dict,
    finding: dict,
    app_name: str,
    epic_key: str | None = None,
    issue_type: str | None = None,
    triage_note: str | None = None,
) -> str | None:
    """Create a Jira issue for a finding. Returns the issue key or None.

    If epic_key is given, the new issue is best-effort linked to that Epic
    after creation; a link failure never fails ticket creation itself.
    issue_type overrides cfg's configured default (e.g. a user's explicit
    choice from the "Create Jira Tickets" modal); either way it is validated
    against the project's real issue type scheme and auto-repaired if
    invalid, so a stale/wrong configured type never silently fails.
    triage_note, if given, is posted as a follow-up Jira comment (e.g.
    "Triaged and added by: Jane Doe on: 2026-09-22") — a best-effort operation
    that never fails ticket creation itself.
    """
    project_key = (cfg.get("project_key") or "").strip()
    if not project_key:
        return None

    sev   = (finding.get("severity") or "unknown").upper()
    tool  = finding.get("tool")  or "Unknown"
    fid   = finding.get("id")    or "Unknown"
    pkg   = finding.get("package") or ""

    if tool == "stig":
        summary = f"[{sev}][STIG] {fid}: {finding.get('title') or app_name}"[:254]
        description = build_stig_description(finding, app_name)
    else:
        summary = f"[{sev}][{tool}] {fid} in {pkg or app_name}"[:254]
        description = build_finding_description(finding, app_name)

    requested_issue_type = (issue_type or cfg.get("issue_type") or "Bug").strip()
    issue_type = await _resolve_issue_type(cfg, project_key, requested_issue_type)
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
            key = r.json().get("key")
            if key and epic_key:
                await link_issue_to_epic(cfg, key, epic_key)
            if key and triage_note:
                await add_comment(cfg, key, triage_note)
            return key
        logger.warning(
            "Jira ticket creation failed for %s/%s: HTTP %s — %s",
            project_key, fid, r.status_code, r.text[:500],
        )
        return None
    except Exception:
        logger.warning("Jira ticket creation raised an exception for %s/%s", project_key, fid, exc_info=True)
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


async def _find_reopen_transition_id(cfg: dict, issue_key: str) -> str | None:
    """Return the transition ID for reopening a closed issue.
    Tries common reopen transition names: 'Reopen', 'To Do', 'Open', 'Backlog', etc.
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
        # Try common reopen transition names in priority order
        for fallback in ("reopen", "to do", "open", "backlog", "in progress", "reopened"):
            for t in transitions:
                if t.get("name", "").lower() == fallback:
                    return t["id"]
    except Exception:
        pass
    return None


async def reopen_ticket(cfg: dict, issue_key: str) -> bool:
    """Reopen a closed Jira issue. Returns True on success.
    
    This is used when a previously fixed vulnerability reappears in a new scan.
    Reopening maintains a single source of truth and shows the full lifecycle
    (open → closed → reopened) instead of creating duplicate tickets.
    """
    tid = await _find_reopen_transition_id(cfg, issue_key)
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

    Reappeared (previously closed ticket, now finding is back):
        → reopen the existing ticket instead of creating a duplicate.

    Mutates *ticket_map* in-place and returns a summary dict.
    """
    result: dict = {"closed": [], "opened": [], "reopened": [], "errors": []}

    project_key   = (cfg.get("project_key") or "").strip()

    now_ts = datetime.now(timezone.utc).isoformat()

    current_fps  = {finding_fingerprint(f, app_name, project_key): f for f in current_findings}
    previous_fps = {finding_fingerprint(f, app_name, project_key): f for f in previous_findings}

    # ── Remediated findings ──────────────────────────────────
    # Check ALL open tickets in the ticket map, not just those from the previous scan.
    # A finding may have been remediated multiple scans ago, so it won't appear in
    # previous_fps, but we still need to close its ticket if it's not in the current scan.
    # Always close tickets for remediated findings (auto_close is always enabled).
    for fp, entry in ticket_map.items():
        # Skip if already closed
        if entry.get("closed_at"):
            continue
        # Skip if not for this app+project (ticket map is global)
        if entry.get("app") != app_name or entry.get("project_key") != project_key:
            continue
        # Skip if finding still present in current scan
        if fp in current_fps:
            continue
        # Finding is gone → close the ticket
        issue_key = entry.get("issue_key", "")
        if not issue_key:
            continue
        ok = await close_ticket(cfg, issue_key)
        if ok:
            ticket_map[fp]["closed_at"] = now_ts
            result["closed"].append(issue_key)
        else:
            result["errors"].append(f"Failed to close {issue_key}")

    # ── Reappeared findings ─────────────────────────────────
    # Reopening is lifecycle management and remains automatic even when new
    # ticket creation requires manual review.
    for fp in current_fps:
        existing = ticket_map.get(fp)
        if not existing or not existing.get("closed_at") or fp in previous_fps:
            continue
        issue_key = existing.get("issue_key", "")
        if not issue_key:
            continue
        ok = await reopen_ticket(cfg, issue_key)
        if ok:
            ticket_map[fp]["closed_at"] = None
            ticket_map[fp]["reopened_at"] = now_ts
            result["reopened"].append(issue_key)
        else:
            result["errors"].append(f"Failed to reopen {issue_key}")

    return result


_SNAPSHOT_FIELDS = (
    "id", "severity", "tool", "package", "version",
    "fixed_version", "title", "references",
)


def _snapshot_finding(finding: dict) -> dict:
    """Capture just enough of a finding to recreate its ticket later, in case
    the finding is no longer present in any scan when a reassignment happens.
    """
    return {key: finding[key] for key in _SNAPSHOT_FIELDS if key in finding}


async def link_issues(cfg: dict, inward_key: str, outward_key: str, link_type: str = "Relates") -> bool:
    """Create a "relates to" link between two issues. Best-effort; returns True on success."""
    body = {
        "type": {"name": link_type},
        "inwardIssue": {"key": inward_key},
        "outwardIssue": {"key": outward_key},
    }
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.post(
                f"{_base(cfg)}/rest/api/3/issueLink",
                auth=_auth(cfg),
                headers={"Accept": "application/json", "Content-Type": "application/json"},
                json=body,
            )
        if r.status_code in (200, 201):
            return True
        logger.warning("Jira link %s -> %s failed: HTTP %s", inward_key, outward_key, r.status_code)
        return False
    except Exception:
        logger.warning("Jira link %s -> %s raised an exception", inward_key, outward_key, exc_info=True)
        return False


async def search_issue_keys(cfg: dict, jql: str, max_results: int = 5) -> list[str]:
    """Return issue keys matching a JQL query; [] on any error."""
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(
                f"{_base(cfg)}/rest/api/3/search/jql",
                auth=_auth(cfg),
                headers={"Accept": "application/json"},
                params={"jql": jql, "fields": "summary", "maxResults": max_results},
            )
        if r.status_code != 200:
            return []
        return [i["key"] for i in r.json().get("issues", []) if i.get("key")]
    except Exception:
        return []


async def create_tickets_batch(
    app_name: str,
    findings_by_fingerprint: dict[str, dict],
    requested_fingerprints: list[str],
    cfg: dict,
    epic_key: str | None = None,
    issue_type: str | None = None,
    triage_note: str | None = None,
) -> dict:
    """Create selected Jira tickets idempotently and persist each success.

    If epic_key is given, every ticket created in this batch is linked to it
    (the caller resolves the user's Epic choice — existing or newly created —
    once per batch via resolve_epic_selection()). If issue_type is given, it
    overrides cfg's configured default ticket type for the whole batch (the
    user's explicit choice from the "Create Jira Tickets" modal). If
    triage_note is given, it is posted as a Jira comment on every ticket
    newly created in this batch (e.g. "Triaged and added by: Jane Doe on:
    2026-09-22") — tickets that already existed are left untouched.
    """
    result = {
        "requested": len(requested_fingerprints),
        "created": [],
        "already_exists": [],
        "ineligible": [],
        "failed": [],
    }
    project_key = (cfg.get("project_key") or "").strip()

    async with _get_lock():
        ticket_map = read_ticket_map()
        for fingerprint in dict.fromkeys(requested_fingerprints):
            finding = findings_by_fingerprint.get(fingerprint)
            if finding is None:
                logger.warning(
                    "Jira ticket creation: fingerprint %s not found among current scan candidates "
                    "for app=%s project=%s (stale selection or the finding's fingerprint inputs "
                    "changed, e.g. target path/app/project — remediated findings simply disappear "
                    "from this list, which is expected).",
                    fingerprint, app_name, project_key,
                )
                result["ineligible"].append({
                    "fingerprint": fingerprint,
                    "reason": "unknown_fingerprint",
                })
                continue
            if finding.get("suppressed"):
                result["ineligible"].append({
                    "fingerprint": fingerprint,
                    "reason": "suppressed",
                })
                continue
            existing = ticket_map.get(fingerprint)
            if existing:
                result["already_exists"].append({
                    "fingerprint": fingerprint,
                    "issue_key": existing.get("issue_key", ""),
                })
                continue

            issue_key = await create_ticket(cfg, finding, app_name, epic_key, issue_type, triage_note)
            if not issue_key:
                result["failed"].append({
                    "fingerprint": fingerprint,
                    "reason": "jira_creation_failed",
                })
                continue

            now_ts = datetime.now(timezone.utc).isoformat()
            ticket_map[fingerprint] = {
                "issue_key": issue_key,
                "app": app_name,
                "project_key": project_key,
                "category": finding.get("category") or "",
                "epic_key": epic_key,
                "issue_type": issue_type or cfg.get("issue_type") or "Bug",
                "finding_id": finding.get("id", ""),
                "severity": finding.get("severity", ""),
                "tool": finding.get("tool", ""),
                "created_at": now_ts,
                "closed_at": None,
                "creation_source": "manual",
                "finding_snapshot": _snapshot_finding(finding),
                "previous_issue_keys": [],
                "reassigned_at": None,
            }
            write_ticket_map(ticket_map)
            result["created"].append({
                "fingerprint": fingerprint,
                "issue_key": issue_key,
            })

    return result


# ── Orphaned ticket detection & recreation ────────────────────
# A tracked ticket can vanish from Jira out-of-band (a user deletes the issue,
# or an admin purges a project). Epyon's ticket map would otherwise keep
# pointing at a dead issue key forever ("already_ticketed" but unclickable).
# reassign_orphaned_tickets() detects this and drops the ticket-map entry
# entirely, putting the finding back in its original, unsubmitted state so it
# reappears as an eligible candidate the user can manually re-submit via the
# normal "Create Jira Ticket" flow — Epyon never recreates the Jira issue
# automatically.

async def _issue_exists(cfg: dict, issue_key: str) -> bool:
    """Return False if the issue is permanently deleted OR sitting in Jira's
    trash — both make the ticket unusable from a tracking perspective.

    We deliberately use a JQL search rather than `GET /rest/api/3/issue/{key}`:
    Jira Cloud's issue trash keeps a "deleted" issue retrievable via direct
    GET (200) for up to ~60 days after a user deletes it from the UI, so a
    direct GET can't tell a live issue apart from a trashed one. A bare
    `issuekey = X` JQL clause is known to sometimes bypass Jira's trash
    filtering too (it resolves via a direct-key-lookup fast path rather than
    the normal search index); scoping the query with `project = ...` avoids
    that fast path and reliably excludes trashed/deleted issues.

    Any other outcome (network error, auth failure, non-200/400 response) is
    treated as 'exists' so transient problems never trigger an unnecessary —
    and disruptive — recreation.
    """
    project_key = (cfg.get("project_key") or issue_key.split("-")[0]).strip()
    jql = f'project = "{project_key}" AND key = "{issue_key}"' if project_key else f'key = "{issue_key}"'
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(
                f"{_base(cfg)}/rest/api/3/search/jql",
                auth=_auth(cfg),
                headers={"Accept": "application/json"},
                params={"jql": jql, "fields": "key", "maxResults": 1},
            )
        if r.status_code == 404:
            return False
        if r.status_code != 200:
            return True
        return bool(r.json().get("issues"))
    except Exception:
        return True


async def reassign_orphaned_tickets(
    app_name: str,
    cfg: dict,
    ticket_map: dict,
) -> dict:
    """Detect tickets whose Jira issue was deleted and reset them to an
    unsubmitted state.

    Mutates *ticket_map* in-place and returns a summary dict. Epyon never
    recreates the Jira issue automatically — the ticket-map entry for an
    orphaned fingerprint is simply removed, so the underlying finding goes
    back to looking exactly like it did before any ticket was ever created
    for it. It will reappear as an eligible candidate in the Jira review UI,
    and the user can manually submit a brand-new ticket for it whenever they
    choose.
    """
    result: dict = {"checked": 0, "orphaned": [], "reassigned": [], "errors": []}
    project_key = (cfg.get("project_key") or "").strip()

    for fp, entry in list(ticket_map.items()):
        if entry.get("app") != app_name or entry.get("project_key") != project_key:
            continue
        issue_key = entry.get("issue_key", "")
        if not issue_key:
            continue
        result["checked"] += 1
        if await _issue_exists(cfg, issue_key):
            continue

        result["orphaned"].append(issue_key)
        del ticket_map[fp]
        result["reassigned"].append({"old": issue_key, "new": None})

    return result


async def reassign_orphaned_and_save(app_name: str, cfg: dict) -> dict:
    """Atomically read → check-for-deleted-tickets → reset → write.

    Exposed for the manual "Check for deleted tickets" UI action; also used
    internally by reconcile_and_save so orphaned entries are cleared out
    automatically on every post-scan/sync reconciliation. Orphaned findings
    are reset to their original unsubmitted state, never auto-recreated.
    """
    async with _get_lock():
        ticket_map = read_ticket_map()
        result = await reassign_orphaned_tickets(app_name, cfg, ticket_map)
        write_ticket_map(ticket_map)
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

    Orphaned-ticket detection runs first so a deleted issue's entry is
    dropped — resetting the finding to its unsubmitted state — before the
    normal close/reopen pass evaluates it. This never recreates a Jira
    issue automatically; the finding simply becomes eligible for manual
    re-submission again.
    """
    async with _get_lock():
        ticket_map = read_ticket_map()
        reassigned = await reassign_orphaned_tickets(app_name, cfg, ticket_map)
        result = await reconcile_app(
            app_name, current_findings, previous_findings, cfg, ticket_map
        )
        result["reassigned"] = reassigned["reassigned"]
        if reassigned["errors"]:
            result["errors"] = result.get("errors", []) + reassigned["errors"]
        write_ticket_map(ticket_map)
    return result

