"""Cross-application finding search (MID-4485).

Pure helpers so the matching/deduplication logic is testable without FastAPI.
"""
from __future__ import annotations

import re
from typing import Any, Iterable

from . import jira_client

QUERY_RE = re.compile(r"^[A-Za-z0-9@][A-Za-z0-9._:@/+\-]{2,99}$")
FIELDS = ("id", "package")

_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def validate_query(q: str) -> str:
    """Return the stripped query or raise ValueError (never echoes the input)."""
    q = (q or "").strip()
    if not QUERY_RE.fullmatch(q):
        raise ValueError(
            "q must be 3-100 characters: letters, digits and . _ : @ / + -"
        )
    return q


def _matches(candidate: dict, needle: str, field: str) -> bool:
    return (candidate.get(field) or "").strip().lower() == needle


def _public_finding(candidate: dict) -> dict:
    ticket = candidate.get("jira_ticket") or {}
    return {
        "id": candidate.get("id", ""),
        "severity": candidate.get("severity", "low"),
        "category": candidate.get("category", ""),
        "tools": [candidate["tool"]] if candidate.get("tool") else [],
        "package": candidate.get("package", ""),
        "version": candidate.get("version", ""),
        "fixed_version": candidate.get("fixed_version", ""),
        "title": (candidate.get("title") or "")[:200],
        "suppressed": bool(candidate.get("suppressed")),
        "jira_issue_key": ticket.get("issue_key", ""),
    }


def build_scan_index(scan_data: dict, app_name: str, project_key: str = "") -> dict:
    """Compact, lookup-ready view of one parsed scan: finding id/package -> findings.

    Jira ticket state is deliberately left out (only the fingerprint is kept) so a
    cached index never serves a stale ticket link.
    """
    candidates = jira_client.build_ticket_candidates(scan_data, app_name, project_key)
    index: dict[str, dict[str, list[dict]]] = {"id": {}, "package": {}}
    for candidate in candidates:
        finding = _public_finding(candidate)
        finding["fingerprint"] = candidate.get("fingerprint", "")
        for field in FIELDS:
            value = (candidate.get(field) or "").strip().lower()
            if value:
                index[field].setdefault(value, []).append(finding)
    return index


def search_index(index: dict, needle: str, field: str, ticket_map: dict | None = None) -> list[dict]:
    """Matching findings from a scan index, deduplicated by (id, package)."""
    tickets = ticket_map or {}
    merged: dict[tuple[str, str], dict] = {}
    for hit in index.get(field, {}).get(needle, []):
        finding = {k: (list(v) if isinstance(v, list) else v) for k, v in hit.items() if k != "fingerprint"}
        finding["jira_issue_key"] = (tickets.get(hit.get("fingerprint")) or {}).get("issue_key", "")
        key = (finding["id"].lower(), finding["package"].lower())
        existing = merged.get(key)
        if not existing:
            merged[key] = finding
            continue
        for tool in finding["tools"]:
            if tool not in existing["tools"]:
                existing["tools"].append(tool)
        if _SEV_RANK.get(finding["severity"], 9) < _SEV_RANK.get(existing["severity"], 9):
            existing["severity"] = finding["severity"]
        existing["fixed_version"] = existing["fixed_version"] or finding["fixed_version"]
        existing["jira_issue_key"] = existing["jira_issue_key"] or finding["jira_issue_key"]
        existing["suppressed"] = existing["suppressed"] and finding["suppressed"]
    return sorted(
        merged.values(),
        key=lambda f: (_SEV_RANK.get(f["severity"], 9), f["id"], f["package"]),
    )


def search_scan(
    scan_data: dict,
    app_name: str,
    needle: str,
    field: str,
    project_key: str = "",
    ticket_map: dict | None = None,
) -> list[dict]:
    """Matching findings in one parsed scan, deduplicated by (id, package)."""
    index = build_scan_index(scan_data, app_name, project_key)
    return search_index(index, needle, field, ticket_map)


def preselect_dirs(dirs: Iterable, include_history: bool, parse_dir_name) -> list:
    """Cheaply narrow scan directories by name, before any scan is parsed.

    Reading metadata for every directory dominates search latency, so group by
    the target and timestamp encoded in each directory name and keep only the
    newest per target (or all of them with include_history).
    """
    by_target: dict[str, list[tuple[str, Any]]] = {}
    for scan_dir in dirs:
        parsed = parse_dir_name(scan_dir.name)
        by_target.setdefault(parsed["target"], []).append((parsed["timestamp"], scan_dir))
    chosen: list = []
    for entries in by_target.values():
        entries.sort(key=lambda e: e[0], reverse=True)
        chosen.extend(d for _, d in (entries if include_history else entries[:1]))
    return chosen


def select_scans(scans: Iterable[dict], include_history: bool) -> list[dict]:
    """Scan metadata (target, timestamp, scan_id) to search, newest first per app."""
    by_app: dict[str, list[dict]] = {}
    for scan in scans:
        by_app.setdefault(scan["target"], []).append(scan)
    selected: list[dict] = []
    for app_scans in by_app.values():
        app_scans.sort(key=lambda s: s.get("timestamp") or "", reverse=True)
        for index, scan in enumerate(app_scans if include_history else app_scans[:1]):
            selected.append({**scan, "is_latest": index == 0})
    return selected
