#!/usr/bin/env python3
"""Post STIG gaps to Jira: one summary comment and one ticket per real gap (MID-4536).

Opt-in (EPYON_STIG_JIRA=true). Reuses web/api/jira_client.py for credentials
(environment only), fingerprints, project-key isolation and the ticket map.
Every failure is logged and swallowed: a scan is never blocked by Jira.
"""
from __future__ import annotations

import argparse
import asyncio
from datetime import datetime, timezone
import hashlib
import json
import logging
import os
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "web"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import stig_records  # noqa: E402

log = logging.getLogger("stig_jira")

MAX_COMMENT_LINES = 40
DEFAULT_MAX_TICKETS = 25


def _slug(app_name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", app_name.lower()).strip("-")


def _signature(assessment: dict[str, Any]) -> str:
    raw = f"{assessment.get('status', '')}|{assessment.get('evidence', '')}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def load_scan(scan_dir: Path) -> tuple[list[dict], dict[str, dict]]:
    """Controls and assessments from every stig-*-{slug}.json pair in the scan dir."""
    controls: list[dict] = []
    assessments: dict[str, dict] = {}
    for cf in sorted(scan_dir.glob("stig-controls-*.json")):
        slug = cf.stem[len("stig-controls-"):]
        rf = scan_dir / f"stig-results-{slug}.json"
        if not rf.is_file():
            continue
        try:
            cdata = json.loads(cf.read_text(encoding="utf-8"))
            rdata = json.loads(rf.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        results = rdata.get("assessments", rdata) if isinstance(rdata, dict) else {}
        for control in cdata.get("controls", []):
            vid = control.get("vuln_id")
            if vid and vid in results:
                controls.append({**control, "_slug": slug, "_stig": cdata.get("stig_name", slug)})
                assessments[f"{slug}:{vid}"] = results[vid]
    return controls, assessments


def select_posts(
    controls: list[dict], assessments: dict[str, dict], previous: dict[str, str]
) -> list[dict]:
    """Open controls plus any whose status or evidence changed since the last post."""
    selected = []
    for control in controls:
        key = f"{control['_slug']}:{control['vuln_id']}"
        assessment = assessments[key]
        changed = previous.get(key) != _signature(assessment)
        if assessment.get("status") == "Open" or (key in previous and changed):
            selected.append({"key": key, "control": control, "assessment": assessment, "changed": changed})
    return selected


def is_real_gap(item: dict) -> bool:
    """A confirmed Open control: not unreviewed, unverified or awaiting an owner."""
    a = item["assessment"]
    return (
        a.get("status") == "Open"
        and not a.get("citation_failures")
        and not a.get("needs_owner_confirmation")
    )


def build_comment(app_name: str, scan_id: str, posts: list[dict]) -> str:
    opened = sum(1 for p in posts if p["assessment"].get("status") == "Open")
    lines = [
        f"Epyon STIG scan {scan_id} for {app_name}: {opened} Open, "
        f"{len(posts) - opened} changed since the last post.",
    ]
    for p in posts[:MAX_COMMENT_LINES]:
        c, a = p["control"], p["assessment"]
        evidence = " ".join(str(a.get("evidence", "")).split())[:160]
        lines.append(
            f"- {stig_records.v_number(c).upper()} [{a.get('status')}] "
            f"{str(c.get('title', ''))[:80]}: {evidence}"
        )
    if len(posts) > MAX_COMMENT_LINES:
        lines.append(f"...and {len(posts) - MAX_COMMENT_LINES} more (see docs/stig-reviews/).")
    return "\n".join(lines)


def gap_finding(item: dict, app_name: str) -> dict:
    c, a = item["control"], item["assessment"]
    return {
        "tool": "stig",
        "id": stig_records.v_number(c).upper(),
        "title": str(c.get("title", ""))[:200],
        "severity": str(c.get("severity") or "medium").lower(),
        "package": "",
        "target": item["control"]["_slug"],
        "description": " ".join(str(a.get("evidence", "")).split())[:1500],
        "stig_name": str(c.get("_stig", "")),
        "status": str(a.get("status", "")),
        "check_content": " ".join(str(c.get("check_content", "")).split())[:1000],
        "fix_text": " ".join(str(c.get("fix_text", "")).split())[:1000],
    }


async def resolve_tracker(jc: Any, cfg: dict, app_name: str, target: Path, scan_dir: Path) -> tuple[str, str]:
    """(key, source). Index line first, then an open tracker; never a key from another project."""
    project = cfg["project_key"]
    for index in (target / stig_records.PUBLISH_SUBDIR / "README.md", *scan_dir.glob("stig-reviews-*/README.md")):
        if index.is_file():
            key = stig_records.tracker_key(index.read_text(encoding="utf-8", errors="replace"), project)
            if key:
                return key, "index"
    jql = (
        f'project = "{project}" AND labels = "stig-tracking" AND labels = "{_slug(app_name)}" '
        "AND statusCategory != Done ORDER BY created ASC"
    )
    found = await jc.search_issue_keys(cfg, jql, 1)
    if found:
        return found[0], "existing"
    if os.environ.get("EPYON_STIG_JIRA_CREATE_TRACKER", "").lower() == "true":
        key = await jc.create_ticket(
            cfg,
            {"tool": "stig-tracking", "id": "STIG review tracking", "severity": "info", "package": app_name},
            app_name,
            issue_type="Task",
        )
        if key:
            return key, "created"
    return "", "none"


async def create_manual(
    jc: Any,
    cfg: dict,
    app_name: str,
    scan_dir: Path,
    selections: list[tuple[str, str]],
    *,
    tracker: str = "",
    epic_key: str | None = None,
    issue_type: str | None = None,
    triage_note: str | None = None,
) -> dict:
    """File tickets for user-selected controls in cfg["project_key"] (the chosen board).

    ``selections`` are (slug, vuln_id) pairs. A tracker from another project is
    rejected; existing tickets (by project-scoped fingerprint) are not duplicated.
    """
    project = cfg["project_key"]
    if tracker and not tracker.upper().startswith(project.upper() + "-"):
        raise ValueError(f"tracking ticket {tracker} is not in project {project}")
    controls, assessments = load_scan(scan_dir)
    by_key = {f"{c['_slug']}:{c['vuln_id']}": c for c in controls}
    result: dict[str, Any] = {
        "requested": len(selections), "created": [], "already_exists": [], "ineligible": [], "failed": [],
    }
    async with jc._get_lock():
        tmap = jc.read_ticket_map()
        for slug, vuln_id in dict.fromkeys(selections):
            key = f"{slug}:{vuln_id}"
            control = by_key.get(key)
            if control is None:
                result["ineligible"].append({"vuln_id": vuln_id, "slug": slug, "reason": "unknown_control"})
                continue
            finding = gap_finding({"control": control, "assessment": assessments[key]}, app_name)
            fp = jc.finding_fingerprint(finding, app_name, project)
            if fp in tmap:
                result["already_exists"].append(
                    {"vuln_id": vuln_id, "slug": slug, "issue_key": tmap[fp].get("issue_key", "")})
                continue
            issue_key = await jc.create_ticket(cfg, finding, app_name, epic_key, issue_type, triage_note)
            if not issue_key:
                result["failed"].append({"vuln_id": vuln_id, "slug": slug, "reason": "jira_creation_failed"})
                continue
            if tracker:
                await jc.link_issues(cfg, issue_key, tracker)
            tmap[fp] = {
                "issue_key": issue_key, "app": app_name, "project_key": project, "category": "stig",
                "epic_key": epic_key, "finding_id": finding["id"], "severity": finding["severity"],
                "tool": "stig", "created_at": datetime.now(timezone.utc).isoformat(), "closed_at": None,
                "creation_source": "manual-stig", "tracking_ticket": tracker or None,
                "previous_issue_keys": [], "reassigned_at": None,
            }
            jc.write_ticket_map(tmap)
            result["created"].append({"vuln_id": vuln_id, "slug": slug, "issue_key": issue_key})
    return result


def _state_path(jc: Any) -> Path:
    return Path(jc._DATA_DIR) / "stig-jira-state.json"


def _read_state(jc: Any) -> dict:
    try:
        return json.loads(_state_path(jc).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _write_state(jc: Any, state: dict) -> None:
    path = _state_path(jc)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(state, indent=2), encoding="utf-8")
    tmp.replace(path)


async def post(app_name: str, target: Path, scan_dir: Path, jc: Any = None) -> dict:
    """Run the posting pass. Returns a result dict; never raises."""
    result: dict[str, Any] = {"status": "skipped", "tracker": "", "comment": False, "created": [], "existing": [], "failed": 0}
    try:
        if jc is None:
            import api.jira_client as jc  # noqa: PLW0127
        cfg = jc.read_config(app_name)
        if not (cfg.get("base_url") and cfg.get("email") and cfg.get("api_token") and cfg.get("project_key")):
            result["status"] = "no_credentials"
            return result
        project = cfg["project_key"]
        controls, assessments = load_scan(scan_dir)
        state = _read_state(jc)
        state_key = f"{_slug(app_name)}|{project}"
        previous = state.get(state_key, {})
        posts = select_posts(controls, assessments, previous)
        if not posts:
            result["status"] = "nothing_to_post"
            return result

        tracker, source = await resolve_tracker(jc, cfg, app_name, target, scan_dir)
        result["tracker"], result["tracker_source"] = tracker, source
        if not tracker:
            result["status"] = "no_tracker"
            return result

        result["comment"] = await jc.add_comment(cfg, tracker, build_comment(app_name, scan_dir.name, posts))
        if not result["comment"]:
            result["failed"] += 1

        limit = int(os.environ.get("EPYON_STIG_JIRA_MAX_TICKETS", DEFAULT_MAX_TICKETS))
        async with jc._get_lock():
            tmap = jc.read_ticket_map()
            for item in (p for p in posts if is_real_gap(p)):
                finding = gap_finding(item, app_name)
                fp = jc.finding_fingerprint(finding, app_name, project)
                if fp in tmap:
                    result["existing"].append(tmap[fp].get("issue_key", ""))
                    continue
                if len(result["created"]) >= limit:
                    break
                jql = (
                    f'project = "{project}" AND labels = "stig" AND labels = "{_slug(app_name)}" '
                    f'AND summary ~ "\\"{finding["id"]}\\"" AND statusCategory != Done'
                )
                found = await jc.search_issue_keys(cfg, jql, 1)
                if found:
                    result["existing"].append(found[0])
                    continue
                key = await jc.create_ticket(cfg, finding, app_name)
                if not key:
                    result["failed"] += 1
                    continue
                await jc.link_issues(cfg, key, tracker)
                tmap[fp] = {
                    "issue_key": key, "app": app_name, "project_key": project,
                    "category": "stig", "finding_id": finding["id"],
                    "severity": finding["severity"], "tool": "stig",
                    "created_at": datetime.now(timezone.utc).isoformat(),
                    "closed_at": None, "creation_source": "stig",
                    "tracking_ticket": tracker, "previous_issue_keys": [],
                    "reassigned_at": None,
                }
                jc.write_ticket_map(tmap)
                result["created"].append(key)

        if result["comment"]:
            state[state_key] = {
                f"{c['_slug']}:{c['vuln_id']}": _signature(assessments[f"{c['_slug']}:{c['vuln_id']}"])
                for c in controls
            }
            _write_state(jc, state)
        result["status"] = "posted"
    except Exception as exc:  # never block a scan on Jira
        log.warning("STIG Jira posting failed: %s", type(exc).__name__)
        result["status"] = "error"
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True)
    parser.add_argument("--scan-dir", required=True)
    parser.add_argument("--app-name", required=True)
    args = parser.parse_args(argv)
    if os.environ.get("EPYON_STIG_JIRA", "").lower() != "true":
        print("[STIG] Jira posting disabled (set EPYON_STIG_JIRA=true to enable).")
        return 0
    try:
        result = asyncio.run(post(args.app_name, Path(args.target), Path(args.scan_dir)))
    except Exception:
        print("[STIG] Jira posting skipped: unexpected error (non-fatal).")
        return 0
    print(
        f"[STIG] Jira: {result['status']}"
        + (f", tracker {result['tracker']}" if result.get("tracker") else "")
        + f", comment={'yes' if result['comment'] else 'no'}"
        + f", created={len(result['created'])}, existing={len(result['existing'])}, failed={result['failed']}"
    )
    if result["status"] == "no_tracker":
        print("[STIG] No tracking ticket found. Name one in docs/stig-reviews/README.md "
              "('Tracked in Jira by KEY') or set EPYON_STIG_JIRA_CREATE_TRACKER=true.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
