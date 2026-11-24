"""Epyon Web — project-level STIG roll-up.

Each repository reports whether its own part of a control is satisfied. A project control is
Not a Finding only when every required part is satisfied; the evidence names what is missing.
"""
from __future__ import annotations

import json
from pathlib import Path

OPEN = "Open"
NOT_REVIEWED = "Not Reviewed"
NOT_APPLICABLE = "Not Applicable"
PASS = "Not a Finding"


def rollup_status(statuses: list[str]) -> str:
    """Any Open makes the control Open; otherwise any missing or unreviewed part leaves it
    Not Reviewed; Not Applicable only when every part is Not Applicable."""
    if not statuses:
        return NOT_REVIEWED
    if OPEN in statuses:
        return OPEN
    if any(s not in (PASS, NOT_APPLICABLE) for s in statuses):
        return NOT_REVIEWED
    if all(s == NOT_APPLICABLE for s in statuses):
        return NOT_APPLICABLE
    return PASS


def load_policy(path: Path) -> tuple[dict[str, list[str]], str]:
    """Per-control required roles from configuration/stig-policy/project-roles.json.

    Format: {"controls": {"APSC-DV-000070" or "V-222387": {"required_roles": ["backend"]}}}.
    Returns ({lower-case control key: roles}, error). A missing file is not an error; an
    unreadable or malformed one is reported and ignored so the roll-up still works.
    """
    if not path.is_file():
        return {}, ""
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        controls = raw["controls"]
        if not isinstance(controls, dict):
            raise TypeError("controls must be an object")
        out = {}
        for key, rule in controls.items():
            roles = rule["required_roles"]
            if not isinstance(roles, list) or not roles or not all(isinstance(r, str) for r in roles):
                raise TypeError(f"{key}: required_roles must be a non-empty list of role names")
            out[str(key).lower()] = [r.lower() for r in roles]
        return out, ""
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return {}, f"{path.name} ignored: {exc}"


def _reason(status: str, parts: list[dict]) -> str:
    if status == PASS:
        return "All required parts satisfied: " + ", ".join(
            f"{p['app']} ({p['role']})" for p in parts if p.get("required", True) and p["status"] == PASS)
    if status == NOT_APPLICABLE:
        return "Not applicable to any part of the project"
    blockers = [p for p in parts if p.get("required", True) and p["status"] not in (PASS, NOT_APPLICABLE)]
    word = "Open" if status == OPEN else "No assessment for"
    return f"{word}: " + ", ".join(
        f"{p['app']} ({p['role']}) is {p['status'] if p['status'] != 'missing' else 'not scanned'}"
        for p in blockers
    )


def rollup(components: list[dict], policy: dict[str, list[str]] | None = None) -> list[dict]:
    """components: [{app, role, stigs: list[stig entry] | None}] where stigs is None when the
    repository has no STIG scan yet. ``policy`` maps a lower-case vuln_id or V-number to the roles
    whose part is required for that control (default: every member role). Returns one entry per
    STIG slug with rolled-up controls."""
    policy = policy or {}
    slugs: dict[str, dict] = {}
    for comp in components:
        for stig in comp["stigs"] or []:
            slugs.setdefault(stig["slug"], {"stig_name": stig.get("stig_name", stig["slug"]),
                                            "release_info": stig.get("release_info", "")})

    out: list[dict] = []
    for slug, meta in sorted(slugs.items()):
        controls: dict[str, dict] = {}
        by_comp: list[tuple[dict, dict[str, dict]]] = []
        for comp in components:
            stigs = comp["stigs"]
            if stigs is None:
                by_comp.append((comp, {}))
                continue
            match = next((s for s in stigs if s["slug"] == slug), None)
            if match is None:
                continue  # this repository has STIG results, but not for this STIG
            by_comp.append((comp, {c["vuln_id"]: c for c in match["controls"]}))
            for c in match["controls"]:
                controls.setdefault(c["vuln_id"], c)

        rows: list[dict] = []
        for vid, base in controls.items():
            parts = []
            for comp, cmap in by_comp:
                c = cmap.get(vid)
                parts.append({"app": comp["app"], "role": comp["role"],
                              "status": c["status"] if c else "missing",
                              "evidence": c.get("evidence", "") if c else ""})
            needed = policy.get(vid.lower())
            if needed is None:
                needed = policy.get(str(base.get("group_id", "")).lower())
            for p in parts:
                p["required"] = needed is None or p["role"] in needed
            counted = [p for p in parts if p["required"]]
            absent = [r for r in (needed or []) if r not in {p["role"] for p in parts}]
            status = rollup_status([NOT_REVIEWED if p["status"] == "missing" else p["status"] for p in counted]
                                   + ([NOT_REVIEWED] if absent else []))
            reason = _reason(status, counted)
            if absent:
                reason = f"No repository with required role: {', '.join(absent)}. " + reason
            if needed is not None and len(counted) != len(parts):
                reason += f" (policy: only {', '.join(needed)} required)"
            rows.append({"vuln_id": vid, "group_id": base.get("group_id", ""), "number": base.get("number"), "severity": base.get("severity", ""),
                         "title": base.get("title", ""), "status": status,
                         "reason": reason, "parts": parts})
        rows.sort(key=lambda r: (r["number"] is None, r["number"] or 0, r["vuln_id"]))
        totals = {"total": len(rows), "open": 0, "pass": 0, "na": 0, "nr": 0}
        for r in rows:
            totals[{OPEN: "open", PASS: "pass", NOT_APPLICABLE: "na"}.get(r["status"], "nr")] += 1
        out.append({"slug": slug, **meta, "totals": totals, "controls": rows})
    return out
