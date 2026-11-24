"""Epyon Web — project-level STIG roll-up.

Each repository reports whether its own part of a control is satisfied. A project control is
Not a Finding only when every required part is satisfied; the evidence names what is missing.
"""
from __future__ import annotations

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


def _reason(status: str, parts: list[dict]) -> str:
    if status == PASS:
        return "All parts satisfied: " + ", ".join(f"{p['app']} ({p['role']})" for p in parts if p["status"] == PASS)
    if status == NOT_APPLICABLE:
        return "Not applicable to any part of the project"
    blockers = [p for p in parts if p["status"] not in (PASS, NOT_APPLICABLE)]
    word = "Open" if status == OPEN else "No assessment for"
    return f"{word}: " + ", ".join(
        f"{p['app']} ({p['role']}) is {p['status'] if p['status'] != 'missing' else 'not scanned'}"
        for p in blockers
    )


def rollup(components: list[dict]) -> list[dict]:
    """components: [{app, role, stigs: list[stig entry] | None}] where stigs is None when the
    repository has no STIG scan yet. Returns one entry per STIG slug with rolled-up controls."""
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
            status = rollup_status([NOT_REVIEWED if p["status"] == "missing" else p["status"] for p in parts])
            rows.append({"vuln_id": vid, "number": base.get("number"), "severity": base.get("severity", ""),
                         "title": base.get("title", ""), "status": status,
                         "reason": _reason(status, parts), "parts": parts})
        rows.sort(key=lambda r: (r["number"] is None, r["number"] or 0, r["vuln_id"]))
        totals = {"total": len(rows), "open": 0, "pass": 0, "na": 0, "nr": 0}
        for r in rows:
            totals[{OPEN: "open", PASS: "pass", NOT_APPLICABLE: "na"}.get(r["status"], "nr")] += 1
        out.append({"slug": slug, **meta, "totals": totals, "controls": rows})
    return out
