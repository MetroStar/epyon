"""Epyon Web — stig_entries helpers."""
from __future__ import annotations

from pathlib import Path
import json
import re


from . import parsers
from . import main as api_main


def _build_stig_entries(scan_id: str, matched: Path) -> list[dict]:
    """Merge STIG controls with assessment results for every STIG in a scan directory."""
    stigs: list[dict] = []
    for results_file in sorted(matched.glob("stig-results-*.json")):
        slug = results_file.stem[len("stig-results-"):]
        controls_file = matched / f"stig-controls-{slug}.json"

        results: dict = {}
        try:
            raw = json.loads(results_file.read_text(encoding="utf-8"))
            # Support new wrapped format {assessments: {...}, token_usage: {...}}
            # and old flat format {vuln_id: {status, evidence}, ...}
            results = raw.get("assessments", raw) if "assessments" in raw else raw
        except Exception:
            pass

        controls_data: dict = {}
        try:
            controls_data = json.loads(controls_file.read_text(encoding="utf-8"))
        except Exception:
            pass

        controls_list = controls_data.get("controls", [])
        merged: list[dict] = []
        for c in controls_list:
            vid = c.get("vuln_id", "")
            assessed = results.get(vid, {})
            merged.append({
                "vuln_id":        vid,
                "group_id":       c.get("group_id", ""),
                "rule_id":        c.get("rule_id", ""),
                "number":         c.get("number"),
                "severity":       c.get("severity", ""),
                "title":          c.get("title", ""),
                "check_content":  c.get("check_content", ""),
                "fix_text":       c.get("fix_text", ""),
                "discussion":     c.get("discussion", ""),
                "status":         assessed.get("status",          "Not Reviewed"),
                "evidence":       assessed.get("evidence",         ""),
                "confidence":     assessed.get("confidence",       0),
                "justification":  assessed.get("justification", ""),
                "human_edit":     assessed.get("human_edit"),
                "locked_by_human": bool(assessed.get("locked_by_human", False)),
                "locked_by_stability": bool(assessed.get("locked_by_stability", False)),
                "stable_count":    assessed.get("stable_count", 0),
                **parsers.stig_record_fields(assessed, c),
            })

        app_slug  = re.sub(r"[^a-z0-9]+", "-", re.sub(r"_\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}$", "", scan_id).lower()).strip("-")
        md_file   = matched / f"findings-{app_slug}-{slug}.md"
        cklb_file = matched / f"findings-{app_slug}-{slug}.cklb"
        stigs.append({
            "slug":        slug,
            "stig_name":   controls_data.get("stig_name", slug),
            "release_info": _release_label(controls_data.get("release_info", ""), slug),
            "total":       len(merged),
            "controls":    merged,
            "md_url":      f"/api/scans/{scan_id}/stig-findings/{app_slug}-{slug}.md"   if md_file.exists()   else None,
            "cklb_url":    f"/api/scans/{scan_id}/stig-findings/{app_slug}-{slug}.cklb" if cklb_file.exists() else None,
        })

    return stigs


def _release_label(stored: str, slug: str) -> str:
    """Scans made before the parser fix stored the XCCDF conventions version (e.g. 1.10.0); use the slug's V6R5 instead."""
    if re.search(r"V\d+R\d+|Release", stored or "", re.IGNORECASE):
        return stored
    m = re.search(r"v(\d+)r(\d+)", slug or "", re.IGNORECASE)
    return f"V{m.group(1)}R{m.group(2)}" if m else (stored or "")
