"""Build a POA&M (Plan of Action and Milestones) CSV from a scan's Open STIG controls and CVEs."""
from __future__ import annotations

import csv
import io
import re
from datetime import datetime, timedelta
from typing import Any

# Matches the SLA thresholds used for the metrics SLA compliance rate.
SLA_DAYS = {"critical": 7, "high": 30, "medium": 90, "low": 180}
_STIG_SEVERITY = {"high": "high", "medium": "medium", "low": "low"}
_CAT = {"critical": "CAT I", "high": "CAT I", "medium": "CAT II", "low": "CAT III"}
_CVE_SEVERITIES = ("critical", "high")
_FORMULA_PREFIX = ("=", "+", "-", "@", "\t", "\r")

COLUMNS = [
    "POA&M ID", "Weakness Name", "Weakness Description", "Weakness Identifier",
    "Detection Source", "Raw Severity", "Category", "Affected Component",
    "Remediation / Mitigation", "Scheduled Completion Date", "Status",
    "Point of Contact", "Resources Required", "Milestones", "Comments",
]


def scan_date(scan_id: str) -> datetime:
    m = re.search(r"_(\d{4}-\d{2}-\d{2})_(\d{2})-(\d{2})-(\d{2})$", scan_id)
    if not m:
        return datetime.utcnow()
    return datetime.strptime(f"{m.group(1)} {m.group(2)}:{m.group(3)}:{m.group(4)}", "%Y-%m-%d %H:%M:%S")


def _safe(value: Any) -> str:
    """Neutralise spreadsheet formula injection from scanner/AI-supplied text."""
    text = "" if value is None else str(value).replace("\r", " ").strip()
    return "'" + text if text.startswith(_FORMULA_PREFIX) else text


def build_rows(scan_id: str, stigs: list[dict], findings: dict) -> list[dict]:
    detected = scan_date(scan_id)
    rows: list[dict] = []

    def due(sev: str) -> str:
        return (detected + timedelta(days=SLA_DAYS[sev])).strftime("%Y-%m-%d")

    for stig in stigs:
        for c in stig.get("controls", []):
            if c.get("status") != "Open":
                continue
            sev = _STIG_SEVERITY.get(str(c.get("severity", "")).lower(), "medium")
            rows.append({
                "Weakness Name": c.get("title", ""),
                "Weakness Description": c.get("discussion", "") or c.get("title", ""),
                "Weakness Identifier": f"{c.get('vuln_id', '')} / {c.get('rule_id', '')}",
                "Detection Source": f"Epyon STIG assessment: {stig.get('stig_name', '')} {stig.get('release_info', '')}".strip()
                                    + f" ({detected:%Y-%m-%d})",
                "Raw Severity": sev.capitalize(),
                "Category": _CAT[sev],
                "Affected Component": stig.get("stig_name", ""),
                "Remediation / Mitigation": c.get("fix_text", ""),
                "Scheduled Completion Date": due(sev),
                "Comments": f"Assessment evidence (confidence {c.get('confidence', 0)}): {c.get('evidence', '')}",
            })

    for sev in _CVE_SEVERITIES:
        for f in findings.get(f"{sev}_findings", []):
            if f.get("suppressed"):
                continue
            pkg = f.get("package_name") or ""
            ver = f.get("package_version") or ""
            fixes = ", ".join(f.get("fix_versions") or [])
            vid = f.get("vulnerability_id") or f.get("id") or ""
            rows.append({
                "Weakness Name": f"{vid} in {pkg}".strip() if pkg else vid,
                "Weakness Description": f.get("description", ""),
                "Weakness Identifier": vid,
                "Detection Source": f"{f.get('tool', '')} ({detected:%Y-%m-%d})",
                "Raw Severity": sev.capitalize(),
                "Category": _CAT[sev],
                "Affected Component": f"{pkg} {ver}".strip() + (f" ({f['target']})" if f.get("target") else ""),
                "Remediation / Mitigation": f"Upgrade to {fixes}" if fixes else "No fixed version available; mitigate or accept risk",
                "Scheduled Completion Date": due(sev),
                "Comments": "CISA KEV: known exploited" if f.get("cisa_kev") else "",
            })

    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    rows.sort(key=lambda r: (order[r["Raw Severity"]], r["Weakness Identifier"]))
    for i, r in enumerate(rows, 1):
        r["POA&M ID"] = f"POAM-{i:04d}"
        r["Status"] = "Ongoing"
    return rows


def to_csv(rows: list[dict]) -> str:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=COLUMNS, lineterminator="\n")
    w.writeheader()
    for r in rows:
        w.writerow({col: _safe(r.get(col, "")) for col in COLUMNS})
    return buf.getvalue()
