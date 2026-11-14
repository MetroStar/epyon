"""Build a POA&M (Plan of Action and Milestones) CSV from a scan's Open STIG controls and CVEs."""
from __future__ import annotations

import csv
import io
import json
import re
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

# Defaults match the SLA thresholds used for the metrics SLA compliance rate.
SLA_DAYS = {"critical": 7, "high": 30, "medium": 90, "low": 180}
SEVERITIES = tuple(SLA_DAYS)
MAX_SLA_DAYS = 3650
_CONFIG_FILE = (Path(__file__).parent / ".." / "data" / "poam-config.json").resolve()
_lock = threading.Lock()
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_STIG_SEVERITY = {"high": "high", "medium": "medium", "low": "low"}
_CAT = {"critical": "CAT I", "high": "CAT I", "medium": "CAT II", "low": "CAT III"}
_CVE_SEVERITIES = ("critical", "high")
_FORMULA_PREFIX = ("=", "+", "-", "@", "\t", "\r")

def app_key(scan_id: str) -> str:
    """Stable per-application key: scan_id without timestamp, lowercased, non-alphanumerics -> '-'."""
    name = re.sub(r"_\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}$", "", scan_id).lower()
    return re.sub(r"[^a-z0-9]+", "-", name).strip("-")


def _read() -> dict:
    try:
        data = json.loads(_CONFIG_FILE.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _write(data: dict) -> None:
    _CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = _CONFIG_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    tmp.replace(_CONFIG_FILE)


def validate_sla(sla: Any) -> dict[str, int]:
    """Return a clean {severity: days} map; raise ValueError on bad input."""
    if not isinstance(sla, dict):
        raise ValueError("sla_days must be an object")
    clean: dict[str, int] = {}
    for sev, days in sla.items():
        if sev not in SEVERITIES:
            raise ValueError(f"Unknown severity '{sev}'")
        if isinstance(days, bool) or not isinstance(days, int) or not 1 <= days <= MAX_SLA_DAYS:
            raise ValueError(f"{sev} must be a whole number of days between 1 and {MAX_SLA_DAYS}")
        clean[sev] = days
    return clean


def get_sla_days() -> dict[str, int]:
    saved = _read().get("sla_days")
    try:
        return {**SLA_DAYS, **validate_sla(saved)} if saved else dict(SLA_DAYS)
    except ValueError:
        return dict(SLA_DAYS)


def set_sla_days(sla: Any) -> dict[str, int]:
    clean = validate_sla(sla)
    with _lock:
        data = _read()
        data["sla_days"] = {**get_sla_days(), **clean}
        _write(data)
    return get_sla_days()


def get_overrides(scan_id: str) -> dict[str, str]:
    raw = (_read().get("due_overrides") or {}).get(app_key(scan_id)) or {}
    return {k: v for k, v in raw.items() if isinstance(v, str) and _DATE_RE.match(v)}


def set_override(scan_id: str, key: str, due_date: str | None) -> None:
    """Pin (or with None, clear) a manual completion date for one POA&M item."""
    if not key or len(key) > 300:
        raise ValueError("Invalid item key")
    if due_date is not None:
        if not _DATE_RE.match(due_date):
            raise ValueError("due_date must be YYYY-MM-DD")
        datetime.strptime(due_date, "%Y-%m-%d")
    with _lock:
        data = _read()
        per_app = data.setdefault("due_overrides", {}).setdefault(app_key(scan_id), {})
        if due_date is None:
            per_app.pop(key, None)
        else:
            per_app[key] = due_date
        _write(data)


COLUMNS = [
    "POA&M ID", "Weakness Name", "Weakness Description", "Weakness Identifier",
    "Detection Source", "Raw Severity", "Category", "Affected Component",
    "Remediation / Mitigation", "Scheduled Completion Date", "Due Date Basis", "Status",
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


def build_rows(
    scan_id: str,
    stigs: list[dict],
    findings: dict,
    sla_days: dict[str, int] | None = None,
    overrides: dict[str, str] | None = None,
) -> list[dict]:
    detected = scan_date(scan_id)
    sla = {**SLA_DAYS, **(sla_days or {})}
    overrides = overrides or {}
    rows: list[dict] = []

    def due(sev: str) -> str:
        return (detected + timedelta(days=sla[sev])).strftime("%Y-%m-%d")

    def schedule(row: dict, key: str, sev: str) -> dict:
        row["Item Key"] = key
        row["Default Due Date"] = due(sev)
        manual = overrides.get(key)
        row["Scheduled Completion Date"] = manual or row["Default Due Date"]
        row["Due Date Basis"] = "Manual" if manual else f"SLA ({sla[sev]}d)"
        return row

    for stig in stigs:
        for c in stig.get("controls", []):
            if c.get("status") != "Open":
                continue
            sev = _STIG_SEVERITY.get(str(c.get("severity", "")).lower(), "medium")
            rows.append(schedule({
                "Weakness Name": c.get("title", ""),
                "Weakness Description": c.get("discussion", "") or c.get("title", ""),
                "Weakness Identifier": f"{c.get('vuln_id', '')} / {c.get('rule_id', '')}",
                "Detection Source": f"Epyon STIG assessment: {stig.get('stig_name', '')} {stig.get('release_info', '')}".strip()
                                    + f" ({detected:%Y-%m-%d})",
                "Raw Severity": sev.capitalize(),
                "Category": _CAT[sev],
                "Affected Component": stig.get("stig_name", ""),
                "Remediation / Mitigation": c.get("fix_text", ""),
                "Comments": f"Assessment evidence (confidence {c.get('confidence', 0)}): {c.get('evidence', '')}",
            }, f"stig:{c.get('vuln_id', '')}", sev))

    for sev in _CVE_SEVERITIES:
        for f in findings.get(f"{sev}_findings", []):
            if f.get("suppressed"):
                continue
            pkg = f.get("package_name") or ""
            ver = f.get("package_version") or ""
            fixes = ", ".join(f.get("fix_versions") or [])
            vid = f.get("vulnerability_id") or f.get("id") or ""
            rows.append(schedule({
                "Weakness Name": f"{vid} in {pkg}".strip() if pkg else vid,
                "Weakness Description": f.get("description", ""),
                "Weakness Identifier": vid,
                "Detection Source": f"{f.get('tool', '')} ({detected:%Y-%m-%d})",
                "Raw Severity": sev.capitalize(),
                "Category": _CAT[sev],
                "Affected Component": f"{pkg} {ver}".strip() + (f" ({f['target']})" if f.get("target") else ""),
                "Remediation / Mitigation": f"Upgrade to {fixes}" if fixes else "No fixed version available; mitigate or accept risk",
                "Comments": "CISA KEV: known exploited" if f.get("cisa_kev") else "",
            }, f"cve:{vid}::{pkg}", sev))

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
