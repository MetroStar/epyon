"""ETK stig-review record rendering for Epyon Layer 13 (MID-4532).

Renders one ``v-xxxxx.md`` entry per assessed control plus a ``README.md``
index, from pinned copies of the ETK record template under
``configuration/stig-review-templates/``. ETK is never read at run time.
Records are ASCII only and have secrets and internal hostnames redacted.
Standard library only.
"""
from __future__ import annotations

import ipaddress
import re
import unicodedata
from pathlib import Path
from typing import Any

TEMPLATE_DIR = Path(__file__).resolve().parents[2] / "configuration" / "stig-review-templates"
if not all((TEMPLATE_DIR / name).is_file() for name in ("entry.md", "index.md")):
    _DEFAULT_TEMPLATE_DIR = Path("/opt/epyon-defaults/configuration/stig-review-templates")
    if all((_DEFAULT_TEMPLATE_DIR / name).is_file() for name in ("entry.md", "index.md")):
        TEMPLATE_DIR = _DEFAULT_TEMPLATE_DIR
RECORD_STATUSES = ("Open", "Not a Finding", "Not Applicable")
NOT_CONFIRMABLE = "not confirmable from this repo"
MIN_RECORD_CONFIDENCE = 1

_CAT = {"high": "CAT I", "medium": "CAT II", "low": "CAT III"}
_ASCII_MAP = str.maketrans({
    "\u2014": "-", "\u2013": "-", "\u2012": "-", "\u2212": "-",
    "\u2018": "'", "\u2019": "'", "\u201c": '"', "\u201d": '"',
    "\u2026": "...", "\u2265": ">=", "\u2264": "<=", "\u2192": "->",
    "\u2022": "-", "\u00a0": " ", "\u2713": "yes", "\u2717": "no",
})

_SECRET_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)", re.DOTALL),
    re.compile(r"\b(?:sk|pk|rk)-[A-Za-z0-9_-]{16,}"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
    re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9._~+/=-]{16,}"),
    re.compile(r"(?i)\b((?:[a-z0-9]+[_-])*(?:password|passwd|secret|token|api[_-]?key|client[_-]?secret)[\"']?\s*[:=]\s*)(?![\"']?\[REDACTED)[\"']?[^\s\"',;|]{6,}"),
)
_HOST_RE = re.compile(r"\b(?:[A-Za-z0-9-]+\.)+(?:internal|local|corp|lan|intra|svc|cluster\.local)\b", re.IGNORECASE)
_IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")


def v_number(control: dict[str, Any]) -> str:
    """Lower-case V-number from the XCCDF group id, falling back to the vuln id."""
    group = str(control.get("group_id") or "").strip()
    if re.fullmatch(r"V-\d+", group, re.IGNORECASE):
        return group.lower()
    fallback = re.sub(r"[^a-z0-9]+", "-", str(control.get("vuln_id") or "unknown").lower()).strip("-")
    return fallback or "unknown"


def vuln_map(controls: list[dict[str, Any]]) -> dict[str, str]:
    """APSC-DV id -> upper-case V-number, for stig-controls-{slug}.json."""
    return {c["vuln_id"]: v_number(c).upper() for c in controls if c.get("vuln_id")}


def sanitize(text: Any) -> str:
    """ASCII-only text with secrets and internal hostnames redacted."""
    value = str(text if text is not None else "")
    for pattern in _SECRET_PATTERNS:
        value = pattern.sub(lambda m: (m.group(1) + "[REDACTED]") if m.lastindex else "[REDACTED]", value)
    value = _HOST_RE.sub("[internal-host]", value)

    def _ip(match: re.Match[str]) -> str:
        try:
            ip = ipaddress.ip_address(match.group(0))
        except ValueError:
            return match.group(0)
        return "[internal-host]" if (ip.is_private or ip.is_loopback or ip.is_link_local) else match.group(0)

    value = _IP_RE.sub(_ip, value)
    value = value.translate(_ASCII_MAP)
    value = unicodedata.normalize("NFKD", value).encode("ascii", "ignore").decode("ascii")
    return "".join(ch for ch in value if ch in "\n\t" or 32 <= ord(ch) < 127)


def _cell(text: Any) -> str:
    """Single-line, pipe-safe table cell."""
    value = sanitize(text).strip()
    value = re.sub(r"\s*\n\s*", "<br>", value)
    return value.replace("|", "\\|") or "-"


def record_status(status: str) -> str:
    """ETK has three statuses; Epyon's 'Not Reviewed' is recorded as Open."""
    return status if status in RECORD_STATUSES else "Open"


def _paths_in(evidence: str) -> list[str]:
    seen: list[str] = []
    for match in re.finditer(r"(?:File|Path):\s*`?([\w./@-]+\.[A-Za-z0-9]+(?::\d+)?)", evidence or ""):
        if match.group(1) not in seen:
            seen.append(match.group(1))
    return seen[:5]


def _first_sentence(text: str, limit: int = 220) -> str:
    flat = " ".join(sanitize(text).split())
    cut = re.split(r"(?<=[.!?])\s", flat, maxsplit=1)[0]
    return cut[:limit].rstrip()


def changes_rows(assessment: dict[str, Any]) -> list[dict[str, str]]:
    """Concrete change rows: the assessor's, else one per file the evidence cites."""
    rows: list[dict[str, str]] = []
    for item in assessment.get("changes_that_may_affect") or []:
        if not isinstance(item, dict):
            continue
        change = str(item.get("change") or "").strip()
        where = str(item.get("where") or item.get("path") or "").strip()
        recheck = str(item.get("recheck") or item.get("re_check") or "").strip()
        if change and where:
            rows.append({"change": change, "where": where, "recheck": recheck or "Re-read the cited evidence"})
    if rows:
        return rows
    return [
        {
            "change": f"Edit to {path.split(':')[0]}",
            "where": path,
            "recheck": "Re-read the cited setting and confirm it still meets the control",
        }
        for path in _paths_in(str(assessment.get("evidence") or ""))
    ]


def automation_text(assessment: dict[str, Any], control: dict[str, Any]) -> str:
    rec = assessment.get("automation_recommendation")
    if isinstance(rec, dict):
        parts = [
            ("Check", rec.get("check")),
            ("Data source", rec.get("data_source")),
            ("Pass/fail rule", rec.get("pass_fail_rule")),
            ("Runs", rec.get("where_it_runs") or rec.get("where")),
        ]
        if all(str(v or "").strip() for _, v in parts):
            return "; ".join(f"{label}: {sanitize(str(value).strip())}" for label, value in parts)
    fix = _first_sentence(str(control.get("fix_text") or control.get("title") or ""))
    return (
        f"Check: automate the STIG check for this control ({fix}); "
        "Data source: repository configuration and code at the scanned commit; "
        "Pass/fail rule: fail when the setting the control requires is absent or weaker than required; "
        "Runs: Epyon Layer 13 on every full or stig scan"
    )


def evidence_text(assessment: dict[str, Any], control: dict[str, Any]) -> tuple[str, str]:
    """(evidence, notes) for the control table; never claims compliance without evidence."""
    status = assessment.get("status", "Open")
    evidence = str(assessment.get("evidence") or "").strip()
    unreviewed = status == "Not Reviewed" or not evidence or evidence.startswith("STIG assessment skipped")
    if unreviewed:
        needed = _first_sentence(str(control.get("check_content") or control.get("title") or "")) or "the control's check text"
        return (
            f"{NOT_CONFIRMABLE}. Evidence needed: {needed}",
            "No AI assessment was available for this control.",
        )
    return evidence, ""


def render_entry(
    control: dict[str, Any],
    assessment: dict[str, Any],
    *,
    scan_date: str,
    reviewer: str,
    method: str,
    template: str | None = None,
) -> str:
    template = template if template is not None else (TEMPLATE_DIR / "entry.md").read_text(encoding="utf-8")
    vnum = v_number(control).upper()
    rule = str(control.get("rule_id") or "").strip()
    version = str(control.get("vuln_id") or "").strip()
    stated = ", ".join(x for x in (rule, version) if x)
    status = record_status(assessment.get("status", "Open"))
    evidence, notes = evidence_text(assessment, control)
    confidence = max(MIN_RECORD_CONFIDENCE, int(assessment.get("confidence") or 0))
    note_parts = [f"Confidence {confidence}/100."]
    if assessment.get("locked_by_human"):
        note_parts.append("Human-reviewed; carried forward unchanged.")
    elif assessment.get("locked_by_previous"):
        note_parts.append("Carried forward from the previous scan.")
    if notes:
        note_parts.append(notes)
    if assessment.get("downgraded_from"):
        note_parts.append(f"Downgraded from {assessment['downgraded_from']} by evidence verification.")
    if assessment.get("verification_note"):
        note_parts.append(f"Verification: {assessment['verification_note']}.")
    for failure in assessment.get("citation_failures") or []:
        note_parts.append(f"Failed citation: {failure}.")
    sev = str(control.get("severity") or "").lower()
    severity = f"{_CAT.get(sev, sev or 'not stated')}" + (f" ({rule})" if rule else "")
    if status == "Open":
        findings = (
            f"Open: {(_first_sentence(evidence) or NOT_CONFIRMABLE).rstrip('.')}. No follow-up ticket has been filed yet."
        )
    else:
        findings = f"None. {status}."
    rows = changes_rows(assessment)
    rows_text = "\n".join(
        f"  | {_cell(r['change'])} | {_cell(r['where'])} | {_cell(r['recheck'])} |" for r in rows
    ) or "  | not recorded; re-run the assessment to populate | - | - |"
    values = {
        "heading": f"{vnum}: {sanitize(control.get('title', '')).strip()} ({stated})" if stated else f"{vnum}: {sanitize(control.get('title', '')).strip()}",
        "reviewed": f"{sanitize(scan_date)} by {sanitize(reviewer)}",
        "ticket": "not linked (generated by an Epyon scan)",
        "severity": sanitize(severity),
        "method": sanitize(method),
        "control_id": _cell(version or vnum),
        "status": status,
        "evidence": _cell(evidence),
        "notes": _cell(" ".join(note_parts)),
        "findings": sanitize(findings),
        "changes_rows": rows_text,
        "automation": automation_text(assessment, control),
    }
    out = template
    for key, value in values.items():
        out = out.replace("{{" + key + "}}", value)
    return out.rstrip() + "\n"


def render_index(
    controls: list[dict[str, Any]],
    assessments: dict[str, dict[str, Any]],
    *,
    repository: str,
    scan_date: str,
    reviewer: str,
    stig_name: str,
    release_info: str,
    template: str | None = None,
) -> str:
    template = template if template is not None else (TEMPLATE_DIR / "index.md").read_text(encoding="utf-8")
    rows = []
    for control in controls:
        assessment = assessments.get(control["vuln_id"], {})
        status = record_status(assessment.get("status", "Open"))
        name = v_number(control)
        findings = "none" if status != "Open" else "open"
        automation = _first_sentence(automation_text(assessment, control), 90)
        rows.append(
            f"| {name.upper()} | [{name}.md]({name}.md) | {_cell(release_info or stig_name)} | "
            f"{_cell(scan_date)} | {_cell(reviewer)} | {status} | {findings} | {_cell(automation)} |"
        )
    values = {
        "repository": sanitize(repository),
        "tracking": "no tracking ticket yet (set one when publishing these records)",
        "date": sanitize(scan_date),
        "stig_name": sanitize(stig_name),
        "rows": "\n".join(rows),
    }
    out = template
    for key, value in values.items():
        out = out.replace("{{" + key + "}}", value)
    return out.rstrip() + "\n"


def write_records(
    out_dir: Path,
    controls: list[dict[str, Any]],
    assessments: dict[str, dict[str, Any]],
    *,
    app_name: str,
    scan_date: str,
    stig_name: str,
    release_info: str,
    model: str,
    has_api_key: bool,
) -> list[Path]:
    """Write the entry files and index into ``out_dir``; returns the paths written."""
    out_dir.mkdir(parents=True, exist_ok=True)
    reviewer = f"Epyon AI assessment ({model})" if has_api_key else "Epyon (no AI key configured)"
    method = (
        "Static review of repository files by Epyon Layer 13; no commands were run and no "
        "runtime state was inspected. Evidence cites the file and setting that was read."
        if has_api_key
        else "No assessment was made: no AI key was configured for this scan."
    )
    written: list[Path] = []
    for control in controls:
        assessment = assessments.get(control["vuln_id"], {})
        path = out_dir / f"{v_number(control)}.md"
        path.write_text(
            render_entry(control, assessment, scan_date=scan_date, reviewer=reviewer, method=method),
            encoding="ascii",
        )
        written.append(path)
    index = out_dir / "README.md"
    index.write_text(
        render_index(
            controls, assessments, repository=app_name, scan_date=scan_date,
            reviewer=reviewer, stig_name=stig_name, release_info=release_info,
        ),
        encoding="ascii",
    )
    written.append(index)
    return written
