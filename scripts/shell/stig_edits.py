"""Epyon STIG human-edit store.

A person's edits to a control (status, evidence, justification) live outside any scan, in
web/data/stig-edits/{app}.json (a volume-mounted directory), so they survive scan pruning and
re-scans. Scans read them as human reviews and verify them against the code; a scan never
rewrites or discards the person's text.
"""
from __future__ import annotations

import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VALID_STATUSES = ("Not a Finding", "Not Applicable", "Open", "Not Reviewed")
_TEXT_LIMIT = 20_000
_PATH = "Epyon edit store (web/data/stig-edits)"


def edits_dir() -> Path:
    override = os.environ.get("EPYON_STIG_EDITS_DIR")
    return Path(override) if override else Path(__file__).resolve().parents[2] / "web" / "data" / "stig-edits"


def app_key(app_name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", app_name.lower()).strip("-")


def family(slug: str) -> str:
    """STIG slug without its release (u-asd-stig-v6r5-manual-xccdf -> u-asd-stig-manual-xccdf)."""
    return re.sub(r"-?v\d+r\d+", "", slug)


def _file(app_name: str) -> Path:
    key = app_key(app_name)
    if not key:
        raise ValueError("Invalid application name")
    return edits_dir() / f"{key}.json"


def load(app_name: str) -> dict[str, dict[str, dict[str, Any]]]:
    """{slug: {vuln_id: edit}} for an application; empty when there are none or the file is unreadable."""
    try:
        data = json.loads(_file(app_name).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _write(app_name: str, data: dict) -> None:
    path = _file(app_name)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def save_edit(app_name: str, slug: str, vuln_id: str, status: str, evidence: str,
              justification: str, editor: str) -> dict[str, Any]:
    if status not in VALID_STATUSES:
        raise ValueError(f"Invalid status. Must be one of: {sorted(VALID_STATUSES)}")
    if len(evidence) > _TEXT_LIMIT or len(justification) > _TEXT_LIMIT:
        raise ValueError("Evidence and justification are limited to 20,000 characters")
    edit = {
        "status": status, "evidence": evidence, "justification": justification,
        "edited_by": editor or "unknown",
        "edited_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    data = load(app_name)
    data.setdefault(slug, {})[vuln_id] = edit
    _write(app_name, data)
    return edit


def clear_edit(app_name: str, slug: str, vuln_id: str) -> bool:
    data = load(app_name)
    if vuln_id not in data.get(slug, {}):
        return False
    del data[slug][vuln_id]
    if not data[slug]:
        del data[slug]
    _write(app_name, data)
    return True


def _entry_text(edit: dict[str, Any]) -> str:
    parts = [f"Status: {edit['status']}", f"Evidence: {edit.get('evidence', '')}"]
    if edit.get("justification"):
        parts.append(f"Justification: {edit['justification']}")
    return "\n".join(parts)


def edits_for_scan(app_name: str, slug: str, controls: list[dict[str, Any]]
                   ) -> tuple[dict[str, dict[str, Any]], dict[str, str]]:
    """Return (prior_by_vuln_id, reopen_reasons_by_vuln_id) for one STIG in a scan.

    Edits for this slug become priors carrying a `human_review`, which makes the assessment
    verify them against the code instead of trusting them. Edits made against another release
    of the same STIG do not apply: the control is assessed fresh and says why.
    """
    stored = load(app_name)
    own = stored.get(slug, {})
    prior: dict[str, dict[str, Any]] = {}
    reasons: dict[str, str] = {}
    fam = family(slug)
    for ctrl in controls:
        vid = ctrl["vuln_id"]
        edit = own.get(vid)
        if edit:
            prior[vid] = {
                "status": edit["status"], "evidence": edit.get("evidence", ""), "confidence": 0,
                "human_edit": edit,
                "human_review": {
                    "status_text": edit["status"], "reviewed": edit.get("edited_at", "")[:10],
                    "reviewer": edit.get("edited_by", ""), "path": _PATH, "entry": _entry_text(edit)[:4000],
                    "index_row": "", "precheck": [], "changed_paths": [],
                },
            }
            continue
        for other_slug, other in stored.items():
            if other_slug != slug and family(other_slug) == fam and vid in other:
                e = other[vid]
                reasons[vid] = (
                    f"STIG release changed ({other_slug} to {slug}); the edit by {e.get('edited_by', '?')} "
                    f"on {e.get('edited_at', '')[:10]} was not carried over, so the control was re-assessed"
                )
                break
    return prior, reasons


def apply_outcome(prior: dict[str, Any], assessment: dict[str, Any]) -> dict[str, Any]:
    """Record the person's edit on a finished assessment without overwriting their text.

    Confirmed (the assessment kept the edited status): the control shows the person's evidence
    and justification and is locked. Contradicted or unverifiable (it changed): the assessment
    stands, and the edit and the reason are attached.
    """
    edit = prior["human_edit"]
    out = dict(assessment)
    out["human_edit"] = {k: edit.get(k, "") for k in ("status", "evidence", "justification", "edited_by", "edited_at")}
    by = f"{edit.get('edited_by', '?')} on {edit.get('edited_at', '')[:10]}"
    if assessment.get("status") == edit["status"]:
        out["verification_note"] = f"Edited by {by}; checked against the repository and confirmed: {assessment.get('evidence', '')}".strip()
        out["evidence"] = edit.get("evidence") or assessment.get("evidence", "")
        out["justification"] = edit.get("justification", "")
        out["confidence"] = max(int(assessment.get("confidence", 0) or 0), 85)
        out["locked_by_human"] = True
    else:
        out["verification_note"] = (
            f"Edit by {by} (status {edit['status']}) could not be confirmed against the repository, "
            f"so the assessed status {assessment.get('status')} stands. Your text is kept below."
        )
    return out
