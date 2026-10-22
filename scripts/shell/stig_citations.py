#!/usr/bin/env python3
"""Deterministic verification of STIG evidence citations (MID-4533).

Plain file reads only: no model calls. A control whose citations fail, whose
Not Applicable answer states no search, or whose compliance rests on a party
outside the repo is downgraded to Open with a confidence below the freeze
threshold, and the reason is recorded on the assessment.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

FREEZE_THRESHOLD = 85
DOWNGRADED_CONFIDENCE_CAP = 60
MAX_FILE_BYTES = 2_000_000
LINE_WINDOW = 2

_EXCLUDED_DIRS = {
    "node_modules", ".git", "dist", "build", "target", "vendor", "__pycache__",
    ".venv", "venv", ".next", "coverage", ".tox", "site-packages", ".terraform",
}
_LOCK_SUFFIXES = (".lock", "-lock.json", ".min.js", ".map")
_LOCK_NAMES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "Pipfile.lock", "go.sum"}

_CITATION = re.compile(r"(?im)^\s*[-*]?\s*(?:file|path)s?\s*:\s*(?P<body>.+)$")
_PATH_LINE = re.compile(r"^(?P<path>[^\s:`\"']+?)(?::(?P<line>\d+)(?:-(?P<end>\d+))?)?(?P<rest>(?:\s|$).*)$")
_QUOTED = re.compile(r'"([^"\n]{3,})"|`([^`\n]{3,})`')

_ABSENCE = re.compile(
    r"(?i)\b(searched|no match|no matches|not found|no occurrences?|absence|absent|"
    r"does not (?:contain|use|include|have|implement|expose)|no [\w\- ]{0,40}"
    r"(?:found|present|detected|exists?|used|configured))\b"
)
_EXTERNAL_OWNER = re.compile(
    r"(?i)\b(?:delegated to|handled by|managed by|inherited from|provided by|enforced by|"
    r"responsibility of|owned by|outside (?:of )?(?:the )?(?:repo|repository|application))\b"
    r"[^.\n]{0,60}?\b(?:identity provider|idp|sso|infrastructure|hosting|cloud provider|"
    r"platform team|vendor|operations team|network team|load balancer|kubernetes cluster)\b"
)


def _excluded(rel: Path) -> str:
    """Reason the path cannot be cited as evidence, or ''."""
    name = rel.name
    if name == ".env" or (name.startswith(".env.") and name not in {".env.example", ".env.template"}):
        return "environment files are never read"
    if any(part in _EXCLUDED_DIRS for part in rel.parts[:-1]):
        return "dependency or generated directory"
    if name in _LOCK_NAMES or name.endswith(_LOCK_SUFFIXES):
        return "lock or generated file"
    return ""


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip().lower()


def parse_citations(evidence: str) -> list[dict[str, Any]]:
    """Citations found in the evidence: path, optional line range, quoted snippets."""
    found: list[dict[str, Any]] = []
    for match in _CITATION.finditer(evidence or ""):
        body = match.group("body").strip().strip("`")
        m = _PATH_LINE.match(body)
        if not m or "/" not in m.group("path") and "." not in m.group("path"):
            continue
        rest = m.group("rest")
        snippets = [a or b for a, b in _QUOTED.findall(rest.replace('\\"', '"'))]
        found.append({
            "path": m.group("path"),
            "line": int(m.group("line")) if m.group("line") else None,
            "end": int(m.group("end")) if m.group("end") else None,
            "snippets": snippets,
            "text": match.group(0).strip(),
        })
    return found


def verify_citation(cite: dict[str, Any], target_dir: str | Path) -> str:
    """Empty string when the citation holds, else the reason it failed."""
    root = Path(target_dir).resolve()
    raw = cite["path"] + (f":{cite['line']}" if cite["line"] else "")
    try:
        full = (root / cite["path"]).resolve()
        rel = full.relative_to(root)
    except (ValueError, OSError):
        return f"{raw}: path is outside the repository"
    reason = _excluded(rel)
    if reason:
        return f"{raw}: not verifiable ({reason})"
    if not full.is_file():
        return f"{raw}: file not found"
    try:
        if full.stat().st_size > MAX_FILE_BYTES:
            return f"{raw}: file too large to verify"
        lines = full.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return f"{raw}: file could not be read"

    line, end = cite["line"], cite["end"] or cite["line"]
    if line is not None:
        if line < 1 or line > len(lines):
            return f"{raw}: line does not exist (file has {len(lines)} lines)"
        lo, hi = max(1, line - LINE_WINDOW), min(len(lines), (end or line) + LINE_WINDOW)
        haystack = _norm(" ".join(lines[lo - 1:hi]))
        where = raw
    else:
        haystack = _norm(" ".join(lines))
        where = raw
    for snippet in cite["snippets"]:
        if _norm(snippet) not in haystack:
            return f'{where}: quoted text "{snippet[:60]}" not found'
    return ""


def has_absence_statement(evidence: str) -> bool:
    return bool(_ABSENCE.search(evidence or ""))


def external_owner(evidence: str) -> str:
    m = _EXTERNAL_OWNER.search(evidence or "")
    return m.group(0).strip() if m else ""


def verify_assessment(assessment: dict[str, Any], target_dir: str | Path, control: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return the assessment, downgraded in place when verification fails."""
    status = assessment.get("status")
    if status not in ("Not a Finding", "Not Applicable", "Open"):
        return assessment
    evidence = str(assessment.get("evidence") or "")
    problems: list[str] = []
    failures: list[str] = []

    for cite in parse_citations(evidence):
        why = verify_citation(cite, target_dir)
        if why:
            failures.append(why)
    if failures:
        problems.append("citation verification failed")

    if status == "Not Applicable" and not has_absence_statement(evidence):
        problems.append("Not Applicable needs an evidence-of-absence statement (what was searched, no match)")

    owner = external_owner(evidence) if status in ("Not a Finding", "Not Applicable") else ""
    if owner:
        problems.append(f'needs owner confirmation ("{owner[:80]}")')
        assessment["needs_owner_confirmation"] = True

    if failures:
        assessment["citation_failures"] = failures
    if not problems:
        return assessment

    needed = ""
    if control:
        needed = re.split(r"(?<=[.!?])\s", " ".join(str(control.get("check_content") or "").split()), maxsplit=1)[0][:200]
    assessment["verification_note"] = "; ".join(problems) + (f". Evidence needed: {needed}" if needed else "")
    if status != "Open":
        assessment["status"] = "Open"
        assessment["downgraded_from"] = status
    assessment["confidence"] = min(int(assessment.get("confidence") or 0), DOWNGRADED_CONFIDENCE_CAP)
    return assessment
