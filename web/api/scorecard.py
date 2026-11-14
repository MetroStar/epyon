"""Score Card sign-off and evidence-package helpers.

A sign-off records that a named reviewer accepted a specific score. It stores a
digest of the score, so any rescore that changes a number invalidates it.
"""
from __future__ import annotations

import hashlib
import io
import json
import re
import threading
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

_FILE = (Path(__file__).parent / ".." / "data" / "scorecard-signoffs.json").resolve()
_lock = threading.Lock()
_NAME_RE = re.compile(r"^[^\x00-\x1f\x7f]{2,100}$")
MAX_COMMENT = 2000
MAX_BUNDLE_BYTES = 50 * 1024 * 1024
MAX_FILE_BYTES = 10 * 1024 * 1024


def score_digest(trl: dict) -> str:
    """Digest of everything a reviewer is approving: version, grade, weights and every dimension score."""
    payload = {
        "scoring_version": trl.get("scoring_version"),
        "trl_level": trl.get("trl_level"),
        "weighted_score": trl.get("weighted_score"),
        "weights": trl.get("weights"),
        "dimensions": {k: v.get("score") for k, v in (trl.get("dimension_scores") or {}).items()},
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()


def _read() -> dict:
    try:
        data = json.loads(_FILE.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _write(data: dict) -> None:
    _FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = _FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    tmp.replace(_FILE)


def get_signoff(scan_id: str, trl: Optional[dict] = None) -> Optional[dict]:
    """Return the sign-off for a scan, with `valid` set when the score still matches."""
    entry = _read().get(scan_id)
    if not isinstance(entry, dict):
        return None
    out = dict(entry)
    out["valid"] = bool(trl) and out.get("score_digest") == score_digest(trl)
    return out


def save_signoff(scan_id: str, trl: dict, reviewer: Any, comment: Any) -> dict:
    """Record a sign-off for the current score; raise ValueError on bad input."""
    if not isinstance(reviewer, str) or not _NAME_RE.match(reviewer.strip()):
        raise ValueError("reviewer must be a name of 2-100 characters")
    comment = "" if comment is None else comment
    if not isinstance(comment, str) or len(comment) > MAX_COMMENT:
        raise ValueError(f"comment must be text of at most {MAX_COMMENT} characters")
    entry = {
        "reviewer": reviewer.strip(),
        "comment": comment.strip(),
        "signed_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "score_digest": score_digest(trl),
        "scoring_version": trl.get("scoring_version"),
        "trl_level": trl.get("trl_level"),
        "weighted_score": trl.get("weighted_score"),
    }
    with _lock:
        data = _read()
        data[scan_id] = entry
        _write(data)
    return get_signoff(scan_id, trl) or entry


def clear_signoff(scan_id: str) -> bool:
    with _lock:
        data = _read()
        removed = data.pop(scan_id, None) is not None
        if removed:
            _write(data)
    return removed


def build_evidence_zip(scans_root: Path, scan_id: str, trl: dict, signoff: Optional[dict]) -> bytes:
    """Zip the score, a hash manifest and the source artifacts the score relied on.

    Sources are re-hashed at bundle time; a mismatch with the recorded hash is
    flagged in the manifest instead of being hidden. Paths are confined to scans_root.
    """
    root = scans_root.resolve()
    manifest: list[dict] = []
    total = 0
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("trl-assessment.json", json.dumps(trl, indent=2))
        if signoff:
            zf.writestr("signoff.json", json.dumps(signoff, indent=2))
        for item in trl.get("evidence_manifest", []):
            rel = str(item.get("path", ""))
            entry = {"path": rel, "recorded_sha256": item.get("sha256")}
            target = (root / rel).resolve()
            try:
                target.relative_to(root)
            except ValueError:
                entry["status"] = "rejected: outside scans directory"
                manifest.append(entry)
                continue
            if not target.is_file():
                entry["status"] = "missing"
            elif target.stat().st_size > MAX_FILE_BYTES or total + target.stat().st_size > MAX_BUNDLE_BYTES:
                entry["status"] = "omitted: size limit"
            else:
                data = target.read_bytes()
                total += len(data)
                digest = hashlib.sha256(data).hexdigest()
                entry["current_sha256"] = digest
                entry["status"] = "ok" if digest == item.get("sha256") else "changed since scoring"
                zf.writestr(f"artifacts/{rel}", data)
            manifest.append(entry)
        zf.writestr("manifest.json", json.dumps({
            "scan_id": scan_id,
            "scoring_version": trl.get("scoring_version"),
            "score_digest": score_digest(trl),
            "artifacts": manifest,
        }, indent=2))
    return buf.getvalue()
