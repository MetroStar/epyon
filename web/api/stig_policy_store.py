"""Settings-uploaded STIG guidance: organization rules and per-application references.

Files live in web/data/stig-policy/. Content is guidance text only (no secrets);
the assessor appends it to its prompt and never lets it change the output format.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

_DATA_DIR = (Path(__file__).parent / ".." / "data" / "stig-policy").resolve()
ORG_RULES_FILE = _DATA_DIR / "org-rules.md"
ORG_RULES_MAX_BYTES = 4000
REFERENCE_MAX_BYTES = 8000


def app_slug(name: str) -> str:
    return re.sub(r"[^a-z0-9._-]+", "-", (name or "").lower()).strip("-.")


def validate_text(text: object, max_bytes: int) -> str:
    """Return cleaned text or raise ValueError; rejects non-text, NULs and oversize input."""
    if not isinstance(text, str):
        raise ValueError("content must be text")
    if "\x00" in text:
        raise ValueError("content must be plain text")
    cleaned = text.replace("\r\n", "\n").strip()
    if not cleaned:
        raise ValueError("content is empty")
    if len(cleaned.encode("utf-8")) > max_bytes:
        raise ValueError(f"content exceeds {max_bytes} bytes")
    return cleaned + "\n"


def reference_path(app_name: str) -> Path:
    slug = app_slug(app_name)
    if not slug:
        raise ValueError("invalid application name")
    return _DATA_DIR / "references" / f"{slug}.md"


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    path.chmod(0o600)


def _read(path: Path) -> Optional[str]:
    try:
        return path.read_text(encoding="utf-8") if path.is_file() else None
    except (OSError, UnicodeDecodeError):
        return None


def get_org_rules() -> Optional[str]:
    return _read(ORG_RULES_FILE)


def save_org_rules(text: object) -> str:
    cleaned = validate_text(text, ORG_RULES_MAX_BYTES)
    _write(ORG_RULES_FILE, cleaned)
    return cleaned


def delete_org_rules() -> bool:
    return _delete(ORG_RULES_FILE)


def get_reference(app_name: str) -> Optional[str]:
    return _read(reference_path(app_name))


def save_reference(app_name: str, text: object) -> str:
    cleaned = validate_text(text, REFERENCE_MAX_BYTES)
    _write(reference_path(app_name), cleaned)
    return cleaned


def delete_reference(app_name: str) -> bool:
    return _delete(reference_path(app_name))


def list_references() -> list[str]:
    ref_dir = _DATA_DIR / "references"
    return sorted(p.stem for p in ref_dir.glob("*.md")) if ref_dir.is_dir() else []


def _delete(path: Path) -> bool:
    try:
        path.unlink()
        return True
    except FileNotFoundError:
        return False


def scan_env(app_name: str) -> dict[str, str]:
    """Environment variables that point the assessor at uploaded guidance files."""
    env: dict[str, str] = {}
    if ORG_RULES_FILE.is_file():
        env["EPYON_STIG_POLICY_EXTRA_FILE"] = str(ORG_RULES_FILE)
    try:
        ref = reference_path(app_name)
    except ValueError:
        return env
    if ref.is_file():
        env["EPYON_STIG_REFERENCE_FILE"] = str(ref)
    return env
