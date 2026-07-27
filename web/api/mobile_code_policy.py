"""
Mobile code policy management for Epyon.

Stores and manages approved mobile code types and files per DoD mobile code policy.
Policy is stored in web/data/mobile-code-policy.json.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Paths
_HERE = Path(__file__).parent
_DATA_DIR = (_HERE / ".." / "data").resolve()
_POLICY_FILE = _DATA_DIR / "mobile-code-policy.json"


def read_policy() -> dict[str, Any]:
    """Read the mobile code policy from disk."""
    if not _POLICY_FILE.exists():
        return {
            "approval_required": True,
            "approved_types": [],
            "approved_files": [],
            "approved_extensions": [],
            "notes": "",
            "last_updated": None,
        }
    
    try:
        with open(_POLICY_FILE, "r", encoding="utf-8") as f:
            policy = json.load(f)
        # Ensure all required fields exist
        policy.setdefault("approval_required", True)
        policy.setdefault("approved_types", [])
        policy.setdefault("approved_files", [])
        policy.setdefault("approved_extensions", [])
        policy.setdefault("notes", "")
        return policy
    except Exception:
        return {
            "approval_required": True,
            "approved_types": [],
            "approved_files": [],
            "approved_extensions": [],
            "notes": "",
            "last_updated": None,
        }


def write_policy(policy: dict[str, Any]) -> None:
    """Write the mobile code policy to disk."""
    _POLICY_FILE.parent.mkdir(parents=True, exist_ok=True)
    
    # Add timestamp
    policy["last_updated"] = datetime.now(timezone.utc).isoformat()
    
    with open(_POLICY_FILE, "w", encoding="utf-8") as f:
        json.dump(policy, f, indent=2)


def get_available_mobile_code_types() -> list[dict[str, str]]:
    """Return list of all known mobile code types with descriptions."""
    return [
        {
            "type": "javascript_web",
            "description": "JavaScript in web contexts (HTML, JSP, PHP)",
            "category": "Category 2",
            "risk_level": "medium",
        },
        {
            "type": "java_applet",
            "description": "Java Applets",
            "category": "Category 1B",
            "risk_level": "high",
        },
        {
            "type": "flash",
            "description": "Adobe Flash/Shockwave",
            "category": "Category 1B",
            "risk_level": "high",
        },
        {
            "type": "activex",
            "description": "ActiveX Controls",
            "category": "Category 1A",
            "risk_level": "critical",
        },
        {
            "type": "vbscript",
            "description": "VBScript",
            "category": "Category 1B",
            "risk_level": "high",
        },
        {
            "type": "browser_extension",
            "description": "Browser Extensions",
            "category": "Category 2",
            "risk_level": "medium",
        },
        {
            "type": "webstart",
            "description": "Java WebStart (JNLP)",
            "category": "Category 1B",
            "risk_level": "high",
        },
        {
            "type": "downloadable_executable",
            "description": "Downloadable Executables",
            "category": "Category 1B",
            "risk_level": "high",
        },
    ]


def approve_mobile_code_type(mobile_code_type: str) -> bool:
    """Add a mobile code type to the approved list."""
    policy = read_policy()
    if mobile_code_type not in policy["approved_types"]:
        policy["approved_types"].append(mobile_code_type)
        write_policy(policy)
        return True
    return False


def unapprove_mobile_code_type(mobile_code_type: str) -> bool:
    """Remove a mobile code type from the approved list."""
    policy = read_policy()
    if mobile_code_type in policy["approved_types"]:
        policy["approved_types"].remove(mobile_code_type)
        write_policy(policy)
        return True
    return False


def approve_file(file_path: str) -> bool:
    """Add a specific file to the approved list."""
    policy = read_policy()
    if file_path not in policy["approved_files"]:
        policy["approved_files"].append(file_path)
        write_policy(policy)
        return True
    return False


def unapprove_file(file_path: str) -> bool:
    """Remove a specific file from the approved list."""
    policy = read_policy()
    if file_path in policy["approved_files"]:
        policy["approved_files"].remove(file_path)
        write_policy(policy)
        return True
    return False
