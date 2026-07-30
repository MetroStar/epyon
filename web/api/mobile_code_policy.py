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
    """Write the mobile code policy to disk (no audit logging)."""
    _POLICY_FILE.parent.mkdir(parents=True, exist_ok=True)
    
    # Add timestamp
    policy["last_updated"] = datetime.now(timezone.utc).isoformat()
    
    with open(_POLICY_FILE, "w", encoding="utf-8") as f:
        json.dump(policy, f, indent=2)


def write_policy_with_audit(policy: dict[str, Any], user: str, reason: str = "", reference: str = "") -> None:
    """
    Write the mobile code policy with audit logging.
    
    Compares the new policy with the existing policy and logs all changes:
    - Types added/removed from approved_types
    - Files added/removed from approved_files
    - Extensions added/removed from approved_extensions
    
    Args:
        policy: New policy dict to write
        user: User identifier (IP, email, or "system")
        reason: Justification for the changes
        reference: Ticket ID, CR number, etc.
    """
    from . import mobile_code_policy_audit
    
    # Read old policy for diffing
    old_policy = read_policy()
    old_types = set(old_policy.get("approved_types", []))
    old_files = set(old_policy.get("approved_files", []))
    old_extensions = set(old_policy.get("approved_extensions", []))
    
    new_types = set(policy.get("approved_types", []))
    new_files = set(policy.get("approved_files", []))
    new_extensions = set(policy.get("approved_extensions", []))
    
    # Log type changes
    for type_id in new_types - old_types:
        mobile_code_policy_audit.log_policy_change(
            action="approve_type",
            target=type_id,
            user=user,
            previous_status="requires_approval",
            new_status="approved",
            reason=reason,
            reference=reference
        )
    
    for type_id in old_types - new_types:
        mobile_code_policy_audit.log_policy_change(
            action="unapprove_type",
            target=type_id,
            user=user,
            previous_status="approved",
            new_status="requires_approval",
            reason=reason,
            reference=reference
        )
    
    # Log file changes
    for file_path in new_files - old_files:
        mobile_code_policy_audit.log_policy_change(
            action="approve_file",
            target=file_path,
            user=user,
            previous_status="requires_approval",
            new_status="approved",
            reason=reason,
            reference=reference
        )
    
    for file_path in old_files - new_files:
        mobile_code_policy_audit.log_policy_change(
            action="unapprove_file",
            target=file_path,
            user=user,
            previous_status="approved",
            new_status="requires_approval",
            reason=reason,
            reference=reference
        )
    
    # Log extension changes
    for ext in new_extensions - old_extensions:
        mobile_code_policy_audit.log_policy_change(
            action="approve_extension",
            target=ext,
            user=user,
            previous_status="requires_approval",
            new_status="approved",
            reason=reason,
            reference=reference
        )
    
    for ext in old_extensions - new_extensions:
        mobile_code_policy_audit.log_policy_change(
            action="unapprove_extension",
            target=ext,
            user=user,
            previous_status="approved",
            new_status="requires_approval",
            reason=reason,
            reference=reference
        )
    
    # Write the new policy
    write_policy(policy)


def get_available_mobile_code_types() -> list[dict[str, str]]:
    """Return list of all known mobile code types with descriptions.
    
    Type names match those emitted by run-mobile-code-scan.py (canonical schema).
    """
    return [
        {
            "type": "inline_javascript",
            "description": "Inline JavaScript (unsigned)",
            "category": "Category 1A",
            "risk_level": "critical",
        },
        {
            "type": "external_javascript",
            "description": "External JavaScript",
            "category": "Category 1B",
            "risk_level": "high",
        },
        {
            "type": "java_applet",
            "description": "Java Applets",
            "category": "Category 1A",
            "risk_level": "critical",
        },
        {
            "type": "flash",
            "description": "Adobe Flash/Shockwave",
            "category": "Category 1A",
            "risk_level": "critical",
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
            "category": "Category 1A",
            "risk_level": "critical",
        },
        {
            "type": "browser_extension",
            "description": "Browser Extensions",
            "category": "Category 2",
            "risk_level": "medium",
        },
        {
            "type": "java_webstart",
            "description": "Java WebStart (JNLP)",
            "category": "Category 1B",
            "risk_level": "high",
        },
        {
            "type": "downloadable_executable",
            "description": "Downloadable Executables",
            "category": "Category 2",
            "risk_level": "medium",
        },
    ]


def approve_mobile_code_type(mobile_code_type: str) -> bool:
    """Add a mobile code type to the approved list.
    
    Args:
        mobile_code_type: Type ID (must match canonical schema)
    
    Returns:
        True if added, False if already approved
    
    Raises:
        ValueError: If mobile_code_type is not a known type
    """
    # Validate type exists in canonical schema
    known_types = {t["type"] for t in get_available_mobile_code_types()}
    if mobile_code_type not in known_types:
        raise ValueError(
            f"Unknown mobile code type: {mobile_code_type}. "
            f"Valid types: {', '.join(sorted(known_types))}"
        )
    
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
