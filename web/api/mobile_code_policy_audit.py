"""
mobile_code_policy_audit.py — Audit trail for mobile code policy changes

Maintains an append-only audit log of all mobile code policy modifications
(approvals, unapprovals) for security compliance and accountability.

Log format: JSONL (newline-delimited JSON)
Location: web/data/mobile-code-policy-audit.jsonl

Each log entry contains:
- timestamp: ISO 8601 timestamp with timezone
- action: approve_type | unapprove_type | approve_file | unapprove_file
- user: User identifier (IP address, username, or "system")
- target: The type or file being modified
- previous_status: Status before change
- new_status: Status after change
- reason: Human-readable justification
- reference: Ticket ID, change request number, etc.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional

_AUDIT_LOG_FILE = Path(__file__).parent.parent / "data" / "mobile-code-policy-audit.jsonl"


def _ensure_audit_log_exists() -> None:
    """Ensure audit log file and parent directory exist."""
    _AUDIT_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    if not _AUDIT_LOG_FILE.exists():
        _AUDIT_LOG_FILE.touch()


def log_policy_change(
    action: str,
    target: str,
    user: str,
    previous_status: str,
    new_status: str,
    reason: str = "",
    reference: str = ""
) -> None:
    """
    Append a policy change event to the audit log.
    
    Args:
        action: One of: approve_type, unapprove_type, approve_file, unapprove_file
        target: The type (e.g., "javascript_web") or file path being modified
        user: User identifier (IP, email, or "system")
        previous_status: Status before change (approved/requires_approval/unapproved)
        new_status: Status after change
        reason: Justification for the change
        reference: Ticket ID, CR number, etc.
    """
    _ensure_audit_log_exists()
    
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action": action,
        "user": user,
        "target": target,
        "previous_status": previous_status,
        "new_status": new_status,
        "reason": reason,
        "reference": reference,
    }
    
    with open(_AUDIT_LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


def read_audit_log(
    limit: Optional[int] = None,
    action_filter: Optional[str] = None,
    user_filter: Optional[str] = None,
    target_filter: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Read audit log entries with optional filtering.
    
    Args:
        limit: Maximum number of entries to return (most recent first)
        action_filter: Only return entries matching this action
        user_filter: Only return entries from this user
        target_filter: Only return entries for this target (substring match)
    
    Returns:
        List of audit log entries, newest first
    """
    _ensure_audit_log_exists()
    
    entries = []
    with open(_AUDIT_LOG_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                
                # Apply filters
                if action_filter and entry.get("action") != action_filter:
                    continue
                if user_filter and entry.get("user") != user_filter:
                    continue
                if target_filter and target_filter not in entry.get("target", ""):
                    continue
                
                entries.append(entry)
            except json.JSONDecodeError:
                continue  # Skip malformed lines
    
    # Return newest first
    entries.reverse()
    
    if limit:
        entries = entries[:limit]
    
    return entries


def get_policy_change_stats() -> Dict[str, Any]:
    """
    Calculate statistics about policy changes.
    
    Returns:
        Dictionary with:
        - total_changes: Total number of policy modifications
        - by_action: Count of each action type
        - by_user: Count per user
        - recent_changes: Last 10 changes
        - approval_rate: Ratio of approvals to total actions
    """
    entries = read_audit_log()
    
    stats = {
        "total_changes": len(entries),
        "by_action": {},
        "by_user": {},
        "unique_targets": set(),
        "recent_changes": entries[:10] if entries else [],
    }
    
    for entry in entries:
        action = entry.get("action", "unknown")
        user = entry.get("user", "unknown")
        target = entry.get("target", "")
        
        stats["by_action"][action] = stats["by_action"].get(action, 0) + 1
        stats["by_user"][user] = stats["by_user"].get(user, 0) + 1
        stats["unique_targets"].add(target)
    
    # Convert set to count
    stats["unique_targets"] = len(stats["unique_targets"])
    
    # Calculate approval rate
    approve_count = (
        stats["by_action"].get("approve_type", 0) +
        stats["by_action"].get("approve_file", 0)
    )
    unapprove_count = (
        stats["by_action"].get("unapprove_type", 0) +
        stats["by_action"].get("unapprove_file", 0)
    )
    total_actions = approve_count + unapprove_count
    
    stats["approval_rate"] = (
        round(approve_count / total_actions * 100, 1)
        if total_actions > 0 else None
    )
    
    return stats


def get_target_history(target: str) -> List[Dict[str, Any]]:
    """
    Get the complete change history for a specific target (type or file).
    
    Args:
        target: Mobile code type or file path
    
    Returns:
        List of audit entries for this target, newest first
    """
    return read_audit_log(target_filter=target)
