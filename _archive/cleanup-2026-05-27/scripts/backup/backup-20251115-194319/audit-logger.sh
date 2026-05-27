#!/bin/bash

# Centralized Audit Logging Function
# Usage: source ./audit-logger.sh && log_audit_event "action_description"

# Configuration
AUDIT_LOG_DIR="$REPO_ROOT/reports/security-reports"
AUDIT_LOG="$AUDIT_LOG_DIR/audit.log"

# Ensure audit log directory exists
mkdir -p "$AUDIT_LOG_DIR"

# Function to log audit events
log_audit_event() {
    local ACTION="${1:-'UNKNOWN_ACTION'}"
    local TIMESTAMP=$(date -u "+%Y-%m-%d %H:%M:%S UTC")
    local USER_ID=$(whoami)
    local REAL_USER="${SUDO_USER:-$(whoami)}"
    local HOSTNAME=$(hostname)
    local SCRIPT_NAME=$(basename "${BASH_SOURCE[1]}")
    local SCRIPT_PATH=$(readlink -f "${BASH_SOURCE[1]}")
    local PID="$$"
    local PPID="$PPID"
    local TARGET="${TARGET_DIR:-$(pwd)}"
    local GIT_USER=$(git config user.name 2>/dev/null || echo 'unknown')
    local SESSION="${SSH_CONNECTION:-local}"
    
    # Create audit entry
    local AUDIT_ENTRY="[$TIMESTAMP] USER:$USER_ID REAL_USER:$REAL_USER HOST:$HOSTNAME SCRIPT:$SCRIPT_NAME PATH:$SCRIPT_PATH ACTION:$ACTION TARGET:$TARGET PID:$PID PPID:$PPID SESSION:$SESSION GIT_USER:$GIT_USER"
    
    # Write to audit log with proper permissions
    echo "$AUDIT_ENTRY" >> "$AUDIT_LOG"
    
    # Ensure audit log is readable by authorized users only
    chmod 640 "$AUDIT_LOG" 2>/dev/null || true
    
    # Optional: Echo to stderr for real-time visibility
    if [ "${AUDIT_VERBOSE:-false}" = "true" ]; then
        echo "🔍 AUDIT: $ACTION by $USER_ID" >&2
    fi
}

# Function to log script start
log_script_start() {
    local SCRIPT_ARGS="$*"
    log_audit_event "SCRIPT_START: $(basename ${BASH_SOURCE[1]}) $SCRIPT_ARGS"
}

# Function to log script completion
log_script_end() {
    local EXIT_CODE="${1:-0}"
    local DURATION="${2:-unknown}"
    log_audit_event "SCRIPT_END: $(basename ${BASH_SOURCE[1]}) exit_code=$EXIT_CODE duration=${DURATION}s"
}

# Function to log security scan events
log_security_scan() {
    local TOOL_NAME="$1"
    local SCAN_TYPE="$2"
    local RESULTS_COUNT="${3:-0}"
    log_audit_event "SECURITY_SCAN: tool=$TOOL_NAME type=$SCAN_TYPE results=$RESULTS_COUNT"
}

# Function to log authentication events
log_auth_event() {
    local AUTH_TYPE="$1"
    local AUTH_STATUS="$2"
    log_audit_event "AUTH_EVENT: type=$AUTH_TYPE status=$AUTH_STATUS"
}

# Function to view recent audit entries
show_audit_log() {
    local LINES="${1:-20}"
    if [ -f "$AUDIT_LOG" ]; then
        echo "🔍 Recent Audit Entries (last $LINES):"
        echo "======================================="
        tail -n "$LINES" "$AUDIT_LOG"
    else
        echo "No audit log found at: $AUDIT_LOG"
    fi
}

# Function to search audit log
search_audit_log() {
    local SEARCH_TERM="$1"
    if [ -f "$AUDIT_LOG" ]; then
        echo "🔍 Audit Search Results for: $SEARCH_TERM"
        echo "==========================================="
        grep -i "$SEARCH_TERM" "$AUDIT_LOG" || echo "No matches found."
    else
        echo "No audit log found at: $AUDIT_LOG"
    fi
}

# Export functions for use by other scripts
export -f log_audit_event log_script_start log_script_end log_security_scan log_auth_event