#!/bin/bash

# Filter Ignored Findings
# Functions to check if a finding should be ignored based on .epyon-ignore.yml rules

IGNORE_CACHE="${IGNORE_CACHE:-/tmp/epyon-ignore-cache.json}"
SUPPRESSED_LOG="${SUPPRESSED_LOG:-/tmp/epyon-suppressed-findings.log}"

# Initialize suppressed findings log
init_suppressed_log() {
    cat > "$SUPPRESSED_LOG" << 'EOF'
# Suppressed Security Findings Report

This report lists all security findings that were suppressed by .epyon-ignore.yml rules.

---

EOF
}

# Log a suppressed finding
log_suppressed() {
    local tool="$1"
    local type="$2"
    local value="$3"
    local reason="$4"
    local severity="${5:-N/A}"
    
    cat >> "$SUPPRESSED_LOG" << EOF
## Suppressed: $value
- **Tool**: $tool
- **Type**: $type
- **Severity**: $severity
- **Reason**: $reason

EOF
}

# Check if a tool is ignored
is_tool_ignored() {
    local tool_name="$1"
    
    if [[ ! -f "$IGNORE_CACHE" ]]; then
        return 1
    fi
    
    local ignored=$(jq -r --arg tool "$tool_name" '
        .ignores[] | 
        select(.type == "tool" and (.value | ascii_downcase) == ($tool | ascii_downcase)) |
        .value
    ' "$IGNORE_CACHE" 2>/dev/null || echo "")
    
    if [[ -n "$ignored" ]]; then
        local reason=$(jq -r --arg tool "$tool_name" '
            .ignores[] | 
            select(.type == "tool" and (.value | ascii_downcase) == ($tool | ascii_downcase)) |
            .reason
        ' "$IGNORE_CACHE" 2>/dev/null || echo "No reason provided")
        
        log_suppressed "$tool_name" "tool" "$tool_name" "$reason" "N/A" 2>/dev/null || true
        return 0
    fi
    
    return 1
}

# Check if a CVE is ignored
is_cve_ignored() {
    local cve_id="$1"
    local tool="${2:-unknown}"
    
    if [[ ! -f "$IGNORE_CACHE" ]]; then
        return 1
    fi
    
    # Check if CVE is in ignore list and not expired
    local ignored=$(jq -r --arg cve "$cve_id" '
        .ignores[] | 
        select(.type == "cve" and .value == $cve and .expired == false) |
        .value
    ' "$IGNORE_CACHE" 2>/dev/null || echo "")
    
    if [[ -n "$ignored" ]]; then
        local reason=$(jq -r --arg cve "$cve_id" '
            .ignores[] | 
            select(.type == "cve" and .value == $cve and .expired == false) |
            .reason
        ' "$IGNORE_CACHE" 2>/dev/null || echo "No reason provided")
        
        log_suppressed "$tool" "cve" "$cve_id" "$reason" "Varies" 2>/dev/null || true
        return 0
    fi
    
    return 1
}

# Check if a package is ignored (exact version match)
is_package_ignored() {
    local package_name="$1"
    local package_version="${2:-}"
    local tool="${3:-unknown}"
    
    if [[ ! -f "$IGNORE_CACHE" ]]; then
        return 1
    fi
    
    # Check exact package@version match
    if [[ -n "$package_version" ]]; then
        local package_full="${package_name}@${package_version}"
        local ignored=$(jq -r --arg pkg "$package_full" '
            .ignores[] | 
            select(.type == "package" and .value == $pkg and .expired == false) |
            .value
        ' "$IGNORE_CACHE" 2>/dev/null || echo "")
        
        if [[ -n "$ignored" ]]; then
            local reason=$(jq -r --arg pkg "$package_full" '
                .ignores[] | 
                select(.type == "package" and .value == $pkg and .expired == false) |
                .reason
            ' "$IGNORE_CACHE" 2>/dev/null || echo "No reason provided")
            
            log_suppressed "$tool" "package" "$package_full" "$reason" "Varies" 2>/dev/null || true
            return 0
        fi
    fi
    
    # Check package name only (all versions)
    local ignored=$(jq -r --arg pkg "$package_name" '
        .ignores[] | 
        select(.type == "package" and .value == $pkg and .expired == false) |
        .value
    ' "$IGNORE_CACHE" 2>/dev/null || echo "")
    
    if [[ -n "$ignored" ]]; then
        local reason=$(jq -r --arg pkg "$package_name" '
            .ignores[] | 
            select(.type == "package" and .value == $pkg and .expired == false) |
            .reason
        ' "$IGNORE_CACHE" 2>/dev/null || echo "No reason provided")
        
        log_suppressed "$tool" "package" "$package_name (all versions)" "$reason" "Varies" 2>/dev/null || true
        return 0
    fi
    
    return 1
}

# Check if a file path is ignored (glob pattern matching)
is_path_ignored() {
    local file_path="$1"
    local tool="${2:-unknown}"
    
    if [[ ! -f "$IGNORE_CACHE" ]]; then
        return 1
    fi
    
    # Get all path patterns
    local patterns=$(jq -r '.ignores[] | select(.type == "path" and .expired == false) | .value' "$IGNORE_CACHE" 2>/dev/null || echo "")
    
    while IFS= read -r pattern; do
        if [[ -z "$pattern" ]]; then
            continue
        fi
        
        # Use bash glob pattern matching
        # shellcheck disable=SC2053
        if [[ "$file_path" == $pattern ]]; then
            local reason=$(jq -r --arg pat "$pattern" '
                .ignores[] | 
                select(.type == "path" and .value == $pat and .expired == false) |
                .reason
            ' "$IGNORE_CACHE" 2>/dev/null || echo "No reason provided")
            
            log_suppressed "$tool" "path" "$file_path (matched: $pattern)" "$reason" "Varies" 2>/dev/null || true
            return 0
        fi
    done <<< "$patterns"
    
    return 1
}

# Check if a secret detector should be ignored for specific paths
is_secret_ignored() {
    local detector_name="$1"
    local file_path="$2"
    local tool="${3:-TruffleHog}"
    
    if [[ ! -f "$IGNORE_CACHE" ]]; then
        return 1
    fi
    
    # Check secret-detector type with path restrictions
    local ignore_entry=$(jq -r --arg detector "$detector_name" '
        .ignores[] | 
        select(.type == "secret-detector" and .value == $detector and .expired == false)
    ' "$IGNORE_CACHE" 2>/dev/null || echo "")
    
    if [[ -n "$ignore_entry" ]]; then
        # Check if paths are specified
        local paths=$(echo "$ignore_entry" | jq -r '.paths[]? // empty' 2>/dev/null || echo "")
        
        if [[ -z "$paths" ]]; then
            # No path restriction - ignore everywhere
            local reason=$(echo "$ignore_entry" | jq -r '.reason' 2>/dev/null || echo "No reason provided")
            log_suppressed "$tool" "secret-detector" "$detector_name" "$reason" "Critical" 2>/dev/null || true
            return 0
        fi
        
        # Check if file matches any of the paths
        while IFS= read -r pattern; do
            if [[ -z "$pattern" ]]; then
                continue
            fi
            
            # shellcheck disable=SC2053
            if [[ "$file_path" == $pattern ]]; then
                local reason=$(echo "$ignore_entry" | jq -r '.reason' 2>/dev/null || echo "No reason provided")
                log_suppressed "$tool" "secret-detector" "$detector_name in $file_path" "$reason" "Critical" 2>/dev/null || true
                return 0
            fi
        done <<< "$paths"
    fi
    
    # Check secret-pattern type
    local pattern_entry=$(jq -r --arg pattern "$detector_name" '
        .ignores[] | 
        select(.type == "secret-pattern" and .expired == false) |
        select($pattern | test(.value))
    ' "$IGNORE_CACHE" 2>/dev/null || echo "")
    
    if [[ -n "$pattern_entry" ]]; then
        local reason=$(echo "$pattern_entry" | jq -r '.reason' 2>/dev/null || echo "No reason provided")
        log_suppressed "$tool" "secret-pattern" "$detector_name" "$reason" "Critical" 2>/dev/null || true
        return 0
    fi
    
    return 1
}

# Export functions
export -f is_tool_ignored
export -f is_cve_ignored
export -f is_package_ignored
export -f is_path_ignored
export -f is_secret_ignored
export -f log_suppressed
