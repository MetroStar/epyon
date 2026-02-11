#!/bin/bash

# Parse .epyon-ignore.yml
# Reads ignore rules from target repository and exports them for filtering

# Colors
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
RED='\033[0;31m'
NC='\033[0m'

# Main parsing function (so this can be sourced without exiting)
parse_ignore_rules() {
    local IGNORE_FILE="${1:-}"
    
    if [[ -z "$IGNORE_FILE" ]]; then
        IGNORE_FILE="${TARGET_DIR:-}/.epyon-ignore.yml"
    fi
    
    local IGNORE_CACHE="${IGNORE_CACHE:-/tmp/epyon-ignore-cache.json}"

    # Check if ignore file exists
    if [[ ! -f "$IGNORE_FILE" ]]; then
        # No ignore file - create empty cache
        echo '{"ignores": []}' > "$IGNORE_CACHE" 2>/dev/null || true
        return 0
        fi

        echo -e "${CYAN}📋 Parsing ignore rules from: .epyon-ignore.yml${NC}"

    # Parse YAML to JSON using Python (more reliable than yq in bash)
    python3 -c "
import yaml
import json
import sys
from datetime import datetime

try:
    with open('$IGNORE_FILE', 'r') as f:
        data = yaml.safe_load(f)
    
    if not data or 'ignores' not in data:
        print(json.dumps({'ignores': []}))
        sys.exit(0)
    
    # Process ignores and check expiration
    processed = []
    current_date = datetime.now()
    
    for ignore in data.get('ignores', []):
        ignore_entry = {
            'type': ignore.get('type', ''),
            'value': ignore.get('value', ''),
            'reason': ignore.get('reason', ''),
            'expires': ignore.get('expires', ''),
            'approved_by': ignore.get('approved_by', ''),
            'paths': ignore.get('paths', []),
            'expired': False
        }
        
        # Check expiration
        if ignore_entry['expires']:
            try:
                expire_date = datetime.strptime(ignore_entry['expires'], '%Y-%m-%d')
                if current_date > expire_date:
                    ignore_entry['expired'] = True
            except:
                pass
        
        processed.append(ignore_entry)
    
    print(json.dumps({'ignores': processed}, indent=2))
    
except Exception as e:
    # Silent skip on error - just return empty ignores
    print(json.dumps({'ignores': []}))
    sys.exit(0)
" > "$IGNORE_CACHE" 2>/dev/null || echo '{"ignores": []}' > "$IGNORE_CACHE"

# Count and report
TOTAL_IGNORES=$(jq '.ignores | length' "$IGNORE_CACHE" 2>/dev/null || echo "0")
EXPIRED_IGNORES=$(jq '[.ignores[] | select(.expired == true)] | length' "$IGNORE_CACHE" 2>/dev/null || echo "0")

if [[ $TOTAL_IGNORES -gt 0 ]]; then
    echo -e "${CYAN}  ✓ Loaded $TOTAL_IGNORES ignore rule(s)${NC}"
    
    if [[ $EXPIRED_IGNORES -gt 0 ]]; then
        echo -e "${YELLOW}  ⚠️  Warning: $EXPIRED_IGNORES ignore rule(s) have expired${NC}"
        jq -r '.ignores[] | select(.expired == true) | "    - \(.type): \(.value) (expired: \(.expires))"' "$IGNORE_CACHE" 2>/dev/null || true
    fi
fi
}

# If script is executed (not sourced), run the function
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    TARGET_DIR="${TARGET_DIR:-}"
    IGNORE_FILE="${TARGET_DIR}/.epyon-ignore.yml"
    IGNORE_CACHE="/tmp/epyon-ignore-cache.json"
    parse_ignore_rules "$IGNORE_FILE"
    exit 0
fi
