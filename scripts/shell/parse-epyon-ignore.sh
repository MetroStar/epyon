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

    echo -e "${CYAN}📋 Parsing ignore file: $IGNORE_FILE${NC}"
    
    # Show first few lines of YAML for debugging
    echo -e "${CYAN}📄 YAML file content (first 10 lines):${NC}"
    head -10 "$IGNORE_FILE" 2>/dev/null || true

    # Parse YAML to JSON using Python (more reliable than yq in bash)
    local PARSE_OUTPUT=$(python3 -c "
import sys
import json
import re
from datetime import datetime

try:
    import yaml
except ImportError:
    print(json.dumps({'ignores': [], 'error': 'PyYAML module not installed'}), file=sys.stderr)
    print(json.dumps({'ignores': []}))
    sys.exit(0)

# A recurring hand-edit mistake: a newly pasted '- type: ...' entry under
# 'ignores:' is indented differently (usually 0 spaces) than its sibling
# entries (usually 2 spaces). YAML requires every item in a block sequence
# to share one indentation level, so this single mismatched entry breaks
# parsing of the *entire* ignores list — not just the new entry — and
# PyYAML's 'expected <block end>, but found -' error gives no hint that
# every other (previously working) suppression rule just silently stopped
# applying too. Detect this specific shape and reindent the offending
# entry (and its own continuation lines) to match its siblings so the file
# still parses, while surfacing a warning so the source file still gets
# fixed by a human.
def autofix_sequence_indentation(text):
    from collections import Counter

    lines = text.splitlines()
    key_re = re.compile(r'^(\s*)ignores:\s*\$')
    marker_re = re.compile(r'^(\s*)-\s')

    # Pass 1: locate the 'ignores:' block and collect every entry marker's
    # indentation. A non-marker line only ends the block once it dedents to
    # (or above) the 'ignores:' key's own indent — a malformed '- type: ...'
    # marker may itself sit at that same (or shallower) indent, so markers
    # never terminate the block on their own.
    in_block = False
    ignores_key_indent = 0
    block_start = None
    block_end = len(lines)
    marker_indents = []
    for i, line in enumerate(lines):
        if not in_block:
            m = key_re.match(line)
            if m:
                in_block = True
                ignores_key_indent = len(m.group(1))
                block_start = i + 1
            continue
        stripped = line.strip()
        if stripped == '' or stripped.startswith('#'):
            continue
        indent = len(line) - len(line.lstrip(' '))
        m = marker_re.match(line)
        if m:
            marker_indents.append(len(m.group(1)))
            continue
        if indent <= ignores_key_indent:
            block_end = i
            break

    if block_start is None or not marker_indents:
        return text, []

    # The majority indentation is treated as correct; any entry (and its
    # own continuation lines) at a different indent gets uniformly shifted
    # to match. Which specific entries are 'the odd ones out' is cosmetic —
    # unifying the whole list to one consistent level is what makes it
    # parse, regardless of which level is chosen as the target.
    base_indent = Counter(marker_indents).most_common(1)[0][0]

    fixed = list(lines)
    notes = []
    current_delta = 0
    for i in range(block_start, block_end):
        line = lines[i]
        stripped = line.strip()
        if stripped == '' or stripped.startswith('#'):
            continue
        m = marker_re.match(line)
        if m:
            marker_indent = len(m.group(1))
            current_delta = base_indent - marker_indent
            if current_delta != 0:
                notes.append(
                    'line %d: entry indentation (%d space(s)) does not match the '
                    'other entries under \'ignores:\' (%d space(s)) \u2014 normalized '
                    'for this run only so the file still parses; please fix the '
                    'indentation in the file itself so every entry is consistent.'
                    % (i + 1, marker_indent, base_indent)
                )
        if current_delta > 0:
            fixed[i] = (' ' * current_delta) + line
        elif current_delta < 0:
            strip_n = -current_delta
            if line[:strip_n].strip() == '':
                fixed[i] = line[strip_n:]

    return '\n'.join(fixed) + ('\n' if text.endswith('\n') else ''), notes

autofix_notes = []
try:
    with open('$IGNORE_FILE', 'r') as f:
        raw_text = f.read()

    try:
        data = yaml.safe_load(raw_text)
    except yaml.YAMLError:
        fixed_text, autofix_notes = autofix_sequence_indentation(raw_text)
        if not autofix_notes:
            raise
        data = yaml.safe_load(fixed_text)

    if not data or 'ignores' not in data:
        print(json.dumps({'ignores': [], 'warnings': autofix_notes}))
        sys.exit(0)
    
    # Process ignores and check expiration
    processed = []
    normalization_warnings = list(autofix_notes)
    current_date = datetime.now()

    # Rule types actually understood by the suppression matchers
    # (filter-ignored-findings.sh / web/api/parsers.py). A tool name used as
    # the 'type' itself (e.g. 'type: anchore') is a common mistake — the
    # correct form is 'type: tool, value: anchore' — and silently produces a
    # rule that never matches anything. Normalize it instead of dropping it.
    KNOWN_TYPES = {
        'cve', 'ghsa', 'vulnerability', 'package', 'path', 'file', 'tool',
        'secret-detector', 'secret', 'detector', 'secret-pattern',
    }
    KNOWN_TOOL_NAMES = {
        'grype', 'trivy', 'trufflehog', 'checkov', 'clamav', 'anchore',
        'xeol', 'pip-audit', 'safety', 'sonarqube',
    }

    for ignore in data.get('ignores', []):
        raw_type = (ignore.get('type', '') or '').strip()
        entry_type = raw_type
        entry_value = ignore.get('value', '')

        if raw_type.lower() in KNOWN_TOOL_NAMES and raw_type.lower() not in KNOWN_TYPES:
            normalization_warnings.append(
                f'.epyon-ignore.yml rule has type: \"{raw_type}\" — this is not a '
                f'recognized rule type and would silently never match. Treating it '
                f'as type: tool, value: {raw_type} (suppress the whole tool). Update '
                f'the rule to \"type: tool\" / \"value: {raw_type}\" to silence this warning.'
            )
            entry_type = 'tool'
            entry_value = raw_type

        ignore_entry = {
            'type': entry_type,
            'value': entry_value,
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
    
    print(json.dumps({'ignores': processed, 'warnings': normalization_warnings}, indent=2))
    
except yaml.YAMLError as e:
    print(json.dumps({'ignores': [], 'error': str(e)}), file=sys.stderr)
    print(json.dumps({'ignores': []}))
    sys.exit(0)
except Exception as e:
    print(json.dumps({'ignores': [], 'error': str(e)}), file=sys.stderr)
    print(json.dumps({'ignores': []}))
    sys.exit(0)
" 2>&1)
    
    echo "$PARSE_OUTPUT" | grep -v '"error"' > "$IGNORE_CACHE" 2>/dev/null || echo '{"ignores": []}' > "$IGNORE_CACHE"
    
    # Check for errors in output
    if echo "$PARSE_OUTPUT" | grep -q '"error"'; then
        local error_msg=$(echo "$PARSE_OUTPUT" | jq -r '.error // empty' 2>/dev/null)
        if [[ -n "$error_msg" ]]; then
            echo -e "${YELLOW}⚠️  YAML parsing error: $error_msg${NC}"
        fi
    fi

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

# Surface any rule-type normalization warnings (e.g. `type: anchore` instead of
# the correct `type: tool, value: anchore`) so a rule that would otherwise
# silently never match gets noticed instead of quietly doing nothing.
NORMALIZATION_WARNINGS=$(jq -r '.warnings[]? // empty' "$IGNORE_CACHE" 2>/dev/null || echo "")
if [[ -n "$NORMALIZATION_WARNINGS" ]]; then
    while IFS= read -r _warn; do
        [[ -n "$_warn" ]] && echo -e "${YELLOW}  ⚠️  $_warn${NC}"
    done <<< "$NORMALIZATION_WARNINGS"
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
