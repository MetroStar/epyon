#!/bin/bash

# Cleanup Old Scan Directories
# Removes scan directories older than a configurable retention period

set -euo pipefail

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

# Defaults
RETENTION_DAYS=30
DRY_RUN=false
QUIET=false

show_help() {
    echo -e "${WHITE}Cleanup Old Scan Directories${NC}"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Removes scan directories from the scans/ folder that are older than"
    echo "the configured retention period."
    echo ""
    echo "Options:"
    echo "  -d, --days DAYS     Retention period in days (default: ${RETENTION_DAYS})"
    echo "  -n, --dry-run       Show what would be deleted without deleting"
    echo "  -q, --quiet         Suppress non-error output"
    echo "  -h, --help          Show this help message and exit"
    echo ""
    echo "Examples:"
    echo "  $0                  # Delete scans older than 30 days"
    echo "  $0 --days 7         # Delete scans older than 7 days"
    echo "  $0 --dry-run        # Preview which scans would be deleted"
    echo ""
    exit 0
}

require_value() {
    if [[ -z "${2:-}" ]]; then
        echo -e "${RED}Error: $1 requires a value.${NC}" >&2
        echo "Run with --help for usage examples." >&2
        exit 1
    fi
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        -d|--days)
            require_value "$1" "${2:-}"
            RETENTION_DAYS="$2"
            shift 2
            ;;
        -n|--dry-run)
            DRY_RUN=true
            shift
            ;;
        -q|--quiet)
            QUIET=true
            shift
            ;;
        -h|--help)
            show_help
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}" >&2
            echo "Run with --help for usage examples." >&2
            exit 1
            ;;
    esac
done

# Resolve workspace root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
SCANS_DIR="${SCANS_DIR:-${WORKSPACE_ROOT}/scans}"

if [ ! -d "$SCANS_DIR" ]; then
    echo -e "${YELLOW}No scans directory found at: $SCANS_DIR${NC}"
    exit 0
fi

[[ "$QUIET" == false ]] && echo -e "${CYAN}Scanning for directories older than ${RETENTION_DAYS} days in: ${SCANS_DIR}${NC}"

# Find expired scan directories
mapfile -t expired < <(find "$SCANS_DIR" -maxdepth 1 -mindepth 1 -type d \
    -mtime "+${RETENTION_DAYS}" 2>/dev/null | sort)

if [[ ${#expired[@]} -eq 0 ]]; then
    [[ "$QUIET" == false ]] && echo -e "${GREEN}No scan directories older than ${RETENTION_DAYS} days found.${NC}"
    exit 0
fi

[[ "$QUIET" == false ]] && echo -e "${YELLOW}Found ${#expired[@]} scan director$([ ${#expired[@]} -eq 1 ] && echo y || echo ies) to clean up:${NC}"

removed=0
for scan_dir in "${expired[@]}"; do
    [ -d "$scan_dir" ] || continue
    [[ "$QUIET" == false ]] && echo "  - $scan_dir"
    if [[ "$DRY_RUN" == true ]]; then
        echo -e "    ${YELLOW}[dry-run] would delete${NC}"
    else
        rm -rf "$scan_dir"
        (( removed++ )) || true
    fi
done

if [[ "$DRY_RUN" == true ]]; then
    [[ "$QUIET" == false ]] && echo -e "${YELLOW}Dry-run complete — nothing was deleted.${NC}"
else
    [[ "$QUIET" == false ]] && echo -e "${GREEN}Removed ${removed} old scan director$([ $removed -eq 1 ] && echo y || echo ies).${NC}"
fi
