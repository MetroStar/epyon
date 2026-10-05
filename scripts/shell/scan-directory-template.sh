#!/bin/bash

# Universal Scan Directory Security Tool Template
# This template shows how each security tool should be structured to use scan directories

# Function to initialize scan environment
init_scan_environment() {
    local tool_name="$1"
    
    # SCAN_DIR must be provided by orchestrator
    if [[ -z "$SCAN_DIR" ]]; then
        echo "❌ ERROR: SCAN_DIR environment variable must be set"
        echo "This tool must be called from run-target-security-scan.sh"
        exit 1
    fi
    
    # Use centralized scan directory structure
    OUTPUT_DIR="$SCAN_DIR/$tool_name"
    SCAN_LOG="$SCAN_DIR/$tool_name/scan.log"
    SCAN_STATUS_FILE="$SCAN_DIR/$tool_name/status.json"
    
    # Create tool-specific directory within scan
    mkdir -p "$OUTPUT_DIR"
    
    echo "🗂️  Using scan directory: $SCAN_DIR"
    echo "📁 Tool output: $OUTPUT_DIR"
    
    # Export for use in tool script
    export OUTPUT_DIR
    export SCAN_LOG
    export SCAN_STATUS_FILE
}

# Function to record scan status (success, failure, skipped)
# Usage: record_scan_status <status> [reason]
# Status: "success", "failed", "skipped"
record_scan_status() {
    local status="$1"
    local reason="${2:-}"
    local tool_name=$(basename "$(dirname "$SCAN_STATUS_FILE")")
    
    if [[ -z "$SCAN_STATUS_FILE" ]]; then
        echo "⚠️  WARNING: SCAN_STATUS_FILE not set, cannot record status"
        return 1
    fi
    
    cat > "$SCAN_STATUS_FILE" <<EOF
{
  "tool": "$tool_name",
  "status": "$status",
  "reason": "$reason",
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
}
EOF
}

# Function to create result files with proper naming
create_result_file() {
    local tool_name="$1"
    local result_type="$2"  # e.g., "results", "summary", "scan"
    local extension="${3:-json}"
    
    # Scan directory mode - simpler naming
    echo "$OUTPUT_DIR/${result_type}.${extension}"
}

# Function to create current symlinks (no longer needed in isolated scans)
create_current_links() {
    local tool_name="$1"
    # No-op - scan isolation means no symlinks to centralized location
    return 0
}

# Function to count files in a directory for scan reporting
# Usage: count_files <directory> [extension_pattern]
# Example: count_files /path/to/project "*.py"
count_scannable_files() {
    local target_dir="$1"
    local pattern="${2:-*}"
    
    if [[ ! -d "$target_dir" ]]; then
        echo "0"
        return
    fi
    
    # Count files matching pattern, excluding common dependency directories
    local count
    count=$(find "$target_dir" -type f -name "$pattern" \
        -not -path "*/node_modules/*" \
        -not -path "*/.git/*" \
        -not -path "*/venv/*" \
        -not -path "*/__pycache__/*" \
        -not -path "*/dist/*" \
        -not -path "*/build/*" \
        -not -path "*/.venv/*" \
        -not -path "*/vendor/*" \
        2>/dev/null | wc -l | tr -d ' ')
    echo "$count"
}

# Function to display file count summary
# Usage: display_file_count <directory> <description> [extension_pattern]
display_file_count() {
    local target_dir="$1"
    local description="$2"
    local pattern="${3:-*}"
    
    local count
    count=$(count_scannable_files "$target_dir" "$pattern")
    
    echo -e "${CYAN}📊 $description: $count files${NC}"
    echo "$description: $count files" >> "$SCAN_LOG" 2>/dev/null || true
}

# Function to get detailed file type breakdown
# Usage: get_file_breakdown <directory>
get_file_breakdown() {
    local target_dir="$1"
    
    if [[ ! -d "$target_dir" ]]; then
        echo "Directory not found"
        return
    fi
    
    echo -e "   ${WHITE}File Type Breakdown:${NC}"
    
    # Count each file type separately for shell compatibility
    local js_count py_count yaml_count tf_count docker_count shell_count helm_count
    
    js_count=$(find "$target_dir" -type f \( -name "*.js" -o -name "*.jsx" -o -name "*.ts" -o -name "*.tsx" \) \
        -not -path "*/node_modules/*" -not -path "*/.git/*" 2>/dev/null | wc -l | tr -d ' ')
    py_count=$(find "$target_dir" -type f -name "*.py" \
        -not -path "*/venv/*" -not -path "*/__pycache__/*" -not -path "*/.venv/*" 2>/dev/null | wc -l | tr -d ' ')
    yaml_count=$(find "$target_dir" -type f \( -name "*.yaml" -o -name "*.yml" \) \
        -not -path "*/node_modules/*" 2>/dev/null | wc -l | tr -d ' ')
    tf_count=$(find "$target_dir" -type f \( -name "*.tf" -o -name "*.tfvars" \) 2>/dev/null | wc -l | tr -d ' ')
    docker_count=$(find "$target_dir" -type f \( -name "Dockerfile*" -o -name "*.dockerfile" -o -name "docker-compose*.yml" \) 2>/dev/null | wc -l | tr -d ' ')
    shell_count=$(find "$target_dir" -type f \( -name "*.sh" -o -name "*.bash" \) 2>/dev/null | wc -l | tr -d ' ')
    helm_count=$(find "$target_dir" -type f \( -name "Chart.yaml" -o -name "values.yaml" \) 2>/dev/null | wc -l | tr -d ' ')
    
    [[ $js_count -gt 0 ]] && echo "   • JavaScript/TypeScript: $js_count files"
    [[ $py_count -gt 0 ]] && echo "   • Python: $py_count files"
    [[ $yaml_count -gt 0 ]] && echo "   • YAML/YML: $yaml_count files"
    [[ $tf_count -gt 0 ]] && echo "   • Terraform: $tf_count files"
    [[ $docker_count -gt 0 ]] && echo "   • Docker: $docker_count files"
    [[ $shell_count -gt 0 ]] && echo "   • Shell Scripts: $shell_count files"
    [[ $helm_count -gt 0 ]] && echo "   • Helm Charts: $helm_count files"
    return 0
}

# Function to finalize scan results
finalize_scan_results() {
    local tool_name="$1"
    
    create_current_links "$tool_name"
    
    echo "✅ $tool_name scan completed"
    echo "📁 Results stored in: $OUTPUT_DIR"
    
    if [[ -n "$SCAN_DIR" ]]; then
        echo "🗂️  Scan directory: $SCAN_DIR"
    fi
}

# ── Docker-outside-of-Docker path translation ─────────────────────────────────
# When Epyon runs inside its own container (docker-compose deployment / web UI
# job runner), it mounts the HOST's /var/run/docker.sock to spawn scan tools
# (Syft, Trivy, Checkov, Grype/Anchore, Safety) as *sibling* containers rather
# than nested ones. `docker run -v <path>:...` bind-mount sources are always
# resolved by the HOST's Docker daemon against the HOST filesystem — never
# against Epyon's own container filesystem. Any path under Epyon's container
# (e.g. /app/tmp/clone-<job>, the web UI's per-job clone workspace) that isn't
# ALSO bind-mounted from the host at the identical location will silently
# resolve to an empty/nonexistent directory on the host, so the sibling
# container "succeeds" while scanning nothing — a false-clean result with no
# error surfaced.
#
# HOST_PROJECT_DIR (set in docker-compose.yml to the absolute host path of the
# Epyon checkout) lets us translate a container path like /app/tmp/clone-123
# to its real host equivalent (e.g. $HOST_PROJECT_DIR/tmp/clone-123) before
# handing it to `docker run -v`, as long as the same subtree is bind-mounted
# 1:1 between host and container (see docker-compose.yml's `./tmp:/app/tmp`
# and `./scans:/app/scans` mounts). When HOST_PROJECT_DIR isn't set — e.g.
# running natively (CI runners, local `./epyon.sh`) where the container-side
# path already *is* a real host path — the path is returned unchanged.
to_host_path() {
    local path="$1"
    if [[ -n "${HOST_PROJECT_DIR:-}" && "$path" == /app/* ]]; then
        printf '%s/%s' "${HOST_PROJECT_DIR%/}" "${path#/app/}"
    else
        printf '%s' "$path"
    fi
}

# ── .epyon-ignore.yml scan-time path exclusion ────────────────────────────────
# Returns non-expired `type: path` glob patterns from a target repo's
# .epyon-ignore.yml, one per line, so individual scan tools can pass them to
# their native --skip-path/--skip-dirs/--exclude-paths/--exclude-dir flags and
# genuinely never scan that content — rather than relying solely on suppressing
# the finding after the fact (which not every tool/dashboard section honors).
# Usage: while IFS= read -r pat; do ...; done < <(get_epyon_ignore_exclude_paths "$target")
get_epyon_ignore_exclude_paths() {
    local target_dir="${1:-}"
    local ignore_file="${target_dir%/}/.epyon-ignore.yml"
    [[ -f "$ignore_file" ]] || return 0
    command -v python3 &>/dev/null || return 0
    python3 -c "
import sys
from datetime import datetime
try:
    import yaml
except ImportError:
    sys.exit(0)
try:
    with open('$ignore_file') as f:
        data = yaml.safe_load(f) or {}
except Exception:
    sys.exit(0)
now = datetime.now()
for ig in data.get('ignores', []) or []:
    if ig.get('type') != 'path':
        continue
    expires = ig.get('expires')
    if expires:
        try:
            if now > datetime.strptime(expires, '%Y-%m-%d'):
                continue
        except Exception:
            pass
    value = ig.get('value')
    if value:
        print(value)
" 2>/dev/null
}

# ── Dockerfile base-image auto-discovery ──────────────────────────────────────
# Shared by run-trivy-scan.sh and run-anchore-scan.sh so both tools baseline
# against the SAME, real, publicly-pullable image when no fixed
# PRIMARY_BASELINE_IMAGE / APPROVED_BASE_IMAGES entry is configured, instead of
# each maintaining its own copy of this logic (which previously drifted apart
# and was a source of cross-tool/cross-environment result inconsistency).
# Scans every Dockerfile* in $1, honoring the same .epyon-ignore.yml path
# exclusions as the rest of the scan, and emits only each Dockerfile's FINAL
# stage image (one per Dockerfile, deduplicated across the repo) — not every
# `FROM` line. Multi-stage builder stages (e.g. `FROM golang:1.24-alpine AS
# builder`, used only to compile a helper binary) are discarded by `docker
# build` and never present in the shipped artifact, so treating them as a scan
# baseline produced irrelevant, unfixable noise (and sometimes pointed at
# internal/private-registry-only images with no bearing on the real runtime
# image). `FROM <stage>` references to an earlier named stage are resolved to
# that stage's image so the reported result is always a real, pullable image
# (or correctly skipped if that chain bottoms out in `scratch` or an
# unresolved build-arg like `FROM $BASE_IMAGE`).
# Usage: mapfile -t images < <(discover_dockerfile_base_images "$target")
discover_dockerfile_base_images() {
    local target_dir="${1:-}"
    local find_exclude_args=(-not -path '*/node_modules/*' -not -path '*/.git/*')
    local pat pat_glob
    while IFS= read -r pat; do
        if [[ -n "$pat" ]]; then
            pat_glob="${pat%/\*\*}"
            find_exclude_args+=(-not -path "*/${pat_glob}/*")
        fi
    done < <(get_epyon_ignore_exclude_paths "$target_dir")

    local discovered=()
    local dockerfile
    while IFS= read -r dockerfile; do
        local -A stage_image=()
        local final_image=""
        local line image stage
        while IFS= read -r line; do
            image=$(awk '{print $2}' <<<"$line")
            [[ -z "$image" ]] && continue
            stage=$(awk 'BEGIN{IGNORECASE=1} {for(i=1;i<=NF;i++) if(tolower($i)=="as") print $(i+1)}' <<<"$line")
            # If this FROM references an earlier named stage (not an external
            # image), resolve it to that stage's already-resolved image.
            if [[ -n "${stage_image[$image]+x}" ]]; then
                image="${stage_image[$image]}"
            fi
            final_image="$image"
            [[ -n "$stage" ]] && stage_image["$stage"]="$image"
        done < <(grep -i '^FROM ' "$dockerfile")

        [[ -z "$final_image" ]] && continue
        [[ "$final_image" == "scratch" ]] && continue
        [[ "$final_image" == *'$'* ]] && continue
        discovered+=("$final_image")
    done < <(find "$target_dir" -name 'Dockerfile*' "${find_exclude_args[@]}" 2>/dev/null)

    [ ${#discovered[@]} -eq 0 ] && return 0
    printf '%s\n' "${discovered[@]}" | sort -u
}

# ── Docker auto-start utility ─────────────────────────────────────────────────
# Call ensure_docker_running to guarantee the Docker daemon is up before any
# tool that requires it.  Tries Colima, Docker Desktop, Rancher Desktop,
# OrbStack (macOS) and systemctl (Linux) in order.  Waits up to 60 s.
ensure_docker_running() {
    if ! command -v docker &>/dev/null; then
        echo "❌ Docker is not installed — cannot run this scan layer." >&2
        echo "   Install Docker Desktop, Colima, Rancher Desktop, or OrbStack." >&2
        exit 1
    fi

    if docker info &>/dev/null; then
        return 0   # already running
    fi

    echo "⚠️  Docker is not running — attempting to start it automatically..."

    if [[ "$(uname)" == "Darwin" ]]; then
        if command -v colima &>/dev/null; then
            echo "   Detected Colima — starting..."
            colima start 2>/dev/null || true
            sleep 3
        fi
        if [[ -d "/Applications/Docker.app" ]]; then
            echo "   Detected Docker Desktop — starting..."
            open -a Docker 2>/dev/null || true
        fi
        if [[ -d "/Applications/Rancher Desktop.app" ]]; then
            echo "   Detected Rancher Desktop — starting..."
            open -a "Rancher Desktop" 2>/dev/null || true
        fi
        if [[ -d "/Applications/OrbStack.app" ]]; then
            echo "   Detected OrbStack — starting..."
            open -a OrbStack 2>/dev/null || true
        fi
    elif [[ "$(uname)" == "Linux" ]]; then
        if command -v systemctl &>/dev/null; then
            echo "   Starting Docker Engine service..."
            sudo systemctl start docker 2>/dev/null || true
            sleep 3
        fi
    fi

    # Wait up to 60 s for the daemon to become responsive
    echo -n "   Waiting for Docker"
    local waited=0
    while ! docker info &>/dev/null; do
        if [[ $waited -ge 60 ]]; then
            echo ""
            echo "❌ Docker did not start within 60 seconds." >&2
            echo "   Please start Docker manually and retry." >&2
            exit 1
        fi
        echo -n "."
        sleep 2
        waited=$((waited + 2))
    done
    echo " ✅ Docker is ready."
}

# If this script is sourced, make functions available
# If run directly, show usage
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "This is a template/library script for security tools."
    echo "Usage: source this script in security tool scripts"
    echo ""
    echo "Example usage in a security tool:"
    echo "  source scan-directory-template.sh"
    echo "  init_scan_environment 'grype'"
    echo "  RESULTS_FILE=\$(create_result_file 'grype' 'results')"
    echo "  # ... run tool and save to \$RESULTS_FILE ..."
    echo "  finalize_scan_results 'grype'"
fi