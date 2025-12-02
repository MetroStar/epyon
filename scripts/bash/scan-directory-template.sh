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
    
    # Create tool-specific directory within scan
    mkdir -p "$OUTPUT_DIR"
    
    echo "🗂️  Using scan directory: $SCAN_DIR"
    echo "📁 Tool output: $OUTPUT_DIR"
    
    # Export for use in tool script
    export OUTPUT_DIR
    export SCAN_LOG
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