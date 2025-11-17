#!/bin/bash

# Universal Scan Directory Security Tool Template
# This template shows how each security tool should be structured to use scan directories

# Function to initialize scan environment
init_scan_environment() {
    local tool_name="$1"
    
    # Use SCAN_DIR if provided (from orchestrator), otherwise create individual structure
    if [[ -n "$SCAN_DIR" ]]; then
        # Orchestrated scan - use centralized scan directory
        OUTPUT_DIR="$SCAN_DIR/$tool_name"
        SCAN_LOG="$SCAN_DIR/$tool_name/scan.log"
        CURRENT_LINK_DIR="$(dirname "$(dirname "$SCAN_DIR")")/reports/${tool_name}-reports"
        
        # Create tool-specific directory within scan
        mkdir -p "$OUTPUT_DIR"
        mkdir -p "$CURRENT_LINK_DIR"
        
        echo "🗂️  Using scan directory: $SCAN_DIR"
        echo "📁 Tool output: $OUTPUT_DIR"
    else
        # Standalone execution - use traditional reports structure
        SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
        REPORTS_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
        
        # Generate scan ID for standalone execution
        REPO_PATH="${1:-${TARGET_DIR:-$(pwd)}}"
        TARGET_NAME=$(basename "$REPO_PATH")
        USERNAME=$(whoami)
        TIMESTAMP=$(date '+%Y-%m-%d_%H-%M-%S')
        SCAN_ID="${TARGET_NAME}_${USERNAME}_${TIMESTAMP}"
        
        OUTPUT_DIR="$REPORTS_ROOT/reports/${tool_name}-reports"
        SCAN_LOG="$OUTPUT_DIR/${SCAN_ID}_${tool_name}-scan.log"
        CURRENT_LINK_DIR="$OUTPUT_DIR"
        
        mkdir -p "$OUTPUT_DIR"
        
        echo "📁 Standalone mode - using reports directory: $OUTPUT_DIR"
    fi
    
    # Export for use in tool script
    export OUTPUT_DIR
    export SCAN_LOG
    export CURRENT_LINK_DIR
}

# Function to create result files with proper naming
create_result_file() {
    local tool_name="$1"
    local result_type="$2"  # e.g., "results", "summary", "scan"
    local extension="${3:-json}"
    
    if [[ -n "$SCAN_DIR" ]]; then
        # Scan directory mode - simpler naming
        echo "$OUTPUT_DIR/${result_type}.${extension}"
    else
        # Traditional mode - with scan ID prefix
        echo "$OUTPUT_DIR/${SCAN_ID}_${tool_name}-${result_type}.${extension}"
    fi
}

# Function to create current symlinks
create_current_links() {
    local tool_name="$1"
    
    if [[ -n "$SCAN_DIR" ]]; then
        # Create symlinks in reports directory pointing to scan directory
        cd "$CURRENT_LINK_DIR"
        ln -sf "../../scans/$SCAN_ID/$tool_name/results.json" "${tool_name}-results.json" 2>/dev/null || true
        ln -sf "../../scans/$SCAN_ID/$tool_name/scan.log" "${tool_name}-scan.log" 2>/dev/null || true
        ln -sf "../../scans/$SCAN_ID/$tool_name/summary.json" "${tool_name}-summary.json" 2>/dev/null || true
    else
        # Traditional symlink creation
        cd "$OUTPUT_DIR"
        if [[ -f "${SCAN_ID}_${tool_name}-results.json" ]]; then
            ln -sf "${SCAN_ID}_${tool_name}-results.json" "${tool_name}-results.json"
        fi
        if [[ -f "${SCAN_ID}_${tool_name}-scan.log" ]]; then
            ln -sf "${SCAN_ID}_${tool_name}-scan.log" "${tool_name}-scan.log"
        fi
    fi
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