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