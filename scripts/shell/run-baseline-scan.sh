#!/bin/bash

# ███████╗██████╗ ██╗   ██╗ ██████╗ ███╗   ██╗
# ██╔════╝██╔══██╗╚██╗ ██╔╝██╔═══██╗████╗  ██║
# █████╗  ██████╔╝ ╚████╔╝ ██║   ██║██╔██╗ ██║
# ██╔══╝  ██╔═══╝   ╚██╔╝  ██║   ██║██║╚██╗██║
# ███████╗██║        ██║   ╚██████╔╝██║ ╚████║
# ╚══════╝╚═╝        ╚═╝    ╚═════╝ ╚═╝  ╚═══╝
#
# Baseline Security Scanner
# Scans comet-starter repository to detect scanner drift
# 
# Usage:
#   ./run-baseline-scan.sh [options]
#
# Options:
#   --update-repo    Update the baseline repository before scanning
#   --compare        Compare latest baseline scan with previous baseline
#   --list          List all baseline scans
#   --help          Show this help message
#
# Purpose:
#   Provides consistent baseline scanning against MetroStar/comet-starter
#   to detect scanner drift and validate tool consistency over time.

set -euo pipefail

# Configuration
BASELINE_REPO_URL="https://github.com/MetroStar/comet-starter.git"
BASELINE_REPO_URL_SSH="git@github.com:MetroStar/comet-starter.git"
BASELINE_REPO_NAME="comet-starter"
BASELINE_DIR="${PWD}/baseline"
BASELINE_REPO_PATH="${BASELINE_DIR}/${BASELINE_REPO_NAME}"
BASELINE_SCANS_DIR="${BASELINE_DIR}/scans"
BASELINE_REFERENCE_FILE="${BASELINE_DIR}/.baseline-reference"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Function to print colored output
print_banner() {
    echo -e "${CYAN}"
    cat << "EOF"
███████╗██████╗ ██╗   ██╗ ██████╗ ███╗   ██╗
██╔════╝██╔══██╗╚██╗ ██╔╝██╔═══██╗████╗  ██║
█████╗  ██████╔╝ ╚████╔╝ ██║   ██║██╔██╗ ██║
██╔══╝  ██╔═══╝   ╚██╔╝  ██║   ██║██║╚██╗██║
███████╗██║        ██║   ╚██████╔╝██║ ╚████║
╚══════╝╚═╝        ╚═╝    ╚═════╝ ╚═╝  ╚═══╝

Baseline Security Scanner - Scanner Drift Detection
EOF
    echo -e "${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

print_success() {
    echo -e "${GREEN}✅${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠️${NC} $1"
}

print_error() {
    echo -e "${RED}❌${NC} $1"
}

# Function to show help
show_help() {
    cat << EOF
Baseline Security Scanner - Scanner Drift Detection

USAGE:
    ./run-baseline-scan.sh [OPTIONS]

OPTIONS:
    --update-repo       Update the baseline repository before scanning
    --compare          Compare latest scan with the marked baseline
    --set-baseline     Mark a specific scan as the official baseline
    --list             List all baseline scans with summary statistics
    --help             Show this help message

DESCRIPTION:
    Scans the MetroStar/comet-starter repository to establish a baseline
    for scanner validation and drift detection. Each scan is timestamped
    and stored in the scans/ directory with a "baseline-" prefix.

EXAMPLES:
    # Run initial baseline scan
    ./run-baseline-scan.sh

    # Update repository and run new baseline scan
    ./run-baseline-scan.sh --update-repo

    # Mark latest scan as the official baseline
    ./run-baseline-scan.sh --set-baseline

    # Compare latest scan with marked baseline
    ./run-baseline-scan.sh --compare

    # List all baseline scans
    ./run-baseline-scan.sh --list

BASELINE REPOSITORY:
    ${BASELINE_REPO_URL}
    
SCAN STORAGE:
    baseline/scans/comet-starter_\${USER}_\${TIMESTAMP}/

BASELINE REFERENCE:
    ${BASELINE_REFERENCE_FILE}

PURPOSE:
    • Detect scanner drift over time
    • Validate tool consistency
    • Track false positive/negative rates
    • Ensure 0% margin of error between scans

EOF
}

# Function to clone or update baseline repository
setup_baseline_repo() {
    local update_repo=$1

    print_info "Setting up baseline repository..."

    # Create baseline directory if it doesn't exist
    mkdir -p "${BASELINE_DIR}"

    if [ -d "${BASELINE_REPO_PATH}" ]; then
        if [ "${update_repo}" = true ]; then
            print_info "Updating existing baseline repository..."
            cd "${BASELINE_REPO_PATH}"
            
            # Store current commit before update
            OLD_COMMIT=$(git rev-parse HEAD)
            OLD_COMMIT_SHORT=$(git rev-parse --short HEAD)
            
            git fetch origin main
            git reset --hard origin/main
            
            NEW_COMMIT=$(git rev-parse HEAD)
            NEW_COMMIT_SHORT=$(git rev-parse --short HEAD)
            
            if [ "${OLD_COMMIT}" != "${NEW_COMMIT}" ]; then
                print_success "Repository updated: ${OLD_COMMIT_SHORT} → ${NEW_COMMIT_SHORT}"
                git log --oneline "${OLD_COMMIT}..${NEW_COMMIT}" | head -5
            else
                print_info "Repository already up to date: ${NEW_COMMIT_SHORT}"
            fi
            
            cd - > /dev/null
        else
            print_info "Using existing baseline repository (use --update-repo to update)"
            cd "${BASELINE_REPO_PATH}"
            CURRENT_COMMIT=$(git rev-parse --short HEAD)
            print_info "Current commit: ${CURRENT_COMMIT}"
            cd - > /dev/null
        fi
    else
        print_info "Cloning baseline repository..."
        
        # Try HTTPS first
        if git clone "${BASELINE_REPO_URL}" "${BASELINE_REPO_PATH}"; then
            print_success "Baseline repository cloned successfully (HTTPS)"
        else
            print_warning "HTTPS clone failed, trying SSH..."
            # Try SSH as fallback
            if git clone "${BASELINE_REPO_URL_SSH}" "${BASELINE_REPO_PATH}"; then
                print_success "Baseline repository cloned successfully (SSH)"
            else
                print_error "Failed to clone repository via both HTTPS and SSH"
                print_info "GitHub may be experiencing issues. Try again later or clone manually:"
                print_info "  git clone ${BASELINE_REPO_URL} ${BASELINE_REPO_PATH}"
                exit 1
            fi
        fi
        
        cd "${BASELINE_REPO_PATH}"
        CURRENT_COMMIT=$(git rev-parse --short HEAD)
        print_info "Initial commit: ${CURRENT_COMMIT}"
        cd - > /dev/null
    fi

    # Verify repository exists
    if [ ! -d "${BASELINE_REPO_PATH}" ]; then
        print_error "Failed to setup baseline repository"
        exit 1
    fi
}

# Function to set a scan as the official baseline
set_baseline_reference() {
    local scan_id=$1
    
    print_info "Setting baseline reference..."
    echo ""

    # If no scan_id provided, use the most recent scan
    if [ -z "${scan_id}" ]; then
        scan_id=$(find "${BASELINE_SCANS_DIR}" -maxdepth 1 -type d \( -name "baseline-*" -o -name "${BASELINE_REPO_NAME}_*" \) 2>/dev/null | sort -r | head -1 | xargs basename)
        
        if [ -z "${scan_id}" ]; then
            print_error "No baseline scans found"
            echo "Run a baseline scan first: ./run-baseline-scan.sh"
            exit 1
        fi
        
        print_info "Using most recent scan: ${scan_id}"
    fi

    # Verify scan exists
    if [ ! -d "${BASELINE_SCANS_DIR}/${scan_id}" ]; then
        print_error "Scan directory not found: ${BASELINE_SCANS_DIR}/${scan_id}"
        exit 1
    fi

    # Verify dashboard exists
    if [ ! -f "${BASELINE_SCANS_DIR}/${scan_id}/consolidated-reports/dashboards/security-dashboard.html" ]; then
        print_warning "Dashboard not found for this scan"
    fi

    # Create baseline directory if needed
    mkdir -p "${BASELINE_DIR}"

    # Create baseline reference file with scan info
    cat > "${BASELINE_REFERENCE_FILE}" << EOF
# Epyon Baseline Reference
# This file marks the official baseline scan for drift detection
# Created: $(date)

BASELINE_SCAN_ID="${scan_id}"
BASELINE_SCAN_PATH="baseline/scans/${scan_id}"
BASELINE_DASHBOARD="baseline/scans/${scan_id}/consolidated-reports/dashboards/security-dashboard.html"
BASELINE_SET_DATE="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
BASELINE_SET_BY="${USER}"
EOF

    # Calculate hash of the scan results for integrity verification
    if command -v sha256sum &> /dev/null; then
        HASH_COMMAND="sha256sum"
    elif command -v shasum &> /dev/null; then
        HASH_COMMAND="shasum -a 256"
    else
        print_warning "No hash command available (sha256sum or shasum)"
        HASH_COMMAND=""
    fi

    if [ -n "${HASH_COMMAND}" ]; then
        # Hash the security findings summary
        if [ -f "${BASELINE_SCANS_DIR}/${scan_id}/security-findings-summary.json" ]; then
            HASH=$(${HASH_COMMAND} "${BASELINE_SCANS_DIR}/${scan_id}/security-findings-summary.json" | awk '{print $1}')
            echo "BASELINE_HASH=\"${HASH}\"" >> "${BASELINE_REFERENCE_FILE}"
            echo "BASELINE_HASH_ALGORITHM=\"SHA256\"" >> "${BASELINE_REFERENCE_FILE}"
        fi
    fi

    # Add metadata if available
    if [ -f "${BASELINE_SCANS_DIR}/${scan_id}/scan-metadata.json" ]; then
        TOTAL_FILES=$(jq -r '.total_files // "N/A"' "${BASELINE_SCANS_DIR}/${scan_id}/scan-metadata.json" 2>/dev/null || echo "N/A")
        REPO_COMMIT=$(jq -r '.repository_commit_short // "N/A"' "${BASELINE_SCANS_DIR}/${scan_id}/scan-metadata.json" 2>/dev/null || echo "N/A")
        echo "BASELINE_TOTAL_FILES=\"${TOTAL_FILES}\"" >> "${BASELINE_REFERENCE_FILE}"
        echo "BASELINE_REPO_COMMIT=\"${REPO_COMMIT}\"" >> "${BASELINE_REFERENCE_FILE}"
    fi

    print_success "Baseline reference set!"
    echo ""
    echo "📌 Official Baseline: ${scan_id}"
    
    if [ -f "scans/${scan_id}/scan-metadata.json" ]; then
        echo "   Files: ${TOTAL_FILES}"
        echo "   Commit: ${REPO_COMMIT}"
    fi
    
    if [ -n "${HASH}" ]; then
        echo "   Hash: ${HASH:0:16}..."
    fi
    
    echo ""
    echo "This scan will be used as the reference for all comparisons."
    echo "To compare against this baseline:"
    echo "  ./run-baseline-scan.sh --compare"
}

# Function to get the current baseline reference
get_baseline_reference() {
    if [ ! -f "${BASELINE_REFERENCE_FILE}" ]; then
        return 1
    fi
    
    # Source the baseline reference file
    source "${BASELINE_REFERENCE_FILE}"
    
    # Verify the baseline scan still exists
    if [ ! -d "${BASELINE_SCAN_PATH}" ]; then
        print_warning "Baseline scan directory no longer exists: ${BASELINE_SCAN_PATH}"
        return 1
    fi
    
    return 0
}

# Function to list all baseline scans
list_baseline_scans() {
    print_info "Listing all baseline scans..."
    echo ""

    # Get the current baseline reference if it exists
    CURRENT_BASELINE_ID=""
    if get_baseline_reference 2>/dev/null; then
        CURRENT_BASELINE_ID="${BASELINE_SCAN_ID}"
    fi

    # Create scans directory if it doesn't exist
    mkdir -p "${BASELINE_SCANS_DIR}"

    # Find scans with either baseline- prefix or comet-starter prefix
    BASELINE_SCANS=$(find "${BASELINE_SCANS_DIR}" -maxdepth 1 -type d \( -name "baseline-*" -o -name "${BASELINE_REPO_NAME}_*" \) 2>/dev/null | sort -r)

    if [ -z "${BASELINE_SCANS}" ]; then
        print_warning "No baseline scans found"
        echo ""
        echo "Run a baseline scan first:"
        echo "  ./run-baseline-scan.sh"
        exit 0
    fi

    local count=0
    for scan_dir in ${BASELINE_SCANS}; do
        count=$((count + 1))
        scan_name=$(basename "${scan_dir}")
        
        # Check if this is the official baseline
        BASELINE_MARKER=""
        if [ "${scan_name}" = "${CURRENT_BASELINE_ID}" ]; then
            BASELINE_MARKER=" ${GREEN}★ OFFICIAL BASELINE${NC}"
        fi
        
        # Extract timestamp from scan name (format: baseline-comet-starter_user_YYYY-MM-DD_HH-MM-SS)
        timestamp=$(echo "${scan_name}" | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2}_[0-9]{2}-[0-9]{2}-[0-9]{2}')
        
        echo -e "${CYAN}[${count}]${NC} ${scan_name}${BASELINE_MARKER}"
        echo "    Timestamp: ${timestamp}"
        
        # Read scan metadata if available
        if [ -f "${scan_dir}/scan-metadata.json" ]; then
            total_files=$(jq -r '.total_files // "N/A"' "${scan_dir}/scan-metadata.json" 2>/dev/null || echo "N/A")
            repo_commit=$(jq -r '.repository_commit // "N/A"' "${scan_dir}/scan-metadata.json" 2>/dev/null || echo "N/A")
            echo "    Files: ${total_files}"
            echo "    Commit: ${repo_commit}"
        fi
        
        # Check for dashboard
        if [ -f "${scan_dir}/consolidated-reports/dashboards/security-dashboard.html" ]; then
            echo -e "    Dashboard: ${GREEN}✓${NC} Available"
        fi
        
        echo ""
    done

    print_success "Found ${count} baseline scan(s)"
}

# Function to compare baseline scans
compare_baseline_scans() {
    print_info "Comparing baseline scans..."
    echo ""

    # Check if there's an official baseline set
    LATEST_SCAN=""
    BASELINE_SCAN=""
    
    if get_baseline_reference 2>/dev/null; then
        # Use the official baseline
        BASELINE_SCAN="${BASELINE_SCAN_PATH}"
        print_info "Using official baseline: ${BASELINE_SCAN_ID}"
        
        # Get the most recent scan that's NOT the baseline
        LATEST_SCAN=$(find "${BASELINE_SCANS_DIR}" -maxdepth 1 -type d \( -name "baseline-*" -o -name "${BASELINE_REPO_NAME}_*" \) ! -name "${BASELINE_SCAN_ID}" 2>/dev/null | sort -r | head -1)
        
        if [ -z "${LATEST_SCAN}" ]; then
            print_warning "No other scans found to compare with baseline"
            echo ""
            echo "Run a new baseline scan:"
            echo "  ./run-baseline-scan.sh --update-repo"
            exit 0
        fi
        
        print_info "Comparing with: $(basename ${LATEST_SCAN})"
    else
        print_info "No official baseline set - comparing two most recent scans"
        echo ""
        
        # Find the two most recent baseline scans (with either naming pattern)
        LATEST_SCANS=$(find "${BASELINE_SCANS_DIR}" -maxdepth 1 -type d \( -name "baseline-*" -o -name "${BASELINE_REPO_NAME}_*" \) 2>/dev/null | sort -r | head -2)
        SCAN_COUNT=$(echo "${LATEST_SCANS}" | wc -l | tr -d ' ')

        if [ "${SCAN_COUNT}" -lt 2 ]; then
            print_warning "Need at least 2 baseline scans for comparison"
            echo ""
            echo "Current baseline scans: ${SCAN_COUNT}"
            echo "Run another baseline scan:"
            echo "  ./run-baseline-scan.sh --update-repo"
            exit 0
        fi
        
        LATEST_SCAN=$(echo "${LATEST_SCANS}" | head -1)
        BASELINE_SCAN=$(echo "${LATEST_SCANS}" | tail -1)
    fi

    echo ""
    print_info "Baseline: $(basename ${BASELINE_SCAN})"
    print_info "Latest:   $(basename ${LATEST_SCAN})"
    echo ""

    # Compare dashboards
    LATEST_DASHBOARD="${LATEST_SCAN}/consolidated-reports/dashboards/security-dashboard.html"
    BASELINE_DASHBOARD="${BASELINE_SCAN}/consolidated-reports/dashboards/security-dashboard.html"

    if [ ! -f "${LATEST_DASHBOARD}" ] || [ ! -f "${BASELINE_DASHBOARD}" ]; then
        print_error "Dashboard files not found for comparison"
        exit 1
    fi

    # Extract finding counts from dashboards (simplified - looks for severity counts)
    echo -e "${CYAN}Comparison Summary:${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    # Compare file counts
    if [ -f "${LATEST_SCAN}/scan-metadata.json" ] && [ -f "${BASELINE_SCAN}/scan-metadata.json" ]; then
        LATEST_FILES=$(jq -r '.total_files' "${LATEST_SCAN}/scan-metadata.json" 2>/dev/null || echo "0")
        BASELINE_FILES=$(jq -r '.total_files' "${BASELINE_SCAN}/scan-metadata.json" 2>/dev/null || echo "0")
        
        echo "Files Scanned:"
        echo "  Latest:   ${LATEST_FILES}"
        echo "  Baseline: ${BASELINE_FILES}"
        
        if [ "${LATEST_FILES}" != "${BASELINE_FILES}" ]; then
            print_warning "File count changed - repository may have been updated"
        else
            print_success "File count consistent"
        fi
        echo ""
    fi

    # Open both dashboards for manual comparison
    print_info "Opening dashboards for visual comparison..."
    # Cross-platform browser opening
    if [[ "$OSTYPE" == "darwin"* ]]; then
        open "${BASELINE_DASHBOARD}" 2>/dev/null || true
        sleep 1
        open "${LATEST_DASHBOARD}" 2>/dev/null || true
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        xdg-open "${BASELINE_DASHBOARD}" 2>/dev/null || true
        sleep 1
        xdg-open "${LATEST_DASHBOARD}" 2>/dev/null || true
    elif [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "cygwin" ]]; then
        start "${BASELINE_DASHBOARD}" 2>/dev/null || true
        sleep 1
        start "${LATEST_DASHBOARD}" 2>/dev/null || true
    else
        echo "Baseline: ${BASELINE_DASHBOARD}"
        echo "Latest: ${LATEST_DASHBOARD}"
    fi

    echo ""
    print_success "Dashboards opened in browser for comparison"
    echo ""
    echo "Manual Review Checklist:"
    echo "  □ Compare Critical/High/Medium/Low counts"
    echo "  □ Verify same vulnerabilities detected"
    echo "  □ Check for new false positives"
    echo "  □ Validate tool consistency"
    echo "  □ Document any scanner drift"
}

# Function to run baseline scan
run_baseline_scan() {
    print_info "Starting baseline security scan..."
    echo ""

    # Create baseline scans directory
    mkdir -p "${BASELINE_SCANS_DIR}"

    # Get current commit for tracking
    cd "${BASELINE_REPO_PATH}"
    REPO_COMMIT=$(git rev-parse HEAD)
    REPO_COMMIT_SHORT=$(git rev-parse --short HEAD)
    cd - > /dev/null

    print_info "Scanning commit: ${REPO_COMMIT_SHORT}"

    # Check if target scan script exists
    TARGET_SCAN_SCRIPT="${PWD}/scripts/shell/run-target-security-scan.sh"
    if [ ! -f "${TARGET_SCAN_SCRIPT}" ]; then
        print_error "Target scan script not found: ${TARGET_SCAN_SCRIPT}"
        exit 1
    fi

    # Run full security scan on baseline repository
    print_info "Executing full security scan..."
    echo ""

    # Record timestamp before scan to help locate results
    SCAN_START_TIME=$(date +%s)
    
    # Set custom scan name and output directory for baseline
    export CUSTOM_SCAN_NAME="${BASELINE_REPO_NAME}"
    export BASELINE_SCAN_OUTPUT="${BASELINE_SCANS_DIR}"
    
    "${TARGET_SCAN_SCRIPT}" "${BASELINE_REPO_PATH}" full

    # Find the most recent scan in baseline/scans/ (created within last 5 minutes)
    LATEST_BASELINE=$(find "${BASELINE_SCANS_DIR}" -maxdepth 1 -type d \( -name "baseline-*" -o -name "${BASELINE_REPO_NAME}_*" \) -newermt "@${SCAN_START_TIME}" 2>/dev/null | sort -r | head -1)

    if [ -z "${LATEST_BASELINE}" ]; then
        # Fallback: check if scan was created in scans/ and move it
        TEMP_SCAN=$(find scans/ -maxdepth 1 -type d -name "${BASELINE_REPO_NAME}_*" -newermt "@${SCAN_START_TIME}" 2>/dev/null | sort -r | head -1)
        
        if [ -n "${TEMP_SCAN}" ]; then
            print_info "Moving scan to baseline directory..."
            SCAN_NAME=$(basename "${TEMP_SCAN}")
            mv "${TEMP_SCAN}" "${BASELINE_SCANS_DIR}/"
            LATEST_BASELINE="${BASELINE_SCANS_DIR}/${SCAN_NAME}"
            print_success "Moved to: ${LATEST_BASELINE}"
        else
            # Final fallback: find any recent scan in baseline dir
            LATEST_BASELINE=$(find "${BASELINE_SCANS_DIR}" -maxdepth 1 -type d -name "${BASELINE_REPO_NAME}_*" 2>/dev/null | sort -r | head -1)
        fi
    fi

    if [ -z "${LATEST_BASELINE}" ]; then
        print_error "Failed to locate baseline scan results"
        print_info "Expected scan directory pattern: ${BASELINE_REPO_NAME}_* in ${BASELINE_SCANS_DIR}"
        exit 1
    fi

    # Add repository commit to scan metadata
    if [ -f "${LATEST_BASELINE}/scan-metadata.json" ]; then
        # Add commit info to metadata
        TMP_FILE=$(mktemp)
        jq --arg commit "${REPO_COMMIT}" --arg commit_short "${REPO_COMMIT_SHORT}" \
           '. + {repository_commit: $commit, repository_commit_short: $commit_short}' \
           "${LATEST_BASELINE}/scan-metadata.json" > "${TMP_FILE}"
        mv "${TMP_FILE}" "${LATEST_BASELINE}/scan-metadata.json"
    fi

    echo ""
    print_success "Baseline scan complete!"
    echo ""
    echo "Scan Results: ${LATEST_BASELINE}"
    echo "Dashboard:    ${LATEST_BASELINE}/consolidated-reports/dashboards/security-dashboard.html"
    echo ""
    echo "To compare with previous baseline:"
    echo "  ./run-baseline-scan.sh --compare"
}

# Main execution
main() {
    local update_repo=false
    local compare_mode=false
    local list_mode=false
    local set_baseline_mode=false
    local scan_id=""

    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --update-repo)
                update_repo=true
                shift
                ;;
            --compare)
                compare_mode=true
                shift
                ;;
            --set-baseline)
                set_baseline_mode=true
                shift
                # Check if next arg is a scan ID
                if [[ $# -gt 0 ]] && [[ ! "$1" =~ ^-- ]]; then
                    scan_id="$1"
                    shift
                fi
                ;;
            --list)
                list_mode=true
                shift
                ;;
            --help|-h)
                show_help
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                echo ""
                show_help
                exit 1
                ;;
        esac
    done

    print_banner

    # Handle set baseline mode
    if [ "${set_baseline_mode}" = true ]; then
        set_baseline_reference "${scan_id}"
        exit 0
    fi

    # Handle list mode
    if [ "${list_mode}" = true ]; then
        list_baseline_scans
        exit 0
    fi

    # Handle compare mode
    if [ "${compare_mode}" = true ]; then
        compare_baseline_scans
        exit 0
    fi

    # Setup baseline repository
    setup_baseline_repo "${update_repo}"

    # Run baseline scan
    run_baseline_scan
}

# Run main function
main "$@"
