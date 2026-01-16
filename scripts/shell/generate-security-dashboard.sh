#!/bin/bash

# Generate Interactive Security Dashboard
# Creates an interactive HTML dashboard with expandable tool sections showing detailed vulnerabilities

# Use less strict mode for robustness with jq parsing
set -u

# Colors for help output
WHITE='\033[1;37m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

# Display EPYON banner
echo -e "${CYAN}"
cat << "EOF"
███████╗██████╗ ██╗   ██╗ ██████╗ ███╗   ██╗
██╔════╝██╔══██╗╚██╗ ██╔╝██╔═══██╗████╗  ██║
█████╗  ██████╔╝ ╚████╔╝ ██║   ██║██╔██╗ ██║
██╔══╝  ██╔═══╝   ╚██╔╝  ██║   ██║██║╚██╗██║
███████╗██║        ██║   ╚██████╔╝██║ ╚████║
╚══════╝╚═╝        ╚═╝    ╚═════╝ ╚═╝  ╚═══╝
EOF
echo -e "${NC}"
echo -e "${GREEN}Absolute Security Control - Dashboard Generator${NC}"
echo ""

# Help function
show_help() {
    echo -e "${WHITE}Interactive Security Dashboard Generator${NC}"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Creates an interactive HTML dashboard consolidating all security scan results"
    echo "with expandable sections, filtering, sorting, and detailed vulnerability views."
    echo ""
    echo "Options:"
    echo "  -h, --help          Show this help message and exit"
    echo ""
    echo "Environment Variables:"
    echo "  SCAN_DIR            Specific scan directory to generate dashboard for"
    echo "                      (default: auto-detects latest scan)"
    echo ""
    echo "Output:"
    echo "  Dashboard saved to: {SCAN_DIR}/consolidated-reports/dashboards/security-dashboard.html"
    echo ""
    echo "Dashboard Features:"
    echo "  - Severity summary with clickable filter chips"
    echo "  - Expandable sections for each security tool"
    echo "  - Detailed vulnerability information"
    echo "  - False positive assessment checklists"
    echo "  - SBOM package viewer with search"
    echo "  - Sortable and filterable findings"
    echo "  - CWE IDs, PURL, and CVE links"
    echo ""
    echo "Supported Tools:"
    echo "  - Trivy (container vulnerabilities)"
    echo "  - Grype (dependency vulnerabilities)"
    echo "  - TruffleHog (secret detection)"
    echo "  - Checkov (IaC security)"
    echo "  - ClamAV (malware detection)"
    echo "  - Xeol (EOL detection)"
    echo "  - SBOM (software inventory)"
    echo "  - SonarQube (code quality)"
    echo ""
    echo "Examples:"
    echo "  $0                              # Generate for latest scan"
    echo "  SCAN_DIR=/path/to/scan $0       # Generate for specific scan"
    echo ""
    echo "Notes:"
    echo "  - Requires jq to be installed"
    echo "  - Auto-detects latest scan in scans/ directory"
    exit 0
}

# Parse arguments
for arg in "$@"; do
    case $arg in
        -h|--help)
            show_help
            ;;
    esac
done

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Default paths
SCANS_DIR="${WORKSPACE_ROOT}/scans"

# Use SCAN_DIR if provided, otherwise auto-detect latest
if [[ -n "${SCAN_DIR:-}" ]]; then
    LATEST_SCAN="$SCAN_DIR"
    echo "Using provided scan directory: $(basename "$LATEST_SCAN")"
else
    # Get the most recent scan directory (any username)
    LATEST_SCAN=$(find "$SCANS_DIR" -maxdepth 1 -type d -name "*_*_*" 2>/dev/null | sort -r | head -n 1)
    
    if [ -z "$LATEST_SCAN" ]; then
        echo "❌ No scan directories found in $SCANS_DIR"
        exit 1
    fi
    
    echo "🔍 Auto-detected latest scan: $(basename "$LATEST_SCAN")"
fi

SCAN_NAME=$(basename "$LATEST_SCAN")
echo "Generating interactive dashboard from: $SCAN_NAME"

# Set output to the scan directory's consolidated reports
OUTPUT_DIR="${LATEST_SCAN}/consolidated-reports/dashboards"
OUTPUT_HTML="${OUTPUT_DIR}/security-dashboard.html"

# ============================================
# COLLECT DETAILED STATISTICS FROM EACH TOOL
# ============================================

# Get target directory from scan ID
TARGET_NAME=$(echo "$SCAN_NAME" | cut -d'_' -f1)
SCAN_USER=$(echo "$SCAN_NAME" | cut -d'_' -f2)
SCAN_TIMESTAMP=$(echo "$SCAN_NAME" | cut -d'_' -f3-)

# ---- Read Scan Metadata (File Statistics) ----
SCAN_METADATA_FILE="${LATEST_SCAN}/scan-metadata.json"
TOTAL_FILES_SCANNED=0
JS_TS_FILES=0
PYTHON_FILES=0
YAML_FILES=0
JSON_CONFIG_FILES=0
TERRAFORM_FILES=0
DOCKERFILE_COUNT=0
SHELL_SCRIPT_FILES=0
TARGET_DIRECTORY="N/A"

if [ -f "$SCAN_METADATA_FILE" ] && command -v jq &> /dev/null; then
    echo "📊 Reading scan metadata from: $SCAN_METADATA_FILE"
    TOTAL_FILES_SCANNED=$(jq -r '.file_statistics.total_files // 0' "$SCAN_METADATA_FILE" 2>/dev/null || echo "0")
    JS_TS_FILES=$(jq -r '.file_statistics.javascript_typescript // 0' "$SCAN_METADATA_FILE" 2>/dev/null || echo "0")
    PYTHON_FILES=$(jq -r '.file_statistics.python // 0' "$SCAN_METADATA_FILE" 2>/dev/null || echo "0")
    YAML_FILES=$(jq -r '.file_statistics.yaml_yml // 0' "$SCAN_METADATA_FILE" 2>/dev/null || echo "0")
    JSON_CONFIG_FILES=$(jq -r '.file_statistics.json // 0' "$SCAN_METADATA_FILE" 2>/dev/null || echo "0")
    TERRAFORM_FILES=$(jq -r '.file_statistics.terraform // 0' "$SCAN_METADATA_FILE" 2>/dev/null || echo "0")
    DOCKERFILE_COUNT=$(jq -r '.file_statistics.dockerfiles // 0' "$SCAN_METADATA_FILE" 2>/dev/null || echo "0")
    SHELL_SCRIPT_FILES=$(jq -r '.file_statistics.shell_scripts // 0' "$SCAN_METADATA_FILE" 2>/dev/null || echo "0")
    TARGET_DIRECTORY=$(jq -r '.target_directory // "N/A"' "$SCAN_METADATA_FILE" 2>/dev/null || echo "N/A")
    echo "✅ Loaded file statistics: $TOTAL_FILES_SCANNED total files"
else
    echo "⚠️  No scan metadata found - file counts will show as 0"
    echo "   Run a new scan to generate file statistics"
fi

# ---- Load Remediation Suggestions for inline display ----
REMEDIATION_FILE="${LATEST_SCAN}/remediation-suggestions.json"
REMEDIATION_DATA_FILE="/tmp/remediation_map_$$.txt"
if [ -f "$REMEDIATION_FILE" ] && command -v jq &> /dev/null; then
    echo "💊 Loading remediation suggestions for inline display..."
    jq -r '.remediations[] | "\(.cve)|\(.package.name)|\(.package.fixed_version)|\(.remediation.update_command)"' "$REMEDIATION_FILE" 2>/dev/null > "$REMEDIATION_DATA_FILE"
fi

# Function to get remediation for a CVE and package
get_remediation() {
    local cve="$1"
    local pkg="$2"
    if [ -f "$REMEDIATION_DATA_FILE" ]; then
        grep "^${cve}|${pkg}|" "$REMEDIATION_DATA_FILE" 2>/dev/null || echo ""
    fi
}

# Function to inject remediation into vulnerability HTML
inject_remediation() {
    local cve="$1"
    local pkg="$2"
    
    local remediation_data=$(get_remediation "$cve" "$pkg")
    if [ -n "$remediation_data" ]; then
        IFS='|' read -r _cve _pkg fix_ver cmd <<< "$remediation_data"
        echo "<div class=\"detail-section\" style=\"background: linear-gradient(135deg, #f0fdf4 0%, #dcfce7 100%); border-left: 4px solid #10b981; padding: 15px; margin: 10px 0; border-radius: 6px;\">"
        echo "<h5 style=\"color: #047857; margin-bottom: 10px;\">💊 Automated Fix Available</h5>"
        echo "<div style=\"margin: 8px 0;\"><strong style=\"color: #065f46;\">Upgrade to:</strong> <code style=\"background: #bbf7d0; padding: 4px 8px; border-radius: 4px; color: #065f46;\">${fix_ver}</code></div>"
        echo "<div style=\"margin: 8px 0;\"><strong style=\"color: #065f46;\">Command:</strong></div>"
        echo "<code style=\"display: block; background: #dcfce7; color: #065f46; padding: 10px; border-radius: 4px; font-family: 'Courier New', monospace; font-size: 0.9em; margin: 5px 0;\">${cmd}</code>"
        echo "<div style=\"margin-top: 10px; padding: 8px; background: #fef3c7; border-radius: 4px; font-size: 0.85em;\">"
        echo "<strong style=\"color: #92400e;\">⚠️ Before applying:</strong> Review changelog, test in dev, run tests, commit lock files"
        echo "</div>"
        echo "</div>"
    fi
}

# Function to check tool scan status
# Returns: status (success|failed|skipped), reason
check_tool_status() {
    local tool_dir="$1"
    local status_file="$tool_dir/status.json"
    
    if [ -f "$status_file" ] && command -v jq &> /dev/null; then
        local status=$(jq -r '.status // "unknown"' "$status_file" 2>/dev/null || echo "unknown")
        local reason=$(jq -r '.reason // ""' "$status_file" 2>/dev/null || echo "")
        echo "${status}|${reason}"
    else
        echo "unknown|"
    fi
}

# Function to generate status banner HTML for failed/skipped scans
generate_status_banner() {
    local status="$1"
    local reason="$2"
    local tool_name="$3"
    
    if [ "$status" = "failed" ]; then
        echo "<div class=\"stats-detail-box\" style=\"background: linear-gradient(135deg, #fee2e2 0%, #fecaca 100%); border-left: 4px solid #dc2626; margin-bottom: 15px;\">"
        echo "<h4 style=\"color: #991b1b;\">❌ Scan Failed</h4>"
        echo "<p style=\"color: #7f1d1d; margin: 8px 0;\"><strong>Reason:</strong> ${reason:-Unknown error}</p>"
        echo "<p style=\"color: #7f1d1d; font-size: 0.9em;\">The $tool_name scan did not complete successfully. Check the scan logs for details.</p>"
        echo "</div>"
    elif [ "$status" = "skipped" ]; then
        echo "<div class=\"stats-detail-box\" style=\"background: linear-gradient(135deg, #fef3c7 0%, #fde68a 100%); border-left: 4px solid #f59e0b; margin-bottom: 15px;\">"
        echo "<h4 style=\"color: #92400e;\">⏭️ Scan Skipped</h4>"
        echo "<p style=\"color: #78350f; margin: 8px 0;\"><strong>Reason:</strong> ${reason:-Not applicable to this project}</p>"
        echo "<p style=\"color: #78350f; font-size: 0.9em;\">This scan was skipped for this project.</p>"
        echo "</div>"
    fi
}

# ---- TruffleHog Statistics ----
TH_DIR="${LATEST_SCAN}/trufflehog"
TH_FILE="$TH_DIR/trufflehog-filesystem-results.json"
TH_FILES_SCANNED=0
TH_TOTAL_FINDINGS=0
TH_VERIFIED=0
TH_UNVERIFIED=0
TH_DETECTORS_USED=0
TH_SCAN_DURATION="N/A"
TH_FILES_WITH_FINDINGS=0
TH_CRITICAL=0
TH_HIGH=0
TH_FINDINGS=""
TH_STATUS="unknown"
TH_STATUS_REASON=""

# Check tool status first
if [ -d "$TH_DIR" ]; then
    IFS='|' read -r TH_STATUS TH_STATUS_REASON <<< "$(check_tool_status "$TH_DIR")"
fi

if [ -f "$TH_FILE" ]; then
    # Count only actual findings (lines with DetectorName), not log entries
    set +o pipefail
    TH_TOTAL_FINDINGS=$(grep -c '"DetectorName"' "$TH_FILE" 2>/dev/null || true)
    TH_TOTAL_FINDINGS=$(echo "${TH_TOTAL_FINDINGS:-0}" | tr -d ' \n\t')
    set -o pipefail
    [[ "$TH_TOTAL_FINDINGS" =~ ^[0-9]+$ ]] || TH_TOTAL_FINDINGS=0
    
    # Count verified secrets
    set +o pipefail
    TH_VERIFIED=$(grep '"DetectorName"' "$TH_FILE" 2>/dev/null | grep -c '"Verified":true' 2>/dev/null || true)
    TH_VERIFIED=$(echo "${TH_VERIFIED:-0}" | tr -d ' \n\t')
    set -o pipefail
    TH_VERIFIED=$(echo "$TH_VERIFIED" | tr -d ' \n\t')
    [[ "$TH_VERIFIED" =~ ^[0-9]+$ ]] || TH_VERIFIED=0
    
    TH_UNVERIFIED=$((TH_TOTAL_FINDINGS - TH_VERIFIED))
    [[ "$TH_UNVERIFIED" =~ ^[0-9]+$ ]] || TH_UNVERIFIED=0
    
    set +o pipefail
    TH_DETECTORS_USED=$(grep -oE '"DetectorName":"[^"]+' "$TH_FILE" 2>/dev/null | sort -u | wc -l | tr -d ' \n\t')
    set -o pipefail
    TH_DETECTORS_USED="${TH_DETECTORS_USED:-0}"
    [[ "$TH_DETECTORS_USED" =~ ^[0-9]+$ ]] || TH_DETECTORS_USED=0
    
    set +o pipefail
    TH_FILES_WITH_FINDINGS=$(grep -oE '"file":"[^"]+' "$TH_FILE" 2>/dev/null | sort -u | wc -l | tr -d ' \n\t')
    set -o pipefail
    TH_FILES_WITH_FINDINGS="${TH_FILES_WITH_FINDINGS:-0}"
    [[ "$TH_FILES_WITH_FINDINGS" =~ ^[0-9]+$ ]] || TH_FILES_WITH_FINDINGS=0
    
    # Set severity counts - verified = critical, unverified = medium
    TH_CRITICAL=$TH_VERIFIED
    TH_HIGH=$TH_UNVERIFIED
    
    # Generate findings HTML with clickable details (use set +e to handle grep returning 1 when no matches)
    set +e
    TH_FINDINGS_HTML=$(grep -E '"DetectorName"' "$TH_FILE" 2>/dev/null | grep -v 'node_modules' | grep -v 'vendor/' | grep -v 'venv/' | grep -v '__pycache__' | head -n 30 | jq -s -r '
        map("<div class=\"finding-item severity-" + (if .Verified then "critical" else "medium" end) + "\" data-source=\"app\" onclick=\"toggleFindingDetails(this)\">
            <div class=\"finding-header\">
                <span class=\"badge badge-tool\">TruffleHog</span>
                <span class=\"badge badge-" + (if .Verified then "critical" else "medium" end) + "\">" + (if .Verified then "VERIFIED" else "UNVERIFIED" end) + "</span>
                <span class=\"badge\" style=\"background:#2C3539;color:#9ca3af;border:1px solid #4a5568;\">" + .DetectorName + "</span>
                <span class=\"badge\" style=\"background:#152a1f;color:#4ade80;font-size:0.7em;border:1px solid #10b981;\">💻 App Code</span>
            </div>
            <div class=\"finding-title\">" + .DetectorName + " - " + (if .Verified then "Verified Secret Found!" else "Potential Secret Detected" end) + "</div>
            <div class=\"finding-desc\">" + (.DetectorDescription // "Secret or credential pattern detected in source code") + "</div>
            <div class=\"finding-details\" style=\"display:none;\">
                <div><strong>Detector:</strong> <code>" + .DetectorName + "</code></div>
                <div><strong>Source:</strong> 💻 Application Code (secrets in source files)</div>
                <div><strong>Verified:</strong> " + (if .Verified then "<span style=\"color:#C41E3A;font-weight:bold;\">Yes - Active credential!</span>" else "<span style=\"color:#fb923c;\">No - Potential secret</span>" end) + "</div>
                <div><strong>File:</strong> <code>" + (.SourceMetadata.Data.Filesystem.file | split("/") | last) + "</code></div>
                <div><strong>Line:</strong> <code>" + (.SourceMetadata.Data.Filesystem.line | tostring) + "</code></div>
                <div><strong>Full Path:</strong> <code style=\"font-size: 0.8em;word-break:break-all;\">" + .SourceMetadata.Data.Filesystem.file + "</code></div>
                <div><strong>Description:</strong> " + (.DetectorDescription // "No description available") + "</div>
            </div>
        </div>") | 
        join("")
    ' 2>/dev/null)
    set -e
    
    if [ -n "$TH_FINDINGS_HTML" ] && [ "$TH_FINDINGS_HTML" != "" ]; then
        TH_FINDINGS="<p style=\"color:#9ca3af;margin-bottom:15px;font-size:0.9em;\">👆 Click on any finding below to expand details</p>${TH_FINDINGS_HTML}"
    else
        TH_FINDINGS="<p class=\"no-findings\">✅ No secrets or credentials detected</p>"
    fi
else
    TH_CRITICAL=0
    TH_HIGH=0
    TH_FINDINGS="<p class=\"no-findings\">No scan data available</p>"
fi

# ---- ClamAV Statistics ----
CLAMAV_LOG="${LATEST_SCAN}/clamav/scan.log"
CLAMAV_FILES_SCANNED=0
CLAMAV_DATA_SCANNED="0 MB"
CLAMAV_SCAN_TIME="N/A"
CLAMAV_ENGINE_VERSION="N/A"
CLAMAV_VIRUS_DB_COUNT=0
CLAMAV_INFECTED=0
CLAMAV_DIRECTORIES=0
if [ -f "$CLAMAV_LOG" ]; then
    CLAMAV_FILES_SCANNED=$(grep "Scanned files:" "$CLAMAV_LOG" 2>/dev/null | grep -oE '[0-9]+' | head -1 || echo "0")
    CLAMAV_DATA_SCANNED=$(grep "Data scanned:" "$CLAMAV_LOG" 2>/dev/null | head -1 | sed 's/Data scanned: //' || echo "N/A")
    CLAMAV_SCAN_TIME=$(grep "^Time:" "$CLAMAV_LOG" 2>/dev/null | head -1 | sed 's/Time: //' || echo "N/A")
    CLAMAV_ENGINE_VERSION=$(grep "Engine version:" "$CLAMAV_LOG" 2>/dev/null | head -1 | sed 's/Engine version: //' || echo "N/A")
    CLAMAV_VIRUS_DB_COUNT=$(grep "Known viruses:" "$CLAMAV_LOG" 2>/dev/null | head -1 | grep -oE '[0-9]+' || echo "0")
    CLAMAV_INFECTED=$(grep "Infected files:" "$CLAMAV_LOG" 2>/dev/null | head -1 | grep -oE '[0-9]+' || echo "0")
    CLAMAV_DIRECTORIES=$(grep "Scanned directories:" "$CLAMAV_LOG" 2>/dev/null | head -1 | grep -oE '[0-9]+' || echo "0")
fi
CLAMAV_CRITICAL=${CLAMAV_INFECTED:-0}
if [ "$CLAMAV_CRITICAL" -gt 0 ]; then
    CLAMAV_FINDINGS="<div class=\"finding-item severity-critical\" data-source=\"app\">
        <div class=\"finding-header\">
            <span class=\"badge badge-tool\">ClamAV</span>
            <span class=\"badge badge-critical\">CRITICAL</span>
            <span class=\"badge\" style=\"background:#152a1f;color:#4ade80;font-size:0.7em;border:1px solid #10b981;\">💻 App Code</span>
        </div>
        <div class=\"finding-title\">⚠️ Malware Detected</div>
        <div class=\"finding-desc\">$CLAMAV_CRITICAL infected files found</div>
        <div class=\"finding-details\">
            <div><strong>Source:</strong> 💻 Application Code (filesystem scan)</div>
            <div><strong>Action Required:</strong> Review scan results and quarantine infected files</div>
        </div>
    </div>"
else
    CLAMAV_FINDINGS="<p class=\"no-findings\">✅ No malware detected</p>"
fi

# ---- Trivy Statistics ----
TRIVY_DIR="${LATEST_SCAN}/trivy"
TRIVY_IMAGES_SCANNED=0
TRIVY_TOTAL_VULNS=0
TRIVY_CRITICAL=0
TRIVY_HIGH=0
TRIVY_MEDIUM=0
TRIVY_LOW=0
TRIVY_FINDINGS=""
TRIVY_DETAILS=""
if [ -d "$TRIVY_DIR" ]; then
    TRIVY_IMAGES_SCANNED=$(find "$TRIVY_DIR" -name "*.json" -type f ! -type l 2>/dev/null | wc -l | tr -d ' \n' || echo "0")
    [[ "$TRIVY_IMAGES_SCANNED" =~ ^[0-9]+$ ]] || TRIVY_IMAGES_SCANNED=0
    
    # Parse vulnerabilities from all Trivy JSON files
    for trivy_file in "$TRIVY_DIR"/*.json; do
        # Skip symlinks to avoid duplicate counting
        if [ -f "$trivy_file" ] && [ ! -L "$trivy_file" ] && grep -q '"SchemaVersion"' "$trivy_file" 2>/dev/null; then
            # Extract JSON portion (skip any log lines at the beginning)
            set +o pipefail
            json_content=$(sed -n '/^{/,$p' "$trivy_file" 2>/dev/null || cat "$trivy_file")
            set -o pipefail
            
            crit_count=$(echo "$json_content" | jq '[.Results[]?.Vulnerabilities[]? | select(.Severity=="CRITICAL")] | length' 2>/dev/null || echo "0")
            high_count=$(echo "$json_content" | jq '[.Results[]?.Vulnerabilities[]? | select(.Severity=="HIGH")] | length' 2>/dev/null || echo "0")
            med_count=$(echo "$json_content" | jq '[.Results[]?.Vulnerabilities[]? | select(.Severity=="MEDIUM")] | length' 2>/dev/null || echo "0")
            low_count=$(echo "$json_content" | jq '[.Results[]?.Vulnerabilities[]? | select(.Severity=="LOW")] | length' 2>/dev/null || echo "0")
            
            # Ensure numeric
            [[ "$crit_count" =~ ^[0-9]+$ ]] || crit_count=0
            [[ "$high_count" =~ ^[0-9]+$ ]] || high_count=0
            [[ "$med_count" =~ ^[0-9]+$ ]] || med_count=0
            [[ "$low_count" =~ ^[0-9]+$ ]] || low_count=0
            
            TRIVY_CRITICAL=$((TRIVY_CRITICAL + crit_count))
            TRIVY_HIGH=$((TRIVY_HIGH + high_count))
            TRIVY_MEDIUM=$((TRIVY_MEDIUM + med_count))
            TRIVY_LOW=$((TRIVY_LOW + low_count))
            
            # Extract individual vulnerability details for ALL severity levels (limit to top 50 per file)
            set +e
            vuln_details=$(echo "$json_content" | jq -r '
                def html_escape: gsub("<"; "&lt;") | gsub(">"; "&gt;") | gsub("\""; "&quot;") | gsub("\n"; " ");
                def status_badge_color: if . == "fixed" then "#c6f6d5;color:#2f855a" elif . == "affected" then "#fed7d7;color:#c53030" else "#feebc8;color:#c05621" end;
                def status_text_color: if . == "fixed" then "#2f855a" elif . == "affected" then "#c53030" else "#c05621" end;
                def fixed_color: if . == "No fix available" then "color:#c53030;" else "color:#2f855a;" end;
                def format_date: if . == "Unknown" then "Unknown" else (. | split("T")[0]) end;
                def cwes_display: if . == "" then "Not specified" else . end;
                [.Results[]? | select(.Vulnerabilities != null) | 
                 .Target as $target |
                 .Type as $pkg_type |
                 .Vulnerabilities[]? | 
                 {target: $target, 
                  pkg_type: $pkg_type,
                  id: .VulnerabilityID, 
                  pkg: .PkgName, 
                  severity: .Severity, 
                  severity_lc: (.Severity | ascii_downcase),
                  installed: .InstalledVersion, 
                  fixed: (.FixedVersion // "No fix available"),
                  status: (.Status // "unknown"),
                  status_uc: ((.Status // "unknown") | ascii_upcase),
                  status_badge: ((.Status // "unknown") | status_badge_color),
                  status_color: ((.Status // "unknown") | status_text_color),
                  fixed_style: ((.FixedVersion // "No fix available") | fixed_color),
                  title: ((.Title // .VulnerabilityID) | html_escape | .[0:80]), 
                  desc: ((.Description // "No description available") | html_escape),
                  desc_short: ((.Description // "No description available") | html_escape | .[0:120]),
                  primary_url: (.PrimaryURL // ""),
                  published: ((.PublishedDate // "Unknown") | format_date),
                  modified: ((.LastModifiedDate // "Unknown") | format_date),
                  cwes: (((.CweIDs // []) | join(", ")) | cwes_display),
                  refs: ((.References // []) | .[0:3] | join(" ")),
                  data_source: (.DataSource.Name // "Unknown"),
                  purl: ((.PkgIdentifier.PURL // "") | html_escape),
                  source_type: (if ($target | test("(bitnami|node|python|alpine|ubuntu|debian|nginx|redis|postgres|mysql|mongo|openjdk)"; "i")) or ($target | test("\\(.*\\)$")) or (.PkgType // "" | test("(debian|ubuntu|alpine|rhel|centos|fedora|os-pkgs|photon)"; "i")) then "image" else "app" end)}
                ] | sort_by(.severity | if . == "CRITICAL" then 0 elif . == "HIGH" then 1 elif . == "MEDIUM" then 2 else 3 end) | .[0:50] | .[] |
                "<div class=\"finding-item severity-" + .severity_lc + "\" data-pkg=\"" + .pkg + "\" data-status=\"" + .status + "\" data-cve=\"" + .id + "\" data-source=\"" + .source_type + "\" onclick=\"toggleFindingDetails(this)\">\n<div class=\"finding-header\">\n<span class=\"badge badge-tool\">Trivy</span>\n<span class=\"badge badge-" + .severity_lc + "\">" + .severity + "</span>\n<span class=\"badge\" style=\"background:#2C3539;color:#9ca3af;border:1px solid #4a5568;\">" + .id + "</span>\n<span class=\"badge\" style=\"background:" + .status_badge + ";\">" + .status_uc + "</span>\n<span class=\"badge\" style=\"background:" + (if .source_type == "image" then "#1a2a3a;border:1px solid #3b82f6;color:#60a5fa" else "#152a1f;border:1px solid #10b981;color:#4ade80" end) + ";font-size:0.7em;\">" + (if .source_type == "image" then "📦 Container Image" else "💻 App Code" end) + "</span>\n</div>
<div class=\"finding-title\">" + .pkg + "@" + .installed + " - " + .title + "</div>
<div class=\"finding-desc\">" + .desc_short + "...</div>
<div class=\"finding-details\" style=\"display:none;\">
<div class=\"detail-section\"><h5>Vulnerability Info</h5>
<div><strong>CVE ID:</strong> <code>" + .id + "</code> <a href=\"" + .primary_url + "\" target=\"_blank\" style=\"color:#C41E3A;\">View Details</a></div>
<div><strong>CWE IDs:</strong> <code>" + .cwes + "</code></div>
<div><strong>Data Source:</strong> " + .data_source + "</div>
<div><strong>Published:</strong> " + .published + "</div>
<div><strong>Last Modified:</strong> " + .modified + "</div>
</div>
<div class=\"detail-section\"><h5>Package Info</h5>
<div><strong>Package:</strong> <code>" + .pkg + "</code></div>
<div><strong>Type:</strong> <code>" + .pkg_type + "</code></div>
<div><strong>Installed:</strong> <code>" + .installed + "</code></div>
<div><strong>Fixed Version:</strong> <code style=\"" + .fixed_style + "\">" + .fixed + "</code></div>
<div><strong>Status:</strong> <span style=\"font-weight:600;color:" + .status_color + ";\">" + .status_uc + "</span></div>
<div><strong>PURL:</strong> <code style=\"font-size:0.8em;word-break:break-all;\">" + .purl + "</code></div>
</div>
<!--REMEDIATION_MARKER:" + .id + ":" + .pkg + "-->
<div class=\"detail-section\"><h5>False Positive Assessment</h5>
<div class=\"fp-checklist\">
<label><input type=\"checkbox\" class=\"fp-check\"> Package not used in production</label>
<label><input type=\"checkbox\" class=\"fp-check\"> Vulnerable code path not reachable</label>
<label><input type=\"checkbox\" class=\"fp-check\"> Compensating controls in place</label>
<label><input type=\"checkbox\" class=\"fp-check\"> Risk accepted per security policy</label>
</div>
<div style=\"margin-top:10px;\"><strong>Target:</strong> <code>" + .target + "</code></div>
</div>
<div class=\"detail-section\"><h5>Description</h5>
<div style=\"background:#f7fafc;padding:12px;border-radius:6px;font-size:0.9em;line-height:1.6;\">" + .desc + "</div>
</div>
</div>
</div>"
            ' 2>/dev/null)
            set -e
            
            if [ -n "$vuln_details" ]; then
                # Process remediation markers
                processed_details=""
                while IFS= read -r line; do
                    if [[ "$line" =~ \<!--REMEDIATION_MARKER:([^:]+):([^-]+)--\> ]]; then
                        cve="${BASH_REMATCH[1]}"
                        pkg="${BASH_REMATCH[2]}"
                        processed_details="${processed_details}$(inject_remediation "$cve" "$pkg")
"
                    else
                        processed_details="${processed_details}${line}
"
                    fi
                done <<< "$vuln_details"
                
                TRIVY_DETAILS="${TRIVY_DETAILS}${processed_details}"
            fi
        fi
    done
    TRIVY_TOTAL_VULNS=$((TRIVY_CRITICAL + TRIVY_HIGH + TRIVY_MEDIUM + TRIVY_LOW))
    
    if [ "$TRIVY_TOTAL_VULNS" -gt 0 ]; then
        TRIVY_FINDINGS="<div class=\"finding-summary\">
            <span class=\"badge badge-critical\">$TRIVY_CRITICAL Critical</span>
            <span class=\"badge badge-high\">$TRIVY_HIGH High</span>
            <span class=\"badge badge-medium\">$TRIVY_MEDIUM Medium</span>
            <span class=\"badge badge-low\">$TRIVY_LOW Low</span>
        </div>
        <div class=\"trivy-controls\" style=\"margin-bottom:20px;\">
            <div style=\"display:flex;gap:10px;flex-wrap:wrap;align-items:center;\">
                <span style=\"font-weight:600;color:#4a5568;\">Filter by Status:</span>
                <button class=\"filter-chip filter-chip-all active\" onclick=\"filterTrivyByStatus('all')\">All</button>
                <button class=\"filter-chip\" style=\"background:#c6f6d5;color:#2f855a;\" onclick=\"filterTrivyByStatus('fixed')\">🔧 Has Fix</button>
                <button class=\"filter-chip\" style=\"background:#fed7d7;color:#c53030;\" onclick=\"filterTrivyByStatus('affected')\">⚠️ No Fix</button>
            </div>
            <div style=\"margin-top:10px;\">
                <input type=\"text\" id=\"trivy-search\" placeholder=\"🔍 Search by CVE, package name, or description...\" 
                    onkeyup=\"filterTrivyBySearch(this.value)\" 
                    style=\"width:100%;padding:10px 15px;border:2px solid #e2e8f0;border-radius:8px;font-size:0.95em;\">
            </div>
        </div>
        <p style=\"color:#718096;margin-bottom:15px;font-size:0.9em;\">
            💡 <strong>Tip:</strong> Click any finding to expand details. Use the checkboxes to track false positive assessments. 
            Green \"FIXED\" status means a patched version is available.
        </p>
        ${TRIVY_DETAILS}"
    else
        TRIVY_FINDINGS="<p class=\"no-findings\">✅ No vulnerabilities detected in container images</p>"
    fi
else
    TRIVY_FINDINGS="<p class=\"no-findings\">No Trivy scan data available</p>"
fi

# ---- Grype Statistics ----
GRYPE_DIR="${LATEST_SCAN}/grype"
GRYPE_TARGETS_SCANNED=0
GRYPE_TOTAL_VULNS=0
GRYPE_CRITICAL=0
GRYPE_HIGH=0
GRYPE_MEDIUM=0
GRYPE_LOW=0
GRYPE_FINDINGS=""
GRYPE_DETAILS=""
if [ -d "$GRYPE_DIR" ]; then
    GRYPE_TARGETS_SCANNED=$(find "$GRYPE_DIR" -name "*.json" -type f ! -name "*.log" 2>/dev/null | wc -l | tr -d ' \n' || echo "0")
    [[ "$GRYPE_TARGETS_SCANNED" =~ ^[0-9]+$ ]] || GRYPE_TARGETS_SCANNED=0
    
    for grype_file in "$GRYPE_DIR"/*.json; do
        # Skip symlinks to avoid double counting
        if [ -f "$grype_file" ] && [ ! -L "$grype_file" ]; then
            crit_count=$(jq '[.matches[]? | select(.vulnerability.severity=="Critical")] | length' "$grype_file" 2>/dev/null || echo "0")
            high_count=$(jq '[.matches[]? | select(.vulnerability.severity=="High")] | length' "$grype_file" 2>/dev/null || echo "0")
            med_count=$(jq '[.matches[]? | select(.vulnerability.severity=="Medium")] | length' "$grype_file" 2>/dev/null || echo "0")
            low_count=$(jq '[.matches[]? | select(.vulnerability.severity=="Low")] | length' "$grype_file" 2>/dev/null || echo "0")
            
            # Ensure numeric
            [[ "$crit_count" =~ ^[0-9]+$ ]] || crit_count=0
            [[ "$high_count" =~ ^[0-9]+$ ]] || high_count=0
            [[ "$med_count" =~ ^[0-9]+$ ]] || med_count=0
            [[ "$low_count" =~ ^[0-9]+$ ]] || low_count=0
            
            GRYPE_CRITICAL=$((GRYPE_CRITICAL + crit_count))
            GRYPE_HIGH=$((GRYPE_HIGH + high_count))
            GRYPE_MEDIUM=$((GRYPE_MEDIUM + med_count))
            GRYPE_LOW=$((GRYPE_LOW + low_count))
            
            # Extract individual vulnerability details for ALL severity levels (limit to top 50 per file)
            set +e
            vuln_details=$(jq -r '
                (.source.type // "unknown") as $scan_type |
                [.matches[]? | 
                 {id: .vulnerability.id, pkg: .artifact.name, version: .artifact.version, 
                  severity: .vulnerability.severity, 
                  fixed: (.vulnerability.fix.versions[0] // "Not fixed"),
                  desc: (.vulnerability.description // "No description available"),
                  pkg_type: (.artifact.type // "unknown"),
                  source_type: (if $scan_type == "image" then "image" elif (.artifact.type // "" | test("(deb|apk|rpm|alpm|portage|photon)"; "i")) then "image" else "app" end)}
                ] | sort_by(.severity | if . == "Critical" then 0 elif . == "High" then 1 elif . == "Medium" then 2 else 3 end) | .[0:50] | .[] |
                "<div class=\"finding-item severity-\(.severity | ascii_downcase)\" data-source=\"\(.source_type)\" onclick=\"toggleFindingDetails(this)\">
                    <div class=\"finding-header\">
                        <span class=\"badge badge-tool\">Grype</span>
                        <span class=\"badge badge-\(.severity | ascii_downcase)\">\(.severity)</span>
                        <span class=\"badge\" style=\"background:#2C3539;color:#9ca3af;border:1px solid #4a5568;\">\(.id)</span>
                        <span class=\"badge\" style=\"background:\(if .source_type == "image" then "#1a2a3a;border:1px solid #3b82f6;color:#60a5fa" else "#152a1f;border:1px solid #10b981;color:#4ade80" end);font-size:0.7em;\">\(if .source_type == "image" then "📦 Container Image" else "💻 App Code" end)</span>
                    </div>
                    <div class=\"finding-title\">\(.pkg)@\(.version)</div>
                    <div class=\"finding-desc\">\(.desc | .[0:200])...</div>
                    <div class=\"finding-details\" style=\"display:none;\">
                        <div><strong>CVE ID:</strong> <code>\(.id)</code></div>
                        <div><strong>Package:</strong> <code>\(.pkg)</code></div>
                        <div><strong>Package Type:</strong> <code>\(.pkg_type)</code></div>
                        <div><strong>Source:</strong> \(if .source_type == "image" then "📦 Container Image (bundled in base image)" else "💻 Application Code" end)</div>
                        <div><strong>Installed Version:</strong> <code>\(.version)</code></div>
                        <div><strong>Fixed Version:</strong> <code>\(.fixed)</code></div>
                        <div><strong>Full Description:</strong> \(.desc)</div>
                        <!--REMEDIATION_MARKER:\(.id):\(.pkg)-->
                    </div>
                </div>"
            ' "$grype_file" 2>/dev/null)
            set -e
            
            if [ -n "$vuln_details" ]; then
                # Process remediation markers
                processed_details=""
                while IFS= read -r line; do
                    if [[ "$line" =~ \<!--REMEDIATION_MARKER:([^:]+):([^-]+)--\> ]]; then
                        cve="${BASH_REMATCH[1]}"
                        pkg="${BASH_REMATCH[2]}"
                        remediation_html=$(inject_remediation "$cve" "$pkg")
                        processed_details+="$remediation_html
"
                    else
                        processed_details+="$line
"
                    fi
                done <<< "$vuln_details"
                
                GRYPE_DETAILS="${GRYPE_DETAILS}${processed_details}"
            fi
        fi
    done
    GRYPE_TOTAL_VULNS=$((GRYPE_CRITICAL + GRYPE_HIGH + GRYPE_MEDIUM + GRYPE_LOW))
    
    if [ "$GRYPE_TOTAL_VULNS" -gt 0 ]; then
        GRYPE_FINDINGS="<div class=\"finding-summary\">
            <span class=\"badge badge-critical\">$GRYPE_CRITICAL Critical</span>
            <span class=\"badge badge-high\">$GRYPE_HIGH High</span>
            <span class=\"badge badge-medium\">$GRYPE_MEDIUM Medium</span>
            <span class=\"badge badge-low\">$GRYPE_LOW Low</span>
        </div>
        <p style=\"color:#718096;margin-bottom:15px;font-size:0.9em;\">👆 Click on any finding below to expand details (showing up to 50 per target)</p>
        ${GRYPE_DETAILS}"
    else
        GRYPE_FINDINGS="<p class=\"no-findings\">✅ No vulnerabilities detected</p>"
    fi
else
    GRYPE_FINDINGS="<p class=\"no-findings\">No Grype scan data available</p>"
fi

# ---- SBOM Statistics ----
SBOM_DIR="${LATEST_SCAN}/sbom"
SBOM_PACKAGES=0
SBOM_FILES_GENERATED=0
SBOM_PACKAGE_TYPES=""
SBOM_FINDINGS=""
if [ -d "$SBOM_DIR" ]; then
    SBOM_FILES_GENERATED=$(find "$SBOM_DIR" -name "*.json" -type f 2>/dev/null | wc -l | tr -d ' \n' || echo "0")
    [[ "$SBOM_FILES_GENERATED" =~ ^[0-9]+$ ]] || SBOM_FILES_GENERATED=0
    
    # Collect all packages from SBOM files
    SBOM_ALL_PACKAGES=""
    for sbom_file in "$SBOM_DIR"/*.json; do
        if [ -f "$sbom_file" ]; then
            pkg_count=$(jq '.artifacts | length' "$sbom_file" 2>/dev/null || echo "0")
            [[ "$pkg_count" =~ ^[0-9]+$ ]] || pkg_count=0
            SBOM_PACKAGES=$((SBOM_PACKAGES + pkg_count))
            
            # Get package types summary
            if [ "$pkg_count" -gt 0 ]; then
                SBOM_PACKAGE_TYPES=$(jq -r '.artifacts[].type' "$sbom_file" 2>/dev/null | sort | uniq -c | sort -rn | head -10)
            fi
        fi
    done
    
    # Generate SBOM findings HTML with package details
    if [ "$SBOM_PACKAGES" -gt 0 ]; then
        # Find the main SBOM file with packages
        for sbom_file in "$SBOM_DIR"/*.json; do
            if [ -f "$sbom_file" ]; then
                pkg_count=$(jq '.artifacts | length' "$sbom_file" 2>/dev/null || echo "0")
                if [ "$pkg_count" -gt 0 ]; then
                    # Generate package type breakdown with clickable filter chips
                    SBOM_TYPE_BREAKDOWN=$(jq -r '[.artifacts[].type] | group_by(.) | map({type: .[0], count: length}) | sort_by(-.count) | .[:15] | map("<button class=\"sbom-filter-chip\" data-type=\"\(.type)\" onclick=\"filterSBOMByType(this, '"'"'\(.type)'"'"')\"><span class=\"type-name\">\(.type)</span><span class=\"type-count\">\(.count)</span></button>") | join("")' "$sbom_file" 2>/dev/null)
                    
                    # Generate package list (first 500 packages) with data attributes for filtering/sorting
                    SBOM_PACKAGE_LIST=$(jq -r '.artifacts | sort_by(.type) | .[:500] | map("<div class=\"sbom-package-item\" data-name=\"\(.name | ascii_downcase)\" data-type=\"\(.type // "unknown")\" data-version=\"\(.version // "0.0.0")\" data-language=\"\(.language // "unknown")\" onclick=\"toggleFindingDetails(this)\">
                        <div class=\"finding-header\">
                            <span class=\"badge badge-tool\">\(.type // "unknown")</span>
                            <span class=\"badge sbom-version-badge\">\(.version // "N/A")</span>
                            <span class=\"badge sbom-lang-badge\">\(.language // "")</span>
                        </div>
                        <div class=\"finding-title\">\(.name)</div>
                        <div class=\"finding-details\" style=\"display: none;\">
                            <div><strong>Name:</strong> <code>\(.name)</code></div>
                            <div><strong>Version:</strong> <code>\(.version // "N/A")</code></div>
                            <div><strong>Type:</strong> <code>\(.type // "unknown")</code></div>
                            <div><strong>Language:</strong> <code>\(.language // "N/A")</code></div>
                            <div><strong>Licenses:</strong> <code>\(((.licenses // []) | map(.value // .spdxExpression // "Unknown") | join(", ")) // "Not specified")</code></div>
                            <div><strong>PURL:</strong> <code>\(.purl // "N/A")</code></div>
                            <div><strong>CPEs:</strong> <code>\(((.cpes // []) | map(.cpe // .) | .[0:3] | join(", ")) // "N/A")</code></div>
                        </div>
                    </div>") | join("\n")' "$sbom_file" 2>/dev/null)
                    
                    SBOM_FINDINGS="<div class=\"sbom-controls\">
                        <div class=\"sbom-filter-section\">
                            <span class=\"filter-label\">🔍 Filter by Type:</span>
                            <div class=\"sbom-filter-chips\">
                                <button class=\"sbom-filter-chip active\" data-type=\"all\" onclick=\"filterSBOMByType(this, 'all')\">
                                    <span class=\"type-name\">All</span>
                                    <span class=\"type-count\">${SBOM_PACKAGES}</span>
                                </button>
                                ${SBOM_TYPE_BREAKDOWN}
                            </div>
                        </div>
                        <div class=\"sbom-sort-section\">
                            <span class=\"filter-label\">⇅ Sort by:</span>
                            <div class=\"sbom-sort-buttons\">
                                <button class=\"sbom-sort-btn active\" onclick=\"sortSBOMPackages('name')\" id=\"sbom-sort-name\">📝 Name</button>
                                <button class=\"sbom-sort-btn\" onclick=\"sortSBOMPackages('type')\" id=\"sbom-sort-type\">📦 Type</button>
                                <button class=\"sbom-sort-btn\" onclick=\"sortSBOMPackages('version')\" id=\"sbom-sort-version\">🏷️ Version</button>
                            </div>
                        </div>
                        <div class=\"sbom-search-box\">
                            <input type=\"text\" id=\"sbom-search\" placeholder=\"🔍 Search packages by name, type, or version...\" onkeyup=\"filterSBOMPackages(this.value)\">
                        </div>
                    </div>
                    <div class=\"sbom-results-bar\" id=\"sbom-results-bar\">
                        <span id=\"sbom-results-count\">Showing ${SBOM_PACKAGES} packages</span>
                        <a class=\"clear-filter\" onclick=\"resetSBOMFilters()\" style=\"display: none;\" id=\"sbom-clear-filter\">Clear Filters ✕</a>
                    </div>
                    <div class=\"sbom-package-list\" id=\"sbom-package-list\">
                        ${SBOM_PACKAGE_LIST}
                    </div>
                    <p style=\"text-align: center; color: #718096; margin-top: 15px;\">Showing first 500 of ${SBOM_PACKAGES} total packages</p>"
                    break
                fi
            fi
        done
    fi
    
    if [ -z "$SBOM_FINDINGS" ]; then
        SBOM_FINDINGS="<p class=\"no-findings\">✅ No packages cataloged in SBOM</p>"
    fi
else
    SBOM_FINDINGS="<p class=\"no-findings\">No SBOM data available</p>"
fi

# ---- Checkov Statistics ----
CHECKOV_DIR="${LATEST_SCAN}/checkov"
CHECKOV_PASSED=0
CHECKOV_FAILED=0
CHECKOV_SKIPPED=0
CHECKOV_FILES_SCANNED=0
CHECKOV_CHECK_TYPES=""
if [ -d "$CHECKOV_DIR" ]; then
    for checkov_file in "$CHECKOV_DIR"/*.json; do
        # Skip symlinks to avoid duplicate processing
        if [ -f "$checkov_file" ] && [ ! -L "$checkov_file" ] && [[ "$(basename "$checkov_file")" != *"summary"* ]]; then
            # Checkov output is an array - iterate through all check types
            # First element [0] is summary, subsequent elements contain results by check type
            
            # Sum up all passed/failed/skipped from all check types
            passed=$(jq '[.[] | select(.results?) | .results.passed_checks | length] | add // 0' "$checkov_file" 2>/dev/null || echo "0")
            failed=$(jq '[.[] | select(.results?) | .results.failed_checks | length] | add // 0' "$checkov_file" 2>/dev/null || echo "0")
            skipped=$(jq '[.[] | select(.results?) | .results.skipped_checks | length] | add // 0' "$checkov_file" 2>/dev/null || echo "0")
            
            # Get check types scanned
            check_types=$(jq -r '[.[] | select(.check_type?) | .check_type] | unique | join(", ")' "$checkov_file" 2>/dev/null || echo "")
            
            [[ "$passed" =~ ^[0-9]+$ ]] || passed=0
            [[ "$failed" =~ ^[0-9]+$ ]] || failed=0
            [[ "$skipped" =~ ^[0-9]+$ ]] || skipped=0
            
            CHECKOV_PASSED=$((CHECKOV_PASSED + passed))
            CHECKOV_FAILED=$((CHECKOV_FAILED + failed))
            CHECKOV_SKIPPED=$((CHECKOV_SKIPPED + skipped))
            CHECKOV_CHECK_TYPES="$check_types"
        fi
    done
fi
# Note: Checkov failed checks are IaC misconfigurations, NOT vulnerability criticals
# They should be counted as HIGH priority issues, not CRITICAL vulnerabilities
CHECKOV_CRITICAL=0
CHECKOV_HIGH=$CHECKOV_FAILED
CHECKOV_TOTAL=$((CHECKOV_PASSED + CHECKOV_FAILED + CHECKOV_SKIPPED))

# Read Checkov statistics file for detailed info
CHECKOV_STATS_FILE="$CHECKOV_DIR/checkov-statistics.json"
CHECKOV_FILES_SCANNED=0
CHECKOV_YAML_COUNT=0
CHECKOV_TF_COUNT=0
CHECKOV_DOCKER_COUNT=0
CHECKOV_JSON_COUNT=0
CHECKOV_HELM_COUNT=0
CHECKOV_SCAN_DURATION="N/A"
if [ -f "$CHECKOV_STATS_FILE" ]; then
    CHECKOV_FILES_SCANNED=$(jq -r '.files_scanned // 0' "$CHECKOV_STATS_FILE" 2>/dev/null || echo "0")
    CHECKOV_YAML_COUNT=$(jq -r '.yaml_count // 0' "$CHECKOV_STATS_FILE" 2>/dev/null || echo "0")
    CHECKOV_TF_COUNT=$(jq -r '.terraform_count // 0' "$CHECKOV_STATS_FILE" 2>/dev/null || echo "0")
    CHECKOV_DOCKER_COUNT=$(jq -r '.dockerfile_count // 0' "$CHECKOV_STATS_FILE" 2>/dev/null || echo "0")
    CHECKOV_JSON_COUNT=$(jq -r '.json_count // 0' "$CHECKOV_STATS_FILE" 2>/dev/null || echo "0")
    CHECKOV_HELM_COUNT=$(jq -r '.helm_count // 0' "$CHECKOV_STATS_FILE" 2>/dev/null || echo "0")
    CHECKOV_SCAN_DURATION=$(jq -r '.scan_duration // "N/A"' "$CHECKOV_STATS_FILE" 2>/dev/null || echo "N/A")
fi

# Build Checkov findings display
if [ "$CHECKOV_TOTAL" -gt 0 ]; then
    CHECKOV_FINDINGS="<div class=\"stats-grid-small\">
        <div class=\"stat-item\"><strong>✅ Passed:</strong> ${CHECKOV_PASSED}</div>
        <div class=\"stat-item\"><strong>❌ Failed:</strong> ${CHECKOV_FAILED}</div>
        <div class=\"stat-item\"><strong>⏭️ Skipped:</strong> ${CHECKOV_SKIPPED}</div>
        <div class=\"stat-item\"><strong>📊 Total Checks:</strong> ${CHECKOV_TOTAL}</div>
        <div class=\"stat-item\"><strong>📁 Files Scanned:</strong> ${CHECKOV_FILES_SCANNED}</div>
        <div class=\"stat-item\"><strong>⏱️ Scan Duration:</strong> ${CHECKOV_SCAN_DURATION}s</div>
    </div>"
    if [ "$CHECKOV_FILES_SCANNED" -gt 0 ]; then
        CHECKOV_FINDINGS="${CHECKOV_FINDINGS}<div style='margin-top:10px;padding:10px;background:#e0f2fe;border-left:3px solid #0369a1;'>"
        CHECKOV_FINDINGS="${CHECKOV_FINDINGS}<strong>File Type Breakdown:</strong><br/>"
        CHECKOV_FINDINGS="${CHECKOV_FINDINGS}📄 YAML/YML: ${CHECKOV_YAML_COUNT} | 🏗️ Terraform: ${CHECKOV_TF_COUNT} | 🐳 Dockerfiles: ${CHECKOV_DOCKER_COUNT} | 📋 JSON: ${CHECKOV_JSON_COUNT} | ⎈ Helm: ${CHECKOV_HELM_COUNT}"
        CHECKOV_FINDINGS="${CHECKOV_FINDINGS}</div>"
    fi
    if [ -n "$CHECKOV_CHECK_TYPES" ]; then
        CHECKOV_FINDINGS="${CHECKOV_FINDINGS}<p style=\"margin-top: 10px; color: #718096;\">Frameworks: ${CHECKOV_CHECK_TYPES}</p>"
    fi
    
    # Add failed checks details if any failures exist
    if [ "$CHECKOV_FAILED" -gt 0 ]; then
        CHECKOV_FINDINGS="${CHECKOV_FINDINGS}<div class=\"findings-section\" style=\"margin-top: 15px;\">
            <h4 style=\"color: #dd6b20; margin-bottom: 10px;\">⚠️ Failed IaC Checks (${CHECKOV_FAILED})</h4>
            <p style=\"color:#718096;margin-bottom:15px;font-size:0.9em;\">👆 Click on any finding below to expand details. These are IaC/Dockerfile misconfigurations, not vulnerabilities.</p>"
        
        # Extract failed checks from all Checkov JSON files
        for checkov_file in "$CHECKOV_DIR"/*.json; do
            # Skip symlinks to avoid duplicate processing
            if [ -f "$checkov_file" ] && [ ! -L "$checkov_file" ] && [[ "$(basename "$checkov_file")" != *"summary"* ]]; then
                # Get failed checks as TSV for easy parsing
                while IFS=$'\t' read -r check_id check_name file_path line_start guideline; do
                    if [ -n "$check_id" ]; then
                        # Escape HTML entities
                        check_name_escaped=$(echo "$check_name" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g')
                        file_display=$(basename "$file_path" 2>/dev/null || echo "$file_path")
                        guideline_escaped=$(echo "$guideline" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g')
                        CHECKOV_FINDINGS="${CHECKOV_FINDINGS}
<div class=\"finding-item severity-high\" data-source=\"app\" onclick=\"toggleFindingDetails(this)\">
    <div class=\"finding-header\">
        <span class=\"badge badge-tool\">Checkov</span>
        <span class=\"badge badge-high\">HIGH</span>
        <span class=\"badge\" style=\"background:#2C3539;color:#9ca3af;border:1px solid #4a5568;\">${check_id}</span>
        <span class=\"badge\" style=\"background:#152a1f;color:#4ade80;font-size:0.7em;border:1px solid #10b981;\">💻 App Code</span>
    </div>
    <div class=\"finding-title\">${check_name_escaped}</div>
    <div class=\"finding-desc\">IaC misconfiguration in ${file_display} at line ${line_start}</div>
    <div class=\"finding-details\" style=\"display:none;\">
        <div><strong>Check ID:</strong> <code>${check_id}</code></div>
        <div><strong>Check Name:</strong> ${check_name_escaped}</div>
        <div><strong>Source:</strong> 💻 Application Code (IaC/Dockerfile configuration)</div>
        <div><strong>File:</strong> <code>${file_display}</code></div>
        <div><strong>Full Path:</strong> <code style=\"font-size:0.8em;word-break:break-all;\">${file_path}</code></div>
        <div><strong>Line:</strong> ${line_start}</div>
        <div><strong>Guideline:</strong> ${guideline_escaped:-No guideline available}</div>
    </div>
</div>"
                    fi
                done < <(jq -r '[.[] | select(.results?) | .results.failed_checks[]] | .[] | [.check_id, .check_name, .file_path, (.file_line_range[0] // "N/A" | tostring), (.guideline // "")] | @tsv' "$checkov_file" 2>/dev/null)
            fi
        done
        
        CHECKOV_FINDINGS="${CHECKOV_FINDINGS}
        </div>"
    fi
else
    CHECKOV_FINDINGS="<p class=\"no-findings\">No Checkov results available</p>"
fi

# ---- SonarQube Statistics ----
SONAR_DIR="${LATEST_SCAN}/sonar"
LATEST_SONAR=$(find "$SONAR_DIR" -name "*_sonar-analysis-results.json" -type f 2>/dev/null | sort -r | head -n 1 || echo "")
SONAR_STATUS="N/A"
SONAR_BUGS=0
SONAR_VULNS=0
SONAR_CODE_SMELLS=0
SONAR_COVERAGE="N/A"
SONAR_TOTAL_TESTS=0
SONAR_PASSED_TESTS=0
SONAR_FAILED_TESTS=0
SONAR_SKIPPED_TESTS=0
SONAR_HOST_URL="N/A"
SONAR_PROJECT_KEY="N/A"
SONAR_PROJECT_URL=""

if [ -f "$LATEST_SONAR" ]; then
    SONAR_STATUS=$(jq -r '.status // "NO_DATA"' "$LATEST_SONAR" 2>/dev/null || echo "NO_DATA")
    SONAR_TOTAL_TESTS=$(jq -r '.test_results.total_tests // 0' "$LATEST_SONAR" 2>/dev/null || echo "0")
    SONAR_PASSED_TESTS=$(jq -r '.test_results.passed_tests // 0' "$LATEST_SONAR" 2>/dev/null || echo "0")
    SONAR_FAILED_TESTS=$(jq -r '.test_results.failed_tests // 0' "$LATEST_SONAR" 2>/dev/null || echo "0")
    SONAR_SKIPPED_TESTS=$(jq -r '.test_results.skipped_tests // 0' "$LATEST_SONAR" 2>/dev/null || echo "0")
    SONAR_COVERAGE=$(jq -r '.coverage.statement_coverage // "N/A"' "$LATEST_SONAR" 2>/dev/null || echo "N/A")
    SONAR_HOST_URL=$(jq -r '.host // "N/A"' "$LATEST_SONAR" 2>/dev/null || echo "N/A")
    SONAR_PROJECT_KEY=$(jq -r '.project // "N/A"' "$LATEST_SONAR" 2>/dev/null || echo "N/A")
    
    # Generate project dashboard URL
    if [ "$SONAR_HOST_URL" != "N/A" ] && [ "$SONAR_PROJECT_KEY" != "N/A" ]; then
        SONAR_PROJECT_URL="${SONAR_HOST_URL}/dashboard?id=${SONAR_PROJECT_KEY}"
    fi
    
    if [ "$SONAR_STATUS" = "NO_PROJECT_DETECTED" ]; then
        SONAR_FINDINGS="<p class=\"no-findings\">No SonarQube project detected</p>"
        SONAR_CRITICAL=0
        SONAR_HIGH=0
    else
        SONAR_FINDINGS="<div class=\"stats-detail-box\" style=\"background:linear-gradient(135deg, #1a1d23 0%, #2C3539 100%);border:2px solid #3b82f6;box-shadow:0 4px 12px rgba(59, 130, 246, 0.3);\">"
        SONAR_FINDINGS="${SONAR_FINDINGS}<h4 style=\"color:#0369a1;margin-bottom:10px;\">📊 Test Summary</h4>"
        SONAR_FINDINGS="${SONAR_FINDINGS}<div class=\"stats-grid-small\">"
        SONAR_FINDINGS="${SONAR_FINDINGS}<div class=\"stat-item\"><strong>Total Tests:</strong> ${SONAR_TOTAL_TESTS}</div>"
        SONAR_FINDINGS="${SONAR_FINDINGS}<div class=\"stat-item\"><strong>✅ Passed:</strong> ${SONAR_PASSED_TESTS}</div>"
        SONAR_FINDINGS="${SONAR_FINDINGS}<div class=\"stat-item\"><strong>❌ Failed:</strong> ${SONAR_FAILED_TESTS}</div>"
        SONAR_FINDINGS="${SONAR_FINDINGS}<div class=\"stat-item\"><strong>⏭️ Skipped:</strong> ${SONAR_SKIPPED_TESTS}</div>"
        SONAR_FINDINGS="${SONAR_FINDINGS}<div class=\"stat-item\"><strong>📈 Coverage:</strong> ${SONAR_COVERAGE}</div>"
        SONAR_FINDINGS="${SONAR_FINDINGS}<div class=\"stat-item\"><strong>🎯 Status:</strong> ${SONAR_STATUS}</div>"
        SONAR_FINDINGS="${SONAR_FINDINGS}</div>"
        if [ -n "$SONAR_PROJECT_URL" ]; then
            SONAR_FINDINGS="${SONAR_FINDINGS}<div style=\"margin-top:15px;padding:10px;background:white;border-radius:4px;\">"
            SONAR_FINDINGS="${SONAR_FINDINGS}<strong>🔗 Project Dashboard:</strong><br/>"
            SONAR_FINDINGS="${SONAR_FINDINGS}<a href=\"${SONAR_PROJECT_URL}\" target=\"_blank\" style=\"color:#0369a1;text-decoration:underline;word-break:break-all;\">${SONAR_PROJECT_URL}</a>"
            SONAR_FINDINGS="${SONAR_FINDINGS}</div>"
        fi
        SONAR_FINDINGS="${SONAR_FINDINGS}</div>"
        SONAR_FINDINGS="${SONAR_FINDINGS}<p class=\"no-findings\" style=\"margin-top:10px;\">✅ SonarQube analysis complete</p>"
        SONAR_CRITICAL=0
        SONAR_HIGH=0
    fi
else
    SONAR_CRITICAL=0
    SONAR_HIGH=0
    SONAR_FINDINGS="<p class=\"no-findings\">No SonarQube data available</p>"
fi

# ---- Helm Statistics ----
HELM_DIR="${LATEST_SCAN}/helm"
HELM_CHARTS_SCANNED=0
HELM_CHARTS_BUILT=0
HELM_LINT_ERRORS=0
HELM_LINT_WARNINGS=0
if [ -d "$HELM_DIR" ]; then
    # First try to read from structured JSON results file
    HELM_RESULTS_JSON="$HELM_DIR/helm-build-results.json"
    if [ -f "$HELM_RESULTS_JSON" ]; then
        HELM_CHARTS_SCANNED=$(jq -r '.charts_found // 0' "$HELM_RESULTS_JSON" 2>/dev/null || echo "0")
        HELM_CHARTS_BUILT=$(jq -r '.charts_built // 0' "$HELM_RESULTS_JSON" 2>/dev/null || echo "0")
        HELM_LINT_ERRORS=$(jq -r '.lint_issues // 0' "$HELM_RESULTS_JSON" 2>/dev/null || echo "0")
        HELM_LINT_WARNINGS=$(jq -r '.lint_warnings // 0' "$HELM_RESULTS_JSON" 2>/dev/null || echo "0")
        [[ "$HELM_CHARTS_SCANNED" =~ ^[0-9]+$ ]] || HELM_CHARTS_SCANNED=0
        [[ "$HELM_CHARTS_BUILT" =~ ^[0-9]+$ ]] || HELM_CHARTS_BUILT=0
        [[ "$HELM_LINT_ERRORS" =~ ^[0-9]+$ ]] || HELM_LINT_ERRORS=0
        [[ "$HELM_LINT_WARNINGS" =~ ^[0-9]+$ ]] || HELM_LINT_WARNINGS=0
    else
        # Fallback: Count built charts (.tgz files)
        HELM_CHARTS_BUILT=$(find "$HELM_DIR" -name "*.tgz" -type f 2>/dev/null | wc -l | tr -d ' \n' || echo "0")
        [[ "$HELM_CHARTS_BUILT" =~ ^[0-9]+$ ]] || HELM_CHARTS_BUILT=0
        
        # Fallback: Parse helm lint log for errors/warnings
        HELM_LINT_LOG=$(find "$HELM_DIR" -name "*lint*.log" -type f 2>/dev/null | head -1)
        if [ -f "$HELM_LINT_LOG" ]; then
            HELM_LINT_ERRORS=$(grep -ci "error" "$HELM_LINT_LOG" 2>/dev/null || echo "0")
            HELM_LINT_WARNINGS=$(grep -ci "warning" "$HELM_LINT_LOG" 2>/dev/null || echo "0")
            [[ "$HELM_LINT_ERRORS" =~ ^[0-9]+$ ]] || HELM_LINT_ERRORS=0
            [[ "$HELM_LINT_WARNINGS" =~ ^[0-9]+$ ]] || HELM_LINT_WARNINGS=0
        fi
        
        # Fallback: Count charts found (from log or yaml files)
        HELM_BUILD_LOG=$(find "$HELM_DIR" -name "*build*.log" -o -name "*.log" -type f 2>/dev/null | head -1)
        if [ -f "$HELM_BUILD_LOG" ]; then
            HELM_CHARTS_SCANNED=$(grep -c "Found Helm chart" "$HELM_BUILD_LOG" 2>/dev/null || echo "0")
            [[ "$HELM_CHARTS_SCANNED" =~ ^[0-9]+$ ]] || HELM_CHARTS_SCANNED=0
        fi
        
        # Fallback: If no log found, count by template yamls
        if [ "$HELM_CHARTS_SCANNED" -eq 0 ]; then
            HELM_CHARTS_SCANNED=$(find "$HELM_DIR" -name "*-template-output.yaml" -type f 2>/dev/null | wc -l | tr -d ' \n' || echo "0")
            [[ "$HELM_CHARTS_SCANNED" =~ ^[0-9]+$ ]] || HELM_CHARTS_SCANNED=0
        fi
    fi
fi
HELM_CRITICAL=$HELM_LINT_ERRORS
HELM_HIGH=$HELM_LINT_WARNINGS

# Build Helm findings display
if [ "$HELM_CHARTS_SCANNED" -gt 0 ] || [ "$HELM_CHARTS_BUILT" -gt 0 ]; then
    HELM_FINDINGS="<div class=\"stats-grid-small\">
        <div class=\"stat-item\"><strong>📦 Charts Found:</strong> ${HELM_CHARTS_SCANNED}</div>
        <div class=\"stat-item\"><strong>🏗️ Charts Built:</strong> ${HELM_CHARTS_BUILT}</div>
        <div class=\"stat-item\"><strong>❌ Lint Errors:</strong> ${HELM_LINT_ERRORS}</div>
        <div class=\"stat-item\"><strong>⚠️ Lint Warnings:</strong> ${HELM_LINT_WARNINGS}</div>
    </div>"
    if [ "$HELM_LINT_ERRORS" -eq 0 ] && [ "$HELM_LINT_WARNINGS" -eq 0 ]; then
        HELM_FINDINGS="${HELM_FINDINGS}<p style=\"margin-top: 10px; color: #38a169;\">✅ All charts passed linting</p>"
    fi
else
    HELM_FINDINGS="<p class=\"no-findings\">No Helm charts found in project</p>"
fi

# ---- Xeol (EOL Detection) Statistics ----
XEOL_DIR="${LATEST_SCAN}/xeol"
XEOL_CRITICAL=0
XEOL_HIGH=0
XEOL_MEDIUM=0
XEOL_LOW=0
XEOL_TOTAL_EOL=0
XEOL_IMAGES_SCANNED=0
XEOL_FILESYSTEM_PATHS=0
XEOL_DB_VERSION="unknown"
XEOL_SCAN_DURATION="N/A"
XEOL_EOL_PACKAGES=""
XEOL_FINDINGS=""

if [ -d "$XEOL_DIR" ]; then
    # Try to read from statistics file first
    XEOL_STATS_FILE="$XEOL_DIR/xeol-statistics.json"
    if [ -f "$XEOL_STATS_FILE" ] && jq empty "$XEOL_STATS_FILE" 2>/dev/null; then
        XEOL_IMAGES_SCANNED=$(jq -r '.base_images_scanned // 0' "$XEOL_STATS_FILE" 2>/dev/null || echo "0")
        XEOL_FILESYSTEM_PATHS=$(jq -r '.filesystem_paths // 0' "$XEOL_STATS_FILE" 2>/dev/null || echo "0")
        XEOL_TOTAL_EOL=$(jq -r '.eol_components_found // 0' "$XEOL_STATS_FILE" 2>/dev/null || echo "0")
        XEOL_DB_VERSION=$(jq -r '.database_version // "unknown"' "$XEOL_STATS_FILE" 2>/dev/null || echo "unknown")
        XEOL_SCAN_DURATION=$(jq -r '.scan_duration // "N/A"' "$XEOL_STATS_FILE" 2>/dev/null || echo "N/A")
        # EOL packages is now a JSON array, convert to readable format
        XEOL_EOL_PACKAGES=$(jq -r '.eol_packages[]? | "\(.name) \(.version)"' "$XEOL_STATS_FILE" 2>/dev/null | head -10 || echo "")
    else
        # Fallback: Count actual JSON files (not symlinks)
        XEOL_IMAGES_SCANNED=$(find "$XEOL_DIR" -name "*xeol-*.json" -type f 2>/dev/null | wc -l | tr -d ' \n' || echo "0")
        [[ "$XEOL_IMAGES_SCANNED" =~ ^[0-9]+$ ]] || XEOL_IMAGES_SCANNED=0
        
        for xeol_file in "$XEOL_DIR"/*xeol-*.json; do
            if [ -f "$xeol_file" ] && [ ! -L "$xeol_file" ]; then
                eol_count=$(jq '.matches | length' "$xeol_file" 2>/dev/null || echo "0")
                [[ "$eol_count" =~ ^[0-9]+$ ]] || eol_count=0
                XEOL_TOTAL_EOL=$((XEOL_TOTAL_EOL + eol_count))
                
                # Collect package names
                if [ "$eol_count" -gt 0 ]; then
                    PKG_LIST=$(jq -r '.matches[]? | "\(.artifact.name) \(.artifact.version)"' "$xeol_file" 2>/dev/null | head -5)
                    XEOL_EOL_PACKAGES="${XEOL_EOL_PACKAGES}${PKG_LIST}\n"
                fi
            fi
        done
    fi
    
    [[ "$XEOL_IMAGES_SCANNED" =~ ^[0-9]+$ ]] || XEOL_IMAGES_SCANNED=0
    [[ "$XEOL_TOTAL_EOL" =~ ^[0-9]+$ ]] || XEOL_TOTAL_EOL=0
    
    # Count by severity (Xeol uses "Cycle" info, treat EOL as High)
    if [ "$XEOL_TOTAL_EOL" -gt 0 ]; then
        XEOL_HIGH=$XEOL_TOTAL_EOL
    fi
    
    # Build detailed findings display with expandable EOL components
    if [ "$XEOL_TOTAL_EOL" -gt 0 ]; then
        XEOL_FINDINGS="<div class=\"findings-section\" style=\"margin-top: 15px;\">
            <h4 style=\"color: #dd6b20; margin-bottom: 10px;\">⚰️ End-of-Life Components (${XEOL_TOTAL_EOL})</h4>
            <p style=\"color:#718096;margin-bottom:15px;font-size:0.9em;\">👆 Click on any finding below to expand details. These components are no longer receiving security updates.</p>"
        
        # Extract detailed EOL findings from all Xeol JSON files
        for xeol_file in "$XEOL_DIR"/*xeol-*.json; do
            if [ -f "$xeol_file" ] && [ ! -L "$xeol_file" ]; then
                # Get source info (image or filesystem)
                SOURCE_TARGET=$(jq -r '.source.target // "unknown"' "$xeol_file" 2>/dev/null || echo "unknown")
                SOURCE_TYPE=$(jq -r '.source.type // "unknown"' "$xeol_file" 2>/dev/null || echo "unknown")
                
                # Determine source badge
                if [[ "$SOURCE_TYPE" == "image" ]] || [[ "$SOURCE_TARGET" == *":"* ]]; then
                    SOURCE_BADGE="📦 Container Image"
                    SOURCE_LABEL="image"
                else
                    SOURCE_BADGE="💻 Filesystem"
                    SOURCE_LABEL="app"
                fi
                
                # Extract each EOL match as TSV for easy parsing
                while IFS=$'\t' read -r pkg_name pkg_version pkg_type eol_date cycle_eol location_path; do
                    if [ -n "$pkg_name" ]; then
                        # Escape HTML entities
                        pkg_name_escaped=$(echo "$pkg_name" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g')
                        pkg_version_escaped=$(echo "$pkg_version" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g')
                        location_escaped=$(echo "$location_path" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g')
                        
                        # Format EOL date
                        if [ "$eol_date" != "null" ] && [ -n "$eol_date" ]; then
                            eol_display="EOL since $eol_date"
                            eol_badge_color="#dc2626"
                        else
                            eol_display="End of Life"
                            eol_badge_color="#ea580c"
                        fi
                        
                        # Create finding item
                        XEOL_FINDINGS="${XEOL_FINDINGS}
<div class=\"finding-item severity-high\" data-source=\"${SOURCE_LABEL}\" onclick=\"toggleFindingDetails(this)\">
    <div class=\"finding-header\">
        <span class=\"badge badge-tool\">Xeol</span>
        <span class=\"badge badge-high\">HIGH</span>
        <span class=\"badge\" style=\"background:${eol_badge_color};color:white;\">⚰️ EOL</span>
        <span class=\"badge\" style=\"background:#152a1f;color:#4ade80;font-size:0.7em;border:1px solid #10b981;\">${SOURCE_BADGE}</span>
    </div>
    <div class=\"finding-title\">${pkg_name_escaped} ${pkg_version_escaped}</div>
    <div class=\"finding-desc\">${eol_display} - No longer receiving security updates</div>
    <div class=\"finding-details\" style=\"display:none;\">
        <div><strong>Package Name:</strong> <code>${pkg_name_escaped}</code></div>
        <div><strong>Version:</strong> <code>${pkg_version_escaped}</code></div>
        <div><strong>Package Type:</strong> ${pkg_type}</div>
        <div><strong>EOL Status:</strong> <span style=\"color:#dc2626;font-weight:bold;\">${eol_display}</span></div>
        <div><strong>Cycle EOL:</strong> ${cycle_eol}</div>
        <div><strong>Source:</strong> ${SOURCE_BADGE}</div>
        <div><strong>Target:</strong> <code style=\"font-size:0.8em;word-break:break-all;\">${SOURCE_TARGET}</code></div>
        <div><strong>Location:</strong> <code style=\"font-size:0.8em;word-break:break-all;\">${location_escaped}</code></div>
        <div style=\"margin-top:10px;padding:10px;background:#fef3c7;border-left:3px solid #f59e0b;\">
            <strong>⚠️ Risk:</strong> This component is End-of-Life and no longer receives security patches or updates. 
            Consider upgrading to a supported version or finding an alternative package.
            <br/><br/>
            <strong>📚 Resources:</strong><br/>
            • Check <a href=\"https://endoflife.date/${pkg_name_escaped}\" target=\"_blank\" style=\"color:#0369a1;\">endoflife.date/${pkg_name_escaped}</a> for lifecycle information<br/>
            • Review vendor documentation for migration paths
        </div>
    </div>
</div>"
                    fi
                done < <(jq -r '.matches[]? | [
                    .artifact.name // "unknown",
                    .artifact.version // "unknown", 
                    .artifact.type // "unknown",
                    .eolDate // "null",
                    .cycle.eol // "unknown",
                    .artifact.locations[0].path // "N/A"
                ] | @tsv' "$xeol_file" 2>/dev/null)
            fi
        done
        
        XEOL_FINDINGS="${XEOL_FINDINGS}
        </div>"
    else
        XEOL_FINDINGS="<p class=\"no-findings\">✅ No end-of-life components detected</p>"
    fi
else
    XEOL_FINDINGS="<p class=\"no-findings\">No Xeol data available</p>"
fi

# ---- Anchore Statistics ----
ANCHORE_DIR="${LATEST_SCAN}/anchore"
ANCHORE_CRITICAL=0
ANCHORE_HIGH=0
ANCHORE_MEDIUM=0
ANCHORE_LOW=0
ANCHORE_TOTAL_VULNS=0
ANCHORE_STATUS="N/A"
ANCHORE_FINDINGS=""
if [ -d "$ANCHORE_DIR" ]; then
    ANCHORE_FILE=$(find "$ANCHORE_DIR" -name "anchore-results.json" -o -name "*_anchore-results.json" 2>/dev/null | head -n 1)
    if [ -f "$ANCHORE_FILE" ]; then
        ANCHORE_STATUS=$(jq -r '.status // "unknown"' "$ANCHORE_FILE" 2>/dev/null || echo "unknown")
        
        if [ "$ANCHORE_STATUS" = "placeholder" ]; then
            ANCHORE_FINDINGS="<p class=\"no-findings\">ℹ️ Anchore integration planned for future release</p>"
        else
            # Parse actual Anchore results
            ANCHORE_CRITICAL=$(jq '[.results.vulnerabilities[]? | select(.severity=="Critical")] | length' "$ANCHORE_FILE" 2>/dev/null || echo "0")
            ANCHORE_HIGH=$(jq '[.results.vulnerabilities[]? | select(.severity=="High")] | length' "$ANCHORE_FILE" 2>/dev/null || echo "0")
            ANCHORE_MEDIUM=$(jq '[.results.vulnerabilities[]? | select(.severity=="Medium")] | length' "$ANCHORE_FILE" 2>/dev/null || echo "0")
            ANCHORE_LOW=$(jq '[.results.vulnerabilities[]? | select(.severity=="Low")] | length' "$ANCHORE_FILE" 2>/dev/null || echo "0")
            
            [[ "$ANCHORE_CRITICAL" =~ ^[0-9]+$ ]] || ANCHORE_CRITICAL=0
            [[ "$ANCHORE_HIGH" =~ ^[0-9]+$ ]] || ANCHORE_HIGH=0
            [[ "$ANCHORE_MEDIUM" =~ ^[0-9]+$ ]] || ANCHORE_MEDIUM=0
            [[ "$ANCHORE_LOW" =~ ^[0-9]+$ ]] || ANCHORE_LOW=0
            
            ANCHORE_TOTAL_VULNS=$((ANCHORE_CRITICAL + ANCHORE_HIGH + ANCHORE_MEDIUM + ANCHORE_LOW))
            
            if [ "$ANCHORE_TOTAL_VULNS" -gt 0 ]; then
                ANCHORE_FINDINGS="<p class=\"no-findings\">🔍 ${ANCHORE_TOTAL_VULNS} vulnerabilities detected</p>"
            else
                ANCHORE_FINDINGS="<p class=\"no-findings\">✅ No vulnerabilities detected by Anchore</p>"
            fi
        fi
    else
        ANCHORE_FINDINGS="<p class=\"no-findings\">No Anchore results file found</p>"
    fi
else
    ANCHORE_FINDINGS="<p class=\"no-findings\">No Anchore data available</p>"
fi

# Calculate totals
TOTAL_CRITICAL=$((TH_CRITICAL + CLAMAV_CRITICAL + TRIVY_CRITICAL + GRYPE_CRITICAL + SONAR_CRITICAL + CHECKOV_CRITICAL + HELM_CRITICAL + XEOL_CRITICAL + ANCHORE_CRITICAL))
TOTAL_HIGH=$((TH_HIGH + TRIVY_HIGH + GRYPE_HIGH + SONAR_HIGH + CHECKOV_HIGH + HELM_HIGH + XEOL_HIGH + ANCHORE_HIGH))
TOTAL_MEDIUM=$((TRIVY_MEDIUM + GRYPE_MEDIUM + XEOL_MEDIUM + ANCHORE_MEDIUM))
TOTAL_LOW=$((TRIVY_LOW + GRYPE_LOW + XEOL_LOW + ANCHORE_LOW))
TOTAL_FINDINGS=$((TOTAL_CRITICAL + TOTAL_HIGH + TOTAL_MEDIUM + TOTAL_LOW))

# Calculate source-based totals (Container Image vs Application/Filesystem)
# Container image vulnerabilities come from Trivy/Grype base image scans
TOTAL_IMAGE_VULNS=$((TRIVY_CRITICAL + TRIVY_HIGH + TRIVY_MEDIUM + TRIVY_LOW + GRYPE_CRITICAL + GRYPE_HIGH + GRYPE_MEDIUM + GRYPE_LOW + XEOL_CRITICAL + XEOL_HIGH + XEOL_MEDIUM + XEOL_LOW))
# Application/Config vulnerabilities come from Checkov, TruffleHog, Helm, SonarQube
TOTAL_APP_VULNS=$((TH_CRITICAL + TH_HIGH + CHECKOV_HIGH + HELM_CRITICAL + HELM_HIGH + SONAR_CRITICAL + SONAR_HIGH))

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Generate the dashboard HTML
cat > "$OUTPUT_HTML" << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>EPYON - Absolute Security Control</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #1a1d23 0%, #2C3539 50%, #1a1d23 100%);
            min-height: 100vh;
            padding: 20px;
            color: #e8eaed;
        }
        
        .container {
            max-width: 1600px;
            margin: 0 auto;
        }
        
        .header {
            background: linear-gradient(135deg, #0f1419 0%, #1a1d23 100%);
            border-radius: 16px;
            padding: 40px;
            margin-bottom: 30px;
            box-shadow: 0 10px 40px rgba(196, 30, 58, 0.4);
            text-align: center;
            border: 2px solid #C41E3A;
        }
        
        .header h1 {
            font-size: 2.8em;
            margin-bottom: 10px;
            background: linear-gradient(135deg, #C41E3A 0%, #FF1493 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            font-weight: 700;
            letter-spacing: 2px;
        }
        
        .header .subtitle {
            color: #9ca3af;
            font-size: 1.1em;
            margin-top: 10px;
            font-weight: 500;
        }
        
        .alert-banner {
            background: linear-gradient(135deg, #C41E3A 0%, #8B0000 100%);
            color: white;
            padding: 25px;
            border-radius: 12px;
            margin-bottom: 30px;
            box-shadow: 0 4px 20px rgba(196, 30, 58, 0.5);
            text-align: center;
            animation: pulse 2s infinite;
            border: 1px solid #FF1493;
        }
        
        @keyframes pulse {
            0%, 100% { transform: scale(1); }
            50% { transform: scale(1.02); }
        }
        
        .alert-banner h2 {
            font-size: 1.8em;
            margin-bottom: 10px;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: linear-gradient(135deg, #1a1d23 0%, #2C3539 100%);
            border-radius: 12px;
            padding: 30px;
            text-align: center;
            box-shadow: 0 4px 20px rgba(0,0,0,0.3);
            transition: all 0.3s ease;
            cursor: pointer;
            border: 1px solid #4a5568;
        }
        
        .stat-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 8px 30px rgba(196, 30, 58, 0.4);
            border-color: #C41E3A;
        }
        
        .stat-number {
            font-size: 3em;
            font-weight: bold;
            margin: 15px 0;
        }
        
        .stat-label {
            color: #9ca3af;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
            font-weight: 600;
        }
        
        .critical-stat { color: #C41E3A; border-top: 4px solid #C41E3A; }
        .high-stat { color: #FF1493; border-top: 4px solid #FF1493; }
        .medium-stat { color: #f97316; border-top: 4px solid #f97316; }
        .low-stat { color: #4ade80; border-top: 4px solid #4ade80; }
        
        .tools-section {
            display: grid;
            gap: 20px;
        }
        
        .tool-card {
            background: #1a1d23;
            border-radius: 12px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.3);
            overflow: hidden;
            transition: all 0.3s ease;
            border: 1px solid #2C3539;
        }
        
        .tool-header {
            padding: 25px;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: linear-gradient(135deg, #2C3539 0%, #1a1d23 100%);
            border-bottom: 2px solid #4a5568;
            transition: all 0.3s ease;
            color: #e8eaed;
        }
        
        .tool-header:hover {
            background: linear-gradient(135deg, #3a4148 0%, #2C3539 100%);
            border-bottom-color: #C41E3A;
        }
        
        .tool-header.active {
            background: linear-gradient(135deg, #C41E3A 0%, #8B0000 100%);
            color: white;
            border-bottom-color: #FF1493;
        }
        
        .tool-title {
            display: flex;
            align-items: center;
            gap: 15px;
            font-size: 1.4em;
            font-weight: 600;
        }
        
        .tool-icon {
            font-size: 1.5em;
        }
        
        .tool-stats {
            display: flex;
            gap: 15px;
            align-items: center;
        }
        
        .tool-stat-badge {
            padding: 8px 16px;
            border-radius: 20px;
            font-size: 0.9em;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 5px;
        }
        
        .badge-critical { background: #fed7d7; color: #c53030; }
        .badge-high { background: #feebc8; color: #c05621; }
        .badge-medium { background: #2a1f15; color: #fb923c; border: 1px solid #f97316; }
        .badge-low { background: #c6f6d5; color: #2f855a; }
        .badge-clean { background: #c6f6d5; color: #2f855a; }
        
        .tool-header.active .tool-stat-badge {
            background: rgba(255,255,255,0.2);
            color: white;
        }
        
        .expand-icon {
            font-size: 1.2em;
            transition: transform 0.3s ease;
        }
        
        .tool-header.active .expand-icon {
            transform: rotate(180deg);
        }
        
        .tool-content {
            max-height: 0;
            overflow: hidden;
            transition: max-height 0.5s ease;
        }
        
        .tool-content.active {
            max-height: 2000px;
            overflow-y: auto;
        }
        
        .tool-findings {
            padding: 30px;
            background: #0f1419;
        }
        
        .finding-item {
            background: #1a1d23;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 15px;
            border-left: 4px solid #4a5568;
            transition: all 0.2s ease;
            cursor: pointer;
            border: 1px solid #2C3539;
        }
        
        .finding-item:hover {
            transform: translateX(5px);
            box-shadow: 0 4px 12px rgba(196, 30, 58, 0.3);
            border-color: #C41E3A;
        }
        
        .finding-item.expanded {
            transform: translateX(5px);
            box-shadow: 0 8px 24px rgba(196, 30, 58, 0.4);
            border-left-width: 6px;
            background: #1f2329;
        }
        
        .finding-item .finding-details {
            margin-top: 15px;
            padding-top: 15px;
            border-top: 1px dashed #4a5568;
            animation: slideDown 0.3s ease;
        }
        
        @keyframes slideDown {
            from { opacity: 0; transform: translateY(-10px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        .finding-item.severity-critical {
            border-left-color: #C41E3A;
            background: #2a1215;
            border-color: #C41E3A;
        }
        
        .finding-item.severity-high {
            border-left-color: #FF1493;
            background: #2a1521;
            border-color: #FF1493;
        }
        
        .finding-item.severity-medium {
            border-left-color: #f97316;
            background: #2a1f15;
            border-color: #ea580c;
        }
            background: #fef5e7;
        }
        
        .finding-item.severity-low {
            border-left-color: #4ade80;
            background: #1a2e1f;
            border-color: #10b981;
        }
        
        .finding-header {
            display: flex;
            gap: 10px;
            margin-bottom: 12px;
            flex-wrap: wrap;
        }
        
        .badge {
            padding: 6px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: 600;
        }
        
        .badge-tool {
            background: linear-gradient(135deg, #C41E3A 0%, #8B1328 100%);
            color: white;
        }
        
        .badge-verified {
            background: #e53e3e;
            color: white;
            animation: pulse-badge 2s infinite;
        }
        
        @keyframes pulse-badge {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.7; }
        }
        
        .finding-title {
            font-size: 1.1em;
            font-weight: 600;
            margin-bottom: 8px;
            color: #f3f4f6;
        }
        
        .finding-desc {
            color: #d1d5db;
            margin-bottom: 12px;
            line-height: 1.6;
        }
        
        .finding-details {
            background: #374151;
            padding: 15px;
            border-radius: 6px;
            font-size: 0.9em;
            color: #f3f4f6;
            cursor: text;
            user-select: text;
        }
        
        .finding-details * {
            user-select: text;
        }
        
        .finding-details::selection,
        .finding-details *::selection {
            background: #3b82f6;
            color: white;
        }
        
        .finding-details div {
            margin-bottom: 8px;
        }
        
        .finding-details div:last-child {
            margin-bottom: 0;
        }
        
        .finding-details code {
            background: #1f2937;
            color: #60a5fa;
            padding: 3px 8px;
            border-radius: 4px;
            font-family: 'Monaco', 'Courier New', monospace;
            font-size: 0.9em;
            word-break: break-all;
        }
        
        /* Detail sections for expanded findings */
        .detail-section {
            background: #374151;
            border: 1px solid #4b5563;
            border-radius: 8px;
            padding: 15px;
            margin-bottom: 12px;
            color: #f3f4f6;
        }
        
        .detail-section h5 {
            color: #f9fafb;
            margin: 0 0 12px 0;
            font-size: 0.95em;
            border-bottom: 1px solid #6b7280;
            padding-bottom: 8px;
        }
        
        .detail-section div {
            margin-bottom: 6px;
        }
        
        /* False Positive Checklist */
        .fp-checklist {
            display: flex;
            flex-direction: column;
            gap: 8px;
        }
        
        .fp-checklist label {
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 8px 12px;
            background: #1f2937;
            color: #f3f4f6;
            border: 1px solid #4b5563;
            border-radius: 6px;
            cursor: pointer;
            transition: all 0.2s ease;
            font-size: 0.9em;
        }
        
        .fp-checklist label:hover {
            background: #374151;
            border-color: #6b7280;
        }
        
        .fp-check {
            width: 18px;
            height: 18px;
            accent-color: #38a169;
        }
        
        .fp-checklist label:has(.fp-check:checked) {
            background: #c6f6d5;
            border-color: #9ae6b4;
            color: #276749;
        }
        
        /* Status badge colors */
        .status-fixed {
            background: #c6f6d5 !important;
            color: #2f855a !important;
        }
        
        .status-affected {
            background: #fed7d7 !important;
            color: #c53030 !important;
        }
        
        .status-unknown {
            background: #feebc8 !important;
            color: #c05621 !important;
        }
        
        .stats-detail-box {
            background: linear-gradient(135deg, #1a1d23 0%, #2C3539 100%);
            border: 1px solid #C41E3A;
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 4px 12px rgba(196, 30, 58, 0.3);
        }
        
        .stats-detail-box h4 {
            color: #FF1493;
            margin-bottom: 15px;
            font-size: 1.1em;
        }
        
        .stats-grid-small {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 12px;
        }
        
        .stat-item {
            background: #0f1419;
            padding: 10px 15px;
            border-radius: 8px;
            font-size: 0.9em;
            box-shadow: 0 2px 6px rgba(0,0,0,0.4);
            border: 1px solid #4a5568;
            color: #e8eaed;
        }
        
        .stat-item strong {
            color: #60a5fa;
        }
        
        .finding-summary {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
            margin-bottom: 20px;
        }
        
        .no-findings {
            text-align: center;
            padding: 40px;
            color: #4ade80;
            font-size: 1.2em;
        }
        
        /* SBOM Viewer Styles */
        .sbom-controls {
            background: linear-gradient(135deg, #1a1d23 0%, #2C3539 100%);
            border: 1px solid #3b82f6;
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 20px;
        }
        
        .sbom-filter-section {
            margin-bottom: 15px;
        }
        
        .sbom-filter-section .filter-label,
        .sbom-sort-section .filter-label {
            font-weight: 600;
            color: #0369a1;
            margin-right: 10px;
            display: inline-block;
            margin-bottom: 10px;
        }
        
        .sbom-filter-chips {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
        }
        
        .sbom-filter-chip {
            display: flex;
            align-items: center;
            gap: 6px;
            background: #1f2937;
            color: #7dd3fc;
            border: 2px solid #7dd3fc;
            border-radius: 20px;
            padding: 6px 14px;
            cursor: pointer;
            transition: all 0.2s ease;
            font-size: 0.9em;
        }
        
        .sbom-filter-chip:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(0,0,0,0.3);
            background: #374151;
        }
        
        .sbom-filter-chip.active {
            background: linear-gradient(135deg, #0369a1 0%, #0284c7 100%);
            border-color: #0369a1;
            color: white;
        }
        
        .sbom-filter-chip.active .type-name {
            color: white;
        }
        
        .sbom-filter-chip.active .type-count {
            background: rgba(255,255,255,0.3);
            color: white;
        }
        
        .sbom-filter-chip .type-name {
            font-weight: 600;
            color: #0369a1;
        }
        
        .sbom-filter-chip .type-count {
            background: #e0f2fe;
            color: #0369a1;
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 0.85em;
            font-weight: 600;
        }
        
        .sbom-sort-section {
            margin-bottom: 15px;
        }
        
        .sbom-sort-buttons {
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
        }
        
        .sbom-sort-btn {
            padding: 8px 16px;
            border-radius: 8px;
            border: 2px solid #4b5563;
            background: #1f2937;
            color: #e5e7eb;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s ease;
        }
        
        .sbom-sort-btn:hover {
            background: #374151;
            border-color: #6b7280;
        }
        
        .sbom-sort-btn.active {
            background: linear-gradient(135deg, #C41E3A 0%, #8B1328 100%);
            color: white;
            border-color: #C41E3A;
        }
        
        .sbom-results-bar {
            background: #1f2937;
            padding: 12px 20px;
            border-radius: 8px;
            margin-bottom: 15px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border: 1px solid #4b5563;
        }
        
        #sbom-results-count {
            font-weight: 600;
            color: #f3f4f6;
        }
        
        .sbom-type-breakdown {
            margin-bottom: 20px;
        }
        
        .sbom-type-breakdown h4 {
            color: #60a5fa;
            margin-bottom: 15px;
        }
        
        .sbom-types-grid {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
        }
        
        .sbom-type-chip {
            display: flex;
            align-items: center;
            gap: 8px;
            background: linear-gradient(135deg, #1e3a5f 0%, #1e40af 100%);
            border: 1px solid #3b82f6;
            border-radius: 20px;
            padding: 8px 16px;
            cursor: pointer;
            transition: all 0.2s ease;
        }
        
        .sbom-type-chip:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
        }
        
        .sbom-type-chip .type-name {
            font-weight: 600;
            color: #93c5fd;
        }
        
        .sbom-type-chip .type-count {
            background: #1e293b;
            color: #93c5fd;
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 0.85em;
            font-weight: 600;
        }
        
        .sbom-version-badge {
            background: #1e3a5f !important;
            color: #93c5fd !important;
        }
        
        .sbom-lang-badge {
            background: #422006 !important;
            color: #fcd34d !important;
        }
        
        .sbom-search-box {
            margin-top: 15px;
        }
        
        .sbom-search-box input {
            width: 100%;
            padding: 12px 20px;
            border: 2px solid #4b5563;
            background: #1f2937;
            color: #f3f4f6;
            border-radius: 10px;
            font-size: 1em;
            transition: all 0.2s ease;
        }
        
        .sbom-search-box input:focus {
            outline: none;
            border-color: #C41E3A;
            box-shadow: 0 0 0 3px rgba(196,30,58,0.1);
        }
        
        .sbom-package-list {
            max-height: 600px;
            overflow-y: auto;
        }
        
        .sbom-package-item {
            background: #1f2937;
            border-radius: 8px;
            padding: 15px 20px;
            margin-bottom: 10px;
            border-left: 4px solid #3b82f6;
            border: 1px solid #374151;
            color: #f3f4f6;
            transition: all 0.2s ease;
            cursor: pointer;
        }
        
        .sbom-package-item:hover {
            transform: translateX(5px);
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
        }
        
        .sbom-package-item.expanded {
            background: #1e3a5f;
            border-left-width: 6px;
            border-color: #3b82f6;
        }
        
        .sbom-package-item.filtered-out {
            display: none;
        }
        
        .footer {
            background: #1a1d23;
            border: 1px solid #4b5563;
            border-radius: 12px;
            padding: 30px;
            margin-top: 30px;
            text-align: center;
            box-shadow: 0 4px 20px rgba(0,0,0,0.3);
            color: #e5e7eb;
        }
        
        .footer-links {
            display: flex;
            gap: 20px;
            justify-content: center;
            margin-top: 20px;
            flex-wrap: wrap;
        }
        
        .footer-link {
            color: #C41E3A;
            text-decoration: none;
            font-weight: 600;
            transition: all 0.2s;
        }
        
        .footer-link:hover {
            color: #8B1328;
            text-decoration: underline;
        }
        
        /* Filter Controls */
        .filter-bar {
            background: linear-gradient(135deg, #1a1d23 0%, #2C3539 100%);
            border-radius: 12px;
            padding: 20px 30px;
            margin-bottom: 30px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.4);
            display: flex;
            flex-wrap: wrap;
            gap: 15px;
            align-items: center;
            border: 1px solid #4a5568;
        }
        
        .filter-label {
            font-weight: 600;
            color: #e8eaed;
            margin-right: 10px;
        }
        
        .filter-chips {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }
        
        .filter-chip {
            padding: 8px 16px;
            border-radius: 25px;
            border: 2px solid transparent;
            font-weight: 600;
            font-size: 0.9em;
            cursor: pointer;
            transition: all 0.3s ease;
            display: flex;
            align-items: center;
            gap: 6px;
        }
        
        .filter-chip:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        }
        
        .filter-chip.active {
            transform: scale(1.05);
            box-shadow: 0 4px 12px rgba(0,0,0,0.2);
        }
        
        .filter-chip-all {
            background: #2C3539;
            color: #e8eaed;
            border-color: #4a5568;
        }
        .filter-chip-all.active {
            background: linear-gradient(135deg, #C41E3A 0%, #8B0000 100%);
            color: white;
            border-color: #FF1493;
        }
        
        .filter-chip-critical {
            background: #2a1215;
            color: #C41E3A;
            border-color: #C41E3A;
        }
        .filter-chip-critical.active {
            background: linear-gradient(135deg, #C41E3A 0%, #8B0000 100%);
            color: white;
            border-color: #FF1493;
        }
        
        .filter-chip-high {
            background: #2a1521;
            color: #FF1493;
            border-color: #FF1493;
        }
        .filter-chip-high.active {
            background: linear-gradient(135deg, #FF1493 0%, #C41E3A 100%);
            color: white;
            border-color: #FF69B4;
        }
        
        .filter-chip-medium {
            background: #2a1f15;
            color: #fb923c;
            border-color: #f97316;
        }
        .filter-chip-medium.active {
            background: #f97316;
            color: #1a1d23;
            border-color: #fb923c;
        }
        
        .filter-chip-low {
            background: #152a1f;
            color: #4ade80;
            border-color: #10b981;
        }
        .filter-chip-low.active {
            background: #10b981;
            color: #1a1d23;
            border-color: #4ade80;
        }
        
        .filter-chip .chip-count {
            background: rgba(0,0,0,0.1);
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 0.85em;
        }
        
        .filter-chip.active .chip-count {
            background: rgba(255,255,255,0.3);
        }
        
        .sort-controls {
            display: flex;
            gap: 10px;
            margin-left: auto;
            align-items: center;
        }
        
        .sort-btn {
            padding: 8px 16px;
            border-radius: 8px;
            border: 1px solid #4a5568;
            background: #2C3539;
            color: #e8eaed;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.2s ease;
            display: flex;
            align-items: center;
            gap: 6px;
        }
        
        .sort-btn:hover {
            background: #3a4148;
            border-color: #C41E3A;
        }
        
        .sort-btn.active {
            background: #C41E3A;
            color: white;
            border-color: #C41E3A;
        }
        
        .filter-results {
            background: #1a1d23;
            padding: 12px 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border: 1px solid #4a5568;
        }
        
        .filter-results-count {
            font-weight: 600;
            color: #e8eaed;
        }
        
        .clear-filter {
            color: #C41E3A;
            text-decoration: none;
            cursor: pointer;
            font-weight: 500;
        }
        
        .clear-filter:hover {
            text-decoration: underline;
        }
        
        .finding-item.filtered-out {
            display: none !important;
        }
        
        .tool-card.filtered-out {
            opacity: 0.4;
        }
        
        @media (max-width: 768px) {
            .stats-grid {
                grid-template-columns: repeat(2, 1fr);
            }
            
            .tool-header {
                flex-direction: column;
                gap: 15px;
                text-align: center;
            }
            
            .tool-stats {
                flex-wrap: wrap;
                justify-content: center;
            }
        }
    </style>
</head>
<body>
    <div class="container">
EOF

# Add alert banner if critical findings exist
if [ "$TOTAL_CRITICAL" -gt 0 ]; then
    cat >> "$OUTPUT_HTML" << EOF
        <div class="alert-banner">
            <h2>⚠️ CRITICAL SECURITY ALERT</h2>
            <p><strong>${TOTAL_CRITICAL} Critical Findings Detected</strong> - Immediate Action Required!</p>
        </div>
EOF
fi

# Add header and stats
cat >> "$OUTPUT_HTML" << EOF
        <div class="header">
            <h1>EPYON</h1>
            <p class="subtitle" style="color: #9ca3af; font-size: 1.3em; font-weight: 600; margin-top: 5px;">Absolute Security Control</p>
            <p class="subtitle" style="margin-top: 20px;"><strong>Scan:</strong> $SCAN_NAME</p>
            <p class="subtitle"><strong>Generated:</strong> $(date '+%B %d, %Y at %I:%M %p')</p>
        </div>

        <!-- Scan Overview Section -->
        <div class="scan-overview" style="background: linear-gradient(135deg, #C41E3A 0%, #8B0000 100%); border-radius: 16px; padding: 24px; margin-bottom: 24px; color: white; box-shadow: 0 10px 40px rgba(196, 30, 58, 0.5); border: 1px solid #FF1493;">
            <h2 style="margin: 0 0 16px 0; font-size: 1.4em; display: flex; align-items: center; gap: 10px;">
                📊 Scan Overview
            </h2>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px;">
                <div style="background: rgba(255,255,255,0.15); border-radius: 12px; padding: 16px; backdrop-filter: blur(10px);">
                    <div style="font-size: 2em; font-weight: bold;">${TOTAL_FILES_SCANNED}</div>
                    <div style="opacity: 0.9;">📄 Total Files Scanned</div>
                </div>
                <div style="background: rgba(255,255,255,0.15); border-radius: 12px; padding: 16px; backdrop-filter: blur(10px);">
                    <div style="font-size: 2em; font-weight: bold;">10</div>
                    <div style="opacity: 0.9;">🛡️ Security Layers</div>
                </div>
                <div style="background: rgba(255,255,255,0.15); border-radius: 12px; padding: 16px; backdrop-filter: blur(10px);">
                    <div style="font-size: 2em; font-weight: bold;">${TOTAL_FINDINGS}</div>
                    <div style="opacity: 0.9;">🔍 Total Findings</div>
                </div>
            </div>
            
            <!-- File Type Breakdown -->
            <div style="margin-top: 20px; background: rgba(255,255,255,0.1); border-radius: 12px; padding: 16px;">
                <h3 style="margin: 0 0 12px 0; font-size: 1em; opacity: 0.9;">📁 Files Analyzed by Type</h3>
                <div style="display: flex; flex-wrap: wrap; gap: 8px;">
EOF

# Add file type badges only if count > 0
if [ "$JS_TS_FILES" -gt 0 ]; then
    cat >> "$OUTPUT_HTML" << EOF
                    <span style="background: rgba(255,255,255,0.2); padding: 6px 12px; border-radius: 20px; font-size: 0.85em;">
                        <strong>JS/TS:</strong> ${JS_TS_FILES}
                    </span>
EOF
fi

if [ "$PYTHON_FILES" -gt 0 ]; then
    cat >> "$OUTPUT_HTML" << EOF
                    <span style="background: rgba(255,255,255,0.2); padding: 6px 12px; border-radius: 20px; font-size: 0.85em;">
                        <strong>Python:</strong> ${PYTHON_FILES}
                    </span>
EOF
fi

if [ "$YAML_FILES" -gt 0 ]; then
    cat >> "$OUTPUT_HTML" << EOF
                    <span style="background: rgba(255,255,255,0.2); padding: 6px 12px; border-radius: 20px; font-size: 0.85em;">
                        <strong>YAML:</strong> ${YAML_FILES}
                    </span>
EOF
fi

if [ "$JSON_CONFIG_FILES" -gt 0 ]; then
    cat >> "$OUTPUT_HTML" << EOF
                    <span style="background: rgba(255,255,255,0.2); padding: 6px 12px; border-radius: 20px; font-size: 0.85em;">
                        <strong>JSON:</strong> ${JSON_CONFIG_FILES}
                    </span>
EOF
fi

if [ "$TERRAFORM_FILES" -gt 0 ]; then
    cat >> "$OUTPUT_HTML" << EOF
                    <span style="background: rgba(255,255,255,0.2); padding: 6px 12px; border-radius: 20px; font-size: 0.85em;">
                        <strong>Terraform:</strong> ${TERRAFORM_FILES}
                    </span>
EOF
fi

if [ "$DOCKERFILE_COUNT" -gt 0 ]; then
    cat >> "$OUTPUT_HTML" << EOF
                    <span style="background: rgba(255,255,255,0.2); padding: 6px 12px; border-radius: 20px; font-size: 0.85em;">
                        <strong>Dockerfiles:</strong> ${DOCKERFILE_COUNT}
                    </span>
EOF
fi

if [ "$SHELL_SCRIPT_FILES" -gt 0 ]; then
    cat >> "$OUTPUT_HTML" << EOF
                    <span style="background: rgba(255,255,255,0.2); padding: 6px 12px; border-radius: 20px; font-size: 0.85em;">
                        <strong>Shell:</strong> ${SHELL_SCRIPT_FILES}
                    </span>
EOF
fi

# Show message if no file stats available
if [ "$TOTAL_FILES_SCANNED" -eq 0 ]; then
    cat >> "$OUTPUT_HTML" << EOF
                    <span style="background: rgba(255,255,255,0.2); padding: 6px 12px; border-radius: 20px; font-size: 0.85em; font-style: italic;">
                        ℹ️ File statistics not available for this scan
                    </span>
EOF
fi

cat >> "$OUTPUT_HTML" << EOF
                </div>
            </div>
            
            <div style="margin-top: 12px; font-size: 0.85em; opacity: 0.8;">
                <strong>Target:</strong> <code style="background: rgba(0,0,0,0.2); padding: 2px 8px; border-radius: 4px;">${TARGET_DIRECTORY}</code>
            </div>
        </div>

        <div class="stats-grid">
            <div class="stat-card critical-stat">
                <div class="stat-label">Critical</div>
                <div class="stat-number">${TOTAL_CRITICAL}</div>
                <p>Immediate action required</p>
            </div>
            <div class="stat-card high-stat">
                <div class="stat-label">High</div>
                <div class="stat-number">${TOTAL_HIGH}</div>
                <p>High priority issues</p>
            </div>
            <div class="stat-card medium-stat">
                <div class="stat-label">Medium</div>
                <div class="stat-number">${TOTAL_MEDIUM}</div>
                <p>Medium priority issues</p>
            </div>
            <div class="stat-card low-stat">
                <div class="stat-label">Low</div>
                <div class="stat-number">${TOTAL_LOW}</div>
                <p>Low priority issues</p>
            </div>
        </div>

        <div class="filter-bar">
            <span class="filter-label">🔍 Filter by Severity:</span>
            <div class="filter-chips">
                <button class="filter-chip filter-chip-all active" onclick="filterBySeverity('all')">
                    All <span class="chip-count">${TOTAL_FINDINGS}</span>
                </button>
                <button class="filter-chip filter-chip-critical" onclick="filterBySeverity('critical')">
                    ❗ Critical <span class="chip-count">${TOTAL_CRITICAL}</span>
                </button>
                <button class="filter-chip filter-chip-high" onclick="filterBySeverity('high')">
                    ⚠️ High <span class="chip-count">${TOTAL_HIGH}</span>
                </button>
                <button class="filter-chip filter-chip-medium" onclick="filterBySeverity('medium')">
                    ⚡ Medium <span class="chip-count">${TOTAL_MEDIUM}</span>
                </button>
                <button class="filter-chip filter-chip-low" onclick="filterBySeverity('low')">
                    📌 Low <span class="chip-count">${TOTAL_LOW}</span>
                </button>
            </div>
        </div>
        
        <div class="filter-bar" style="margin-top: 10px;">
            <span class="filter-label">📦 Filter by Source:</span>
            <div class="filter-chips">
                <button class="filter-chip source-chip source-chip-all active" onclick="filterBySource('all')" id="source-all">
                    All Sources <span class="chip-count" id="source-count-all">${TOTAL_FINDINGS}</span>
                </button>
                <button class="filter-chip source-chip source-chip-image" onclick="filterBySource('image')" id="source-image" style="background: #1a2a3a; border-color: #3b82f6; color: #60a5fa;">
                    🐳 Container Image <span class="chip-count" id="source-count-image">0</span>
                </button>
                <button class="filter-chip source-chip source-chip-app" onclick="filterBySource('app')" id="source-app" style="background: #2a1f15; border-color: #f97316; color: #fb923c;">
                    📁 Application/Config <span class="chip-count" id="source-count-app">0</span>
                </button>
            </div>
            <div class="sort-controls">
                <span class="filter-label">Sort:</span>
                <button class="sort-btn active" onclick="sortFindings('severity')" id="sort-severity">
                    ↕️ Severity
                </button>
                <button class="sort-btn" onclick="sortFindings('tool')" id="sort-tool">
                    🔧 Tool
                </button>
            </div>
        </div>
        
        <!-- Source Legend -->
        <div style="background: #1a1d23; border-radius: 8px; padding: 12px 16px; margin-top: 15px; margin-bottom: 15px; font-size: 0.85em; border-left: 4px solid #C41E3A; border: 1px solid #4a5568;">
            <strong style="color: #e8eaed;">📋 Understanding Vulnerability Sources:</strong>
            <div style="display: flex; flex-wrap: wrap; gap: 20px; margin-top: 8px;">
                <div style="display: flex; align-items: center; gap: 6px;">
                    <span style="background: #2C3539; padding: 2px 8px; border-radius: 4px; color: #60a5fa; border: 1px solid #3b82f6;">🐳 Container Image</span>
                    <span style="color: #9ca3af;">= Bundled in base image (npm, pip, OS packages)</span>
                </div>
                <div style="display: flex; align-items: center; gap: 6px;">
                    <span style="background: #2C3539; padding: 2px 8px; border-radius: 4px; color: #fb923c; border: 1px solid #f97316;">📁 Application/Config</span>
                    <span style="color: #9ca3af;">= Your code, secrets, IaC misconfigurations</span>
                </div>
            </div>
        </div>
        
        <div class="filter-results" id="filter-results" style="display: none;">
            <span class="filter-results-count" id="filter-count">Showing 0 findings</span>
            <a class="clear-filter" onclick="filterBySeverity('all'); filterBySource('all');">Clear Filters ✕</a>
        </div>

        <div class="tools-section">
            <!-- TruffleHog -->
            <div class="tool-card">
                <div class="tool-header" onclick="toggleTool('trufflehog')">
                    <div class="tool-title">
                        <span class="tool-icon">🔍</span>
                        <div>
                            <div>TruffleHog</div>
                            <div style="font-size: 0.6em; font-weight: 400; color: #718096;">Secret Detection</div>
                        </div>
                    </div>
                    <div class="tool-stats">
EOF

# Add TruffleHog stats
if [ "$TH_CRITICAL" -gt 0 ]; then
    echo "                        <span class=\"tool-stat-badge badge-critical\">❗ ${TH_CRITICAL}</span>" >> "$OUTPUT_HTML"
fi
if [ "$TH_HIGH" -gt 0 ]; then
    echo "                        <span class=\"tool-stat-badge badge-high\">⚠️ ${TH_HIGH}</span>" >> "$OUTPUT_HTML"
fi
if [ "$TH_CRITICAL" -eq 0 ] && [ "$TH_HIGH" -eq 0 ]; then
    echo "                        <span class=\"tool-stat-badge badge-clean\">✅ Clean</span>" >> "$OUTPUT_HTML"
fi

cat >> "$OUTPUT_HTML" << EOF
                        <span class="expand-icon">▼</span>
                    </div>
                </div>
                <div class="tool-content" id="trufflehog-content">
                    <div class="tool-findings">
EOF

# Show status banner if failed or skipped
if [ "$TH_STATUS" = "failed" ] || [ "$TH_STATUS" = "skipped" ]; then
    generate_status_banner "$TH_STATUS" "$TH_STATUS_REASON" "TruffleHog" >> "$OUTPUT_HTML"
fi

cat >> "$OUTPUT_HTML" << EOF
                        <div class="stats-detail-box">
                            <h4>📊 Scan Statistics</h4>
                            <div class="stats-grid-small">
                                <div class="stat-item"><strong>Total Findings:</strong> ${TH_TOTAL_FINDINGS}</div>
                                <div class="stat-item"><strong>Verified Secrets:</strong> ${TH_VERIFIED}</div>
                                <div class="stat-item"><strong>Unverified:</strong> ${TH_UNVERIFIED}</div>
                                <div class="stat-item"><strong>Detector Types Used:</strong> ${TH_DETECTORS_USED}</div>
                                <div class="stat-item"><strong>Files with Findings:</strong> ${TH_FILES_WITH_FINDINGS:-0}</div>
                            </div>
                        </div>
                        ${TH_FINDINGS}
                    </div>
                </div>
            </div>

            <!-- ClamAV -->
            <div class="tool-card">
                <div class="tool-header" onclick="toggleTool('clamav')">
                    <div class="tool-title">
                        <span class="tool-icon">🦠</span>
                        <div>
                            <div>ClamAV</div>
                            <div style="font-size: 0.6em; font-weight: 400; color: #718096;">Malware Scanner</div>
                        </div>
                    </div>
                    <div class="tool-stats">
EOF

# Add ClamAV stats
if [ "$CLAMAV_CRITICAL" -gt 0 ]; then
    echo "                        <span class=\"tool-stat-badge badge-critical\">❗ ${CLAMAV_CRITICAL}</span>" >> "$OUTPUT_HTML"
else
    echo "                        <span class=\"tool-stat-badge badge-clean\">✅ Clean</span>" >> "$OUTPUT_HTML"
fi

cat >> "$OUTPUT_HTML" << EOF
                        <span class="expand-icon">▼</span>
                    </div>
                </div>
                <div class="tool-content" id="clamav-content">
                    <div class="tool-findings">
                        <div class="stats-detail-box">
                            <h4>📊 Scan Statistics</h4>
                            <div class="stats-grid-small">
                                <div class="stat-item"><strong>Files Scanned:</strong> ${CLAMAV_FILES_SCANNED}</div>
                                <div class="stat-item"><strong>Directories Scanned:</strong> ${CLAMAV_DIRECTORIES}</div>
                                <div class="stat-item"><strong>Data Scanned:</strong> ${CLAMAV_DATA_SCANNED}</div>
                                <div class="stat-item"><strong>Scan Duration:</strong> ${CLAMAV_SCAN_TIME}</div>
                                <div class="stat-item"><strong>Engine Version:</strong> ${CLAMAV_ENGINE_VERSION}</div>
                                <div class="stat-item"><strong>Virus Database:</strong> ${CLAMAV_VIRUS_DB_COUNT} signatures</div>
                                <div class="stat-item"><strong>Infected Files:</strong> ${CLAMAV_INFECTED}</div>
                            </div>
                        </div>
                        ${CLAMAV_FINDINGS}
                    </div>
                </div>
            </div>

            <!-- SonarQube -->
            <div class="tool-card">
                <div class="tool-header" onclick="toggleTool('sonar')">
                    <div class="tool-title">
                        <span class="tool-icon">📊</span>
                        <div>
                            <div>SonarQube</div>
                            <div style="font-size: 0.6em; font-weight: 400; color: #718096;">Code Quality</div>
                        </div>
                    </div>
                    <div class="tool-stats">
                        <span class="tool-stat-badge badge-clean">✅ Clean</span>
                        <span class="expand-icon">▼</span>
                    </div>
                </div>
                <div class="tool-content" id="sonar-content">
                    <div class="tool-findings">
                        ${SONAR_FINDINGS}
                    </div>
                </div>
            </div>

            <!-- Checkov -->
            <div class="tool-card">
                <div class="tool-header" onclick="toggleTool('checkov')">
                    <div class="tool-title">
                        <span class="tool-icon">🔐</span>
                        <div>
                            <div>Checkov</div>
                            <div style="font-size: 0.6em; font-weight: 400; color: #718096;">IaC Security</div>
                        </div>
                    </div>
                    <div class="tool-stats">
EOF

# Add Checkov stats dynamically
if [ "$CHECKOV_FAILED" -gt 0 ]; then
    echo "                        <span class=\"tool-stat-badge badge-high\">⚠️ ${CHECKOV_FAILED} Failed</span>" >> "$OUTPUT_HTML"
else
    echo "                        <span class=\"tool-stat-badge badge-clean\">✅ Clean</span>" >> "$OUTPUT_HTML"
fi

cat >> "$OUTPUT_HTML" << EOF
                        <span class="expand-icon">▼</span>
                    </div>
                </div>
                <div class="tool-content" id="checkov-content">
                    <div class="tool-findings">
                        ${CHECKOV_FINDINGS}
                    </div>
                </div>
            </div>

            <!-- Helm -->
            <div class="tool-card">
                <div class="tool-header" onclick="toggleTool('helm')">
                    <div class="tool-title">
                        <span class="tool-icon">⚓</span>
                        <div>
                            <div>Helm</div>
                            <div style="font-size: 0.6em; font-weight: 400; color: #718096;">Chart Validation</div>
                        </div>
                    </div>
                    <div class="tool-stats">
                        <span class="tool-stat-badge badge-clean">✅ Clean</span>
                        <span class="expand-icon">▼</span>
                    </div>
                </div>
                <div class="tool-content" id="helm-content">
                    <div class="tool-findings">
                        ${HELM_FINDINGS}
                    </div>
                </div>
            </div>

            <!-- Trivy -->
            <div class="tool-card">
                <div class="tool-header" onclick="toggleTool('trivy')">
                    <div class="tool-title">
                        <span class="tool-icon">🐳</span>
                        <div>
                            <div>Trivy</div>
                            <div style="font-size: 0.6em; font-weight: 400; color: #718096;">Container Vulnerability Scanner</div>
                        </div>
                    </div>
                    <div class="tool-stats">
EOF

# Add Trivy stats
if [ "$TRIVY_CRITICAL" -gt 0 ]; then
    echo "                        <span class=\"tool-stat-badge badge-critical\">❗ ${TRIVY_CRITICAL}</span>" >> "$OUTPUT_HTML"
fi
if [ "$TRIVY_HIGH" -gt 0 ]; then
    echo "                        <span class=\"tool-stat-badge badge-high\">⚠️ ${TRIVY_HIGH}</span>" >> "$OUTPUT_HTML"
fi
if [ "$TRIVY_CRITICAL" -eq 0 ] && [ "$TRIVY_HIGH" -eq 0 ]; then
    echo "                        <span class=\"tool-stat-badge badge-clean\">✅ Clean</span>" >> "$OUTPUT_HTML"
fi

cat >> "$OUTPUT_HTML" << EOF
                        <span class="expand-icon">▼</span>
                    </div>
                </div>
                <div class="tool-content" id="trivy-content">
                    <div class="tool-findings">
                        <div class="stats-detail-box">
                            <h4>📊 Scan Statistics</h4>
                            <div class="stats-grid-small">
                                <div class="stat-item"><strong>Images Scanned:</strong> ${TRIVY_IMAGES_SCANNED}</div>
                                <div class="stat-item"><strong>Total Vulnerabilities:</strong> ${TRIVY_TOTAL_VULNS}</div>
                                <div class="stat-item"><strong>Critical:</strong> ${TRIVY_CRITICAL}</div>
                                <div class="stat-item"><strong>High:</strong> ${TRIVY_HIGH}</div>
                                <div class="stat-item"><strong>Medium:</strong> ${TRIVY_MEDIUM}</div>
                                <div class="stat-item"><strong>Low:</strong> ${TRIVY_LOW}</div>
                            </div>
                        </div>
                        ${TRIVY_FINDINGS}
                    </div>
                </div>
            </div>

            <!-- Grype -->
            <div class="tool-card">
                <div class="tool-header" onclick="toggleTool('grype')">
                    <div class="tool-title">
                        <span class="tool-icon">🦑</span>
                        <div>
                            <div>Grype</div>
                            <div style="font-size: 0.6em; font-weight: 400; color: #718096;">Vulnerability Detector</div>
                        </div>
                    </div>
                    <div class="tool-stats">
EOF

# Add Grype stats
if [ "$GRYPE_CRITICAL" -gt 0 ]; then
    echo "                        <span class=\"tool-stat-badge badge-critical\">❗ ${GRYPE_CRITICAL}</span>" >> "$OUTPUT_HTML"
fi
if [ "$GRYPE_HIGH" -gt 0 ]; then
    echo "                        <span class=\"tool-stat-badge badge-high\">⚠️ ${GRYPE_HIGH}</span>" >> "$OUTPUT_HTML"
fi
if [ "$GRYPE_CRITICAL" -eq 0 ] && [ "$GRYPE_HIGH" -eq 0 ]; then
    echo "                        <span class=\"tool-stat-badge badge-clean\">✅ Clean</span>" >> "$OUTPUT_HTML"
fi

cat >> "$OUTPUT_HTML" << EOF
                        <span class="expand-icon">▼</span>
                    </div>
                </div>
                <div class="tool-content" id="grype-content">
                    <div class="tool-findings">
                        <div class="stats-detail-box">
                            <h4>📊 Scan Statistics</h4>
                            <div class="stats-grid-small">
                                <div class="stat-item"><strong>Targets Scanned:</strong> ${GRYPE_TARGETS_SCANNED}</div>
                                <div class="stat-item"><strong>Total Vulnerabilities:</strong> ${GRYPE_TOTAL_VULNS}</div>
                                <div class="stat-item"><strong>Critical:</strong> ${GRYPE_CRITICAL}</div>
                                <div class="stat-item"><strong>High:</strong> ${GRYPE_HIGH}</div>
                                <div class="stat-item"><strong>Medium:</strong> ${GRYPE_MEDIUM}</div>
                                <div class="stat-item"><strong>Low:</strong> ${GRYPE_LOW}</div>
                            </div>
                        </div>
                        ${GRYPE_FINDINGS}
                    </div>
                </div>
            </div>

            <!-- SBOM -->
            <div class="tool-card">
                <div class="tool-header" onclick="toggleTool('sbom')">
                    <div class="tool-title">
                        <span class="tool-icon">📦</span>
                        <div>
                            <div>SBOM</div>
                            <div style="font-size: 0.6em; font-weight: 400; color: #718096;">Software Bill of Materials</div>
                        </div>
                    </div>
                    <div class="tool-stats">
                        <span class="tool-stat-badge" style="background: #e0f2fe; color: #0369a1;">📊 ${SBOM_PACKAGES} packages</span>
                        <span class="expand-icon">▼</span>
                    </div>
                </div>
                <div class="tool-content" id="sbom-content">
                    <div class="tool-findings">
                        <div class="stats-detail-box">
                            <h4>📊 SBOM Statistics</h4>
                            <div class="stats-grid-small">
                                <div class="stat-item"><strong>SBOM Files Generated:</strong> ${SBOM_FILES_GENERATED}</div>
                                <div class="stat-item"><strong>Total Packages Cataloged:</strong> ${SBOM_PACKAGES}</div>
                            </div>
                        </div>
                        ${SBOM_FINDINGS}
                    </div>
                </div>
            </div>
EOF

# ---- Xeol (EOL Detection) Section ----
cat >> "$OUTPUT_HTML" << EOF
            <!-- Xeol (EOL Detection) -->
            <div class="tool-card">
                <div class="tool-header" onclick="toggleTool('xeol')">
                    <div class="tool-title">
                        <span class="tool-icon">📅</span>
                        <div>
                            <div>Xeol</div>
                            <div style="font-size: 0.6em; font-weight: 400; color: #718096;">End-of-Life Detection</div>
                        </div>
                    </div>
                    <div class="tool-stats">
EOF

# Add Xeol stats
if [ "$XEOL_HIGH" -gt 0 ]; then
    echo "                        <span class=\"tool-stat-badge badge-high\">⚠️ ${XEOL_HIGH} EOL</span>" >> "$OUTPUT_HTML"
else
    echo "                        <span class=\"tool-stat-badge badge-clean\">✅ Clean</span>" >> "$OUTPUT_HTML"
fi

cat >> "$OUTPUT_HTML" << EOF
                        <span class="expand-icon">▼</span>
                    </div>
                </div>
                <div class="tool-content" id="xeol-content">
                    <div class="tool-findings">
                        <div class="stats-detail-box">
                            <h4>📊 EOL Detection Statistics</h4>
                            <div class="stats-grid-small">
                                <div class="stat-item"><strong>🐳 Base Images Scanned:</strong> ${XEOL_IMAGES_SCANNED}</div>
                                <div class="stat-item"><strong>📁 Filesystem Paths:</strong> ${XEOL_FILESYSTEM_PATHS}</div>
                                <div class="stat-item"><strong>⚰️ EOL Components:</strong> ${XEOL_TOTAL_EOL}</div>
                                <div class="stat-item"><strong>🗄️ Database Version:</strong> ${XEOL_DB_VERSION}</div>
                                <div class="stat-item"><strong>⏱️ Scan Duration:</strong> ${XEOL_SCAN_DURATION}s</div>
                                <div class="stat-item"><strong>📊 Data Source:</strong> endoflife.date</div>
                            </div>
                        </div>
                        ${XEOL_FINDINGS}
                    </div>
                </div>
            </div>

            <!-- Anchore -->
            <div class="tool-card">
                <div class="tool-header" onclick="toggleTool('anchore')">
                    <div class="tool-title">
                        <span class="tool-icon">⚓</span>
                        <div>
                            <div>Anchore</div>
                            <div style="font-size: 0.6em; font-weight: 400; color: #718096;">Enterprise Security Scanner</div>
                        </div>
                    </div>
                    <div class="tool-stats">
EOF

# Add Anchore stats
if [ "$ANCHORE_CRITICAL" -gt 0 ]; then
    echo "                        <span class=\"tool-stat-badge badge-critical\">❗ ${ANCHORE_CRITICAL}</span>" >> "$OUTPUT_HTML"
fi
if [ "$ANCHORE_HIGH" -gt 0 ]; then
    echo "                        <span class=\"tool-stat-badge badge-high\">⚠️ ${ANCHORE_HIGH}</span>" >> "$OUTPUT_HTML"
fi
if [ "$ANCHORE_CRITICAL" -eq 0 ] && [ "$ANCHORE_HIGH" -eq 0 ]; then
    if [ "$ANCHORE_STATUS" = "placeholder" ]; then
        echo "                        <span class=\"tool-stat-badge\" style=\"background: #e0f2fe; color: #0369a1;\">ℹ️ Planned</span>" >> "$OUTPUT_HTML"
    else
        echo "                        <span class=\"tool-stat-badge badge-clean\">✅ Clean</span>" >> "$OUTPUT_HTML"
    fi
fi

cat >> "$OUTPUT_HTML" << EOF
                        <span class="expand-icon">▼</span>
                    </div>
                </div>
                <div class="tool-content" id="anchore-content">
                    <div class="tool-findings">
                        <div class="stats-detail-box">
                            <h4>📊 Anchore Statistics</h4>
                            <div class="stats-grid-small">
                                <div class="stat-item"><strong>Status:</strong> ${ANCHORE_STATUS}</div>
                                <div class="stat-item"><strong>Total Vulnerabilities:</strong> ${ANCHORE_TOTAL_VULNS}</div>
                                <div class="stat-item"><strong>Critical:</strong> ${ANCHORE_CRITICAL}</div>
                                <div class="stat-item"><strong>High:</strong> ${ANCHORE_HIGH}</div>
                                <div class="stat-item"><strong>Medium:</strong> ${ANCHORE_MEDIUM}</div>
                                <div class="stat-item"><strong>Low:</strong> ${ANCHORE_LOW}</div>
                            </div>
                        </div>
                        ${ANCHORE_FINDINGS}
                    </div>
                </div>
            </div>
        </div>

        <div class="footer">
            <p style="color: #718096; margin-bottom: 10px;">
                Comprehensive Security Architecture Scanner
            </p>
            <p style="color: #a0aec0; font-size: 0.9em;">
                Total Findings: <strong style="color: #2d3748;">${TOTAL_FINDINGS}</strong> • 
                Tools: <strong style="color: #2d3748;">10</strong> • 
                Files Scanned: <strong style="color: #2d3748;">${CLAMAV_FILES_SCANNED}</strong> •
                Images Scanned: <strong style="color: #2d3748;">${TRIVY_IMAGES_SCANNED}</strong>
            </p>
            <div class="footer-links">
                <a href="../index.html" class="footer-link">📄 All Reports</a>
                <a href="../html-reports/" class="footer-link">📊 HTML Reports</a>
                <a href="../markdown-reports/" class="footer-link">📝 Markdown</a>
                <a href="../csv-reports/" class="footer-link">📈 CSV Data</a>
            </div>
        </div>
    </div>

    <script>
        // Current filter state
        let currentFilter = 'all';
        let currentSourceFilter = 'all';
        let currentSort = 'severity';
        
        // Severity priority for sorting
        const severityOrder = { 'critical': 0, 'high': 1, 'medium': 2, 'low': 3 };
        
        function toggleTool(toolId) {
            const header = document.querySelector('#' + toolId + '-content').previousElementSibling;
            const content = document.getElementById(toolId + '-content');
            
            // Close all other tools
            document.querySelectorAll('.tool-header').forEach(h => {
                if (h !== header) {
                    h.classList.remove('active');
                }
            });
            document.querySelectorAll('.tool-content').forEach(c => {
                if (c !== content) {
                    c.classList.remove('active');
                }
            });
            
            // Toggle current tool
            header.classList.toggle('active');
            content.classList.toggle('active');
        }
        
        // Toggle individual finding details
        function toggleFindingDetails(element) {
            event.stopPropagation();
            
            // Don't toggle if user is selecting text
            const selection = window.getSelection();
            if (selection.toString().length > 0) {
                return;
            }
            
            // Don't toggle if clicking on links, buttons, or interactive elements
            if (event.target.tagName === 'A' || event.target.tagName === 'BUTTON' || event.target.tagName === 'INPUT') {
                return;
            }
            
            const details = element.querySelector('.finding-details');
            const isExpanded = details.style.display === 'block';
            
            // If clicking inside an already expanded details section, don't toggle
            if (isExpanded && event.target.closest('.finding-details')) {
                return;
            }
            
            // Collapse all other findings in the same tool section
            const parent = element.closest('.tool-findings');
            if (parent) {
                parent.querySelectorAll('.finding-details').forEach(d => {
                    d.style.display = 'none';
                });
                parent.querySelectorAll('.finding-item').forEach(f => {
                    f.classList.remove('expanded');
                });
            }
            
            // Toggle this finding
            if (!isExpanded) {
                details.style.display = 'block';
                element.classList.add('expanded');
                element.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
            }
        }
        
        // Filter findings by severity
        function filterBySeverity(severity) {
            currentFilter = severity;
            
            // Update chip active states
            document.querySelectorAll('.filter-chip').forEach(chip => {
                chip.classList.remove('active');
            });
            document.querySelector('.filter-chip-' + severity).classList.add('active');
            
            // Get all finding items
            const findings = document.querySelectorAll('.finding-item');
            let visibleCount = 0;
            
            findings.forEach(finding => {
                const findingSource = finding.dataset.source || 'app';
                
                // Check both severity filter and source filter
                let passesSeverityFilter = (severity === 'all') || finding.classList.contains('severity-' + severity);
                let passesSourceFilter = (typeof currentSourceFilter === 'undefined' || currentSourceFilter === 'all') || (findingSource === currentSourceFilter);
                
                if (passesSeverityFilter && passesSourceFilter) {
                    finding.classList.remove('filtered-out');
                    visibleCount++;
                } else {
                    finding.classList.add('filtered-out');
                }
            });
            
            // Update tool card opacity based on visible findings
            document.querySelectorAll('.tool-card').forEach(card => {
                const visibleInCard = card.querySelectorAll('.finding-item:not(.filtered-out)').length;
                if ((severity !== 'all' || (typeof currentSourceFilter !== 'undefined' && currentSourceFilter !== 'all')) && visibleInCard === 0) {
                    card.classList.add('filtered-out');
                } else {
                    card.classList.remove('filtered-out');
                }
            });
            
            // Show/hide filter results bar
            const resultsBar = document.getElementById('filter-results');
            const countSpan = document.getElementById('filter-count');
            const srcFilter = (typeof currentSourceFilter !== 'undefined') ? currentSourceFilter : 'all';
            
            if (severity === 'all' && srcFilter === 'all') {
                resultsBar.style.display = 'none';
            } else {
                resultsBar.style.display = 'flex';
                let filterText = 'Showing ' + visibleCount + ' findings';
                if (severity !== 'all') filterText += ' (' + severity.toUpperCase() + ')';
                if (srcFilter !== 'all') filterText += ' from ' + (srcFilter === 'image' ? 'Container Image' : 'Application Code');
                countSpan.textContent = filterText;
            }
            
            // Expand tools with visible findings
            if (severity !== 'all') {
                document.querySelectorAll('.tool-card:not(.filtered-out)').forEach(card => {
                    const content = card.querySelector('.tool-content');
                    const header = card.querySelector('.tool-header');
                    if (content && !content.classList.contains('active')) {
                        header.classList.add('active');
                        content.classList.add('active');
                    }
                });
            }
        }
        
        // Filter findings by source (container image vs application code)
        function filterBySource(source) {
            currentSourceFilter = source;
            
            // Update source chip active states
            document.querySelectorAll('.source-chip').forEach(chip => {
                chip.classList.remove('active');
            });
            document.querySelector('.source-chip-' + source).classList.add('active');
            
            // Get all finding items
            const findings = document.querySelectorAll('.finding-item');
            let visibleCount = 0;
            
            findings.forEach(finding => {
                const findingSource = finding.dataset.source || 'app';
                
                // Check both severity filter and source filter
                let passesSourceFilter = (source === 'all') || (findingSource === source);
                let passesSeverityFilter = (currentFilter === 'all') || finding.classList.contains('severity-' + currentFilter);
                
                if (passesSourceFilter && passesSeverityFilter) {
                    finding.classList.remove('filtered-out');
                    visibleCount++;
                } else {
                    finding.classList.add('filtered-out');
                }
            });
            
            // Update tool card opacity based on visible findings
            document.querySelectorAll('.tool-card').forEach(card => {
                const visibleInCard = card.querySelectorAll('.finding-item:not(.filtered-out)').length;
                if ((source !== 'all' || currentFilter !== 'all') && visibleInCard === 0) {
                    card.classList.add('filtered-out');
                } else {
                    card.classList.remove('filtered-out');
                }
            });
            
            // Show/hide filter results bar
            const resultsBar = document.getElementById('filter-results');
            const countSpan = document.getElementById('filter-count');
            
            if (source === 'all' && currentFilter === 'all') {
                resultsBar.style.display = 'none';
            } else {
                resultsBar.style.display = 'flex';
                let filterText = 'Showing ' + visibleCount + ' findings';
                if (source !== 'all') filterText += ' from ' + (source === 'image' ? 'Container Image' : 'Application Code');
                if (currentFilter !== 'all') filterText += ' (' + currentFilter.toUpperCase() + ')';
                countSpan.textContent = filterText;
            }
        }
        
        // Sort findings within each tool
        function sortFindings(sortType) {
            currentSort = sortType;
            
            // Update sort button states
            document.querySelectorAll('.sort-btn').forEach(btn => btn.classList.remove('active'));
            document.getElementById('sort-' + sortType).classList.add('active');
            
            // Get all tool finding containers
            document.querySelectorAll('.tool-findings').forEach(container => {
                const findings = Array.from(container.querySelectorAll('.finding-item'));
                
                if (findings.length === 0) return;
                
                // Sort based on type
                if (sortType === 'severity') {
                    findings.sort((a, b) => {
                        const aSeverity = getSeverityFromClasses(a.classList);
                        const bSeverity = getSeverityFromClasses(b.classList);
                        return severityOrder[aSeverity] - severityOrder[bSeverity];
                    });
                } else if (sortType === 'tool') {
                    // Already grouped by tool, so just sort by tool badge text
                    findings.sort((a, b) => {
                        const aTool = a.querySelector('.badge-tool')?.textContent || '';
                        const bTool = b.querySelector('.badge-tool')?.textContent || '';
                        return aTool.localeCompare(bTool);
                    });
                }
                
                // Re-append in sorted order (moves elements)
                findings.forEach(finding => container.appendChild(finding));
            });
        }
        
        // Helper to get severity from class list
        function getSeverityFromClasses(classList) {
            if (classList.contains('severity-critical')) return 'critical';
            if (classList.contains('severity-high')) return 'high';
            if (classList.contains('severity-medium')) return 'medium';
            if (classList.contains('severity-low')) return 'low';
            return 'low';
        }
        
        // Click on stat cards to filter
        document.querySelectorAll('.stat-card').forEach(card => {
            card.style.cursor = 'pointer';
            card.addEventListener('click', () => {
                if (card.classList.contains('critical-stat')) filterBySeverity('critical');
                else if (card.classList.contains('high-stat')) filterBySeverity('high');
                else if (card.classList.contains('medium-stat')) filterBySeverity('medium');
                else if (card.classList.contains('low-stat')) filterBySeverity('low');
            });
        });
        
        // Filter SBOM packages by search term
        let currentSBOMTypeFilter = 'all';
        let currentSBOMSort = 'name';
        
        function filterSBOMPackages(searchTerm) {
            const packages = document.querySelectorAll('.sbom-package-item');
            const term = searchTerm.toLowerCase().trim();
            let visibleCount = 0;
            
            packages.forEach(pkg => {
                const name = pkg.dataset.name || '';
                const type = pkg.dataset.type || '';
                const version = pkg.dataset.version || '';
                const language = pkg.dataset.language || '';
                
                const matchesSearch = term === '' || 
                    name.includes(term) || 
                    type.toLowerCase().includes(term) || 
                    version.toLowerCase().includes(term) ||
                    language.toLowerCase().includes(term);
                
                const matchesType = currentSBOMTypeFilter === 'all' || type === currentSBOMTypeFilter;
                
                if (matchesSearch && matchesType) {
                    pkg.classList.remove('filtered-out');
                    visibleCount++;
                } else {
                    pkg.classList.add('filtered-out');
                }
            });
            
            updateSBOMResultsBar(visibleCount, term !== '' || currentSBOMTypeFilter !== 'all');
        }
        
        // Filter SBOM by package type
        function filterSBOMByType(button, type) {
            currentSBOMTypeFilter = type;
            
            // Update active chip state
            document.querySelectorAll('.sbom-filter-chip').forEach(chip => {
                chip.classList.remove('active');
            });
            button.classList.add('active');
            
            // Re-apply filters
            const searchTerm = document.getElementById('sbom-search')?.value || '';
            filterSBOMPackages(searchTerm);
        }
        
        // Sort SBOM packages
        function sortSBOMPackages(sortBy) {
            currentSBOMSort = sortBy;
            
            // Update active button
            document.querySelectorAll('.sbom-sort-btn').forEach(btn => btn.classList.remove('active'));
            document.getElementById('sbom-sort-' + sortBy)?.classList.add('active');
            
            const container = document.getElementById('sbom-package-list');
            if (!container) return;
            
            const packages = Array.from(container.querySelectorAll('.sbom-package-item'));
            
            packages.sort((a, b) => {
                let aVal, bVal;
                
                switch(sortBy) {
                    case 'name':
                        aVal = a.dataset.name || '';
                        bVal = b.dataset.name || '';
                        return aVal.localeCompare(bVal);
                    case 'type':
                        aVal = a.dataset.type || '';
                        bVal = b.dataset.type || '';
                        return aVal.localeCompare(bVal) || (a.dataset.name || '').localeCompare(b.dataset.name || '');
                    case 'version':
                        aVal = a.dataset.version || '0';
                        bVal = b.dataset.version || '0';
                        // Simple version comparison
                        return bVal.localeCompare(aVal, undefined, {numeric: true});
                    default:
                        return 0;
                }
            });
            
            // Re-append in sorted order
            packages.forEach(pkg => container.appendChild(pkg));
        }
        
        // Update SBOM results bar
        function updateSBOMResultsBar(count, hasFilter) {
            const countEl = document.getElementById('sbom-results-count');
            const clearEl = document.getElementById('sbom-clear-filter');
            
            if (countEl) {
                let filterText = '';
                if (currentSBOMTypeFilter !== 'all') {
                    filterText = ' (' + currentSBOMTypeFilter + ')';
                }
                countEl.textContent = 'Showing ' + count + ' packages' + filterText;
            }
            
            if (clearEl) {
                clearEl.style.display = hasFilter ? 'inline' : 'none';
            }
        }
        
        // Reset SBOM filters
        function resetSBOMFilters() {
            currentSBOMTypeFilter = 'all';
            
            // Reset search
            const searchInput = document.getElementById('sbom-search');
            if (searchInput) searchInput.value = '';
            
            // Reset type filter chips
            document.querySelectorAll('.sbom-filter-chip').forEach(chip => {
                chip.classList.remove('active');
                if (chip.dataset.type === 'all') chip.classList.add('active');
            });
            
            // Show all packages
            document.querySelectorAll('.sbom-package-item').forEach(pkg => {
                pkg.classList.remove('filtered-out');
            });
            
            // Update results bar
            const totalPackages = document.querySelectorAll('.sbom-package-item').length;
            updateSBOMResultsBar(totalPackages, false);
        }
        
        // Trivy-specific filters
        let currentTrivyStatusFilter = 'all';
        let currentTrivySearchTerm = '';
        
        function filterTrivyByStatus(status) {
            currentTrivyStatusFilter = status;
            
            // Update button states in trivy section
            const trivyContent = document.getElementById('trivy-content');
            if (trivyContent) {
                trivyContent.querySelectorAll('.trivy-controls .filter-chip').forEach(btn => {
                    btn.classList.remove('active');
                });
                event.target.classList.add('active');
            }
            
            applyTrivyFilters();
        }
        
        function filterTrivyBySearch(searchTerm) {
            currentTrivySearchTerm = searchTerm.toLowerCase().trim();
            applyTrivyFilters();
        }
        
        function applyTrivyFilters() {
            const trivyContent = document.getElementById('trivy-content');
            if (!trivyContent) return;
            
            const findings = trivyContent.querySelectorAll('.finding-item');
            let visibleCount = 0;
            
            findings.forEach(finding => {
                let showByStatus = true;
                let showBySearch = true;
                
                // Check status filter
                if (currentTrivyStatusFilter !== 'all') {
                    const status = finding.dataset.status || '';
                    if (currentTrivyStatusFilter === 'fixed') {
                        showByStatus = status === 'fixed';
                    } else if (currentTrivyStatusFilter === 'affected') {
                        showByStatus = status !== 'fixed';
                    }
                }
                
                // Check search filter
                if (currentTrivySearchTerm) {
                    const cve = (finding.dataset.cve || '').toLowerCase();
                    const pkg = (finding.dataset.pkg || '').toLowerCase();
                    const title = (finding.querySelector('.finding-title')?.textContent || '').toLowerCase();
                    const desc = (finding.querySelector('.finding-desc')?.textContent || '').toLowerCase();
                    
                    showBySearch = cve.includes(currentTrivySearchTerm) || 
                                   pkg.includes(currentTrivySearchTerm) ||
                                   title.includes(currentTrivySearchTerm) ||
                                   desc.includes(currentTrivySearchTerm);
                }
                
                if (showByStatus && showBySearch) {
                    finding.classList.remove('filtered-out');
                    visibleCount++;
                } else {
                    finding.classList.add('filtered-out');
                }
            });
            
            // Show filtered count
            console.log('Trivy filter: showing ' + visibleCount + ' of ' + findings.length);
        }
        
        // Count findings by source and update the filter chips
        function updateSourceCounts() {
            const findings = document.querySelectorAll('.finding-item');
            let imageCount = 0;
            let appCount = 0;
            
            findings.forEach(finding => {
                const source = finding.dataset.source || 'app';
                if (source === 'image') {
                    imageCount++;
                } else {
                    appCount++;
                }
            });
            
            document.getElementById('source-count-all').textContent = findings.length;
            document.getElementById('source-count-image').textContent = imageCount;
            document.getElementById('source-count-app').textContent = appCount;
        }
        
        // Auto-expand first tool with findings
        window.addEventListener('DOMContentLoaded', () => {
            // Update source counts based on actual data-source attributes
            updateSourceCounts();
            
            const badges = Array.from(document.querySelectorAll('.tool-stat-badge'));
            const firstIssue = badges.find(badge => badge.textContent.includes('❗') || badge.textContent.includes('⚠️'));
            
            if (firstIssue) {
                const toolCard = firstIssue.closest('.tool-card');
                const toolHeader = toolCard.querySelector('.tool-header');
                toolHeader.click();
            }
            
            // Initial sort by severity
            sortFindings('severity');
        });
    </script>
</body>
</html>
EOF

echo ""
echo "✅ Interactive dashboard generated: $OUTPUT_HTML"
echo ""
echo "Summary:"
echo "  Critical: $TOTAL_CRITICAL"
echo "  High:     $TOTAL_HIGH"
echo "  Medium:   $TOTAL_MEDIUM"
echo "  Low:      $TOTAL_LOW"
echo "  Total:    $TOTAL_FINDINGS"
echo ""
echo "Open the dashboard:"
echo "  open $OUTPUT_HTML"
