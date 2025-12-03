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

# ---- TruffleHog Statistics ----
TH_FILE="${LATEST_SCAN}/trufflehog/trufflehog-filesystem-results.json"
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
        map("<div class=\"finding-item severity-" + (if .Verified then "critical" else "medium" end) + "\" onclick=\"toggleFindingDetails(this)\">
            <div class=\"finding-header\">
                <span class=\"badge badge-tool\">TruffleHog</span>
                <span class=\"badge badge-" + (if .Verified then "critical" else "medium" end) + "\">" + (if .Verified then "VERIFIED" else "UNVERIFIED" end) + "</span>
                <span class=\"badge\" style=\"background:#e2e8f0;color:#4a5568;\">" + .DetectorName + "</span>
            </div>
            <div class=\"finding-title\">" + .DetectorName + " - " + (if .Verified then "Verified Secret Found!" else "Potential Secret Detected" end) + "</div>
            <div class=\"finding-desc\">" + (.DetectorDescription // "Secret or credential pattern detected in source code") + "</div>
            <div class=\"finding-details\" style=\"display:none;\">
                <div><strong>Detector:</strong> <code>" + .DetectorName + "</code></div>
                <div><strong>Verified:</strong> " + (if .Verified then "<span style=\"color:#e53e3e;font-weight:bold;\">Yes - Active credential!</span>" else "<span style=\"color:#d69e2e;\">No - Potential secret</span>" end) + "</div>
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
        TH_FINDINGS="<p style=\"color:#718096;margin-bottom:15px;font-size:0.9em;\">👆 Click on any finding below to expand details</p>${TH_FINDINGS_HTML}"
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
    CLAMAV_DATA_SCANNED=$(grep "Data scanned:" "$CLAMAV_LOG" 2>/dev/null | sed 's/Data scanned: //' || echo "N/A")
    CLAMAV_SCAN_TIME=$(grep "^Time:" "$CLAMAV_LOG" 2>/dev/null | sed 's/Time: //' || echo "N/A")
    CLAMAV_ENGINE_VERSION=$(grep "Engine version:" "$CLAMAV_LOG" 2>/dev/null | sed 's/Engine version: //' || echo "N/A")
    CLAMAV_VIRUS_DB_COUNT=$(grep "Known viruses:" "$CLAMAV_LOG" 2>/dev/null | grep -oE '[0-9]+' || echo "0")
    CLAMAV_INFECTED=$(grep "Infected files:" "$CLAMAV_LOG" 2>/dev/null | grep -oE '[0-9]+' || echo "0")
    CLAMAV_DIRECTORIES=$(grep "Scanned directories:" "$CLAMAV_LOG" 2>/dev/null | grep -oE '[0-9]+' || echo "0")
fi
CLAMAV_CRITICAL=${CLAMAV_INFECTED:-0}
if [ "$CLAMAV_CRITICAL" -gt 0 ]; then
    CLAMAV_FINDINGS="<div class=\"finding-item severity-critical\">
        <div class=\"finding-header\">
            <span class=\"badge badge-tool\">ClamAV</span>
            <span class=\"badge badge-critical\">CRITICAL</span>
        </div>
        <div class=\"finding-title\">⚠️ Malware Detected</div>
        <div class=\"finding-desc\">$CLAMAV_CRITICAL infected files found</div>
        <div class=\"finding-details\">
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
    TRIVY_IMAGES_SCANNED=$(find "$TRIVY_DIR" -name "*.json" -type f 2>/dev/null | wc -l | tr -d ' \n' || echo "0")
    [[ "$TRIVY_IMAGES_SCANNED" =~ ^[0-9]+$ ]] || TRIVY_IMAGES_SCANNED=0
    
    # Parse vulnerabilities from all Trivy JSON files
    for trivy_file in "$TRIVY_DIR"/*.json; do
        if [ -f "$trivy_file" ] && grep -q '"SchemaVersion"' "$trivy_file" 2>/dev/null; then
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
                  purl: ((.PkgIdentifier.PURL // "") | html_escape)}
                ] | sort_by(.severity | if . == "CRITICAL" then 0 elif . == "HIGH" then 1 elif . == "MEDIUM" then 2 else 3 end) | .[0:50] | .[] |
                "<div class=\"finding-item severity-" + .severity_lc + "\" data-pkg=\"" + .pkg + "\" data-status=\"" + .status + "\" data-cve=\"" + .id + "\" onclick=\"toggleFindingDetails(this)\">
<div class=\"finding-header\">
<span class=\"badge badge-tool\">Trivy</span>
<span class=\"badge badge-" + .severity_lc + "\">" + .severity + "</span>
<span class=\"badge\" style=\"background:#e2e8f0;color:#4a5568;\">" + .id + "</span>
<span class=\"badge\" style=\"background:" + .status_badge + ";\">" + .status_uc + "</span>
</div>
<div class=\"finding-title\">" + .pkg + "@" + .installed + " - " + .title + "</div>
<div class=\"finding-desc\">" + .desc_short + "...</div>
<div class=\"finding-details\" style=\"display:none;\">
<div class=\"detail-section\"><h5>Vulnerability Info</h5>
<div><strong>CVE ID:</strong> <code>" + .id + "</code> <a href=\"" + .primary_url + "\" target=\"_blank\" style=\"color:#667eea;\">View Details</a></div>
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
                TRIVY_DETAILS="${TRIVY_DETAILS}${vuln_details}"
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
    GRYPE_TARGETS_SCANNED=$(find "$GRYPE_DIR" -name "grype-*.json" -type f 2>/dev/null | wc -l | tr -d ' \n' || echo "0")
    [[ "$GRYPE_TARGETS_SCANNED" =~ ^[0-9]+$ ]] || GRYPE_TARGETS_SCANNED=0
    
    for grype_file in "$GRYPE_DIR"/grype-*.json; do
        if [ -f "$grype_file" ]; then
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
                [.matches[]? | 
                 {id: .vulnerability.id, pkg: .artifact.name, version: .artifact.version, 
                  severity: .vulnerability.severity, 
                  fixed: (.vulnerability.fix.versions[0] // "Not fixed"),
                  desc: (.vulnerability.description // "No description available")}
                ] | sort_by(.severity | if . == "Critical" then 0 elif . == "High" then 1 elif . == "Medium" then 2 else 3 end) | .[0:50] | .[] |
                "<div class=\"finding-item severity-\(.severity | ascii_downcase)\" onclick=\"toggleFindingDetails(this)\">
                    <div class=\"finding-header\">
                        <span class=\"badge badge-tool\">Grype</span>
                        <span class=\"badge badge-\(.severity | ascii_downcase)\">\(.severity)</span>
                        <span class=\"badge\" style=\"background:#e2e8f0;color:#4a5568;\">\(.id)</span>
                    </div>
                    <div class=\"finding-title\">\(.pkg)@\(.version)</div>
                    <div class=\"finding-desc\">\(.desc | .[0:200])...</div>
                    <div class=\"finding-details\" style=\"display:none;\">
                        <div><strong>CVE ID:</strong> <code>\(.id)</code></div>
                        <div><strong>Package:</strong> <code>\(.pkg)</code></div>
                        <div><strong>Installed Version:</strong> <code>\(.version)</code></div>
                        <div><strong>Fixed Version:</strong> <code>\(.fixed)</code></div>
                        <div><strong>Full Description:</strong> \(.desc)</div>
                    </div>
                </div>"
            ' "$grype_file" 2>/dev/null)
            set -e
            
            if [ -n "$vuln_details" ]; then
                GRYPE_DETAILS="${GRYPE_DETAILS}${vuln_details}"
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
CHECKOV_CRITICAL=$CHECKOV_FAILED
CHECKOV_HIGH=0
CHECKOV_TOTAL=$((CHECKOV_PASSED + CHECKOV_FAILED + CHECKOV_SKIPPED))

# Build Checkov findings display
if [ "$CHECKOV_TOTAL" -gt 0 ]; then
    CHECKOV_FINDINGS="<div class=\"stats-grid-small\">
        <div class=\"stat-item\"><strong>✅ Passed:</strong> ${CHECKOV_PASSED}</div>
        <div class=\"stat-item\"><strong>❌ Failed:</strong> ${CHECKOV_FAILED}</div>
        <div class=\"stat-item\"><strong>⏭️ Skipped:</strong> ${CHECKOV_SKIPPED}</div>
        <div class=\"stat-item\"><strong>📊 Total Checks:</strong> ${CHECKOV_TOTAL}</div>
    </div>"
    if [ -n "$CHECKOV_CHECK_TYPES" ]; then
        CHECKOV_FINDINGS="${CHECKOV_FINDINGS}<p style=\"margin-top: 10px; color: #718096;\">Check types: ${CHECKOV_CHECK_TYPES}</p>"
    fi
    
    # Add failed checks details if any failures exist
    if [ "$CHECKOV_FAILED" -gt 0 ]; then
        CHECKOV_FINDINGS="${CHECKOV_FINDINGS}<div class=\"findings-section\" style=\"margin-top: 15px;\">
            <h4 style=\"color: #e53e3e; margin-bottom: 10px;\">❌ Failed Checks (${CHECKOV_FAILED})</h4>
            <table class=\"findings-table\">
                <thead>
                    <tr>
                        <th>Check ID</th>
                        <th>Check Name</th>
                        <th>File</th>
                        <th>Line</th>
                    </tr>
                </thead>
                <tbody>"
        
        # Extract failed checks from all Checkov JSON files
        for checkov_file in "$CHECKOV_DIR"/*.json; do
            # Skip symlinks to avoid duplicate processing
            if [ -f "$checkov_file" ] && [ ! -L "$checkov_file" ] && [[ "$(basename "$checkov_file")" != *"summary"* ]]; then
                # Get failed checks as TSV for easy parsing
                while IFS=$'\t' read -r check_id check_name file_path line_start; do
                    if [ -n "$check_id" ]; then
                        # Escape HTML entities
                        check_name_escaped=$(echo "$check_name" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g')
                        file_display=$(basename "$file_path" 2>/dev/null || echo "$file_path")
                        CHECKOV_FINDINGS="${CHECKOV_FINDINGS}
                    <tr class=\"severity-critical\">
                        <td><code>${check_id}</code></td>
                        <td>${check_name_escaped}</td>
                        <td><code>${file_display}</code></td>
                        <td>${line_start}</td>
                    </tr>"
                    fi
                done < <(jq -r '[.[] | select(.results?) | .results.failed_checks[]] | .[] | [.check_id, .check_name, .file_path, (.file_line_range[0] // "N/A" | tostring)] | @tsv' "$checkov_file" 2>/dev/null)
            fi
        done
        
        CHECKOV_FINDINGS="${CHECKOV_FINDINGS}
                </tbody>
            </table>
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
if [ -f "$LATEST_SONAR" ]; then
    SONAR_STATUS=$(jq -r '.status' "$LATEST_SONAR" 2>/dev/null || echo "NO_DATA")
    if [ "$SONAR_STATUS" = "NO_PROJECT_DETECTED" ]; then
        SONAR_FINDINGS="<p class=\"no-findings\">No SonarQube project detected</p>"
        SONAR_CRITICAL=0
        SONAR_HIGH=0
    else
        SONAR_FINDINGS="<p class=\"no-findings\">✅ SonarQube analysis complete - check server for details</p>"
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
XEOL_FINDINGS=""
if [ -d "$XEOL_DIR" ]; then
    # Count actual JSON files (not symlinks)
    XEOL_IMAGES_SCANNED=$(find "$XEOL_DIR" -name "*xeol-*.json" -type f 2>/dev/null | wc -l | tr -d ' \n' || echo "0")
    [[ "$XEOL_IMAGES_SCANNED" =~ ^[0-9]+$ ]] || XEOL_IMAGES_SCANNED=0
    
    for xeol_file in "$XEOL_DIR"/*xeol-*.json; do
        if [ -f "$xeol_file" ] && [ ! -L "$xeol_file" ]; then
            eol_count=$(jq '.matches | length' "$xeol_file" 2>/dev/null || echo "0")
            [[ "$eol_count" =~ ^[0-9]+$ ]] || eol_count=0
            XEOL_TOTAL_EOL=$((XEOL_TOTAL_EOL + eol_count))
            
            # Count by severity (Xeol uses "Cycle" info, treat EOL as High)
            if [ "$eol_count" -gt 0 ]; then
                XEOL_HIGH=$((XEOL_HIGH + eol_count))
            fi
        fi
    done
    
    if [ "$XEOL_TOTAL_EOL" -gt 0 ]; then
        XEOL_FINDINGS="<p class=\"finding-item severity-high\">⚠️ ${XEOL_TOTAL_EOL} end-of-life components detected across ${XEOL_IMAGES_SCANNED} scans</p>"
    else
        XEOL_FINDINGS="<p class=\"no-findings\">✅ No end-of-life components detected (${XEOL_IMAGES_SCANNED} targets scanned)</p>"
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

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Generate the dashboard HTML
cat > "$OUTPUT_HTML" << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Interactive Security Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
            color: #2d3748;
        }
        
        .container {
            max-width: 1600px;
            margin: 0 auto;
        }
        
        .header {
            background: white;
            border-radius: 16px;
            padding: 40px;
            margin-bottom: 30px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.15);
            text-align: center;
        }
        
        .header h1 {
            font-size: 2.8em;
            margin-bottom: 10px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        
        .header .subtitle {
            color: #718096;
            font-size: 1.1em;
            margin-top: 10px;
        }
        
        .alert-banner {
            background: linear-gradient(135deg, #e53e3e 0%, #c53030 100%);
            color: white;
            padding: 25px;
            border-radius: 12px;
            margin-bottom: 30px;
            box-shadow: 0 4px 20px rgba(229, 62, 62, 0.3);
            text-align: center;
            animation: pulse 2s infinite;
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
            background: white;
            border-radius: 12px;
            padding: 30px;
            text-align: center;
            box-shadow: 0 4px 20px rgba(0,0,0,0.1);
            transition: all 0.3s ease;
            cursor: pointer;
        }
        
        .stat-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 8px 30px rgba(0,0,0,0.15);
        }
        
        .stat-number {
            font-size: 3em;
            font-weight: bold;
            margin: 15px 0;
        }
        
        .stat-label {
            color: #718096;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
            font-weight: 600;
        }
        
        .critical-stat { color: #e53e3e; border-top: 4px solid #e53e3e; }
        .high-stat { color: #dd6b20; border-top: 4px solid #dd6b20; }
        .medium-stat { color: #d69e2e; border-top: 4px solid #d69e2e; }
        .low-stat { color: #38a169; border-top: 4px solid #38a169; }
        
        .tools-section {
            display: grid;
            gap: 20px;
        }
        
        .tool-card {
            background: white;
            border-radius: 12px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.1);
            overflow: hidden;
            transition: all 0.3s ease;
        }
        
        .tool-header {
            padding: 25px;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: linear-gradient(135deg, #f7fafc 0%, #edf2f7 100%);
            border-bottom: 2px solid #e2e8f0;
            transition: all 0.3s ease;
        }
        
        .tool-header:hover {
            background: linear-gradient(135deg, #edf2f7 0%, #e2e8f0 100%);
        }
        
        .tool-header.active {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
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
        .badge-medium { background: #fef5e7; color: #d69e2e; }
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
        }
        
        .finding-item {
            background: #f7fafc;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 15px;
            border-left: 4px solid #cbd5e0;
            transition: all 0.2s ease;
            cursor: pointer;
        }
        
        .finding-item:hover {
            transform: translateX(5px);
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
        }
        
        .finding-item.expanded {
            transform: translateX(5px);
            box-shadow: 0 8px 24px rgba(0,0,0,0.15);
            border-left-width: 6px;
        }
        
        .finding-item .finding-details {
            margin-top: 15px;
            padding-top: 15px;
            border-top: 1px dashed #e2e8f0;
            animation: slideDown 0.3s ease;
        }
        
        @keyframes slideDown {
            from { opacity: 0; transform: translateY(-10px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        .finding-item.severity-critical {
            border-left-color: #e53e3e;
            background: #fff5f5;
        }
        
        .finding-item.severity-high {
            border-left-color: #dd6b20;
            background: #fffaf0;
        }
        
        .finding-item.severity-medium {
            border-left-color: #d69e2e;
            background: #fef5e7;
        }
        
        .finding-item.severity-low {
            border-left-color: #38a169;
            background: #f0fff4;
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
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
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
            color: #2d3748;
        }
        
        .finding-desc {
            color: #4a5568;
            margin-bottom: 12px;
            line-height: 1.6;
        }
        
        .finding-details {
            background: white;
            padding: 15px;
            border-radius: 6px;
            font-size: 0.9em;
        }
        
        .finding-details div {
            margin-bottom: 8px;
        }
        
        .finding-details div:last-child {
            margin-bottom: 0;
        }
        
        .finding-details code {
            background: #edf2f7;
            padding: 3px 8px;
            border-radius: 4px;
            font-family: 'Monaco', 'Courier New', monospace;
            font-size: 0.9em;
            word-break: break-all;
        }
        
        /* Detail sections for expanded findings */
        .detail-section {
            background: #f7fafc;
            border: 1px solid #e2e8f0;
            border-radius: 8px;
            padding: 15px;
            margin-bottom: 12px;
        }
        
        .detail-section h5 {
            color: #4a5568;
            margin: 0 0 12px 0;
            font-size: 0.95em;
            border-bottom: 1px solid #e2e8f0;
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
            background: white;
            border: 1px solid #e2e8f0;
            border-radius: 6px;
            cursor: pointer;
            transition: all 0.2s ease;
            font-size: 0.9em;
        }
        
        .fp-checklist label:hover {
            background: #edf2f7;
            border-color: #cbd5e0;
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
            background: linear-gradient(135deg, #f0f9ff 0%, #e0f2fe 100%);
            border: 1px solid #7dd3fc;
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 20px;
        }
        
        .stats-detail-box h4 {
            color: #0369a1;
            margin-bottom: 15px;
            font-size: 1.1em;
        }
        
        .stats-grid-small {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 12px;
        }
        
        .stat-item {
            background: white;
            padding: 10px 15px;
            border-radius: 8px;
            font-size: 0.9em;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
        
        .stat-item strong {
            color: #0369a1;
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
            color: #38a169;
            font-size: 1.2em;
        }
        
        /* SBOM Viewer Styles */
        .sbom-controls {
            background: linear-gradient(135deg, #f0f9ff 0%, #e0f2fe 100%);
            border: 1px solid #7dd3fc;
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
            background: white;
            border: 2px solid #7dd3fc;
            border-radius: 20px;
            padding: 6px 14px;
            cursor: pointer;
            transition: all 0.2s ease;
            font-size: 0.9em;
        }
        
        .sbom-filter-chip:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
            background: #e0f2fe;
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
            border: 2px solid #e2e8f0;
            background: white;
            color: #4a5568;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s ease;
        }
        
        .sbom-sort-btn:hover {
            background: #f7fafc;
            border-color: #cbd5e0;
        }
        
        .sbom-sort-btn.active {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border-color: #667eea;
        }
        
        .sbom-results-bar {
            background: #f7fafc;
            padding: 12px 20px;
            border-radius: 8px;
            margin-bottom: 15px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        #sbom-results-count {
            font-weight: 600;
            color: #4a5568;
        }
        
        .sbom-type-breakdown {
            margin-bottom: 20px;
        }
        
        .sbom-type-breakdown h4 {
            color: #0369a1;
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
            background: linear-gradient(135deg, #e0f2fe 0%, #bae6fd 100%);
            border: 1px solid #7dd3fc;
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
            color: #0369a1;
        }
        
        .sbom-type-chip .type-count {
            background: white;
            color: #0369a1;
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 0.85em;
            font-weight: 600;
        }
        
        .sbom-version-badge {
            background: #e0f2fe !important;
            color: #0369a1 !important;
        }
        
        .sbom-lang-badge {
            background: #fef3c7 !important;
            color: #92400e !important;
        }
        
        .sbom-search-box {
            margin-top: 15px;
        }
        
        .sbom-search-box input {
            width: 100%;
            padding: 12px 20px;
            border: 2px solid #e2e8f0;
            border-radius: 10px;
            font-size: 1em;
            transition: all 0.2s ease;
        }
        
        .sbom-search-box input:focus {
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102,126,234,0.1);
        }
        
        .sbom-package-list {
            max-height: 600px;
            overflow-y: auto;
        }
        
        .sbom-package-item {
            background: #f7fafc;
            border-radius: 8px;
            padding: 15px 20px;
            margin-bottom: 10px;
            border-left: 4px solid #7dd3fc;
            transition: all 0.2s ease;
            cursor: pointer;
        }
        
        .sbom-package-item:hover {
            transform: translateX(5px);
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
        }
        
        .sbom-package-item.expanded {
            background: #e0f2fe;
            border-left-width: 6px;
        }
        
        .sbom-package-item.filtered-out {
            display: none;
        }
        
        .footer {
            background: white;
            border-radius: 12px;
            padding: 30px;
            margin-top: 30px;
            text-align: center;
            box-shadow: 0 4px 20px rgba(0,0,0,0.1);
        }
        
        .footer-links {
            display: flex;
            gap: 20px;
            justify-content: center;
            margin-top: 20px;
            flex-wrap: wrap;
        }
        
        .footer-link {
            color: #667eea;
            text-decoration: none;
            font-weight: 600;
            transition: all 0.2s;
        }
        
        .footer-link:hover {
            color: #764ba2;
            text-decoration: underline;
        }
        
        /* Filter Controls */
        .filter-bar {
            background: white;
            border-radius: 12px;
            padding: 20px 30px;
            margin-bottom: 30px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.1);
            display: flex;
            flex-wrap: wrap;
            gap: 15px;
            align-items: center;
        }
        
        .filter-label {
            font-weight: 600;
            color: #4a5568;
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
            background: #e2e8f0;
            color: #4a5568;
        }
        .filter-chip-all.active {
            background: #4a5568;
            color: white;
            border-color: #2d3748;
        }
        
        .filter-chip-critical {
            background: #fff5f5;
            color: #e53e3e;
            border-color: #feb2b2;
        }
        .filter-chip-critical.active {
            background: #e53e3e;
            color: white;
            border-color: #c53030;
        }
        
        .filter-chip-high {
            background: #fffaf0;
            color: #dd6b20;
            border-color: #fbd38d;
        }
        .filter-chip-high.active {
            background: #dd6b20;
            color: white;
            border-color: #c05621;
        }
        
        .filter-chip-medium {
            background: #fffff0;
            color: #d69e2e;
            border-color: #faf089;
        }
        .filter-chip-medium.active {
            background: #d69e2e;
            color: white;
            border-color: #b7791f;
        }
        
        .filter-chip-low {
            background: #f0fff4;
            color: #38a169;
            border-color: #9ae6b4;
        }
        .filter-chip-low.active {
            background: #38a169;
            color: white;
            border-color: #276749;
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
            border: 1px solid #e2e8f0;
            background: white;
            color: #4a5568;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.2s ease;
            display: flex;
            align-items: center;
            gap: 6px;
        }
        
        .sort-btn:hover {
            background: #f7fafc;
            border-color: #cbd5e0;
        }
        
        .sort-btn.active {
            background: #667eea;
            color: white;
            border-color: #667eea;
        }
        
        .filter-results {
            background: #f7fafc;
            padding: 12px 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .filter-results-count {
            font-weight: 600;
            color: #4a5568;
        }
        
        .clear-filter {
            color: #667eea;
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
            <h1>🛡️ Interactive Security Dashboard</h1>
            <p class="subtitle"><strong>Scan:</strong> $SCAN_NAME</p>
            <p class="subtitle"><strong>Generated:</strong> $(date '+%B %d, %Y at %I:%M %p')</p>
        </div>

        <!-- Scan Overview Section -->
        <div class="scan-overview" style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); border-radius: 16px; padding: 24px; margin-bottom: 24px; color: white; box-shadow: 0 10px 40px rgba(102, 126, 234, 0.3);">
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
        
        <div class="filter-results" id="filter-results" style="display: none;">
            <span class="filter-results-count" id="filter-count">Showing 0 findings</span>
            <a class="clear-filter" onclick="filterBySeverity('all')">Clear Filter ✕</a>
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
                        <span class="tool-stat-badge badge-clean">✅ Clean</span>
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
                                <div class="stat-item"><strong>Images Scanned:</strong> ${XEOL_IMAGES_SCANNED}</div>
                                <div class="stat-item"><strong>EOL Components:</strong> ${XEOL_TOTAL_EOL}</div>
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
            const details = element.querySelector('.finding-details');
            const isExpanded = details.style.display === 'block';
            
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
                if (severity === 'all') {
                    finding.classList.remove('filtered-out');
                    visibleCount++;
                } else {
                    const hasSeverity = finding.classList.contains('severity-' + severity);
                    if (hasSeverity) {
                        finding.classList.remove('filtered-out');
                        visibleCount++;
                    } else {
                        finding.classList.add('filtered-out');
                    }
                }
            });
            
            // Update tool card opacity based on visible findings
            document.querySelectorAll('.tool-card').forEach(card => {
                const visibleInCard = card.querySelectorAll('.finding-item:not(.filtered-out)').length;
                if (severity !== 'all' && visibleInCard === 0) {
                    card.classList.add('filtered-out');
                } else {
                    card.classList.remove('filtered-out');
                }
            });
            
            // Show/hide filter results bar
            const resultsBar = document.getElementById('filter-results');
            const countSpan = document.getElementById('filter-count');
            
            if (severity === 'all') {
                resultsBar.style.display = 'none';
            } else {
                resultsBar.style.display = 'flex';
                countSpan.textContent = 'Showing ' + visibleCount + ' ' + severity.toUpperCase() + ' findings';
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
        
        // Auto-expand first tool with findings
        window.addEventListener('DOMContentLoaded', () => {
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
