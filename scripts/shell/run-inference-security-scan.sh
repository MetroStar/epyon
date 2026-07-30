#!/bin/bash

# Layer 19 — Inference Environment Security Scanner
# Scans container and Kubernetes configurations for ML inference security misconfigurations.
# Checks: Dockerfile, docker-compose.yml, Kubernetes manifests (Deployment, Pod, StatefulSet)
# No Docker required — static analysis only.

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

show_help() {
    echo -e "${WHITE}Layer 19 — Inference Environment Security Scanner${NC}"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Scans ML inference environment configurations for security issues."
    echo ""
    echo "Scans:"
    echo "  - Dockerfile: USER directive, COPY permissions, exposed ports"
    echo "  - docker-compose.yml: privileged mode, capabilities, security_opt"
    echo "  - Kubernetes manifests: securityContext settings"
    echo ""
    echo "Options:"
    echo "  -h, --help          Show this help message and exit"
    echo ""
    echo "Environment Variables:"
    echo "  TARGET_DIR              Directory to scan (default: current directory)"
    echo "  SCAN_ID                 Override auto-generated scan ID"
    echo "  SCAN_DIR                Override output directory for scan results"
    echo ""
    echo "Output:"
    echo "  Results are saved to: scans/{SCAN_ID}/inference-security/"
    echo "  - inference-security-results.json     Normalized scan summary"
    echo "  - inference-security.log              Scan process log"
    echo ""
    echo "Scanned file types:"
    echo "  Dockerfile, docker-compose.yml, *.yaml, *.yml (k8s manifests)"
    echo ""
    echo "Examples:"
    echo "  $0                                      # Scan current directory"
    echo "  TARGET_DIR=/path/to/ml-app $0           # Scan specific directory"
    echo ""
    echo "Notes:"
    echo "  - Static analysis only — no Docker daemon required"
    echo "  - Detects common container escape risks"
    echo "  - Kubernetes support for Deployment, Pod, StatefulSet, DaemonSet"
    exit 0
}

for arg in "$@"; do
    case $arg in
        -h|--help) show_help ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/scan-directory-template.sh"

init_scan_environment "inference-security"

TARGET_SCAN_DIR="${TARGET_DIR:-$(pwd)}"
if [[ -z "$TARGET_SCAN_DIR" ]]; then
    echo "[INFO] TARGET_DIR is not set — skipping Layer 19 (inference-security)" >&2
    mkdir -p "$OUTPUT_DIR"
    cat > "${OUTPUT_DIR}/inference-security-results.json" <<EOF
{
  "tool": "inference-security-scan",
  "status": "skipped",
  "reason": "TARGET_DIR not set",
  "scan_id": "${SCAN_ID:-unknown}",
  "target": "",
  "generated_at": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "statistics": {},
  "findings": []
}
EOF
    exit 0
fi
TARGET_SCAN_DIR=$(realpath "${TARGET_SCAN_DIR}" 2>/dev/null) || {
    echo "[INFO] TARGET_DIR does not exist (${TARGET_DIR}) — skipping Layer 19 (inference-security)" >&2
    mkdir -p "$OUTPUT_DIR"
    cat > "${OUTPUT_DIR}/inference-security-results.json" <<EOF
{
  "tool": "inference-security-scan",
  "status": "skipped",
  "reason": "target directory does not exist: ${TARGET_DIR}",
  "scan_id": "${SCAN_ID:-unknown}",
  "target": "${TARGET_DIR}",
  "generated_at": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "statistics": {},
  "findings": []
}
EOF
    exit 0
}

if [[ -n "$SCAN_ID" ]]; then
    TARGET_NAME=$(echo "$SCAN_ID" | cut -d'_' -f1)
    TIMESTAMP=$(echo "$SCAN_ID" | cut -d'_' -f3-)
else
    TARGET_NAME=$(basename "$TARGET_SCAN_DIR")
    TIMESTAMP=$(date '+%Y-%m-%d_%H-%M-%S')
    SCAN_ID="${TARGET_NAME}_$(whoami)_${TIMESTAMP}"
fi

RESULTS_FILE="$OUTPUT_DIR/inference-security-results.json"
SCAN_LOG="$OUTPUT_DIR/inference-security.log"

mkdir -p "$OUTPUT_DIR"

echo -e "${WHITE}============================================${NC}"
echo -e "${WHITE}Layer 19 — Inference Environment Security${NC}"
echo -e "${WHITE}============================================${NC}"
echo "Target Directory : $TARGET_SCAN_DIR"
echo "Output Directory : $OUTPUT_DIR"
echo "Timestamp        : $TIMESTAMP"
echo ""

# ── Initialize findings array and statistics ────────────────────────────────
FINDINGS="[]"
STATS_DOCKERFILES=0
STATS_COMPOSE_FILES=0
STATS_K8S_MANIFESTS=0
STATS_CRITICAL=0
STATS_HIGH=0
STATS_MEDIUM=0
STATS_LOW=0

# ── Scan Dockerfiles ─────────────────────────────────────────────────────────
echo -e "${CYAN}🐳 Scanning Dockerfiles...${NC}"

while IFS= read -r -d '' dockerfile; do
    STATS_DOCKERFILES=$((STATS_DOCKERFILES + 1))
    REL_PATH="${dockerfile#$TARGET_SCAN_DIR/}"
    
    # Check if USER directive exists
    if ! grep -qE '^\s*USER\s+' "$dockerfile"; then
        FINDINGS=$(python3 -c "
import json, sys
findings = json.loads('''$FINDINGS''')
findings.append({
    'type': 'dockerfile_no_user',
    'file': '''$REL_PATH''',
    'severity': 'high',
    'description': 'Dockerfile does not specify USER directive — container runs as root',
    'evidence': 'No USER directive found',
    'recommendation': 'Add USER directive to run as non-root user'
})
print(json.dumps(findings))
" 2>/dev/null)
        STATS_HIGH=$((STATS_HIGH + 1))
    fi
    
    # Check for root user
    if grep -qE '^\s*USER\s+root\s*$' "$dockerfile"; then
        FINDINGS=$(python3 -c "
import json, sys
findings = json.loads('''$FINDINGS''')
findings.append({
    'type': 'dockerfile_root_user',
    'file': '''$REL_PATH''',
    'severity': 'critical',
    'description': 'Dockerfile explicitly sets USER to root',
    'evidence': 'USER root directive found',
    'recommendation': 'Change to non-root user (e.g., USER 1000 or USER appuser)'
})
print(json.dumps(findings))
" 2>/dev/null)
        STATS_CRITICAL=$((STATS_CRITICAL + 1))
    fi
    
    # Check for COPY --chown usage
    if grep -qE '^\s*COPY\s+' "$dockerfile" && ! grep -qE '^\s*COPY\s+--chown=' "$dockerfile"; then
        FINDINGS=$(python3 -c "
import json, sys
findings = json.loads('''$FINDINGS''')
findings.append({
    'type': 'dockerfile_copy_no_chown',
    'file': '''$REL_PATH''',
    'severity': 'medium',
    'description': 'COPY directive does not use --chown flag',
    'evidence': 'COPY without --chown may create root-owned files',
    'recommendation': 'Use COPY --chown=user:group to set proper ownership'
})
print(json.dumps(findings))
" 2>/dev/null)
        STATS_MEDIUM=$((STATS_MEDIUM + 1))
    fi
    
    # Check for exposed privileged ports (< 1024)
    while IFS= read -r port; do
        if [[ "$port" =~ ^[0-9]+$ ]] && [[ "$port" -lt 1024 ]]; then
            FINDINGS=$(python3 -c "
import json, sys
findings = json.loads('''$FINDINGS''')
findings.append({
    'type': 'dockerfile_privileged_port',
    'file': '''$REL_PATH''',
    'severity': 'medium',
    'description': 'Dockerfile exposes privileged port < 1024',
    'evidence': 'EXPOSE $port',
    'recommendation': 'Use non-privileged port >= 1024'
})
print(json.dumps(findings))
" 2>/dev/null)
            STATS_MEDIUM=$((STATS_MEDIUM + 1))
        fi
    done < <(grep -oE '^\s*EXPOSE\s+([0-9]+)' "$dockerfile" | awk '{print $2}')
    
done < <(find "$TARGET_SCAN_DIR" -type f -name 'Dockerfile*' -print0 2>/dev/null)

echo "  Found $STATS_DOCKERFILES Dockerfile(s)"
echo ""

# ── Scan docker-compose.yml files ────────────────────────────────────────────
echo -e "${CYAN}🐳 Scanning docker-compose files...${NC}"

while IFS= read -r -d '' composefile; do
    STATS_COMPOSE_FILES=$((STATS_COMPOSE_FILES + 1))
    REL_PATH="${composefile#$TARGET_SCAN_DIR/}"
    
    # Check for privileged: true
    if grep -qE '^\s*privileged:\s*true' "$composefile"; then
        FINDINGS=$(python3 -c "
import json, sys
findings = json.loads('''$FINDINGS''')
findings.append({
    'type': 'compose_privileged_mode',
    'file': '''$REL_PATH''',
    'severity': 'critical',
    'description': 'docker-compose service runs in privileged mode',
    'evidence': 'privileged: true',
    'recommendation': 'Remove privileged mode or use specific capabilities instead'
})
print(json.dumps(findings))
" 2>/dev/null)
        STATS_CRITICAL=$((STATS_CRITICAL + 1))
    fi
    
    # Check for cap_add: ALL or SYS_ADMIN
    if grep -qE '^\s*-\s*(ALL|SYS_ADMIN|SYS_PTRACE|SYS_MODULE)' "$composefile"; then
        FINDINGS=$(python3 -c "
import json, sys
findings = json.loads('''$FINDINGS''')
findings.append({
    'type': 'compose_dangerous_capabilities',
    'file': '''$REL_PATH''',
    'severity': 'high',
    'description': 'docker-compose adds dangerous Linux capabilities',
    'evidence': 'cap_add with ALL, SYS_ADMIN, SYS_PTRACE, or SYS_MODULE',
    'recommendation': 'Remove dangerous capabilities or use minimal required caps'
})
print(json.dumps(findings))
" 2>/dev/null)
        STATS_HIGH=$((STATS_HIGH + 1))
    fi
    
    # Check for security_opt: apparmor=unconfined or seccomp=unconfined
    if grep -qE '^\s*-\s*(apparmor|seccomp):unconfined' "$composefile"; then
        FINDINGS=$(python3 -c "
import json, sys
findings = json.loads('''$FINDINGS''')
findings.append({
    'type': 'compose_disabled_security',
    'file': '''$REL_PATH''',
    'severity': 'high',
    'description': 'docker-compose disables AppArmor or seccomp security',
    'evidence': 'security_opt with unconfined profile',
    'recommendation': 'Remove unconfined security options or use custom profiles'
})
print(json.dumps(findings))
" 2>/dev/null)
        STATS_HIGH=$((STATS_HIGH + 1))
    fi
    
done < <(find "$TARGET_SCAN_DIR" -type f \( -name 'docker-compose.yml' -o -name 'docker-compose.yaml' \) -print0 2>/dev/null)

echo "  Found $STATS_COMPOSE_FILES docker-compose file(s)"
echo ""

# ── Scan Kubernetes manifests ───────────────────────────────────────────────
echo -e "${CYAN}☸️  Scanning Kubernetes manifests...${NC}"

while IFS= read -r -d '' k8sfile; do
    # Only process files that look like k8s manifests (contain kind: Deployment/Pod/etc)
    if ! grep -qE '^\s*kind:\s*(Deployment|Pod|StatefulSet|DaemonSet|Job|CronJob)' "$k8sfile"; then
        continue
    fi
    
    STATS_K8S_MANIFESTS=$((STATS_K8S_MANIFESTS + 1))
    REL_PATH="${k8sfile#$TARGET_SCAN_DIR/}"
    
    # Check for runAsNonRoot: false or missing
    if grep -qE '^\s*runAsNonRoot:\s*false' "$k8sfile"; then
        FINDINGS=$(python3 -c "
import json, sys
findings = json.loads('''$FINDINGS''')
findings.append({
    'type': 'k8s_run_as_root',
    'file': '''$REL_PATH''',
    'severity': 'critical',
    'description': 'Kubernetes container allows running as root',
    'evidence': 'runAsNonRoot: false in securityContext',
    'recommendation': 'Set runAsNonRoot: true in pod/container securityContext'
})
print(json.dumps(findings))
" 2>/dev/null)
        STATS_CRITICAL=$((STATS_CRITICAL + 1))
    elif ! grep -qE '^\s*runAsNonRoot:\s*true' "$k8sfile"; then
        FINDINGS=$(python3 -c "
import json, sys
findings = json.loads('''$FINDINGS''')
findings.append({
    'type': 'k8s_missing_run_as_non_root',
    'file': '''$REL_PATH''',
    'severity': 'high',
    'description': 'Kubernetes manifest missing runAsNonRoot directive',
    'evidence': 'No runAsNonRoot: true in securityContext',
    'recommendation': 'Add runAsNonRoot: true to pod/container securityContext'
})
print(json.dumps(findings))
" 2>/dev/null)
        STATS_HIGH=$((STATS_HIGH + 1))
    fi
    
    # Check for privileged: true
    if grep -qE '^\s*privileged:\s*true' "$k8sfile"; then
        FINDINGS=$(python3 -c "
import json, sys
findings = json.loads('''$FINDINGS''')
findings.append({
    'type': 'k8s_privileged_container',
    'file': '''$REL_PATH''',
    'severity': 'critical',
    'description': 'Kubernetes container runs in privileged mode',
    'evidence': 'privileged: true in securityContext',
    'recommendation': 'Remove privileged mode or use specific capabilities'
})
print(json.dumps(findings))
" 2>/dev/null)
        STATS_CRITICAL=$((STATS_CRITICAL + 1))
    fi
    
    # Check for allowPrivilegeEscalation: true or missing
    if grep -qE '^\s*allowPrivilegeEscalation:\s*true' "$k8sfile"; then
        FINDINGS=$(python3 -c "
import json, sys
findings = json.loads('''$FINDINGS''')
findings.append({
    'type': 'k8s_allow_privilege_escalation',
    'file': '''$REL_PATH''',
    'severity': 'high',
    'description': 'Kubernetes container allows privilege escalation',
    'evidence': 'allowPrivilegeEscalation: true in securityContext',
    'recommendation': 'Set allowPrivilegeEscalation: false'
})
print(json.dumps(findings))
" 2>/dev/null)
        STATS_HIGH=$((STATS_HIGH + 1))
    elif ! grep -qE '^\s*allowPrivilegeEscalation:\s*false' "$k8sfile"; then
        FINDINGS=$(python3 -c "
import json, sys
findings = json.loads('''$FINDINGS''')
findings.append({
    'type': 'k8s_missing_allow_privilege_escalation',
    'file': '''$REL_PATH''',
    'severity': 'medium',
    'description': 'Kubernetes manifest missing allowPrivilegeEscalation directive',
    'evidence': 'No allowPrivilegeEscalation: false in securityContext',
    'recommendation': 'Add allowPrivilegeEscalation: false to container securityContext'
})
print(json.dumps(findings))
" 2>/dev/null)
        STATS_MEDIUM=$((STATS_MEDIUM + 1))
    fi
    
    # Check for readOnlyRootFilesystem
    if ! grep -qE '^\s*readOnlyRootFilesystem:\s*true' "$k8sfile"; then
        FINDINGS=$(python3 -c "
import json, sys
findings = json.loads('''$FINDINGS''')
findings.append({
    'type': 'k8s_missing_readonly_root_fs',
    'file': '''$REL_PATH''',
    'severity': 'medium',
    'description': 'Kubernetes manifest missing readOnlyRootFilesystem directive',
    'evidence': 'No readOnlyRootFilesystem: true in securityContext',
    'recommendation': 'Add readOnlyRootFilesystem: true to container securityContext'
})
print(json.dumps(findings))
" 2>/dev/null)
        STATS_MEDIUM=$((STATS_MEDIUM + 1))
    fi
    
    # Check for capabilities drop ALL
    if ! grep -qE '^\s*-\s*ALL' "$k8sfile" && grep -qE '^\s*drop:' "$k8sfile"; then
        FINDINGS=$(python3 -c "
import json, sys
findings = json.loads('''$FINDINGS''')
findings.append({
    'type': 'k8s_capabilities_not_dropped',
    'file': '''$REL_PATH''',
    'severity': 'medium',
    'description': 'Kubernetes manifest does not drop all capabilities',
    'evidence': 'capabilities.drop does not include ALL',
    'recommendation': 'Add capabilities.drop: [ALL] to container securityContext'
})
print(json.dumps(findings))
" 2>/dev/null)
        STATS_MEDIUM=$((STATS_MEDIUM + 1))
    fi
    
done < <(find "$TARGET_SCAN_DIR" -type f \( -name '*.yaml' -o -name '*.yml' \) -print0 2>/dev/null)

echo "  Found $STATS_K8S_MANIFESTS Kubernetes manifest(s)"
echo ""

# ── Generate report ──────────────────────────────────────────────────────────
GENERATED_AT="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

python3 - <<PYEOF
import json

findings = json.loads('''$FINDINGS''')

result = {
    "tool": "inference-security-scan",
    "version": "1.0",
    "status": "completed",
    "scan_id": "${SCAN_ID}",
    "target": "${TARGET_SCAN_DIR}",
    "generated_at": "${GENERATED_AT}",
    "statistics": {
        "dockerfiles_scanned": ${STATS_DOCKERFILES},
        "compose_files_scanned": ${STATS_COMPOSE_FILES},
        "k8s_manifests_scanned": ${STATS_K8S_MANIFESTS},
        "total_files": ${STATS_DOCKERFILES} + ${STATS_COMPOSE_FILES} + ${STATS_K8S_MANIFESTS}
    },
    "findings": findings,
    "summary": {
        "total_findings": len(findings),
        "critical_findings": ${STATS_CRITICAL},
        "high_findings": ${STATS_HIGH},
        "medium_findings": ${STATS_MEDIUM},
        "low_findings": ${STATS_LOW}
    }
}

with open("${RESULTS_FILE}", "w") as f:
    json.dump(result, f, indent=2)

print("Results written to ${RESULTS_FILE}")
PYEOF

PYEOF_EXIT=$?

if [[ $PYEOF_EXIT -ne 0 ]]; then
    echo -e "${RED}❌ Failed to write results${NC}"
    exit 1
fi

# ── Print summary ────────────────────────────────────────────────────────────
echo ""
if [[ "$STATS_CRITICAL" -gt 0 ]] || [[ "$STATS_HIGH" -gt 0 ]]; then
    STATUS="open"
    echo -e "${RED}🚨 ALERT: Inference environment security issues detected!${NC}"
    echo -e "${RED}   Critical: ${STATS_CRITICAL}, High: ${STATS_HIGH}, Medium: ${STATS_MEDIUM}${NC}"
    echo -e "${RED}   These configurations may enable container escapes or privilege escalation.${NC}"
else
    STATUS="success"
    echo -e "${GREEN}✅ No critical inference security issues detected${NC}"
fi

echo ""
echo "Results written to: $RESULTS_FILE"
echo ""

STATUS_MSG="Found ${STATS_CRITICAL} critical and ${STATS_HIGH} high inference security issues"
record_scan_status "$STATUS" "$STATUS_MSG"

# Exit with error if critical/high findings
if [[ "$STATS_CRITICAL" -gt 0 ]] || [[ "$STATS_HIGH" -gt 0 ]]; then
    exit 1
else
    exit 0
fi
