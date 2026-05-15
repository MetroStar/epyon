#!/bin/bash

# ███████╗██████╗ ██╗   ██╗ ██████╗ ███╗   ██╗
# ██╔════╝██╔══██╗╚██╗ ██╔╝██╔═══██╗████╗  ██║
# █████╗  ██████╔╝ ╚████╔╝ ██║   ██║██╔██╗ ██║
# ██╔══╝  ██╔═══╝   ╚██╔╝  ██║   ██║██║╚██╗██║
# ███████╗██║        ██║   ╚██████╔╝██║ ╚████║
# ╚══════╝╚═╝        ╚═╝    ╚═════╝ ╚═╝  ╚═══╝
#
# Network Discovery Scanner — Layer 16
# Discovers ports, protocols, and services via static config analysis
# and optional active nmap scanning.
#
# Static Sources:
#   - Dockerfile / Dockerfile.* EXPOSE directives
#   - docker-compose.yml / compose.yaml ports: and expose: blocks
#   - Kubernetes Service and workload manifests (containerPort, targetPort)
#   - Helm chart values.yaml service port definitions
#   - Spring Boot application.yml / application.properties (server.port)
#   - .env / .env.* files (PORT=, SERVER_PORT=, HTTP_PORT=, etc.)
#
# Active Scanning (opt-in, requires Docker):
#   Set NMAP_TARGET=<host_or_ip> to run nmap via instrumentisto/nmap
#   Set NMAP_FULL_SCAN=true to scan all 65535 ports (default: top 1000)
#
# Usage:
#   ./run-network-discovery.sh [target_directory]
#   NMAP_TARGET=localhost ./run-network-discovery.sh [target_directory]

set -o pipefail

trap 'echo "⚠️  Warning: Command failed at line $LINENO (continuing...)" >&2' ERR

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ "${1:-}" != "--help" ]] && [[ "${1:-}" != "-h" ]]; then
    TARGET_DIR="${TARGET_DIR:-${1:-.}}"
    TARGET_DIR=$(realpath "${TARGET_DIR}" 2>/dev/null) || {
        echo "ERROR: Target path does not exist or is invalid: ${TARGET_DIR}" >&2
        exit 1
    }
fi

SCAN_DIR="${SCAN_DIR:-}"
OUTPUT_FILE="network-discovery.json"

# Active scan configuration (all opt-in)
NMAP_TARGET="${NMAP_TARGET:-}"
NMAP_FULL_SCAN="${NMAP_FULL_SCAN:-false}"
NMAP_IMAGE="${NMAP_IMAGE:-instrumentisto/nmap:latest}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

print_banner() {
    echo -e "${CYAN}"
    cat << "EOF"
███████╗██████╗ ██╗   ██╗ ██████╗ ███╗   ██╗
██╔════╝██╔══██╗╚██╗ ██╔╝██╔═══██╗████╗  ██║
█████╗  ██████╔╝ ╚████╔╝ ██║   ██║██╔██╗ ██║
██╔══╝  ██╔═══╝   ╚██╔╝  ██║   ██║██║╚██╗██║
███████╗██║        ██║   ╚██████╔╝██║ ╚████║
╚══════╝╚═╝        ╚═╝    ╚═════╝ ╚═╝  ╚═══╝

Network Discovery Scanner — Layer 16
EOF
    echo -e "${NC}"
}

print_info()    { echo -e "${BLUE}ℹ${NC} $1" >&2; }
print_success() { echo -e "${GREEN}✅${NC} $1" >&2; }
print_warning() { echo -e "${YELLOW}⚠️${NC} $1" >&2; }
print_error()   { echo -e "${RED}❌${NC} $1" >&2; }
print_section() {
    echo "" >&2
    echo -e "${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}" >&2
    echo -e "${MAGENTA}$1${NC}" >&2
    echo -e "${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}" >&2
}

show_help() {
    cat << EOF
Network Discovery Scanner — Layer 16: Ports, Protocols, and Services

USAGE:
    ./run-network-discovery.sh [TARGET_DIR]

ARGUMENTS:
    TARGET_DIR    Directory to scan (default: current directory)

ENVIRONMENT VARIABLES:
    TARGET_DIR        Target directory to scan
    SCAN_DIR          Output directory for results (optional)
    NMAP_TARGET       Host/IP for active nmap scan (opt-in — only scan hosts you own)
    NMAP_FULL_SCAN    Set 'true' to scan all 65535 ports (default: top 1000)
    NMAP_IMAGE        nmap Docker image (default: instrumentisto/nmap:latest)

STATIC DISCOVERY SOURCES:
    1. Dockerfile / Dockerfile.*     — EXPOSE directives
    2. docker-compose.yml variants   — ports: and expose: blocks
    3. Kubernetes manifests          — Service containerPort / targetPort / nodePort
    4. Helm chart values.yaml        — service port definitions
    5. Spring Boot application.yml   — server.port
    6. .env / .env.* files           — PORT=, SERVER_PORT=, HTTP_PORT=, etc.

ACTIVE SCANNING (opt-in):
    Requires Docker. Set NMAP_TARGET=<host_or_ip> to enable.
    WARNING: Only scan hosts you own or have explicit authorization to scan.

OUTPUT:
    \$SCAN_DIR/network/network-discovery.json

EXAMPLES:
    # Static config analysis only
    ./run-network-discovery.sh /path/to/application

    # With active nmap scanning (requires Docker + authorized target)
    NMAP_TARGET=192.168.1.100 ./run-network-discovery.sh /path/to/application

    # Full port range active scan
    NMAP_TARGET=localhost NMAP_FULL_SCAN=true ./run-network-discovery.sh /path/to/app

EOF
}

# ── Static Discovery: Dockerfile EXPOSE ──────────────────────────────────────

scan_dockerfiles() {
    print_section "🐳 Scanning Dockerfiles (EXPOSE directives)"

    local count=0

    while IFS= read -r -d '' file; do
        local rel_path="${file#$TARGET_DIR/}"

        while IFS= read -r expose_line; do
            # Strip 'EXPOSE ' prefix
            local ports_str
            ports_str=$(echo "$expose_line" | sed 's/^[Ee][Xx][Pp][Oo][Ss][Ee][[:space:]]*//' | xargs)

            for token in $ports_str; do
                local port protocol
                if [[ "$token" == */* ]]; then
                    port="${token%/*}"
                    protocol=$(echo "${token#*/}" | tr '[:upper:]' '[:lower:]')
                else
                    port="$token"
                    protocol="tcp"
                fi
                if [[ "$port" =~ ^[0-9]+$ ]]; then
                    echo "${rel_path}|${port}|${protocol}" >> "$TEMP_DOCKERFILES"
                    print_success "  $rel_path: EXPOSE ${port}/${protocol}" >&2
                    count=$((count + 1))
                fi
            done
        done < <(grep -iE "^EXPOSE " "$file" 2>/dev/null)

    done < <(find "${TARGET_DIR}" -maxdepth 6 -type f \
        \( -name "Dockerfile" -o -name "Dockerfile.*" \) \
        ! -name "*.md" ! -name "*.txt" -print0 2>/dev/null)

    if [ "$count" -eq 0 ]; then
        print_warning "No Dockerfile EXPOSE directives found"
    else
        print_success "Found $count port(s) across Dockerfiles"
    fi
}

# ── Static Discovery: Docker Compose ─────────────────────────────────────────

scan_docker_compose() {
    print_section "🐙 Scanning Docker Compose Files"

    local count=0

    while IFS= read -r -d '' file; do
        local rel_path="${file#$TARGET_DIR/}"
        print_info "Parsing: $rel_path"

        local py_output
        py_output=$(FILE="$file" REL_PATH="$rel_path" python3 - << 'PYEOF' 2>/dev/null
import os, sys
try:
    import yaml
except ImportError:
    sys.exit(0)

file = os.environ.get('FILE', '')
rel_path = os.environ.get('REL_PATH', file)

try:
    with open(file, 'r') as f:
        data = yaml.safe_load(f)
except Exception:
    sys.exit(0)

if not isinstance(data, dict):
    sys.exit(0)

for svc_name, svc_data in (data.get('services') or {}).items():
    if not isinstance(svc_data, dict):
        continue

    # ports: block — host:container or just container port
    for port_entry in (svc_data.get('ports') or []):
        port_str = str(port_entry).strip().strip('"').strip("'")
        protocol = 'tcp'
        if '/' in port_str.split(':')[-1]:
            parts = port_str.rsplit('/', 1)
            port_str = parts[0]
            protocol = parts[1].lower()
        # Extract container port from host:container mapping
        container_port = port_str.split(':')[-1]
        # Remove IP prefix if present (e.g. 0.0.0.0:8080:80 -> 80)
        if ':' in container_port:
            container_port = container_port.split(':')[-1]
        try:
            int(container_port)
            print(f'{rel_path}|{svc_name}|ports|{container_port}|{protocol}|{port_entry}')
        except (ValueError, TypeError):
            pass

    # expose: block — container-only ports
    for exp_entry in (svc_data.get('expose') or []):
        exp_str = str(exp_entry).strip()
        try:
            int(exp_str)
            print(f'{rel_path}|{svc_name}|expose|{exp_str}|tcp|{exp_str}')
        except (ValueError, TypeError):
            pass
PYEOF
        )

        if [ -n "$py_output" ]; then
            while IFS= read -r line; do
                echo "$line" >> "$TEMP_COMPOSE"
                local port
                port=$(echo "$line" | cut -d'|' -f4)
                print_success "  $rel_path ($(echo "$line" | cut -d'|' -f2)): port $port" >&2
                count=$((count + 1))
            done < <(echo "$py_output")
        else
            print_warning "  Could not parse $rel_path (PyYAML missing or invalid YAML?)"
        fi

    done < <(find "${TARGET_DIR}" -maxdepth 6 -type f \
        \( -name "docker-compose.yml" -o -name "docker-compose.yaml" \
           -o -name "compose.yml" -o -name "compose.yaml" \
           -o -name "docker-compose.*.yml" -o -name "docker-compose.*.yaml" \) \
        -print0 2>/dev/null)

    if [ "$count" -eq 0 ]; then
        print_warning "No Docker Compose port definitions found"
    else
        print_success "Found $count port(s) across Docker Compose files"
    fi
}

# ── Static Discovery: Kubernetes Manifests ───────────────────────────────────

scan_kubernetes() {
    print_section "☸️  Scanning Kubernetes Manifests"

    local count=0

    while IFS= read -r -d '' file; do
        # Quick filter: only process files that have 'kind:' at line start
        if ! grep -q "^kind:" "$file" 2>/dev/null; then
            continue
        fi

        local rel_path="${file#$TARGET_DIR/}"

        local py_output
        py_output=$(FILE="$file" REL_PATH="$rel_path" python3 - << 'PYEOF' 2>/dev/null
import os, sys
try:
    import yaml
except ImportError:
    sys.exit(0)

file = os.environ.get('FILE', '')
rel_path = os.environ.get('REL_PATH', file)

try:
    with open(file, 'r') as f:
        docs = list(yaml.safe_load_all(f))
except Exception:
    sys.exit(0)

for doc in docs:
    if not isinstance(doc, dict):
        continue
    kind = doc.get('kind', '')
    meta = doc.get('metadata') or {}
    name = meta.get('name', 'unknown')
    namespace = meta.get('namespace', 'default')
    spec = doc.get('spec') or {}

    if kind == 'Service':
        svc_type = spec.get('type', 'ClusterIP')
        for pe in (spec.get('ports') or []):
            if not isinstance(pe, dict):
                continue
            port = pe.get('port', '')
            target_port = pe.get('targetPort', port)
            protocol = pe.get('protocol', 'TCP').upper()
            node_port = pe.get('nodePort', '')
            try:
                int(port)
                print(f'{rel_path}|Service|{name}|{namespace}|{svc_type}|{port}|{target_port}|{protocol}|{node_port}')
            except (ValueError, TypeError):
                pass

    elif kind in ('Deployment', 'DaemonSet', 'StatefulSet', 'Pod',
                  'ReplicaSet', 'CronJob', 'Job'):
        containers = []
        if kind == 'Pod':
            containers = spec.get('containers') or []
        else:
            template = spec.get('template') or {}
            containers = (template.get('spec') or {}).get('containers') or []
            if not containers:  # CronJob nesting
                job_spec = spec.get('jobTemplate', {}).get('spec', {})
                containers = (job_spec.get('template', {}).get('spec') or {}).get('containers') or []

        for container in containers:
            if not isinstance(container, dict):
                continue
            for cp in (container.get('ports') or []):
                if not isinstance(cp, dict):
                    continue
                cp_port = cp.get('containerPort', '')
                protocol = cp.get('protocol', 'TCP').upper()
                try:
                    int(cp_port)
                    print(f'{rel_path}|{kind}|{name}|{namespace}|workload|{cp_port}||{protocol}|')
                except (ValueError, TypeError):
                    pass
PYEOF
        )

        if [ -n "$py_output" ]; then
            while IFS= read -r line; do
                echo "$line" >> "$TEMP_K8S"
                local k_kind k_name k_port k_protocol
                k_kind=$(echo "$line" | cut -d'|' -f2)
                k_name=$(echo "$line" | cut -d'|' -f3)
                k_port=$(echo "$line" | cut -d'|' -f6)
                k_protocol=$(echo "$line" | cut -d'|' -f8)
                print_success "  $rel_path [$k_kind/$k_name]: port ${k_port}/${k_protocol}" >&2
                count=$((count + 1))
            done < <(echo "$py_output")
        fi

    done < <(find "${TARGET_DIR}" -maxdepth 8 -type f \
        \( -name "*.yaml" -o -name "*.yml" \) \
        ! -path "*/node_modules/*" ! -path "*/.git/*" \
        ! -path "*/vendor/*" -print0 2>/dev/null)

    if [ "$count" -eq 0 ]; then
        print_warning "No port definitions found in Kubernetes manifests"
    else
        print_success "Found $count port(s) across Kubernetes manifests"
    fi
}

# ── Static Discovery: Helm Charts ────────────────────────────────────────────

scan_helm_charts() {
    print_section "⛵ Scanning Helm Charts"

    local count=0

    while IFS= read -r -d '' chart_yaml; do
        local chart_dir
        chart_dir=$(dirname "$chart_yaml")
        local values_file="$chart_dir/values.yaml"
        local rel_chart
        rel_chart=$(basename "$chart_dir")

        [ -f "$values_file" ] || continue

        local rel_path="${values_file#$TARGET_DIR/}"
        print_info "Parsing Helm chart: $rel_chart"

        local py_output
        py_output=$(FILE="$values_file" REL_PATH="$rel_path" python3 - << 'PYEOF' 2>/dev/null
import os, sys
try:
    import yaml
except ImportError:
    sys.exit(0)

file = os.environ.get('FILE', '')
rel_path = os.environ.get('REL_PATH', file)

try:
    with open(file, 'r') as f:
        data = yaml.safe_load(f)
except Exception:
    sys.exit(0)

if not isinstance(data, dict):
    sys.exit(0)

def extract_ports(obj, path=''):
    results = []
    if isinstance(obj, dict):
        for key in ('port', 'ports', 'targetPort', 'containerPort', 'nodePort', 'servicePort'):
            if key in obj:
                val = obj[key]
                if isinstance(val, int) and 1 <= val <= 65535:
                    results.append((f'{path}.{key}' if path else key, val, 'TCP'))
                elif isinstance(val, list):
                    for item in val:
                        if isinstance(item, dict):
                            for pk in ('port', 'containerPort', 'targetPort'):
                                p = item.get(pk)
                                if isinstance(p, int) and 1 <= p <= 65535:
                                    proto = item.get('protocol', 'TCP')
                                    results.append((f'{path}.{key}[].{pk}', p, proto))
        for k, v in obj.items():
            results.extend(extract_ports(v, f'{path}.{k}' if path else k))
    return results

seen = set()
for key_path, port, proto in extract_ports(data):
    key = (rel_path, port)
    if key not in seen:
        seen.add(key)
        print(f'{rel_path}|{key_path}|{port}|{proto}')
PYEOF
        )

        if [ -n "$py_output" ]; then
            while IFS= read -r line; do
                echo "$line" >> "$TEMP_HELM"
                local h_port h_proto
                h_port=$(echo "$line" | cut -d'|' -f3)
                h_proto=$(echo "$line" | cut -d'|' -f4)
                print_success "  $rel_path: port ${h_port}/${h_proto}" >&2
                count=$((count + 1))
            done < <(echo "$py_output")
        fi

    done < <(find "${TARGET_DIR}" -maxdepth 8 -type f -name "Chart.yaml" -print0 2>/dev/null)

    if [ "$count" -eq 0 ]; then
        print_warning "No Helm chart port definitions found"
    else
        print_success "Found $count port definition(s) in Helm charts"
    fi
}

# ── Static Discovery: Application Config Files ───────────────────────────────

scan_app_configs() {
    print_section "⚙️  Scanning Application Configuration Files"

    local count=0

    while IFS= read -r -d '' file; do
        local rel_path="${file#$TARGET_DIR/}"
        local port=""

        if [[ "$file" == *.properties ]]; then
            # server.port=8080
            port=$(grep -m1 "^server\.port[[:space:]]*=" "$file" 2>/dev/null \
                | sed 's/.*=[[:space:]]*//' | tr -d '[:space:]')
        elif [[ "$file" == *.yaml ]] || [[ "$file" == *.yml ]]; then
            port=$(FILE="$file" python3 - << 'PYEOF' 2>/dev/null
import os, sys
try:
    import yaml
except ImportError:
    sys.exit(0)
file = os.environ.get('FILE', '')
try:
    with open(file) as f:
        d = yaml.safe_load(f)
except Exception:
    sys.exit(0)
if isinstance(d, dict):
    srv = d.get('server') or {}
    if isinstance(srv, dict):
        p = srv.get('port')
        if isinstance(p, int):
            print(p)
PYEOF
            )
        fi

        if [[ "$port" =~ ^[0-9]+$ ]]; then
            echo "${rel_path}|Spring Boot|${port}" >> "$TEMP_CONFIGS"
            print_success "  $rel_path: server.port = $port" >&2
            count=$((count + 1))
        fi

    done < <(find "${TARGET_DIR}" -maxdepth 8 -type f \
        \( -name "application.yml" -o -name "application.yaml" \
           -o -name "application.properties" \
           -o -name "application-*.yml" -o -name "application-*.yaml" \) \
        ! -path "*/node_modules/*" ! -path "*/.git/*" -print0 2>/dev/null)

    if [ "$count" -eq 0 ]; then
        print_warning "No application config port definitions found"
    else
        print_success "Found $count application config port(s)"
    fi
}

# ── Static Discovery: .env Files ─────────────────────────────────────────────

scan_env_files() {
    print_section "🔧 Scanning .env Files"

    local count=0

    while IFS= read -r -d '' file; do
        local rel_path="${file#$TARGET_DIR/}"

        while IFS='=' read -r key rest; do
            # Skip comments and blank lines
            [[ "$key" =~ ^[[:space:]]*# ]] && continue
            [[ -z "${key// }" ]] && continue

            # Normalize key
            local clean_key
            clean_key=$(echo "$key" | tr -d '[:space:]')
            local value
            value=$(echo "$rest" | sed 's/^[[:space:]]*//' | tr -d '"'"'" | tr -d '[:space:]')

            # Match keys that contain PORT (e.g. PORT, SERVER_PORT, HTTP_PORT, APP_PORT)
            if [[ "$clean_key" =~ PORT ]] && [[ "$value" =~ ^[0-9]+$ ]]; then
                echo "${rel_path}|${clean_key}|${value}" >> "$TEMP_ENV"
                print_success "  $rel_path: $clean_key = $value" >&2
                count=$((count + 1))
            fi
        done < <(grep -E '^[A-Za-z_][A-Za-z0-9_]*PORT[A-Za-z0-9_]*=[0-9]' "$file" 2>/dev/null; \
                 grep -E '^PORT=[0-9]' "$file" 2>/dev/null)

    done < <(find "${TARGET_DIR}" -maxdepth 4 -type f \
        \( -name ".env" -o -name ".env.*" -o -name "*.env" \) \
        ! -name "*.example" ! -name "*.sample" ! -name "*.template" \
        ! -path "*/node_modules/*" ! -path "*/.git/*" \
        -print0 2>/dev/null)

    if [ "$count" -eq 0 ]; then
        print_warning "No PORT variables found in .env files"
    else
        print_success "Found $count port variable(s) in .env files"
    fi
}

# ── Active Scanning: nmap via Docker ─────────────────────────────────────────

run_nmap_scan() {
    print_section "🔭 Active Port Scanning (nmap)"

    print_warning "SECURITY NOTICE: Only scan hosts you own or have explicit written authorization to scan."
    print_info "Target: ${NMAP_TARGET}"

    if ! command -v docker &>/dev/null; then
        print_error "Docker is required for active scanning but is not installed"
        return 1
    fi

    if ! docker info &>/dev/null; then
        print_error "Docker daemon is not running — cannot run nmap scan"
        return 1
    fi

    local nmap_args
    if [[ "${NMAP_FULL_SCAN:-false}" == "true" ]]; then
        nmap_args="-p- -sV -T4"
        print_info "Mode: Full scan (all 65535 ports) — this may take several minutes"
    else
        nmap_args="--top-ports 1000 -sV -T4"
        print_info "Mode: Top 1000 ports with service fingerprinting"
    fi

    local xml_output="${OUTPUT_DIR}/nmap-results.xml"

    print_info "Pulling nmap image: ${NMAP_IMAGE}"
    docker pull "${NMAP_IMAGE}" --quiet 2>/dev/null || true

    print_info "Running nmap scan against ${NMAP_TARGET} ..."
    if ! docker run --rm "${NMAP_IMAGE}" \
        ${nmap_args} -oX - "${NMAP_TARGET}" > "$xml_output" 2>/dev/null; then
        print_error "nmap scan failed"
        return 1
    fi

    if [ ! -s "$xml_output" ]; then
        print_error "nmap produced no output"
        return 1
    fi

    print_success "nmap scan completed. Parsing XML results..."

    # Parse nmap XML to JSON
    local scan_type_flag="${NMAP_FULL_SCAN:-false}"
    NMAP_XML_FILE="$xml_output" \
    NMAP_TARGET_HOST="$NMAP_TARGET" \
    NMAP_SCAN_TYPE="$scan_type_flag" \
    python3 - << 'PYEOF' >> "$TEMP_NMAP" 2>/dev/null
import xml.etree.ElementTree as ET
import json, os, sys

xml_file = os.environ.get('NMAP_XML_FILE', '')
nmap_target = os.environ.get('NMAP_TARGET_HOST', '')
scan_type = 'full' if os.environ.get('NMAP_SCAN_TYPE', '') == 'true' else 'top-1000'

try:
    tree = ET.parse(xml_file)
    root = tree.getroot()
except Exception as e:
    print(f'PARSE_ERROR: {e}', file=sys.stderr)
    sys.exit(1)

nmap_version = root.attrib.get('version', 'unknown')
ports = []

for host in root.findall('host'):
    for port_elem in host.findall('.//port'):
        portid = port_elem.attrib.get('portid', '')
        protocol = port_elem.attrib.get('protocol', 'tcp')
        state_elem = port_elem.find('state')
        state = state_elem.attrib.get('state', 'unknown') if state_elem is not None else 'unknown'
        service_elem = port_elem.find('service')
        service_name = 'unknown'
        service_version = ''
        if service_elem is not None:
            service_name = service_elem.attrib.get('name', 'unknown')
            parts = [p for p in [
                service_elem.attrib.get('product', ''),
                service_elem.attrib.get('version', ''),
                service_elem.attrib.get('extrainfo', '')
            ] if p]
            service_version = ' '.join(parts)
        try:
            ports.append({
                'port': int(portid),
                'protocol': protocol,
                'state': state,
                'service': service_name,
                'version': service_version
            })
        except (ValueError, TypeError):
            pass

result = {
    'target': nmap_target,
    'scan_type': scan_type,
    'nmap_version': nmap_version,
    'open_ports': [p for p in ports if p['state'] == 'open']
}
print(json.dumps(result))
PYEOF

    if [ -s "$TEMP_NMAP" ]; then
        local open_count
        open_count=$(python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
    print(len(d.get('open_ports', [])))
except:
    print(0)
" < "$TEMP_NMAP" 2>/dev/null || echo "0")
        print_success "Active scan found ${open_count} open port(s) on ${NMAP_TARGET}"
    else
        print_warning "Active scan produced no parseable results"
    fi
}

# ── JSON Assembly ─────────────────────────────────────────────────────────────

build_json_output() {
    print_section "📄 Building JSON Output"

    local scan_date
    scan_date=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    SCAN_DATE="$scan_date" \
    TARGET_DIR_VAL="$TARGET_DIR" \
    OUT_PATH="$OUTPUT_PATH" \
    TF_DOCKERFILES="$TEMP_DOCKERFILES" \
    TF_COMPOSE="$TEMP_COMPOSE" \
    TF_K8S="$TEMP_K8S" \
    TF_HELM="$TEMP_HELM" \
    TF_CONFIGS="$TEMP_CONFIGS" \
    TF_ENV="$TEMP_ENV" \
    TF_NMAP="$TEMP_NMAP" \
    python3 - << 'PYEOF' 2>/dev/null
import json, os, sys

scan_date     = os.environ.get('SCAN_DATE', '')
target_dir    = os.environ.get('TARGET_DIR_VAL', '')
output_path   = os.environ.get('OUT_PATH', '')

def read_lines(path):
    try:
        with open(path) as f:
            return [l.rstrip('\n') for l in f if l.strip()]
    except Exception:
        return []

def parse_dockerfiles(lines):
    files = {}
    for line in lines:
        parts = line.split('|')
        if len(parts) < 3:
            continue
        f, port, proto = parts[0], parts[1], parts[2]
        if f not in files:
            files[f] = {'file': f, 'exposed_ports': []}
        try:
            files[f]['exposed_ports'].append({'port': int(port), 'protocol': proto})
        except ValueError:
            pass
    return list(files.values())

def parse_compose(lines):
    files = {}
    for line in lines:
        parts = line.split('|')
        if len(parts) < 5:
            continue
        f, svc, ptype, port_str, proto = parts[0], parts[1], parts[2], parts[3], parts[4]
        raw = parts[5] if len(parts) > 5 else port_str
        if f not in files:
            files[f] = {'file': f, 'services': {}}
        if svc not in files[f]['services']:
            files[f]['services'][svc] = {'name': svc, 'ports': [], 'protocols': set()}
        try:
            files[f]['services'][svc]['ports'].append({
                'container_port': int(port_str),
                'type': ptype,
                'mapping': str(raw)
            })
            files[f]['services'][svc]['protocols'].add(proto)
        except ValueError:
            pass
    result = []
    for fe in files.values():
        svcs = []
        for s in fe['services'].values():
            s['protocols'] = sorted(s['protocols'])
            svcs.append(s)
        result.append({'file': fe['file'], 'services': svcs})
    return result

def parse_k8s(lines):
    entries = []
    for line in lines:
        parts = line.split('|')
        if len(parts) < 8:
            continue
        f, kind, name, ns, svc_type = parts[0], parts[1], parts[2], parts[3], parts[4]
        port, target_port, protocol = parts[5], parts[6], parts[7]
        node_port = parts[8] if len(parts) > 8 else ''
        entry = {
            'file': f, 'kind': kind, 'name': name,
            'namespace': ns, 'type': svc_type,
            'port': int(port) if port.isdigit() else port,
            'protocol': protocol
        }
        if target_port:
            try:
                entry['targetPort'] = int(target_port)
            except ValueError:
                entry['targetPort'] = target_port
        if node_port and node_port.isdigit():
            entry['nodePort'] = int(node_port)
        entries.append(entry)
    return entries

def parse_helm(lines):
    files = {}
    for line in lines:
        parts = line.split('|')
        if len(parts) < 4:
            continue
        f, key_path, port_str, proto = parts[0], parts[1], parts[2], parts[3]
        if f not in files:
            files[f] = {'file': f, 'service_ports': []}
        try:
            files[f]['service_ports'].append({
                'key': key_path,
                'port': int(port_str),
                'protocol': proto
            })
        except ValueError:
            pass
    return list(files.values())

def parse_configs(lines):
    entries = []
    for line in lines:
        parts = line.split('|')
        if len(parts) < 3:
            continue
        f, cfg_type, port_str = parts[0], parts[1], parts[2]
        try:
            entries.append({'file': f, 'type': cfg_type, 'port': int(port_str)})
        except ValueError:
            pass
    return entries

def parse_env(lines):
    files = {}
    for line in lines:
        parts = line.split('|')
        if len(parts) < 3:
            continue
        f, key, val = parts[0], parts[1], parts[2]
        if f not in files:
            files[f] = {'file': f, 'port_vars': []}
        try:
            files[f]['port_vars'].append({'key': key, 'value': int(val)})
        except ValueError:
            pass
    return list(files.values())

def parse_nmap(path):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return None

# Known port→service mapping
PORT_SERVICES = {
    21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
    80: 'http', 110: 'pop3', 143: 'imap', 389: 'ldap', 443: 'https',
    465: 'smtps', 587: 'smtp', 636: 'ldaps', 1433: 'mssql',
    1521: 'oracle', 1883: 'mqtt', 3000: 'http-dev', 3306: 'mysql',
    3389: 'rdp', 4222: 'nats', 4566: 'localstack', 5432: 'postgresql',
    5601: 'kibana', 5672: 'amqp', 5984: 'couchdb', 6379: 'redis',
    6380: 'redis', 7474: 'neo4j', 8025: 'mailhog', 8080: 'http-alt',
    8081: 'http-alt', 8086: 'influxdb', 8443: 'https-alt',
    8888: 'http-alt', 9000: 'http-alt', 9090: 'prometheus',
    9092: 'kafka', 9200: 'elasticsearch', 9300: 'elasticsearch',
    9411: 'zipkin', 15672: 'rabbitmq-management', 27017: 'mongodb',
    27018: 'mongodb', 50051: 'grpc'
}

dockerfiles  = parse_dockerfiles(read_lines(os.environ.get('TF_DOCKERFILES', '')))
compose      = parse_compose(read_lines(os.environ.get('TF_COMPOSE', '')))
k8s          = parse_k8s(read_lines(os.environ.get('TF_K8S', '')))
helm         = parse_helm(read_lines(os.environ.get('TF_HELM', '')))
configs      = parse_configs(read_lines(os.environ.get('TF_CONFIGS', '')))
envfiles     = parse_env(read_lines(os.environ.get('TF_ENV', '')))
active_scan  = parse_nmap(os.environ.get('TF_NMAP', ''))

# Collect all unique ports, protocols, and services
all_ports = set()
all_protocols = set()
all_services = set()

for df in dockerfiles:
    for ep in df['exposed_ports']:
        all_ports.add(ep['port'])
        all_protocols.add(ep['protocol'])

for cf in compose:
    for svc in cf['services']:
        for p in svc['ports']:
            all_ports.add(p['container_port'])
        for proto in svc['protocols']:
            all_protocols.add(proto)

for k in k8s:
    port = k.get('port')
    if isinstance(port, int):
        all_ports.add(port)
    all_protocols.add(k.get('protocol', 'TCP').lower())

for h in helm:
    for p in h['service_ports']:
        all_ports.add(p['port'])
        all_protocols.add(p['protocol'].lower())

for c in configs:
    all_ports.add(c['port'])
    all_protocols.add('tcp')

for e in envfiles:
    for pv in e['port_vars']:
        all_ports.add(pv['value'])
        all_protocols.add('tcp')

if active_scan:
    for p in active_scan.get('open_ports', []):
        all_ports.add(p['port'])
        all_protocols.add(p['protocol'])
        svc = p.get('service', 'unknown')
        if svc and svc != 'unknown':
            all_services.add(svc)

# Infer services from known port numbers
for port in all_ports:
    svc = PORT_SERVICES.get(port)
    if svc:
        all_services.add(svc)

static_sources_found = sum([
    len(dockerfiles) > 0,
    len(compose) > 0,
    len(k8s) > 0,
    len(helm) > 0,
    len(configs) > 0,
    len(envfiles) > 0
])

output = {
    'scan_date': scan_date,
    'target_directory': target_dir,
    'static_discovery': {
        'dockerfiles': dockerfiles,
        'docker_compose': compose,
        'kubernetes': k8s,
        'helm_charts': helm,
        'app_configs': configs,
        'env_files': envfiles
    },
    'active_scan': active_scan,
    'summary': {
        'total_ports_discovered': len(all_ports),
        'unique_ports': sorted(all_ports),
        'protocols': sorted(all_protocols),
        'inferred_services': sorted(all_services),
        'static_sources_found': static_sources_found,
        'active_scan_run': active_scan is not None
    }
}

with open(output_path, 'w') as f:
    json.dump(output, f, indent=2)

print(f'JSON written to: {output_path}', file=sys.stderr)
PYEOF

    if [ -f "$OUTPUT_PATH" ]; then
        print_success "JSON output written to: $OUTPUT_PATH"
    else
        print_error "Failed to write JSON output to $OUTPUT_PATH"
    fi
}

# ── Summary ───────────────────────────────────────────────────────────────────

generate_summary() {
    echo ""
    echo -e "${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${MAGENTA}📊 Network Discovery Summary${NC}"
    echo -e "${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "${CYAN}Target Directory:${NC} ${TARGET_DIR}"
    echo ""
    echo -e "${CYAN}Static Sources Scanned:${NC}"

    local df_count compose_count k8s_count helm_count cfg_count env_count
    df_count=$(wc -l < "$TEMP_DOCKERFILES" 2>/dev/null | tr -d ' '); df_count="${df_count:-0}"
    compose_count=$(wc -l < "$TEMP_COMPOSE" 2>/dev/null | tr -d ' '); compose_count="${compose_count:-0}"
    k8s_count=$(wc -l < "$TEMP_K8S" 2>/dev/null | tr -d ' '); k8s_count="${k8s_count:-0}"
    helm_count=$(wc -l < "$TEMP_HELM" 2>/dev/null | tr -d ' '); helm_count="${helm_count:-0}"
    cfg_count=$(wc -l < "$TEMP_CONFIGS" 2>/dev/null | tr -d ' '); cfg_count="${cfg_count:-0}"
    env_count=$(wc -l < "$TEMP_ENV" 2>/dev/null | tr -d ' '); env_count="${env_count:-0}"

    echo "  Dockerfile EXPOSE:      ${df_count} port(s)"
    echo "  Docker Compose ports:   ${compose_count} port(s)"
    echo "  Kubernetes manifests:   ${k8s_count} port(s)"
    echo "  Helm charts:            ${helm_count} port(s)"
    echo "  App configs:            ${cfg_count} port(s)"
    echo "  .env files:             ${env_count} port(s)"

    if [ -n "${NMAP_TARGET}" ] && [ -s "${TEMP_NMAP}" ]; then
        echo ""
        echo -e "${CYAN}Active Scan (${NMAP_TARGET}):${NC}"
        local open_count
        open_count=$(python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
    print(len(d.get('open_ports', [])))
except:
    print(0)
" < "$TEMP_NMAP" 2>/dev/null || echo "0")
        echo "  nmap open ports:        ${open_count} port(s)"
    else
        echo ""
        echo -e "${CYAN}Active Scan:${NC} Not run (set NMAP_TARGET=<host> to enable)"
    fi

    echo ""

    if [ -f "$OUTPUT_PATH" ] && command -v jq &>/dev/null; then
        local total_ports protocols services
        total_ports=$(jq '.summary.total_ports_discovered' "$OUTPUT_PATH" 2>/dev/null || echo "0")
        protocols=$(jq -r '.summary.protocols | join(", ")' "$OUTPUT_PATH" 2>/dev/null || echo "")
        services=$(jq -r '.summary.inferred_services | join(", ")' "$OUTPUT_PATH" 2>/dev/null || echo "")

        echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${GREEN}Total Unique Ports Discovered: ${total_ports}${NC}"
        [ -n "$protocols" ] && echo -e "${GREEN}Protocols: ${protocols}${NC}"
        [ -n "$services" ]  && echo -e "${GREEN}Inferred Services: ${services}${NC}"
        echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    fi
    echo ""
}

# ── Main ──────────────────────────────────────────────────────────────────────

main() {
    if [[ "${1:-}" == "--help" ]] || [[ "${1:-}" == "-h" ]]; then
        show_help
        exit 0
    fi

    print_banner

    if [ ! -d "${TARGET_DIR}" ]; then
        print_error "Target directory not found: ${TARGET_DIR}"
        exit 1
    fi

    # Set output directory
    if [ -n "${SCAN_DIR}" ]; then
        OUTPUT_DIR="${SCAN_DIR}/network"
    else
        OUTPUT_DIR="${TARGET_DIR}/.epyon-scan/network"
    fi
    mkdir -p "${OUTPUT_DIR}"
    OUTPUT_PATH="${OUTPUT_DIR}/${OUTPUT_FILE}"

    # Initialize temp files
    TEMP_DOCKERFILES="${OUTPUT_DIR}/tmp_dockerfiles.txt"
    TEMP_COMPOSE="${OUTPUT_DIR}/tmp_compose.txt"
    TEMP_K8S="${OUTPUT_DIR}/tmp_k8s.txt"
    TEMP_HELM="${OUTPUT_DIR}/tmp_helm.txt"
    TEMP_CONFIGS="${OUTPUT_DIR}/tmp_configs.txt"
    TEMP_ENV="${OUTPUT_DIR}/tmp_env.txt"
    TEMP_NMAP="${OUTPUT_DIR}/tmp_nmap.json"

    > "$TEMP_DOCKERFILES"
    > "$TEMP_COMPOSE"
    > "$TEMP_K8S"
    > "$TEMP_HELM"
    > "$TEMP_CONFIGS"
    > "$TEMP_ENV"
    > "$TEMP_NMAP"

    print_info "Target Directory: ${TARGET_DIR}"
    print_info "Output File: ${OUTPUT_PATH}"
    echo ""

    # Run static discovery
    scan_dockerfiles
    scan_docker_compose
    scan_kubernetes
    scan_helm_charts
    scan_app_configs
    scan_env_files

    # Run active scan if NMAP_TARGET is set
    if [[ -n "${NMAP_TARGET}" ]]; then
        run_nmap_scan
    else
        print_info "Active scanning disabled — set NMAP_TARGET=<host> to enable (only scan hosts you own)"
    fi

    # Build final JSON
    build_json_output

    # Print summary
    generate_summary

    print_success "Network discovery complete."
    echo ""
}

main "$@"
