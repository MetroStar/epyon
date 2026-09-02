#!/usr/bin/env bash

# ══════════════════════════════════════════════════════════════════════════════
# SHELL COMPATIBILITY AUTO-DETECTION
# ══════════════════════════════════════════════════════════════════════════════
# This script requires bash 4+ for array operations and parameter expansion.
# If invoked with bash < 4 or from a non-bash shell, it will automatically 
# re-execute itself in bash 4+ to ensure compatibility.
# ══════════════════════════════════════════════════════════════════════════════

# Check if we're already running in bash 4+
CURRENT_BASH_MAJOR="${BASH_VERSINFO[0]:-0}"
if [ "$CURRENT_BASH_MAJOR" -lt 4 ]; then
    # Not in bash 4+ — search for a suitable version and re-exec
    for bash_path in \
        /opt/homebrew/bin/bash \
        /usr/local/bin/bash \
        /home/linuxbrew/.linuxbrew/bin/bash \
        /usr/bin/bash \
        /bin/bash; do
        if [ -x "$bash_path" ]; then
            # Check version before re-executing
            FOUND_VERSION=$("$bash_path" --version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+' | head -1)
            FOUND_MAJOR=$(echo "$FOUND_VERSION" | cut -d. -f1)
            
            # Only use bash 4.0+
            if [ -n "$FOUND_MAJOR" ] && [ "$FOUND_MAJOR" -ge 4 ]; then
                # Found suitable bash — re-execute this script with bash 4+
                exec "$bash_path" "$0" "$@"
            fi
        fi
    done
    
    # Bash 4+ not found — print error and exit
    echo "ERROR: This script requires bash 4.0+ but it was not found."
    echo "Current shell: bash ${BASH_VERSION:-unknown} (need 4.0+)"
    echo "macOS users: Install bash 4+ via Homebrew: brew install bash"
    exit 1
fi

# ══════════════════════════════════════════════════════════════════════════════
# CI-only orchestrator for reusable workflow execution.
# ══════════════════════════════════════════════════════════════════════════════
# Keeps layer behavior aligned with epyon-scan.yml while reducing YAML step count.
#
# Performance: Independent layers run in parallel using background jobs.
# Dependency graph:
#   - Layer 1 (SBOM) must complete before Layer 8 (Grype sbom mode)
#   - Layer 3 (Sonar) must complete before Layer 4 (ClamAV) due to .scannerwork cleanup
#   - All other layers are independent and run concurrently.

set -u -o pipefail

DEFAULT_ENV_FILE="/tmp/epyon-env"
ENV_FILE="${EPYON_ENV_FILE:-$DEFAULT_ENV_FILE}"
SCAN_MODE_CLI=""

show_help() {
  cat <<'EOF'
Usage: run-epyon-scan-ci.sh [OPTIONS]

CI orchestrator that executes Epyon scan layers in parallel.

Options:
  -h, --help             Show this help text and exit.
      --env-file PATH    Path to environment file (default: /tmp/epyon-env).
      --scan-mode MODE   Override scan mode (quick|full|nightly|stig).
      --list-modes       Print available scan modes and exit.

Examples:
  run-epyon-scan-ci.sh
  run-epyon-scan-ci.sh --env-file /tmp/epyon-env
  run-epyon-scan-ci.sh --scan-mode quick --env-file /tmp/epyon-env

Required runtime variables (via env file or exported environment):
  SCAN_DIR, TARGET_DIR

Note:
  If --env-file is missing, this script can still run when required variables
  are already exported in the current environment.
EOF
}

show_mode_help() {
  cat <<'EOF'
Available scan modes:
  quick
  full
  nightly
  stig
EOF
}

require_option_value() {
  local opt_name="$1"
  local opt_value="$2"
  if [[ -z "$opt_value" ]] || [[ "$opt_value" == -* ]]; then
    echo "[ERROR] ${opt_name} requires a value"
    echo "[INFO] Run with --help for usage examples."
    exit 1
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      show_help
      exit 0
      ;;
    --list-modes)
      show_mode_help
      exit 0
      ;;
    --env-file)
      require_option_value "$1" "${2:-}"
      ENV_FILE="$2"
      shift 2
      ;;
    --scan-mode)
      require_option_value "$1" "${2:-}"
      SCAN_MODE_CLI="$2"
      shift 2
      ;;
    *)
      echo "[ERROR] Unknown option: $1"
      echo "[INFO] Run with --help for usage examples."
      exit 1
      ;;
  esac
done

RUN_SONAR_IN_QUICK="${RUN_SONAR_IN_QUICK:-false}"
RUN_GARAK_IN_QUICK="${RUN_GARAK_IN_QUICK:-false}"

if [[ -f "$ENV_FILE" ]]; then
  echo "[INFO] Loading environment file: $ENV_FILE"
  set -a
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  set +a
else
  echo "[WARNING] Environment file not found: $ENV_FILE"
fi

if [[ -n "$SCAN_MODE_CLI" ]]; then
  SCAN_MODE="$SCAN_MODE_CLI"
fi

# Enforce required runtime values early with actionable remediation.
MISSING_VARS=()
for required_var in SCAN_DIR TARGET_DIR; do
  if [[ -z "${!required_var:-}" ]]; then
    MISSING_VARS+=("$required_var")
  fi
done
if [[ ${#MISSING_VARS[@]} -gt 0 ]]; then
  echo "[ERROR] Missing required runtime variables: ${MISSING_VARS[*]}"
  echo "[INFO] Provide variables via --env-file or export them before running."
  echo "[INFO] Example env file template:"
  cat <<EOF
SCAN_DIR=/absolute/path/to/scans/<scan-id>
TARGET_DIR=/absolute/path/to/target
SCAN_ID=<scan-id>
TARGET_NAME=<app-name>
SCAN_MODE=full
EOF
  exit 1
fi

# Enforce supported scan modes to prevent accidental drift/false negatives.
# nightly runs all layers 1-12 but skips STIG (Layer 13).
case "${SCAN_MODE:-full}" in
  quick|full|nightly|stig) ;;
  *)
    echo "[WARNING] Unsupported SCAN_MODE='${SCAN_MODE:-}' — defaulting to 'full'"
    SCAN_MODE="full"
    ;;
esac

# Support invocation from workspace root or from inside ./epyon.
if [[ -d "epyon" && -f "epyon/VERSION" ]]; then
  cd epyon || exit 1
fi

# ── Write scan-metadata.json so the web parser can read scan_type ─────────────
# Only write if not already present (web-ui jobs.py writes it first; CI does not).
if [[ -n "${SCAN_DIR:-}" && ! -f "${SCAN_DIR}/scan-metadata.json" ]]; then
  mkdir -p "$SCAN_DIR"
  cat > "${SCAN_DIR}/scan-metadata.json" << _META_EOF
{
  "scan_id": "${SCAN_ID:-${SCAN_NAME:-}}",
  "target_directory": "${TARGET_DIR:-}",
  "target_name": "${TARGET_NAME:-}",
  "scan_type": "${SCAN_MODE:-full}",
  "scan_user": "${GITHUB_ACTOR:-ci}",
  "scan_timestamp": "$(date -u '+%Y-%m-%dT%H:%M:%SZ')",
  "epyon_version": "${EPYON_VERSION:-unknown}",
  "triggered_by": "ci"
}
_META_EOF
fi

# ── Timing infrastructure (bash 3.2 compatible — no declare -A) ──────────────
TIMING_FILE="${SCAN_DIR}/layer-timing.json"
TIMING_DIR="${SCAN_DIR}/.layer-timing"
mkdir -p "$TIMING_DIR"
ORCHESTRATOR_START=$SECONDS

# ── Webhook notification support ──────────────────────────────────────────────
# ── Webhook notification support ──────────────────────────────────────────────
# Send progress notifications to Barbatos or other management UIs.
# Reads: EPYON_CALLBACK_URL, EPYON_JOB_ID, EPYON_WEBHOOK_SECRET, EPYON_WEBHOOK_DEBUG
send_webhook() {
    local event_type="$1"
    local message="$2"
    local status="${3:-info}"
    local tool_name="${4:-}"
    local layer_num="${5:-}"
    local total_layers="${6:-16}"
    local result_file="${7:-}"
    
    # Only send if callback URL is configured
    if [[ -z "${EPYON_CALLBACK_URL:-}" ]]; then
        return 0
    fi
    
    # Use the same relative path pattern as other scripts in this orchestrator
    local webhook_script="scripts/shell/send-webhook-notification.sh"
    
    if [[ ! -x "$webhook_script" ]]; then
        [[ "${EPYON_WEBHOOK_DEBUG:-0}" == "1" ]] && echo "[webhook-debug] send-webhook-notification.sh not found or not executable at $webhook_script" >&2
        return 0
    fi
    
    if [[ "${EPYON_WEBHOOK_DEBUG:-0}" == "1" ]]; then
        # Debug mode - show all output
        "$webhook_script" "$event_type" "$message" "$status" "$tool_name" "$layer_num" "$total_layers" "$result_file" || true
    else
        # Silent mode - suppress stderr
        "$webhook_script" "$event_type" "$message" "$status" "$tool_name" "$layer_num" "$total_layers" "$result_file" 2>/dev/null || true
    fi
}

# Extract layer number from layer name (e.g., "Layer 1 - SBOM" → "1")
_extract_layer_number() {
    local layer_name="$1"
    if [[ "$layer_name" =~ [Ll]ayer[[:space:]]+([0-9]+) ]]; then
        echo "${BASH_REMATCH[1]}"
    else
        echo ""
    fi
}

# Sanitize a layer name into a valid filename/variable-name suffix.
_pkey() { printf '%s' "${1//[^a-zA-Z0-9]/_}"; }

# Map layer name to its primary JSON result file path (for webhook results payload)
_get_layer_result_file() {
  local layer_name="$1"
  case "$layer_name" in
    "Layer 1 - SBOM")
      # SBOM produces filesystem.cyclonedx.json (with dot, not hyphen)
      echo "${SCAN_DIR}/sbom/filesystem.cyclonedx.json"
      ;;
    "Layer 2 - TruffleHog")
      # TruffleHog runs in filesystem mode
      echo "${SCAN_DIR}/trufflehog/trufflehog-filesystem-results.json"
      ;;
    "Layer 3 - SonarQube")
      # SonarQube doesn't produce a local JSON file we can send
      echo ""
      ;;
    "Layer 4 - ClamAV")
      # ClamAV produces clamav-results.json
      echo "${SCAN_DIR}/clamav/clamav-results.json"
      ;;
    "Layer 5 - Helm")
      # Helm produces charts, not scan results
      echo ""
      ;;
    "Layer 6 - Checkov")
      # Checkov produces checkov-results.json (no mode suffix)
      echo "${SCAN_DIR}/checkov/checkov-results.json"
      ;;
    "Layer 7 - Trivy")
      # Trivy runs in filesystem mode, produces trivy-filesystem-results.json
      echo "${SCAN_DIR}/trivy/trivy-filesystem-results.json"
      ;;
    "Layer 8 - Grype")
      # Grype runs in sbom mode first (primary scan), produces grype-sbom-results.json
      echo "${SCAN_DIR}/grype/grype-sbom-results.json"
      ;;
    "Layer 9 - Xeol")
      # Xeol runs in filesystem mode, produces xeol-filesystem-results.json
      echo "${SCAN_DIR}/xeol/xeol-filesystem-results.json"
      ;;
    "Layer 10 - Anchore")
      # Anchore produces anchore-results.json
      echo "${SCAN_DIR}/anchore/anchore-results.json"
      ;;
    "Layer 11 - API Discovery")
      # API Discovery produces api-discovery-results.json
      echo "${SCAN_DIR}/api-discovery/api-discovery-results.json"
      ;;
    "Layer 11.5 - pip-audit")
      # pip-audit produces pip-audit-results.json
      echo "${SCAN_DIR}/pip-audit/pip-audit-results.json"
      ;;
    "Layer 11.6 - Python Safety Check")
      # Safety produces safety-results.json
      echo "${SCAN_DIR}/safety/safety-results.json"
      ;;
    *)
      echo ""
      ;;
  esac
}

_record_start() {
  local layer_name="$1"
  echo "$SECONDS" > "${TIMING_DIR}/start_$(_pkey "$layer_name")"
  
  # Send webhook: tool starting (with layer progress)
  local tool_slug=$(echo "$layer_name" | tr '[:upper:]' '[:lower:]' | tr ' ' '-' | sed 's/[^a-z0-9-]//g')
  local layer_num=$(_extract_layer_number "$layer_name")
  send_webhook "tool_start" "Starting $layer_name" "in_progress" "$tool_slug" "$layer_num" "16"
}

_record_end() {
  local layer_name="$1"
  local result_file="${2:-}"  # Optional: path to tool JSON output
  echo "$SECONDS" > "${TIMING_DIR}/end_$(_pkey "$layer_name")"
  local start
  start=$(cat "${TIMING_DIR}/start_$(_pkey "$layer_name")" 2>/dev/null || echo "$SECONDS")
  local elapsed=$(( SECONDS - start ))
  echo "[TIMING] $layer_name: ${elapsed}s"
  
  # Send webhook: tool completed (with results if available)
  local tool_slug=$(echo "$layer_name" | tr '[:upper:]' '[:lower:]' | tr ' ' '-' | sed 's/[^a-z0-9-]//g')
  local layer_num=$(_extract_layer_number "$layer_name")
  send_webhook "tool_complete" "$layer_name completed in ${elapsed}s" "success" "$tool_slug" "$layer_num" "16" "$result_file"
}

_write_timing_report() {
  echo "{"
  echo "  \"total_elapsed_seconds\": $((SECONDS - ORCHESTRATOR_START)),"
  echo "  \"layers\": {"
  local first=true
  local f
  for f in "${TIMING_DIR}"/start_*; do
    [[ -f "$f" ]] || continue
    local safe_key="${f##*/start_}"
    local start; start=$(cat "$f")
    local end_file="${TIMING_DIR}/end_${safe_key}"
    local end; end=$(cat "$end_file" 2>/dev/null || echo "$SECONDS")
    local elapsed=$(( end - start ))
    if [[ "$first" == "true" ]]; then first=false; else echo ","; fi
    printf '    "%s": %d' "${safe_key//_/ }" "$elapsed"
  done
  echo ""
  echo "  }"
  echo "}"
}

# ── Parallel execution helpers (bash 3.2 compatible — no declare -A) ─────────
# Each parallel layer writes its output to a log file; we cat them in order at the end.
PARALLEL_LOG_DIR="${SCAN_DIR}/.parallel-logs"
mkdir -p "$PARALLEL_LOG_DIR"
PARALLEL_LAYER_NAMES=()

_set_parallel_pid() {
  PARALLEL_LAYER_NAMES+=("$1")
  local vname="PARALLEL_PID_$(_pkey "$1")"
  eval "${vname}=\$2"
}

_get_parallel_pid() {
  local vname="PARALLEL_PID_$(_pkey "$1")"
  eval "echo \"\${${vname}:-}\""
}

# Run a layer as a background job, capturing output to a log file.
run_layer_parallel() {
  local layer_name="$1"
  local log_file="${PARALLEL_LOG_DIR}/${layer_name}.log"
  shift
  (
    _record_start "$layer_name"
    "$@" > "$log_file" 2>&1
    _record_end "$layer_name"
  ) &
  _set_parallel_pid "$layer_name" $!
}

# Wait for a specific layer to complete; replay its log.
await_layer() {
  local layer_name="$1"
  local pid; pid=$(_get_parallel_pid "$layer_name")
  if [[ -z "$pid" ]]; then return 0; fi
  wait "$pid" || true
  local log_file="${PARALLEL_LOG_DIR}/${layer_name}.log"
  if [[ -f "$log_file" ]]; then
    echo "::group::${layer_name}"
    cat "$log_file"
    echo "::endgroup::"
  fi
  local vname="PARALLEL_PID_$(_pkey "$layer_name")"
  eval "unset ${vname}"
}

# Wait for all remaining parallel layers.
await_all_layers() {
  local layer_name
  for layer_name in "${PARALLEL_LAYER_NAMES[@]}"; do
    await_layer "$layer_name"
  done
}

run_group() {
  local title="$1"
  shift
  echo "::group::${title}"
  "$@"
  local rc=$?
  if [[ $rc -ne 0 ]]; then
    echo "[WARNING] ${title} completed with warnings (exit ${rc})"
  fi
  echo "::endgroup::"
  return 0
}

run_layer_script() {
  local title="$1"
  local script_path="$2"
  shift 2

  chmod +x "$script_path"
  run_group "$title" env SCAN_DIR="$SCAN_DIR" TARGET_DIR="$TARGET_DIR" "$script_path" "$@"
}

run_sonar_layer() {
  run_group "Layer 3 - Code Quality (SonarQube)" bash -lc '
    RAW_BASE_KEY="${SONAR_PROJECT_KEY:-${GITHUB_REPOSITORY/\//\_}}"
    if [[ -n "${SUBDIR:-}" ]]; then
      SANITIZED_SUBDIR=$(echo "$SUBDIR" | sed -E "s#[/[:space:]]+#_#g; s#[^A-Za-z0-9._:-]#_#g")
      RAW_BASE_KEY="${RAW_BASE_KEY}_${SANITIZED_SUBDIR}"
    fi

    DERIVED_PROJECT_KEY=$(echo "$RAW_BASE_KEY" | sed -E "s#[^A-Za-z0-9._:-]#_#g; s#_+#_#g; s#^[_:. -]+##; s#[_:. -]+$##")
    if [[ -z "$DERIVED_PROJECT_KEY" ]]; then
      DERIVED_PROJECT_KEY="${GITHUB_REPOSITORY/\//\_}"
    fi

    REPO_NAME="${GITHUB_REPOSITORY#*/}"
    if [[ -n "${SUBDIR:-}" ]]; then
      DERIVED_PROJECT_NAME="${REPO_NAME} (${SUBDIR})"
    else
      DERIVED_PROJECT_NAME="$REPO_NAME"
    fi

    export SONAR_PROJECT_KEY="$DERIVED_PROJECT_KEY"
    export SONAR_PROJECT_NAME="$DERIVED_PROJECT_NAME"

    if [[ -n "${SONAR_PR_NUMBER:-}" ]]; then
      export SONAR_PR_BRANCH="${GITHUB_HEAD_REF:-}"
      export SONAR_PR_BASE="${GITHUB_BASE_REF:-}"
    else
      export SONAR_BRANCH="${GITHUB_REF_NAME:-}"
    fi

    export SONAR_EXTRA_ARGS=""

    echo "Using SONAR_PROJECT_KEY=$SONAR_PROJECT_KEY"
    echo "Using SONAR_PROJECT_NAME=$SONAR_PROJECT_NAME"

    chmod +x scripts/shell/run-sonar-analysis.sh
    SCAN_DIR="$SCAN_DIR" TARGET_DIR="$TARGET_DIR" ./scripts/shell/run-sonar-analysis.sh || echo "SonarQube analysis completed with warnings"
  '
}

run_garak_layer() {
  # Scan mode determines Garak default:
  #   quick/stig     → always skipped (stig mode runs Layer 13 only; Garak is never auto-run)
  #   all others     → skipped unless RUN_GARAK=true (manual opt-in)
  local _should_run="false"
  case "${SCAN_MODE:-full}" in
    quick|stig) _should_run="false" ;;
    *)          _should_run="false" ;;
  esac

  # Explicit RUN_GARAK from entrypoint overrides mode default (quick is never overridable).
  if [[ "${SCAN_MODE:-full}" != "quick" ]]; then
    [[ "${RUN_GARAK:-}" == "true"  ]] && _should_run="true"
    [[ "${RUN_GARAK:-}" == "false" ]] && _should_run="false"
  fi

  # Legacy SKIP_GARAK hard-stop.
  [[ "${SKIP_GARAK:-false}" == "true" ]] && _should_run="false"

  if [[ "$_should_run" == "false" ]]; then
    echo "[INFO] Skipping Layer 12 - LLM Security (scan_mode=${SCAN_MODE:-full})"
    return 0
  fi

  # Resolve target type/name here in the outer shell where env is guaranteed.
  local _target_type="${GARAK_TARGET_TYPE:-openai}"
  local _target_name="${GARAK_TARGET_NAME:-gpt-4o-mini}"

  # Diagnostic: confirm whether API key is present (value never logged).
  if [[ -n "${OPENAI_API_KEY:-}" ]]; then
    echo "[INFO] OPENAI_API_KEY is set (length: ${#OPENAI_API_KEY})"
  else
    echo "[WARNING] OPENAI_API_KEY is not set or empty"
  fi

  case "${_target_type,,}" in
    openai)
      if [[ -z "${OPENAI_API_KEY:-}" ]]; then
        echo "[INFO] OPENAI_API_KEY not available; falling back to test.Blank"
        _target_type="test"
        _target_name="test.Blank"
      fi
      ;;
    anthropic)
      if [[ -z "${ANTHROPIC_API_KEY:-}" ]]; then
        echo "[INFO] ANTHROPIC_API_KEY not available; falling back to test.Blank"
        _target_type="test"
        _target_name="test.Blank"
      fi
      ;;
  esac

  local _probes="${GARAK_PROBES:-promptinject}"

  run_group "Layer 12 - LLM Security (Garak)" \
    env SCAN_DIR="$SCAN_DIR" TARGET_DIR="$TARGET_DIR" \
        GARAK_TARGET_TYPE="$_target_type" GARAK_TARGET_NAME="$_target_name" \
        GARAK_PROBES="$_probes" \
        OPENAI_API_KEY="${OPENAI_API_KEY:-}" ANTHROPIC_API_KEY="${ANTHROPIC_API_KEY:-}" \
    bash -lc '
      chmod +x scripts/shell/run-garak-scan.sh
      ./scripts/shell/run-garak-scan.sh || echo "Garak scan completed with warnings"
    '
}

_detect_model_files() {
  # Returns 0 (true) if any ML model weight files are found under TARGET_DIR.
  local dir="${TARGET_DIR:-}"
  [[ -z "$dir" || ! -d "$dir" ]] && return 1
  local _exts=("pkl" "pickle" "pt" "pth" "ckpt" "bin" "joblib" "npy" "npz" "h5" "hdf5" "safetensors" "onnx" "gguf" "ggml" "msgpack")
  for ext in "${_exts[@]}"; do
    if find "$dir" -type f -name "*.${ext}" -print -quit 2>/dev/null | grep -q .; then
      return 0
    fi
  done
  return 1
}

run_picklescan_layer() {
  # Layer 14 — Comprehensive Model File Analysis (Enhanced Picklescan)
  # Multi-format detection: pickle, pytorch, onnx, tensorflow, config files
  # Runs in full/nightly/baseline/huggingface/local_model modes; skipped for quick and stig.
  # Scripts handle the "no model files" case gracefully (0-file result).
  # Override: RUN_PICKLESCAN=true/false, SKIP_PICKLESCAN=true.
  local _should_run="false"
  case "${SCAN_MODE:-full}" in
    quick|stig) _should_run="false" ;;
    *)          _should_run="true"  ;;
  esac

  [[ "${RUN_PICKLESCAN:-}" == "true"  ]] && _should_run="true"
  [[ "${RUN_PICKLESCAN:-}" == "false" ]] && _should_run="false"
  [[ "${SKIP_PICKLESCAN:-false}" == "true" ]] && _should_run="false"

  if [[ "$_should_run" == "false" ]]; then
    echo "[INFO] Skipping Layer 14 - Enhanced Picklescan (scan_mode=${SCAN_MODE:-full}; set RUN_PICKLESCAN=true to force)"
    return 0
  fi

  # Use enhanced Python scanner with multi-format support
  run_group "Layer 14 - Comprehensive Model File Analysis (Enhanced Picklescan)" bash -lc '
    chmod +x scripts/shell/run-picklescan.py
    python3 scripts/shell/run-picklescan.py \
      --target "$TARGET_DIR" \
      --scan-dir "$SCAN_DIR" \
      --app-name "${TARGET_NAME:-$(basename "$TARGET_DIR")}" \
      --formats pickle,pytorch,onnx,tensorflow,config
  '
}

run_modelcard_layer() {
  # Layer 15 — Model Card Compliance Checker
  # Runs in full/nightly/baseline/huggingface/local_model modes; skipped for quick and stig.
  # Script handles missing README gracefully (status: skipped).
  # Override: RUN_MODELCARD=true/false, SKIP_MODELCARD=true.
  local _should_run="false"
  case "${SCAN_MODE:-full}" in
    quick|stig) _should_run="false" ;;
    *)          _should_run="true"  ;;
  esac

  [[ "${RUN_MODELCARD:-}" == "true"  ]] && _should_run="true"
  [[ "${RUN_MODELCARD:-}" == "false" ]] && _should_run="false"
  [[ "${SKIP_MODELCARD:-false}" == "true" ]] && _should_run="false"

  if [[ "$_should_run" == "false" ]]; then
    echo "[INFO] Skipping Layer 15 - Model Card Compliance (scan_mode=${SCAN_MODE:-full}; set RUN_MODELCARD=true to force)"
    return 0
  fi

  run_layer_script "Layer 15 - Model Card Compliance (modelcard)" "scripts/shell/run-modelcard-check.sh"
}

run_network_discovery_layer() {
  # Layer 16 — Network Discovery (ports, protocols, services)
  # Runs static config analysis (Dockerfile, docker-compose, K8s, Helm, Spring Boot, .env).
  # Active nmap scanning is opt-in: set NMAP_TARGET=<host> to enable.
  # Override: SKIP_NETWORK_DISCOVERY=true to disable.
  if [[ "${SKIP_NETWORK_DISCOVERY:-false}" == "true" ]]; then
    echo "[INFO] Skipping Layer 16 - Network Discovery (SKIP_NETWORK_DISCOVERY=true)"
    return 0
  fi
  run_layer_script "Layer 16 - Network Discovery" "scripts/shell/run-network-discovery.sh"
}

run_model_provenance_layer() {
  # Layer 18 — Model Provenance & Threat Intelligence
  # Validates model signatures, author reputation, and checks against blocklist.
  # Runs in full/nightly/baseline modes; skipped for quick and stig.
  # Override: RUN_MODEL_PROVENANCE=true/false, SKIP_MODEL_PROVENANCE=true.
  local _should_run="false"
  case "${SCAN_MODE:-full}" in
    quick|stig) _should_run="false" ;;
    *)          _should_run="true"  ;;
  esac

  [[ "${RUN_MODEL_PROVENANCE:-}" == "true"  ]] && _should_run="true"
  [[ "${RUN_MODEL_PROVENANCE:-}" == "false" ]] && _should_run="false"
  [[ "${SKIP_MODEL_PROVENANCE:-false}" == "true" ]] && _should_run="false"

  if [[ "$_should_run" == "false" ]]; then
    echo "[INFO] Skipping Layer 18 - Model Provenance (scan_mode=${SCAN_MODE:-full}; set RUN_MODEL_PROVENANCE=true to force)"
    return 0
  fi

  run_layer_script "Layer 18 - Model Provenance & Threat Intelligence" "scripts/shell/run-model-provenance-check.sh"
}

run_inference_security_layer() {
  # Layer 19 — Inference Environment Security
  # Analyzes Dockerfile, docker-compose, and Kubernetes manifests for security misconfigurations.
  # Runs in full/nightly modes; skipped for quick and stig.
  # Override: RUN_INFERENCE_SECURITY=true/false, SKIP_INFERENCE_SECURITY=true.
  local _should_run="false"
  case "${SCAN_MODE:-full}" in
    quick|stig) _should_run="false" ;;
    *)          _should_run="true"  ;;
  esac

  [[ "${RUN_INFERENCE_SECURITY:-}" == "true"  ]] && _should_run="true"
  [[ "${RUN_INFERENCE_SECURITY:-}" == "false" ]] && _should_run="false"
  [[ "${SKIP_INFERENCE_SECURITY:-false}" == "true" ]] && _should_run="false"

  if [[ "$_should_run" == "false" ]]; then
    echo "[INFO] Skipping Layer 19 - Inference Security (scan_mode=${SCAN_MODE:-full}; set RUN_INFERENCE_SECURITY=true to force)"
    return 0
  fi

  run_layer_script "Layer 19 - Inference Environment Security" "scripts/shell/run-inference-security-scan.sh"
}

run_ml_runtime_layer() {
  # Layer 20 — ML Runtime Behavioral Analysis (Opt-in Only)
  # Executes models in sandboxed containers to detect malicious runtime behavior.
  # Resource-intensive: requires Docker/Podman. Defaults to disabled.
  # Enable with: RUN_ML_RUNTIME=true
  # Override: SKIP_ML_RUNTIME=true to force-disable.
  local _should_run="false"

  # Layer 20 is opt-in only — never runs automatically
  [[ "${RUN_ML_RUNTIME:-false}" == "true" ]] && _should_run="true"
  [[ "${SKIP_ML_RUNTIME:-false}" == "true" ]] && _should_run="false"

  if [[ "$_should_run" == "false" ]]; then
    if [[ "${SKIP_ML_RUNTIME:-false}" == "true" ]]; then
      echo "[INFO] Skipping Layer 20 - ML Runtime Analysis (SKIP_ML_RUNTIME=true)"
    else
      echo "[INFO] Skipping Layer 20 - ML Runtime Analysis (set RUN_ML_RUNTIME=true to enable)"
    fi
    return 0
  fi

  run_group "Layer 20 - ML Runtime Behavioral Analysis" bash -lc '
    chmod +x scripts/shell/run-ml-runtime-analysis.py
    python3 scripts/shell/run-ml-runtime-analysis.py \
      --target "$TARGET_DIR" \
      --scan-dir "$SCAN_DIR" \
      --app-name "${TARGET_NAME:-$(basename "$TARGET_DIR")}"
  '
}

# ── Per-tool skip helpers ─────────────────────────────────────────────────────
# Each tool respects a SKIP_<TOOL>=true env var for manual opt-out.
_should_run_tool() {
  local skip_var="$1"   # e.g. SKIP_TRIVY
  [[ "${!skip_var:-false}" == "true" ]] && return 1
  return 0
}

# ── Pre-built SBOM passthrough ────────────────────────────────────────────────
# If the build job uploaded a CycloneDX SBOM artifact, place it in the expected
# location so Grype/Trivy consume it without running Syft (Layer 1).
_install_prebuilt_sbom() {
  local prebuilt_dir="${PREBUILT_SBOM_DIR:-}"
  if [[ -z "$prebuilt_dir" || ! -d "$prebuilt_dir" ]]; then
    return 1  # no pre-built SBOM available
  fi

  local sbom_dir="${SCAN_DIR}/sbom"
  mkdir -p "$sbom_dir"

  # Find the CycloneDX JSON file in the artifact directory
  local cdx_file
  cdx_file=$(find "$prebuilt_dir" -name "*.cyclonedx.json" -o -name "*sbom*.json" | head -1)
  if [[ -z "$cdx_file" ]]; then
    echo "[WARNING] Pre-built SBOM directory exists but contains no JSON files"
    return 1
  fi

  cp "$cdx_file" "$sbom_dir/filesystem-cyclonedx.json"
  echo "[INFO] Installed pre-built SBOM: $(basename "$cdx_file") -> $sbom_dir/filesystem-cyclonedx.json"
  return 0
}

# ══════════════════════════════════════════════════════════════════════════════
# LAYER EXECUTION — PARALLELIZED
# ══════════════════════════════════════════════════════════════════════════════
# Dependency graph:
#   Phase 1 (parallel): Layers 1, 2, 3, 5, 6, 7, 9, 10, 11
#   Phase 2 (after L1):  Layer 8 (Grype — needs SBOM)
#   Phase 2 (after L3):  Layer 4 (ClamAV — needs .scannerwork removed)
#   Phase 3:             Layers 12, 13, 14, 15 (conditional, run sequentially)
# ══════════════════════════════════════════════════════════════════════════════

# Send scan start webhook (Barbatos format: progress step)
send_webhook "scan_start" "Security scan initialized - starting layers" "info" "scan-init"

# Layers 1-12 — skipped entirely when SCAN_MODE=stig (STIG-only run)
if [[ "${SCAN_MODE:-full}" == "stig" ]]; then
  echo "[INFO] scan_mode=stig — skipping Layers 1-12 (STIG-only run)"
else

# ── Phase 1: Independent layers (parallel) ───────────────────────────────────

# Layer 1 — SBOM (Syft). Skip if pre-built SBOM provided by caller.
if _install_prebuilt_sbom; then
  echo "[INFO] Using pre-built SBOM from build job artifact — skipping Layer 1 (Syft)"
  SBOM_READY=true
elif _should_run_tool SKIP_SBOM; then
  _record_start "Layer 1 - SBOM"
  chmod +x scripts/shell/run-complete-sbom-scan.sh
  env SCAN_DIR="$SCAN_DIR" TARGET_DIR="$TARGET_DIR" scripts/shell/run-complete-sbom-scan.sh \
    > "${PARALLEL_LOG_DIR}/layer-01-sbom.log" 2>&1 &
  _set_parallel_pid "Layer 1 - SBOM" $!
  SBOM_READY=false
else
  echo "[INFO] Skipping Layer 1 - SBOM (SKIP_SBOM=true)"
  SBOM_READY=true
fi

# Layer 2 — TruffleHog (no deps)
if _should_run_tool SKIP_TRUFFLEHOG; then
  _record_start "Layer 2 - TruffleHog"
  chmod +x scripts/shell/run-trufflehog-scan.sh
  env SCAN_DIR="$SCAN_DIR" TARGET_DIR="$TARGET_DIR" scripts/shell/run-trufflehog-scan.sh filesystem \
    > "${PARALLEL_LOG_DIR}/layer-02-trufflehog.log" 2>&1 &
  _set_parallel_pid "Layer 2 - TruffleHog" $!
else
  echo "[INFO] Skipping Layer 2 - TruffleHog (SKIP_TRUFFLEHOG=true)"
fi

# Layer 3 — Sonar (no deps, but Layer 4 depends on its completion)
SONAR_PID=""
if _should_run_tool SKIP_SONAR && [[ "${SCAN_MODE:-full}" != "quick" || "${RUN_SONAR_IN_QUICK}" == "true" ]]; then
  _record_start "Layer 3 - SonarQube"
  (
    run_sonar_layer
    rm -rf "${TARGET_DIR:?}/.scannerwork"
  ) > "${PARALLEL_LOG_DIR}/layer-03-sonar.log" 2>&1 &
  SONAR_PID=$!
  _set_parallel_pid "Layer 3 - SonarQube" $SONAR_PID
else
  [[ "${SKIP_SONAR:-false}" == "true" ]] && echo "[INFO] Skipping Layer 3 - Sonar (SKIP_SONAR=true)" || echo "[INFO] Skipping Layer 3 (quick mode)"
fi

# Layer 5 — Helm (no deps)
if _should_run_tool SKIP_HELM && [[ "${SCAN_MODE:-full}" != "quick" ]]; then
  _record_start "Layer 5 - Helm"
  chmod +x scripts/shell/run-helm-build.sh
  env SCAN_DIR="$SCAN_DIR" TARGET_DIR="$TARGET_DIR" scripts/shell/run-helm-build.sh \
    > "${PARALLEL_LOG_DIR}/layer-05-helm.log" 2>&1 &
  _set_parallel_pid "Layer 5 - Helm" $!
else
  [[ "${SKIP_HELM:-false}" == "true" ]] && echo "[INFO] Skipping Layer 5 - Helm (SKIP_HELM=true)" || echo "[INFO] Skipping Layer 5 (quick mode)"
fi

# Layer 6 — Checkov (no deps)
if _should_run_tool SKIP_CHECKOV && [[ "${SCAN_MODE:-full}" != "quick" ]]; then
  _record_start "Layer 6 - Checkov"
  chmod +x scripts/shell/run-checkov-scan.sh
  env CI=true SCAN_DIR="$SCAN_DIR" TARGET_DIR="$TARGET_DIR" scripts/shell/run-checkov-scan.sh \
    > "${PARALLEL_LOG_DIR}/layer-06-checkov.log" 2>&1 &
  _set_parallel_pid "Layer 6 - Checkov" $!
else
  [[ "${SKIP_CHECKOV:-false}" == "true" ]] && echo "[INFO] Skipping Layer 6 - Checkov (SKIP_CHECKOV=true)" || echo "[INFO] Skipping Layer 6 (quick mode)"
fi

# Layer 7 — Trivy (no deps)
if _should_run_tool SKIP_TRIVY; then
  _record_start "Layer 7 - Trivy"
  chmod +x scripts/shell/run-trivy-scan.sh
  (
    SCAN_DIR="$SCAN_DIR" TARGET_DIR="$TARGET_DIR" ./scripts/shell/run-trivy-scan.sh filesystem || true
    SCAN_DIR="$SCAN_DIR" TARGET_DIR="$TARGET_DIR" ./scripts/shell/run-trivy-scan.sh base || true
  ) > "${PARALLEL_LOG_DIR}/layer-07-trivy.log" 2>&1 &
  _set_parallel_pid "Layer 7 - Trivy" $!
else
  echo "[INFO] Skipping Layer 7 - Trivy (SKIP_TRIVY=true)"
fi

# Layer 9 — Xeol (no deps)
if _should_run_tool SKIP_XEOL && [[ "${SCAN_MODE:-full}" != "quick" ]]; then
  _record_start "Layer 9 - Xeol"
  chmod +x scripts/shell/run-xeol-scan.sh
  env SCAN_DIR="$SCAN_DIR" TARGET_DIR="$TARGET_DIR" scripts/shell/run-xeol-scan.sh \
    > "${PARALLEL_LOG_DIR}/layer-09-xeol.log" 2>&1 &
  _set_parallel_pid "Layer 9 - Xeol" $!
else
  [[ "${SKIP_XEOL:-false}" == "true" ]] && echo "[INFO] Skipping Layer 9 - Xeol (SKIP_XEOL=true)" || echo "[INFO] Skipping Layer 9 (quick mode)"
fi

# Layer 10 — Anchore (no deps)
if _should_run_tool SKIP_ANCHORE && [[ "${SCAN_MODE:-full}" != "quick" ]]; then
  _record_start "Layer 10 - Anchore"
  chmod +x scripts/shell/run-anchore-scan.sh
  env SCAN_DIR="$SCAN_DIR" TARGET_DIR="$TARGET_DIR" scripts/shell/run-anchore-scan.sh \
    > "${PARALLEL_LOG_DIR}/layer-10-anchore.log" 2>&1 &
  _set_parallel_pid "Layer 10 - Anchore" $!
else
  [[ "${SKIP_ANCHORE:-false}" == "true" ]] && echo "[INFO] Skipping Layer 10 - Anchore (SKIP_ANCHORE=true)" || echo "[INFO] Skipping Layer 10 (quick mode)"
fi

# Layer 11 — API Discovery (no deps)
if _should_run_tool SKIP_API_DISCOVERY && [[ "${SCAN_MODE:-full}" != "quick" ]]; then
  _record_start "Layer 11 - API Discovery"
  chmod +x scripts/shell/run-api-discovery.sh
  env SCAN_DIR="$SCAN_DIR" TARGET_DIR="$TARGET_DIR" scripts/shell/run-api-discovery.sh \
    > "${PARALLEL_LOG_DIR}/layer-11-api-discovery.log" 2>&1 &
  _set_parallel_pid "Layer 11 - API Discovery" $!
else
  [[ "${SKIP_API_DISCOVERY:-false}" == "true" ]] && echo "[INFO] Skipping Layer 11 - API Discovery (SKIP_API_DISCOVERY=true)" || echo "[INFO] Skipping Layer 11 (quick mode)"
fi

# Layer 11.5 — pip-audit (Direct Dependency Scanning)
# Complements Grype by scanning requirements.txt directly, catching CVEs missed by SBOM-based scanners
if _should_run_tool SKIP_PIP_AUDIT; then
  _record_start "Layer 11.5 - pip-audit"
  chmod +x scripts/shell/run-pip-audit-scan.sh
  env SCAN_DIR="$SCAN_DIR" TARGET_DIR="$TARGET_DIR" scripts/shell/run-pip-audit-scan.sh \
    > "${PARALLEL_LOG_DIR}/layer-11.5-pip-audit.log" 2>&1 &
  _set_parallel_pid "Layer 11.5 - pip-audit" $!
else
  [[ "${SKIP_PIP_AUDIT:-false}" == "true" ]] && echo "[INFO] Skipping Layer 11.5 - pip-audit (SKIP_PIP_AUDIT=true)"
fi

# Layer 11.6 — Python Vulnerability Safety (complement pip-audit with NVD + PyPI advisory coverage)
# Catches CVEs in pip-audit's database gaps (e.g., GHSA-jm82-fx9c-mx94 for pypdf)
if _should_run_tool SKIP_SAFETY; then
  _record_start "Layer 11.6 - Python Safety Check"
  chmod +x scripts/shell/run-safety-scan.sh
  env SCAN_DIR="$SCAN_DIR" TARGET_DIR="$TARGET_DIR" scripts/shell/run-safety-scan.sh \
    > "${PARALLEL_LOG_DIR}/layer-11.6-safety.log" 2>&1 &
  _set_parallel_pid "Layer 11.6 - Python Safety Check" $!
else
  [[ "${SKIP_SAFETY:-false}" == "true" ]] && echo "[INFO] Skipping Layer 11.6 - Python Safety Check (SKIP_SAFETY=true)"
fi

# Layer 16 — Network Discovery (no deps; active scan requires NMAP_TARGET to be set)
if _should_run_tool SKIP_NETWORK_DISCOVERY && [[ "${SCAN_MODE:-full}" != "quick" ]]; then
  _record_start "Layer 16 - Network Discovery"
  chmod +x scripts/shell/run-network-discovery.sh
  env SCAN_DIR="$SCAN_DIR" TARGET_DIR="$TARGET_DIR" \
    NMAP_TARGET="${NMAP_TARGET:-}" \
    NMAP_FULL_SCAN="${NMAP_FULL_SCAN:-false}" \
    scripts/shell/run-network-discovery.sh \
    > "${PARALLEL_LOG_DIR}/layer-16-network-discovery.log" 2>&1 &
  _set_parallel_pid "Layer 16 - Network Discovery" $!
else
  [[ "${SKIP_NETWORK_DISCOVERY:-false}" == "true" ]] && echo "[INFO] Skipping Layer 16 - Network Discovery (SKIP_NETWORK_DISCOVERY=true)" || echo "[INFO] Skipping Layer 16 (quick mode)"
fi

echo "[INFO] Phase 1: ${#PARALLEL_LAYER_NAMES[@]} layers launched in parallel"

# ── Phase 2: Layers with dependencies ────────────────────────────────────────

# Layer 8 — Grype (depends on Layer 1 SBOM)
if _should_run_tool SKIP_GRYPE; then
  # Wait for Layer 1 (SBOM) to complete first
  if [[ "$SBOM_READY" == "false" ]]; then
    echo "[INFO] Layer 8 (Grype) waiting for Layer 1 (SBOM)..."
    await_layer "Layer 1 - SBOM"
    # Send SBOM results to Barbatos
    result_file="${SCAN_DIR}/sbom/filesystem-cyclonedx.json"
    if [[ -f "$result_file" ]]; then
      _record_end "Layer 1 - SBOM" "$result_file"
    else
      _record_end "Layer 1 - SBOM"
    fi
    SBOM_READY=true
  fi

  _record_start "Layer 8 - Grype"
  chmod +x scripts/shell/run-grype-scan.sh
  (
    echo "[grype-debug] Starting Grype SBOM scan..."
    echo "[grype-debug] SCAN_DIR=$SCAN_DIR"
    echo "[grype-debug] TARGET_DIR=$TARGET_DIR"
    
    # Run SBOM scan
    if SCAN_DIR="$SCAN_DIR" TARGET_DIR="$TARGET_DIR" ./scripts/shell/run-grype-scan.sh sbom; then
      echo "[grype-debug] SBOM scan completed successfully"
    else
      echo "[grype-error] SBOM scan failed with exit code $?"
    fi
    
    # Run images scan
    if SCAN_DIR="$SCAN_DIR" TARGET_DIR="$TARGET_DIR" ./scripts/shell/run-grype-scan.sh images; then
      echo "[grype-debug] Images scan completed successfully"
    else
      echo "[grype-error] Images scan failed with exit code $?"
    fi
    
    # Verify output was created
    if [[ ! -d "${SCAN_DIR}/grype" ]]; then
      echo "[grype-error] CRITICAL: grype directory was not created at ${SCAN_DIR}/grype"
      echo "[grype-error] This indicates Grype failed before init_scan_environment completed"
      ls -la "${SCAN_DIR}/" || true
    else
      echo "[grype-debug] Output directory exists: ${SCAN_DIR}/grype"
      ls -la "${SCAN_DIR}/grype/" || true
    fi
  ) > "${PARALLEL_LOG_DIR}/layer-08-grype.log" 2>&1 &
  _set_parallel_pid "Layer 8 - Grype" $!
else
  echo "[INFO] Skipping Layer 8 - Grype (SKIP_GRYPE=true)"
fi

# Layer 4 — ClamAV (depends on Layer 3 Sonar completing to remove .scannerwork)
if _should_run_tool SKIP_CLAMAV; then
  # Wait for Sonar to complete first (if it ran)
  if [[ -n "$SONAR_PID" ]]; then
    echo "[INFO] Layer 4 (ClamAV) waiting for Layer 3 (Sonar)..."
    await_layer "Layer 3 - SonarQube"
    # SonarQube doesn't produce a local JSON file to send
    _record_end "Layer 3 - SonarQube"
  fi

  _record_start "Layer 4 - ClamAV"
  chmod +x scripts/shell/run-clamav-scan.sh
  env SCAN_DIR="$SCAN_DIR" TARGET_DIR="$TARGET_DIR" scripts/shell/run-clamav-scan.sh \
    > "${PARALLEL_LOG_DIR}/layer-04-clamav.log" 2>&1 &
  _set_parallel_pid "Layer 4 - ClamAV" $!
else
  echo "[INFO] Skipping Layer 4 - ClamAV (SKIP_CLAMAV=true)"
fi

# ── Wait for all Phase 1 + Phase 2 layers ────────────────────────────────────
echo "[INFO] Waiting for all parallel layers to complete..."
for layer_name in "${PARALLEL_LAYER_NAMES[@]}"; do
  local_pid=$(_get_parallel_pid "$layer_name")
  [[ -z "$local_pid" ]] && continue
  wait "$local_pid" || true
  # Record end time for layers that haven't been recorded yet
  if [[ ! -f "${TIMING_DIR}/end_$(_pkey "$layer_name")" ]]; then
    # Get the result file path for this layer (if it exists)
    result_file=$(_get_layer_result_file "$layer_name")
    if [[ -n "$result_file" && -f "$result_file" ]]; then
      _record_end "$layer_name" "$result_file"
    else
      _record_end "$layer_name"
    fi
  fi
done

# Replay all layer logs in order for readable CI output
echo ""
echo "[INFO] ═══ Layer Output ═══"
for log_file in $(ls "${PARALLEL_LOG_DIR}"/layer-*.log 2>/dev/null | sort); do
  layer_label=$(basename "$log_file" .log | sed 's/^layer-[0-9]*-//' | tr '-' ' ')
  echo "::group::$(basename "$log_file" .log)"
  cat "$log_file"
  echo "::endgroup::"
done

fi  # end: SCAN_MODE != stig

# ── Phase 3: Conditional sequential layers ────────────────────────────────────
run_garak_layer

# Layer 13 — STIG Compliance Assessment
# Runs only in full/stig modes (NOT nightly) when SKIP_STIG is not true.
if [[ ("${SCAN_MODE:-full}" == "full" || "${SCAN_MODE:-full}" == "stig") && "${SCAN_MODE:-full}" != "nightly" ]] && _should_run_tool SKIP_STIG; then
  run_group "Layer 13 - STIG Compliance Assessment" \
    env \
      OPENAI_API_KEY="${OPENAI_API_KEY:-}" \
      OPENAI_MODEL="${OPENAI_MODEL:-gpt-4o-mini}" \
      SCAN_DIR="$SCAN_DIR" \
      TARGET_DIR="$TARGET_DIR" \
    bash -lc '
      chmod +x scripts/shell/run-stig-scan.sh
      STIGS_DIR="${STIGS_DIR:-configuration/stigs}" \
      APP_NAME="${TARGET_NAME:-$(basename "$TARGET_DIR")}" \
      ./scripts/shell/run-stig-scan.sh "$TARGET_DIR" || echo "[WARNING] STIG assessment completed with warnings"
    '
elif [[ "${SKIP_STIG:-false}" == "true" ]]; then
  echo "[INFO] Skipping Layer 13 - STIG (SKIP_STIG=true)"
else
  echo "[INFO] Skipping Layer 13 - STIG (scan_mode=${SCAN_MODE:-full}; STIG runs only in full or stig mode)"
fi

run_picklescan_layer

run_modelcard_layer

run_model_provenance_layer

run_inference_security_layer

run_ml_runtime_layer

# ── Post-scan: Reports & Dashboard ───────────────────────────────────────────

run_group "Generate Scan Manifest" bash -lc '
  chmod +x scripts/shell/generate-scan-manifest.sh
  ./scripts/shell/generate-scan-manifest.sh "$SCAN_DIR" || echo "Manifest generation completed with warnings"
'

run_group "Generate Security Findings Summary" bash -lc '
  chmod +x scripts/shell/generate-scan-findings-summary.sh
  source scripts/shell/generate-scan-findings-summary.sh
  generate_scan_findings_summary "$(basename "$SCAN_DIR")" "$TARGET_DIR" "$PWD" || echo "Summary generation completed with warnings"
'

run_group "Apply Suppression Rules" bash -lc '
  FINDINGS_SUMMARY="$SCAN_DIR/security-findings-summary.json"
  if [[ ! -f "$FINDINGS_SUMMARY" ]]; then
    echo "[INFO] No findings summary found — skipping suppression filter"
    exit 0
  fi

  # Build ignore cache from the target repo .epyon-ignore.yml (if present).
  # Try multiple candidate locations to handle different workspace layouts
  # (repo at TARGET_DIR, at GITHUB_WORKSPACE root, etc.).
  IGNORE_CACHE="${IGNORE_CACHE:-/tmp/epyon-ignore-cache.json}"
  if [[ -f "scripts/shell/parse-epyon-ignore.sh" ]]; then
    source scripts/shell/parse-epyon-ignore.sh
    _IGNORE_FILE=""
    for _candidate in \
        "${TARGET_DIR:-}/.epyon-ignore.yml" \
        "${GITHUB_WORKSPACE:-}/.epyon-ignore.yml"; do
      if [[ -n "$_candidate" && -f "$_candidate" ]]; then
        _IGNORE_FILE="$_candidate"
        break
      fi
    done
    if [[ -n "$_IGNORE_FILE" ]]; then
      echo "[INFO] Parsing ignore rules from: $_IGNORE_FILE"
      parse_ignore_rules "$_IGNORE_FILE" 2>/dev/null || true
    else
      echo "[INFO] No .epyon-ignore.yml found — skipping suppression filter"
      echo '{"ignores": []}' > "$IGNORE_CACHE"
    fi
  else
    echo "{\"ignores\": []}" > "$IGNORE_CACHE"
  fi

  # Source tool-suppression helpers.
  if [[ -f "scripts/shell/filter-ignored-findings.sh" ]]; then
    source scripts/shell/filter-ignored-findings.sh 2>/dev/null || true
    init_suppressed_log 2>/dev/null || true
  fi

  # Build a jq select filter that removes any tool suppressed in .epyon-ignore.yml.
  SUPPRESSED_TOOLS_JQ=""
  for tool_name in grype trivy trufflehog checkov clamav anchore xeol pip-audit safety; do
    if declare -f is_tool_ignored >/dev/null 2>&1 && is_tool_ignored "$tool_name" 2>/dev/null; then
      echo "[INFO] Suppressing findings from tool: $tool_name"
      SUPPRESSED_TOOLS_JQ="${SUPPRESSED_TOOLS_JQ} and ((.tool // \"\" | ascii_downcase) | startswith(\"${tool_name}\") | not)"
    fi
  done

  FILTERED_SUMMARY="${FINDINGS_SUMMARY%.json}-filtered.json"
  if [[ -n "$SUPPRESSED_TOOLS_JQ" ]]; then
    FILTER_EXPR="select(true ${SUPPRESSED_TOOLS_JQ})"
    JQ_FILTER="
      .critical_findings = [.critical_findings[] | ${FILTER_EXPR}] |
      .high_findings     = [.high_findings[]     | ${FILTER_EXPR}] |
      .medium_findings   = [.medium_findings[]   | ${FILTER_EXPR}] |
      .low_findings      = [.low_findings[]      | ${FILTER_EXPR}] |
      .summary.total_critical = ([.critical_findings[] | ${FILTER_EXPR}] | length) |
      .summary.total_high     = ([.high_findings[]     | ${FILTER_EXPR}] | length) |
      .summary.total_medium   = ([.medium_findings[]   | ${FILTER_EXPR}] | length) |
      .summary.total_low      = ([.low_findings[]      | ${FILTER_EXPR}] | length)
    "
    jq "$JQ_FILTER" "$FINDINGS_SUMMARY" > "$FILTERED_SUMMARY" \
      && echo "[INFO] Wrote filtered findings: $FILTERED_SUMMARY" \
      || echo "[WARNING] Could not write filtered findings — tickets will use raw summary"
  else
    # No active suppressions — write an identical filtered copy so downstream
    # steps (create-jira-tickets.sh) always find a consistent file name.
    cp "$FINDINGS_SUMMARY" "$FILTERED_SUMMARY" \
      && echo "[INFO] No suppressions active — copied raw summary to: $FILTERED_SUMMARY" \
      || echo "[WARNING] Could not copy findings summary"
  fi
'


run_group "Generate Security Dashboard" bash -lc '
  chmod +x scripts/shell/consolidate-security-reports.sh
  SCAN_DIR="$SCAN_DIR" TARGET_DIR="$TARGET_DIR" ./scripts/shell/consolidate-security-reports.sh \
    || echo "Dashboard generation completed with warnings"
'

run_group "Generate TRL Assessment" bash -lc '
  chmod +x scripts/shell/generate-trl-score.py
  python3 scripts/shell/generate-trl-score.py --scan-dir "$SCAN_DIR" \
    || echo "[WARNING] TRL assessment generation failed or completed with warnings"
'

# ── Timing report ─────────────────────────────────────────────────────────────
echo ""
echo "::group::Timing Report"
echo "[TIMING] Total orchestrator: $((SECONDS - ORCHESTRATOR_START))s"
_write_timing_report > "$TIMING_FILE"
cat "$TIMING_FILE"
echo "::endgroup::"

# Retain per-layer logs in the scan artifact for failed-scan diagnosis and auditability.
echo "[INFO] Retaining parallel layer logs: $PARALLEL_LOG_DIR"

# Send scan completion webhook (Barbatos format: {"done": true})
send_webhook "scan_complete" "Scan completed successfully" "success"

SCAN_DIR_REL="${SCAN_DIR#${PWD}/}"
SCAN_ID_VALUE="$(basename "$SCAN_DIR")"

echo "scan_dir=${SCAN_DIR_REL}"
echo "scan_id=${SCAN_ID_VALUE}"

if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  echo "scan_dir=${SCAN_DIR_REL}" >> "$GITHUB_OUTPUT"
  echo "scan_id=${SCAN_ID_VALUE}" >> "$GITHUB_OUTPUT"
fi
