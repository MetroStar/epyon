#!/usr/bin/env bash

# CI-only orchestrator for reusable workflow execution.
# Keeps layer behavior aligned with epyon-scan.yml while reducing YAML step count.
#
# Performance: Independent layers run in parallel using background jobs.
# Dependency graph:
#   - Layer 1 (SBOM) must complete before Layer 8 (Grype sbom mode)
#   - Layer 3 (Sonar) must complete before Layer 4 (ClamAV) due to .scannerwork cleanup
#   - All other layers are independent and run concurrently.

set -u -o pipefail

RUN_SONAR_IN_QUICK="${RUN_SONAR_IN_QUICK:-false}"
RUN_GARAK_IN_QUICK="${RUN_GARAK_IN_QUICK:-false}"

if [[ ! -f /tmp/epyon-env ]]; then
  echo "[ERROR] Missing /tmp/epyon-env"
  exit 1
fi

# Export all sourced values so subshell invocations inherit them.
set -a
# shellcheck disable=SC1091
source /tmp/epyon-env
set +a

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

# Sanitize a layer name into a valid filename/variable-name suffix.
_pkey() { printf '%s' "${1//[^a-zA-Z0-9]/_}"; }

_record_start() {
  echo "$SECONDS" > "${TIMING_DIR}/start_$(_pkey "$1")"
}
_record_end() {
  echo "$SECONDS" > "${TIMING_DIR}/end_$(_pkey "$1")"
  local start
  start=$(cat "${TIMING_DIR}/start_$(_pkey "$1")" 2>/dev/null || echo "$SECONDS")
  local elapsed=$(( SECONDS - start ))
  echo "[TIMING] $1: ${elapsed}s"
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
    if [[ -f "$TARGET_DIR/coverage.xml" ]]; then
      echo "[INFO] coverage.xml found: enabling Sonar Python coverage import"
      export SONAR_EXTRA_ARGS="-Dsonar.python.coverage.reportPaths=coverage.xml"
    else
      echo "[INFO] No coverage.xml found: running Sonar without coverage data"
    fi

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
  # Layer 14 — Pickle/Serialization Safety (picklescan)
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
    echo "[INFO] Skipping Layer 14 - Picklescan (scan_mode=${SCAN_MODE:-full}; set RUN_PICKLESCAN=true to force)"
    return 0
  fi

  run_layer_script "Layer 14 - Pickle/Serialization Safety (picklescan)" "scripts/shell/run-picklescan.sh"
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
    _record_end "Layer 1 - SBOM"
    SBOM_READY=true
  fi

  _record_start "Layer 8 - Grype"
  chmod +x scripts/shell/run-grype-scan.sh
  (
    SCAN_DIR="$SCAN_DIR" TARGET_DIR="$TARGET_DIR" ./scripts/shell/run-grype-scan.sh sbom || true
    SCAN_DIR="$SCAN_DIR" TARGET_DIR="$TARGET_DIR" ./scripts/shell/run-grype-scan.sh images || true
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
    _record_end "$layer_name"
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
  IGNORE_CACHE="${IGNORE_CACHE:-/tmp/epyon-ignore-cache.json}"
  if [[ -f "scripts/shell/parse-epyon-ignore.sh" ]]; then
    source scripts/shell/parse-epyon-ignore.sh
    parse_ignore_rules "${TARGET_DIR}/.epyon-ignore.yml" 2>/dev/null || true
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
  for tool_name in grype trivy trufflehog checkov clamav anchore xeol; do
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

# Clean up parallel log directory
rm -rf "$PARALLEL_LOG_DIR"

SCAN_DIR_REL="${SCAN_DIR#${PWD}/}"
SCAN_ID_VALUE="$(basename "$SCAN_DIR")"

echo "scan_dir=${SCAN_DIR_REL}"
echo "scan_id=${SCAN_ID_VALUE}"

if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  echo "scan_dir=${SCAN_DIR_REL}" >> "$GITHUB_OUTPUT"
  echo "scan_id=${SCAN_ID_VALUE}" >> "$GITHUB_OUTPUT"
fi
