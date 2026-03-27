#!/bin/bash

# CI-only orchestrator for reusable workflow execution.
# Keeps layer behavior aligned with epyon-scan.yml while reducing YAML step count.

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

# Support invocation from workspace root or from inside ./epyon.
if [[ -d "epyon" && -f "epyon/VERSION" ]]; then
  cd epyon || exit 1
fi

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
  #   quick   → always skipped
  #   full    → skipped unless RUN_GARAK=true (manual opt-in)
  #   nightly → runs by default (Full + LLM)
  local _should_run="false"
  case "${SCAN_MODE:-full}" in
    nightly)  _should_run="true"  ;;
    quick)    _should_run="false" ;;
    *)        _should_run="false" ;;
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

# ── Per-tool skip helpers ─────────────────────────────────────────────────────
# Each tool respects a SKIP_<TOOL>=true env var for manual opt-out.
_should_run_tool() {
  local skip_var="$1"   # e.g. SKIP_TRIVY
  [[ "${!skip_var:-false}" == "true" ]] && return 1
  return 0
}

# Layers 1-12 (existing behavior preserved; individual tools are skippable)
if _should_run_tool SKIP_SBOM; then
  run_layer_script "Layer 1 - Generate SBOM" "scripts/shell/run-complete-sbom-scan.sh"
else
  echo "[INFO] Skipping Layer 1 - SBOM (SKIP_SBOM=true)"
fi

if _should_run_tool SKIP_TRUFFLEHOG; then
  run_layer_script "Layer 2 - Secret Detection (TruffleHog)" "scripts/shell/run-trufflehog-scan.sh" "filesystem"
else
  echo "[INFO] Skipping Layer 2 - TruffleHog (SKIP_TRUFFLEHOG=true)"
fi

if _should_run_tool SKIP_SONAR && [[ "${SCAN_MODE:-full}" != "quick" || "${RUN_SONAR_IN_QUICK}" == "true" ]]; then
  run_sonar_layer
else
  [[ "${SKIP_SONAR:-false}" == "true" ]] && echo "[INFO] Skipping Layer 3 - Sonar (SKIP_SONAR=true)" || echo "[INFO] Skipping Layer 3 (quick mode)"
fi

if _should_run_tool SKIP_CLAMAV && [[ "${SCAN_MODE:-full}" != "quick" ]]; then
  run_layer_script "Layer 4 - Malware Detection (ClamAV)" "scripts/shell/run-clamav-scan.sh"
else
  [[ "${SKIP_CLAMAV:-false}" == "true" ]] && echo "[INFO] Skipping Layer 4 - ClamAV (SKIP_CLAMAV=true)" || echo "[INFO] Skipping Layer 4 (quick mode)"
fi

if _should_run_tool SKIP_HELM; then
  run_layer_script "Layer 5 - Helm Chart Build" "scripts/shell/run-helm-build.sh"
else
  echo "[INFO] Skipping Layer 5 - Helm (SKIP_HELM=true)"
fi

if _should_run_tool SKIP_CHECKOV && [[ "${SCAN_MODE:-full}" != "quick" ]]; then
  run_group "Layer 6 - Infrastructure Security (Checkov)" bash -lc '
    chmod +x scripts/shell/run-checkov-scan.sh
    CI=true SCAN_DIR="$SCAN_DIR" TARGET_DIR="$TARGET_DIR" ./scripts/shell/run-checkov-scan.sh || echo "Checkov scan completed with warnings"
  '
else
  [[ "${SKIP_CHECKOV:-false}" == "true" ]] && echo "[INFO] Skipping Layer 6 - Checkov (SKIP_CHECKOV=true)" || echo "[INFO] Skipping Layer 6 (quick mode)"
fi

if _should_run_tool SKIP_TRIVY; then
  run_group "Layer 7 - Container Security (Trivy)" bash -lc '
    chmod +x scripts/shell/run-trivy-scan.sh
    SCAN_DIR="$SCAN_DIR" TARGET_DIR="$TARGET_DIR" ./scripts/shell/run-trivy-scan.sh filesystem || echo "Trivy scan completed with warnings"
    SCAN_DIR="$SCAN_DIR" TARGET_DIR="$TARGET_DIR" ./scripts/shell/run-trivy-scan.sh base || echo "Trivy base image scan completed with warnings"
  '
else
  echo "[INFO] Skipping Layer 7 - Trivy (SKIP_TRIVY=true)"
fi

if _should_run_tool SKIP_GRYPE; then
  run_group "Layer 8 - Vulnerability Detection (Grype)" bash -lc '
    chmod +x scripts/shell/run-grype-scan.sh
    SCAN_DIR="$SCAN_DIR" TARGET_DIR="$TARGET_DIR" ./scripts/shell/run-grype-scan.sh sbom || echo "Grype SBOM scan completed with warnings"
    SCAN_DIR="$SCAN_DIR" TARGET_DIR="$TARGET_DIR" ./scripts/shell/run-grype-scan.sh images || echo "Grype image scan completed with warnings"
  '
else
  echo "[INFO] Skipping Layer 8 - Grype (SKIP_GRYPE=true)"
fi

if _should_run_tool SKIP_XEOL; then
  run_layer_script "Layer 9 - End-of-Life Detection (Xeol)" "scripts/shell/run-xeol-scan.sh"
else
  echo "[INFO] Skipping Layer 9 - Xeol (SKIP_XEOL=true)"
fi

if _should_run_tool SKIP_ANCHORE && [[ "${SCAN_MODE:-full}" != "quick" ]]; then
  run_layer_script "Layer 10 - Anchore Security" "scripts/shell/run-anchore-scan.sh"
else
  [[ "${SKIP_ANCHORE:-false}" == "true" ]] && echo "[INFO] Skipping Layer 10 - Anchore (SKIP_ANCHORE=true)" || echo "[INFO] Skipping Layer 10 (quick mode)"
fi

if _should_run_tool SKIP_API_DISCOVERY; then
  run_layer_script "Layer 11 - API Discovery" "scripts/shell/run-api-discovery.sh"
else
  echo "[INFO] Skipping Layer 11 - API Discovery (SKIP_API_DISCOVERY=true)"
fi

run_garak_layer

run_group "Generate Scan Manifest" bash -lc '
  chmod +x scripts/shell/generate-scan-manifest.sh
  ./scripts/shell/generate-scan-manifest.sh "$SCAN_DIR" || echo "Manifest generation completed with warnings"
'

run_group "Generate Security Findings Summary" bash -lc '
  chmod +x scripts/shell/generate-scan-findings-summary.sh
  source scripts/shell/generate-scan-findings-summary.sh
  generate_scan_findings_summary "$(basename "$SCAN_DIR")" "$TARGET_DIR" "$PWD" || echo "Summary generation completed with warnings"
'

# Emit outputs consumed by later workflow steps.
SCAN_DIR_REL="${SCAN_DIR#${PWD}/}"
SCAN_ID_VALUE="$(basename "$SCAN_DIR")"

echo "scan_dir=${SCAN_DIR_REL}"
echo "scan_id=${SCAN_ID_VALUE}"

if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  echo "scan_dir=${SCAN_DIR_REL}" >> "$GITHUB_OUTPUT"
  echo "scan_id=${SCAN_ID_VALUE}" >> "$GITHUB_OUTPUT"
fi
