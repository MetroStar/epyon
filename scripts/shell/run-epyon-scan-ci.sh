#!/bin/bash

# CI-only orchestrator for reusable workflow execution.
# Keeps layer behavior aligned with epyon-scan.yml while reducing YAML step count.

set -u -o pipefail

RUN_SONAR_IN_QUICK="${RUN_SONAR_IN_QUICK:-true}"
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
  if [[ "${SCAN_MODE:-full}" == "quick" ]]; then
    if [[ "${RUN_GARAK_IN_QUICK}" != "true" ]]; then
      echo "[INFO] Skipping Layer 12 (quick mode)"
      return 0
    fi
  fi

  if [[ "${SKIP_GARAK:-false}" == "true" ]]; then
    echo "[INFO] Skipping Layer 12 (SKIP_GARAK=true)"
    return 0
  fi

  run_group "Layer 12 - LLM Security (Garak)" bash -lc '
    chmod +x scripts/shell/run-garak-scan.sh

    GARAK_TARGET_TYPE_RESOLVED="${GARAK_TARGET_TYPE:-openai}"
    GARAK_TARGET_NAME_RESOLVED="${GARAK_TARGET_NAME:-gpt-4o-mini}"

    case "${GARAK_TARGET_TYPE_RESOLVED,,}" in
      openai)
        if [[ -z "${OPENAI_API_KEY:-}" ]]; then
          echo "[INFO] OPENAI_API_KEY not available; falling back to test.Blank"
          GARAK_TARGET_TYPE_RESOLVED="test"
          GARAK_TARGET_NAME_RESOLVED="test.Blank"
        fi
        ;;
      anthropic)
        if [[ -z "${ANTHROPIC_API_KEY:-}" ]]; then
          echo "[INFO] ANTHROPIC_API_KEY not available; falling back to test.Blank"
          GARAK_TARGET_TYPE_RESOLVED="test"
          GARAK_TARGET_NAME_RESOLVED="test.Blank"
        fi
        ;;
    esac

    SCAN_DIR="$SCAN_DIR" TARGET_DIR="$TARGET_DIR" GARAK_TARGET_TYPE="$GARAK_TARGET_TYPE_RESOLVED" GARAK_TARGET_NAME="$GARAK_TARGET_NAME_RESOLVED" GARAK_PROBES="${GARAK_PROBES:-promptinject}" ./scripts/shell/run-garak-scan.sh || echo "Garak scan completed with warnings"
  '
}

# Layers 1-12 (existing behavior preserved)
run_layer_script "Layer 1 - Generate SBOM" "scripts/shell/run-complete-sbom-scan.sh"
run_layer_script "Layer 2 - Secret Detection (TruffleHog)" "scripts/shell/run-trufflehog-scan.sh" "filesystem"
if [[ "${SCAN_MODE:-full}" != "quick" || "${RUN_SONAR_IN_QUICK}" == "true" ]]; then
  run_sonar_layer
else
  echo "[INFO] Skipping Layer 3 (quick mode)"
fi

if [[ "${SCAN_MODE:-full}" != "quick" ]]; then
  run_layer_script "Layer 4 - Malware Detection (ClamAV)" "scripts/shell/run-clamav-scan.sh"
else
  echo "[INFO] Skipping Layer 4 (quick mode)"
fi

run_layer_script "Layer 5 - Helm Chart Build" "scripts/shell/run-helm-build.sh"

if [[ "${SCAN_MODE:-full}" != "quick" ]]; then
  run_group "Layer 6 - Infrastructure Security (Checkov)" bash -lc '
    chmod +x scripts/shell/run-checkov-scan.sh
    CI=true SCAN_DIR="$SCAN_DIR" TARGET_DIR="$TARGET_DIR" ./scripts/shell/run-checkov-scan.sh || echo "Checkov scan completed with warnings"
  '
else
  echo "[INFO] Skipping Layer 6 (quick mode)"
fi

run_group "Layer 7 - Container Security (Trivy)" bash -lc '
  chmod +x scripts/shell/run-trivy-scan.sh
  SCAN_DIR="$SCAN_DIR" TARGET_DIR="$TARGET_DIR" ./scripts/shell/run-trivy-scan.sh filesystem || echo "Trivy scan completed with warnings"
  SCAN_DIR="$SCAN_DIR" TARGET_DIR="$TARGET_DIR" ./scripts/shell/run-trivy-scan.sh base || echo "Trivy base image scan completed with warnings"
'

run_group "Layer 8 - Vulnerability Detection (Grype)" bash -lc '
  chmod +x scripts/shell/run-grype-scan.sh
  SCAN_DIR="$SCAN_DIR" TARGET_DIR="$TARGET_DIR" ./scripts/shell/run-grype-scan.sh sbom || echo "Grype SBOM scan completed with warnings"
  SCAN_DIR="$SCAN_DIR" TARGET_DIR="$TARGET_DIR" ./scripts/shell/run-grype-scan.sh images || echo "Grype image scan completed with warnings"
'

run_layer_script "Layer 9 - End-of-Life Detection (Xeol)" "scripts/shell/run-xeol-scan.sh"

if [[ "${SCAN_MODE:-full}" != "quick" ]]; then
  run_layer_script "Layer 10 - Anchore Security" "scripts/shell/run-anchore-scan.sh"
else
  echo "[INFO] Skipping Layer 10 (quick mode)"
fi

run_layer_script "Layer 11 - API Discovery" "scripts/shell/run-api-discovery.sh"
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
