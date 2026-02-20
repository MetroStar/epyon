#!/usr/bin/env bash
# =============================================================================
# run-shell-coverage.sh
#
# Generate SonarCloud-compatible shell coverage using kcov + BATS.
# Can be called standalone (e.g. from a CI step) before run-sonar-analysis.sh
# so the coverage XML is already in place when the scanner runs.
#
# Usage:
#   ./run-shell-coverage.sh [REPO_PATH]
#
# Environment variables (all optional — auto-detected if not set):
#   REPO_PATH        Root of the repository being instrumented
#                    (defaults to current working directory)
#   COVERAGE_OUT     Destination for sonar-coverage.xml
#                    (defaults to $REPO_PATH/coverage/sonar-coverage.xml)
#   SCRIPTS_PATH     Path containing the shell scripts to instrument
#                    (defaults to $REPO_PATH/scripts/shell)
#   TESTS_PATH       Path containing *.bats test files
#                    (defaults to $REPO_PATH/tests/shell)
#
# Output:
#   $COVERAGE_OUT    SonarCloud Generic Coverage XML
#                    Ready for sonar.coverageReportPaths
#
# Exit codes:
#   0  Coverage XML written (may be real data or an empty placeholder)
#   1  Fatal error (bad arguments, missing Python, etc.)
# =============================================================================
set -euo pipefail

# ---------------------------------------------------------------------------
# Resolve paths
# ---------------------------------------------------------------------------
REPO_PATH="${1:-${REPO_PATH:-$(pwd)}}"
REPO_PATH=$(cd "$REPO_PATH" && pwd)

SCRIPTS_PATH="${SCRIPTS_PATH:-$REPO_PATH/scripts/shell}"
TESTS_PATH="${TESTS_PATH:-$REPO_PATH/tests/shell}"
COVERAGE_OUT="${COVERAGE_OUT:-$REPO_PATH/coverage/sonar-coverage.xml}"
CONVERTER="$(dirname "$0")/convert-kcov-to-sonar.py"

KCOV_OUTPUT="$REPO_PATH/coverage/kcov-output"
KCOV_MERGED="$REPO_PATH/coverage/kcov-merged"

echo ""
echo "============================================"
echo " Shell Coverage via kcov + BATS"
echo "============================================"
echo "[INFO] Repo      : $REPO_PATH"
echo "[INFO] Scripts   : $SCRIPTS_PATH"
echo "[INFO] Tests     : $TESTS_PATH"
echo "[INFO] Output    : $COVERAGE_OUT"
echo ""

# ---------------------------------------------------------------------------
# Helper: write an empty but valid SonarCloud coverage XML so the scanner
# never fails to parse the file referenced by sonar.coverageReportPaths.
# ---------------------------------------------------------------------------
write_empty_coverage() {
  echo "[INFO] Writing empty coverage placeholder: $COVERAGE_OUT"
  mkdir -p "$(dirname "$COVERAGE_OUT")"
  cat > "$COVERAGE_OUT" << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<coverage version="1"></coverage>
EOF
  echo "[OK] Placeholder written — scanner will not crash"
}

# ---------------------------------------------------------------------------
# Locate BATS test files
# ---------------------------------------------------------------------------
BATS_FILES=()
if [ -d "$TESTS_PATH" ]; then
  while IFS= read -r -d $'\0' f; do
    BATS_FILES+=("$f")
  done < <(find "$TESTS_PATH" -name "*.bats" -print0 2>/dev/null)
fi

if [ ${#BATS_FILES[@]} -eq 0 ]; then
  echo "[INFO] No *.bats files found under $TESTS_PATH"
  echo "[INFO] Skipping shell coverage"
  write_empty_coverage
  exit 0
fi

echo "[INFO] Found ${#BATS_FILES[@]} BATS test file(s)"

# ---------------------------------------------------------------------------
# Ensure kcov is available — apt first, cmake source build as fallback
# ---------------------------------------------------------------------------
install_kcov_from_source() {
  echo "[INFO] Installing kcov build dependencies..."
  sudo apt-get install -y \
    cmake \
    libdw-dev binutils-dev \
    libcurl4-openssl-dev zlib1g-dev libssl-dev \
    python3-dev 2>/dev/null || {
    echo "[WARNING] Could not install kcov build deps"
    return 1
  }

  local src_dir="/tmp/kcov-src"
  local build_dir="$src_dir/build"
  rm -rf "$src_dir"

  echo "[INFO] Cloning kcov..."
  git clone --depth 1 https://github.com/SimonKagstrom/kcov.git "$src_dir" 2>&1 | tail -3 || {
    echo "[WARNING] git clone failed"
    return 1
  }

  echo "[INFO] Building kcov (this may take a few minutes)..."
  cmake -B "$build_dir" -DCMAKE_BUILD_TYPE=Release "$src_dir" 2>&1 | tail -5 || return 1
  cmake --build "$build_dir" --parallel "$(nproc)" 2>&1 | tail -10 || return 1
  sudo cmake --install "$build_dir" 2>&1 | tail -3 || return 1
  echo "[OK] kcov built and installed from source"
}

if ! command -v kcov &>/dev/null; then
  echo "[INFO] kcov not found — attempting installation..."
  if sudo apt-get install -y kcov 2>/dev/null; then
    echo "[OK] kcov installed via apt"
  else
    echo "[INFO] apt install unavailable — building from source..."
    if ! install_kcov_from_source; then
      echo "[WARNING] kcov installation failed — coverage will be empty"
      write_empty_coverage
      exit 0
    fi
  fi
fi

if ! command -v kcov &>/dev/null; then
  echo "[WARNING] kcov still not available after install attempts"
  write_empty_coverage
  exit 0
fi

echo "[OK] kcov: $(kcov --version 2>&1 | head -1)"

# ---------------------------------------------------------------------------
# Locate BATS binary
# ---------------------------------------------------------------------------
BATS_BIN=""
for candidate in \
    "$REPO_PATH/.bats/bin/bats" \
    "$(command -v bats 2>/dev/null || true)"; do
  if [ -x "$candidate" ]; then
    BATS_BIN="$candidate"
    break
  fi
done

if [ -z "$BATS_BIN" ]; then
  echo "[WARNING] bats binary not found — cannot run coverage"
  write_empty_coverage
  exit 0
fi

echo "[OK] bats: $BATS_BIN"

# ---------------------------------------------------------------------------
# Run each BATS file under kcov
# ---------------------------------------------------------------------------
rm -rf "$KCOV_OUTPUT" "$KCOV_MERGED"
mkdir -p "$KCOV_OUTPUT"

echo ""
echo "[INFO] Instrumenting scripts under: $SCRIPTS_PATH"
echo "[INFO] Running ${#BATS_FILES[@]} test file(s) under kcov..."
echo ""

for bats_file in "${BATS_FILES[@]}"; do
  safe_name=$(basename "$bats_file" .bats)
  echo "[INFO] kcov ← $bats_file"
  kcov \
    --include-path="$SCRIPTS_PATH" \
    --bash-parser="$(command -v bash)" \
    "$KCOV_OUTPUT/$safe_name" \
    "$BATS_BIN" "$bats_file" 2>&1 | tail -3 || true
done

# ---------------------------------------------------------------------------
# Merge per-file kcov reports
# ---------------------------------------------------------------------------
echo ""
echo "[INFO] Merging kcov reports..."
mkdir -p "$KCOV_MERGED"

# kcov --merge expects at least one source directory
shopt -s nullglob
per_file_dirs=("$KCOV_OUTPUT"/*/)
shopt -u nullglob

if [ ${#per_file_dirs[@]} -eq 0 ]; then
  echo "[WARNING] kcov produced no output directories"
  write_empty_coverage
  exit 0
fi

kcov --merge "$KCOV_MERGED" "${per_file_dirs[@]}" 2>&1 | tail -5 || true

# kcov may nest the merged output under a subdirectory named after the bats binary
COBERTURA_XML=""
for candidate in \
    "$KCOV_MERGED/cobertura.xml" \
    "$KCOV_MERGED/bats/cobertura.xml" \
    "$KCOV_MERGED"/*/cobertura.xml; do
  if [ -f "$candidate" ]; then
    COBERTURA_XML="$candidate"
    break
  fi
done

if [ -z "$COBERTURA_XML" ]; then
  echo "[WARNING] kcov merge did not produce cobertura.xml"
  write_empty_coverage
  exit 0
fi

echo "[OK] Merged cobertura.xml: $COBERTURA_XML"

# ---------------------------------------------------------------------------
# Convert cobertura.xml → SonarCloud generic coverage XML
# ---------------------------------------------------------------------------
if [ ! -f "$CONVERTER" ]; then
  echo "[WARNING] Converter not found: $CONVERTER"
  write_empty_coverage
  exit 0
fi

if ! command -v python3 &>/dev/null; then
  echo "[WARNING] python3 not available — cannot convert coverage"
  write_empty_coverage
  exit 0
fi

echo "[INFO] Converting to SonarCloud generic coverage format..."
python3 "$CONVERTER" "$COBERTURA_XML" "$COVERAGE_OUT" "$REPO_PATH"

if [ -f "$COVERAGE_OUT" ]; then
  echo ""
  echo "✅ Shell coverage XML ready: $COVERAGE_OUT"
  exit 0
else
  echo "[WARNING] Conversion failed — writing empty placeholder"
  write_empty_coverage
  exit 0
fi
