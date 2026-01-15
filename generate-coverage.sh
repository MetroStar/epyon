#!/bin/bash

# Generate Test Coverage for EPYON
# Uses kcov to generate coverage reports for Bats tests

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COVERAGE_DIR="$SCRIPT_DIR/coverage"

echo "🧪 EPYON Test Coverage Generator"
echo "================================="
echo ""

# Check if kcov is available
if command -v kcov &> /dev/null; then
    echo "✅ Found kcov locally"
    KCOV_CMD="kcov"
elif docker info &> /dev/null; then
    echo "⚠️  kcov not found locally, using Docker..."
    KCOV_CMD="docker run --rm -v $SCRIPT_DIR:/src -w /src kcov/kcov:latest kcov"
else
    echo "❌ Error: kcov not found and Docker not available"
    echo ""
    echo "To install kcov:"
    echo "  macOS: Use Docker method or build from source"
    echo "  Linux: sudo apt-get install kcov"
    echo ""
    echo "Alternative: Use Docker"
    echo "  docker pull kcov/kcov:latest"
    exit 1
fi

# Clean previous coverage
rm -rf "$COVERAGE_DIR"
mkdir -p "$COVERAGE_DIR"

echo ""
echo "🔍 Running tests with coverage..."
echo "Output: $COVERAGE_DIR"
echo ""

# Run tests with coverage
# Exclude .bats framework files from coverage
if [[ "$KCOV_CMD" == "kcov" ]]; then
    kcov \
        --exclude-pattern=/.bats/ \
        --exclude-pattern=/tests/ \
        --include-pattern=/scripts/shell/ \
        --bash-dont-parse-binary-dir \
        "$COVERAGE_DIR" \
        ./run-tests.sh
else
    # Docker version
    docker run --rm \
        -v "$SCRIPT_DIR:/src" \
        -w /src \
        kcov/kcov:latest \
        kcov \
        --exclude-pattern=/.bats/ \
        --exclude-pattern=/tests/ \
        --include-pattern=/scripts/shell/ \
        --bash-dont-parse-binary-dir \
        /src/coverage \
        /src/run-tests.sh
fi

echo ""
echo "✅ Coverage generation complete!"
echo ""
echo "📊 Coverage reports:"
echo "   HTML: $COVERAGE_DIR/index.html"
echo "   Cobertura XML: $COVERAGE_DIR/cobertura.xml"
echo ""
echo "To view HTML report:"
echo "   open $COVERAGE_DIR/index.html"
echo ""
echo "For SonarQube:"
echo "   Coverage report is at: coverage/cobertura.xml"
echo "   Already configured in sonar-project.properties"
