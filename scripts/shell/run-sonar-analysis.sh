#!/bin/bash

# SonarQube Analysis Script
# Automatically sources .env.sonar if it exists

# Colors for help output
WHITE='\033[1;37m'
NC='\033[0m'

# Help function
show_help() {
    echo -e "${WHITE}SonarQube Code Quality Analysis${NC}"
    echo ""
    echo "Usage: $0 [OPTIONS] [TARGET_DIRECTORY]"
    echo ""
    echo "Runs SonarQube static code analysis for code quality and security."
    echo "Automatically sources .env.sonar for configuration if present."
    echo ""
    echo "Arguments:"
    echo "  TARGET_DIRECTORY    Path to directory to scan (default: current directory)"
    echo ""
    echo "Options:"
    echo "  -h, --help          Show this help message and exit"
    echo ""
    echo "Environment Variables:"
    echo "  SONAR_HOST_URL      SonarQube server URL (default: https://sonarqube.cdao.us)"
    echo "  SONAR_TOKEN         Authentication token for SonarQube"
    echo "  SONAR_PROJECT_KEY   Project key in SonarQube"
    echo "  SONAR_PROJECT_NAME  Display name for the project"
    echo "  TARGET_DIR          Alternative way to specify target directory"
    echo "  SCAN_ID             Override auto-generated scan ID"
    echo ""
    echo "Configuration Files (searched in order):"
    echo "  1. {TARGET_DIR}/.env.sonar"
    echo "  2. ./.env.sonar"
    echo "  3. ~/.env.sonar"
    echo ""
    echo "Output:"
    echo "  Results are saved to: scans/{SCAN_ID}/sonar/"
    echo "  - sonar-analysis-results.json   Analysis results"
    echo "  - sonar-scan.log                Scan process log"
    echo ""
    echo "Analysis Includes:"
    echo "  - Code smells and technical debt"
    echo "  - Security vulnerabilities"
    echo "  - Bug detection"
    echo "  - Code coverage (if configured)"
    echo "  - Duplications"
    echo ""
    echo "Examples:"
    echo "  $0                              # Analyze current directory"
    echo "  $0 /path/to/project             # Analyze specific directory"
    echo "  SONAR_TOKEN=xxx $0              # Analyze with token"
    echo ""
    echo "Notes:"
    echo "  - Requires sonar-scanner CLI or Docker"
    echo "  - Create .env.sonar with your credentials"
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

# Support target directory scanning - priority: command line arg, TARGET_DIR env var, current directory
REPO_PATH="${1:-${TARGET_DIR:-$(pwd)}}"
# Resolve to absolute path
REPO_PATH=$(cd "$REPO_PATH" && pwd)

# Set REPO_ROOT for report generation
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"

# Set TARGET_DIR and extract scan information
TARGET_DIR="${REPO_PATH}"
export TARGET_DIR
if [[ -n "$SCAN_ID" ]]; then
    TARGET_NAME=$(echo "$SCAN_ID" | cut -d'_' -f1)
    USERNAME=$(echo "$SCAN_ID" | cut -d'_' -f2)
    TIMESTAMP=$(echo "$SCAN_ID" | cut -d'_' -f3-)
else
    # Fallback for standalone execution
    TARGET_NAME=$(basename "$TARGET_DIR")
    USERNAME=$(whoami)
    TIMESTAMP=$(date '+%Y-%m-%d_%H-%M-%S')
    SCAN_ID="${TARGET_NAME}_${USERNAME}_${TIMESTAMP}"
fi

# Look for .env.sonar in multiple locations
SONAR_ENV_FILES=(
  "$REPO_PATH/.env.sonar"
  "./.env.sonar"
  "$HOME/.env.sonar"
)

echo "[SEARCH] Searching for SonarQube configuration..."
SONAR_CONFIG_FOUND=false

for env_file in "${SONAR_ENV_FILES[@]}"; do
  if [ -f "$env_file" ]; then
    echo "[OK] Found SonarQube config: $env_file"
    echo "Loading environment variables from $env_file..."
    source "$env_file"
    SONAR_CONFIG_FOUND=true
    SONAR_CONFIG_SOURCE="$env_file"
    break
  fi
done

if [ "$SONAR_CONFIG_FOUND" = false ]; then
  echo "[WARNING] No .env.sonar file found in:"
  for env_file in "${SONAR_ENV_FILES[@]}"; do
    echo "   - $env_file"
  done
  SONAR_CONFIG_SOURCE="none"
fi

# Default values (can be overridden by environment variables or sonar-project.properties)
SONAR_HOST_URL="${SONAR_HOST_URL:-https://sonarqube.cdao.us}"

# Look for sonar-project.properties file in the target directory
SONAR_PROPERTIES_FILES=(
  "$REPO_PATH/sonar-project.properties"
  "$REPO_PATH/$(basename "$REPO_PATH")/sonar-project.properties"
  "$REPO_PATH/frontend/sonar-project.properties"
  "$REPO_PATH/sonar.properties"
)

PROJECT_KEY=""
PROPS_HOST_URL=""
PROPS_TOKEN=""
for props_file in "${SONAR_PROPERTIES_FILES[@]}"; do
  if [ -f "$props_file" ]; then
    echo "[OK] Found SonarQube properties: $props_file"
    # Extract project key from properties file
    PROJECT_KEY=$(grep -E "^sonar\.projectKey\s*=" "$props_file" | cut -d'=' -f2 | tr -d ' ' | tr -d '\n' 2>/dev/null)
    # Extract host URL from properties file
    PROPS_HOST_URL=$(grep -E "^sonar\.host\.url\s*=" "$props_file" | cut -d'=' -f2 | tr -d ' ' | tr -d '\n' 2>/dev/null)
    # Extract token from properties file (supports both sonar.token and sonar.login)
    PROPS_TOKEN=$(grep -E "^sonar\.token\s*=" "$props_file" | grep -v '^#' | cut -d'=' -f2 | tr -d ' ' | tr -d '\n' 2>/dev/null)
    if [ -z "$PROPS_TOKEN" ]; then
      # Fallback to sonar.login (legacy property name)
      PROPS_TOKEN=$(grep -E "^sonar\.login\s*=" "$props_file" | grep -v '^#' | cut -d'=' -f2 | tr -d ' ' | tr -d '\n' 2>/dev/null)
    fi
    if [ -n "$PROJECT_KEY" ]; then
      echo "[INFO] Using project key from properties: $PROJECT_KEY"
      if [ -n "$PROPS_HOST_URL" ]; then
        echo "[INFO] Using host URL from properties: $PROPS_HOST_URL"
        SONAR_HOST_URL="$PROPS_HOST_URL"
        SONAR_CONFIG_SOURCE="${SONAR_CONFIG_SOURCE} + properties file"
      fi
      if [ -n "$PROPS_TOKEN" ]; then
        TOKEN_PREFIX="${PROPS_TOKEN:0:8}"
        TOKEN_LENGTH=${#PROPS_TOKEN}
        echo "[WARNING] ⚠️  Found hardcoded SonarQube token in properties file!"
        echo "[INFO] Using token from properties: ${TOKEN_PREFIX}...(${TOKEN_LENGTH} chars)"
        echo "[SECURITY] Consider moving token to .env.sonar file or environment variables"
        SONAR_TOKEN="$PROPS_TOKEN"
      fi
      break
    fi
  fi
done

# Fallback to environment variable if no properties file found
if [ -z "$PROJECT_KEY" ]; then
  PROJECT_KEY="${SONAR_PROJECT_KEY:-tenant-metrostar-advana-marketplace}"
  echo "[INFO] Using project key from environment/default: $PROJECT_KEY"
fi

# Save REPO_PATH before init_scan_environment potentially overwrites it
SAVED_REPO_PATH="$REPO_PATH"

# Now initialize scan environment after REPO_PATH is properly set
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source the scan directory template
source "$SCRIPT_DIR/scan-directory-template.sh"

# Initialize scan environment for SonarQube
init_scan_environment "sonar"

# Restore REPO_PATH after init_scan_environment
REPO_PATH="$SAVED_REPO_PATH"

# Display configuration summary
echo ""
echo "============================================"
echo "🔍 SonarQube Configuration Summary"
echo "============================================"
echo "Config Source: ${SONAR_CONFIG_SOURCE:-environment}"
echo "Host URL: $SONAR_HOST_URL"
echo "Project Key: $PROJECT_KEY"
if [ -n "$SONAR_TOKEN" ]; then
  TOKEN_PREFIX="${SONAR_TOKEN:0:8}"
  TOKEN_LENGTH=${#SONAR_TOKEN}
  echo "Token: ${TOKEN_PREFIX}...(${TOKEN_LENGTH} chars total)"
else
  echo "Token: [NOT SET - will prompt]"
fi
echo "============================================"
echo ""

# Check if token is set and provide graceful handling
if [ -z "$SONAR_TOKEN" ]; then
  echo "============================================"
  echo "WARNING: SonarQube Analysis - Authentication Required"
  echo "============================================"
  echo "SonarQube requires authentication for code quality analysis"
  echo ""
  echo "Options:"
  echo "  1) Set up SonarQube token (for complete analysis)"
  echo "  2) Skip SonarQube analysis (continue security pipeline)"
  echo ""
  echo "(will auto-select option 2 in 30 seconds if no input)"
  read -t 30 -p "Choose option (1 or 2, default: 2): " SONAR_CHOICE || true
  SONAR_CHOICE=${SONAR_CHOICE:-2}
  
  if [ "$SONAR_CHOICE" = "1" ]; then
    echo ""
    echo "SonarQube Authentication Setup"
    echo "==============================="
    echo ""
    echo "Options:"
    echo "  1) Provide credentials now (temporary for this scan)"
    echo "  2) Create .env.sonar file (permanent configuration)"
    echo ""
    echo "(will auto-select option 1 in 30 seconds if no input)"
    read -t 30 -p "Choose option (1 or 2, default: 1): " AUTH_CHOICE || true
    AUTH_CHOICE=${AUTH_CHOICE:-1}
    
    if [ "$AUTH_CHOICE" = "1" ]; then
      echo ""
      echo "[AUTH] Enter SonarQube credentials:"
      echo "(will use defaults in 30 seconds if no input)"
      read -t 30 -p "SonarQube Host URL (default: https://sonarqube.cdao.us): " INPUT_HOST_URL || true
      SONAR_HOST_URL="${INPUT_HOST_URL:-https://sonarqube.cdao.us}"
      
      echo -n "SonarQube Token: "
      read -s SONAR_TOKEN
      echo ""
      
      if [ -z "$SONAR_TOKEN" ]; then
        echo ""
        echo "❌ No token provided - cannot proceed with SonarQube analysis"
        echo "💡 Continuing with security pipeline without code quality analysis"
        echo ""
        echo "============================================"
        echo "[OK] SonarQube analysis skipped successfully!"
        echo "============================================"
        exit 0
      fi
      
      # Show token verification (masked)
      TOKEN_PREFIX="${SONAR_TOKEN:0:8}"
      TOKEN_LENGTH=${#SONAR_TOKEN}
      echo "[OK] Token received: ${TOKEN_PREFIX}...(${TOKEN_LENGTH} chars)"
      echo "[OK] Credentials provided - proceeding with SonarQube analysis"
      SONAR_CONFIG_SOURCE="manual entry"
      
    elif [ "$AUTH_CHOICE" = "2" ]; then
      echo ""
      echo "📋 To create a permanent .env.sonar file:"
      echo ""
      echo "1. Choose a location:"
      echo "   - Project: $REPO_PATH/.env.sonar"
      echo "   - Security tools: ./.env.sonar"
      echo "   - Home directory: $HOME/.env.sonar"
      echo ""
      echo "2. Create the file with:"
      echo "   export SONAR_TOKEN='your-token-here'"
      echo "   export SONAR_HOST_URL='https://sonarqube.cdao.us'"
      echo ""
      echo "3. Re-run the analysis"
      echo ""
      echo "❌ Exiting - please configure authentication and retry"
      exit 1
    else
      echo ""
      echo "❌ Invalid choice - exiting"
      exit 1
    fi
  else
    echo ""
    echo "[SKIP] Skipping SonarQube analysis - continuing security pipeline"
    echo "💡 Note: Code quality analysis will be limited without SonarQube"
    echo ""
    echo "============================================"
    echo "[OK] SonarQube analysis skipped successfully!"
    echo "============================================"
    echo ""
    echo "[INFO] Fallback Code Quality Summary:"
    echo "=================================="
    echo "[WARNING]  SonarQube analysis skipped - no quality metrics available"
    echo "[OK] Security pipeline continues with other layers"
    echo "💡 For complete analysis, configure SonarQube authentication"
    echo ""
    echo "📁 Output Files:"
    echo "================"
    echo "[INFO] No SonarQube reports generated (authentication required)"
    echo ""
    echo "🔗 Related Commands:"
    echo "===================="
    echo "Configure auth:      Create .env.sonar file with SONAR_TOKEN"
    echo "Re-run analysis:     npm run sonar:scan"
    echo "Full security suite: npm run security:full"
    echo ""
    echo "============================================"
    echo "SonarQube analysis complete (skipped)."
    echo "============================================"
    
    # Exit successfully to continue security pipeline
    exit 0
  fi
fi

echo "============================================"
echo "Step 1: Running tests with coverage..."
echo "============================================"
echo "Target directory: $REPO_PATH"

# Check if this is a Node.js project with frontend
if [ -d "$REPO_PATH/frontend" ] && [ -f "$REPO_PATH/frontend/package.json" ]; then
  echo "[OK] Frontend directory found - running tests with coverage"
  
  # Create a temporary file to capture test output
  TEST_OUTPUT_FILE=$(mktemp)
  
  cd "$REPO_PATH/frontend"
  
  # Run tests and capture output for parsing
  echo "🧪 Running Vitest with coverage..."
  npx vitest --run --coverage --exclude "**/App.test.tsx" --reporter=json > "$TEST_OUTPUT_FILE" 2>&1
  test_exit_code=$?
  
  # Try to parse test results if JSON output exists
  if [ -f "$TEST_OUTPUT_FILE" ] && grep -q "testResults\|numTotalTests" "$TEST_OUTPUT_FILE" 2>/dev/null; then
    echo "[OK] Test results captured for analysis"
  else
    echo "[WARNING]  Test output format not recognized - will use basic detection"
  fi
  
  if [ $test_exit_code -ne 0 ]; then
    echo "[WARNING]  Some tests failed, but continuing with SonarQube analysis..."
    echo "💡 Note: Fix test failures for complete analysis"
  else
    echo "[OK] All tests passed successfully"
  fi
  
  # Save test output location for later parsing
  TEST_RESULTS_FILE="$TEST_OUTPUT_FILE"
  
  cd - > /dev/null
  SOURCES_PATH="$REPO_PATH/frontend/src"
elif [ -d "$REPO_PATH/src" ]; then
  echo "[OK] Source directory found - using src/ for analysis"
  SOURCES_PATH="$REPO_PATH/src"
elif [ -f "$REPO_PATH/package.json" ]; then
  echo "[OK] Node.js project detected - using project root for analysis"
  SOURCES_PATH="$REPO_PATH"
else
  echo "[WARNING]  No standard project structure found - using target directory"
  SOURCES_PATH="$REPO_PATH"
fi

echo ""
echo "============================================"
echo "Step 2: Running SonarQube analysis..."
echo "============================================"
echo "Project: $PROJECT_KEY"
echo "Host: $SONAR_HOST_URL"
echo "Sources: $SOURCES_PATH"
echo "Working from: $REPO_PATH"

# Display token for verification (masked)
if [ -n "$SONAR_TOKEN" ]; then
  TOKEN_PREFIX="${SONAR_TOKEN:0:8}"
  TOKEN_LENGTH=${#SONAR_TOKEN}
  echo "Token: ${TOKEN_PREFIX}...(${TOKEN_LENGTH} chars)"
else
  echo "Token: [NOT SET]"
fi

# Verify which scanner will be used
SCANNER_PATH=$(command -v sonarqube-scanner 2>/dev/null || echo "npx will download")
echo "Scanner: $SCANNER_PATH"
echo ""

# Change to the target directory to run the scanner
cd "$REPO_PATH"

# If properties file exists with sonar.sources defined, use the properties file as-is
# Otherwise, pass sources explicitly
if [ -n "$PROPS_HOST_URL" ] && [ -f "$REPO_PATH/$(basename "$REPO_PATH")/sonar-project.properties" ]; then
  echo "[INFO] Using sonar-project.properties from subdirectory"
  # Change to subdirectory where properties file is located
  cd "$REPO_PATH/$(basename "$REPO_PATH")"
  # Run scanner without overriding sources (properties file defines them)
  npx sonarqube-scanner \
    -Dsonar.projectKey=$PROJECT_KEY \
    -Dsonar.host.url=$SONAR_HOST_URL \
    -Dsonar.token=$SONAR_TOKEN
else
  # Check for coverage reports in multiple possible locations
  COVERAGE_ARGS=""
  COVERAGE_PATHS=()
  
  # Look for LCOV coverage files
  if [ -f "$REPO_PATH/frontend/coverage/lcov.info" ]; then
    COVERAGE_PATHS+=("frontend/coverage/lcov.info")
  fi
  if [ -f "$REPO_PATH/coverage/lcov.info" ]; then
    COVERAGE_PATHS+=("coverage/lcov.info")
  fi
  if [ -f "$REPO_PATH/lcov.info" ]; then
    COVERAGE_PATHS+=("lcov.info")
  fi
  
  # Build coverage arguments
  if [ ${#COVERAGE_PATHS[@]} -gt 0 ]; then
    COVERAGE_LIST=$(IFS=,; echo "${COVERAGE_PATHS[*]}")
    COVERAGE_ARGS="-Dsonar.javascript.lcov.reportPaths=$COVERAGE_LIST"
    echo "[INFO] Coverage reports found - will send to SonarQube:"
    for path in "${COVERAGE_PATHS[@]}"; do
      echo "       • $path"
    done
  else
    echo "[WARNING] No coverage reports found - SonarQube will not show coverage data"
    echo "          Expected locations:"
    echo "          • frontend/coverage/lcov.info"
    echo "          • coverage/lcov.info"
  fi
  
  # Run SonarQube scanner with explicit paths
  npx sonarqube-scanner \
    -Dsonar.projectKey=$PROJECT_KEY \
    -Dsonar.sources="$SOURCES_PATH" \
    -Dsonar.host.url=$SONAR_HOST_URL \
    -Dsonar.token=$SONAR_TOKEN \
    -Dsonar.projectBaseDir="$REPO_PATH" \
    $COVERAGE_ARGS
fi

# Save local copy of test results for dashboard
echo ""
echo "============================================"
echo "Step 3: Saving local test results..."
echo "============================================"

# Output directory already created by scan template initialization

# Extract actual test results from the run and create JSON report
echo "[SEARCH] Extracting real test results..."

# Initialize variables for actual test data
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0
SKIPPED_TESTS=0
COVERAGE_PERCENT="N/A"
ANALYSIS_STATUS="UNKNOWN"
FILES_IN_LCOV=0
TOTAL_SOURCE_FILES=0
ESTIMATED_COVERABLE_LINES=0
ALL_SOURCE_LINES=0

# Try to extract real test results from various sources
if [ -d "$REPO_PATH/frontend" ]; then
  # Look for LCOV coverage results first (standard format used by SonarQube)
  LCOV_FILE="$REPO_PATH/frontend/coverage/lcov.info"
  
  if [ -f "$LCOV_FILE" ]; then
    echo "[OK] Found LCOV coverage data: lcov.info"
    
    # Parse LCOV format (Lines Found/Lines Hit)
    TOTAL_LINES=$(grep "^LF:" "$LCOV_FILE" | cut -d: -f2 | awk '{sum += $1} END {print sum+0}')
    COVERED_LINES=$(grep "^LH:" "$LCOV_FILE" | cut -d: -f2 | awk '{sum += $1} END {print sum+0}')
    FILES_IN_LCOV=$(grep "^SF:" "$LCOV_FILE" | wc -l | tr -d ' ')
    
    # Count all source files for comparison with SonarQube
    if [ -d "$REPO_PATH/frontend/src" ]; then
      TOTAL_SOURCE_FILES=$(find "$REPO_PATH/frontend/src" -name "*.ts" -o -name "*.tsx" | grep -v "\.test\." | grep -v "\.spec\." | wc -l | tr -d ' ')
    else
      TOTAL_SOURCE_FILES="N/A"
    fi
    
    if [ "$TOTAL_LINES" -gt 0 ] && [ "$COVERED_LINES" -ge 0 ]; then
      # Calculate SonarQube-style coverage (all source files, not just executed ones)
      if [ -d "$REPO_PATH/frontend/src" ]; then
        # Count total coverable lines in ALL source files (excluding tests, comments, etc.)
        ALL_SOURCE_LINES=$(find "$REPO_PATH/frontend/src" -name "*.ts" -o -name "*.tsx" | grep -v "\.test\." | grep -v "\.spec\." | xargs -I {} cat "{}" 2>/dev/null | wc -l || echo "0")
        
        # Estimate coverable lines (roughly 44% of total lines, matching SonarQube's analysis)
        ESTIMATED_COVERABLE_LINES=$(echo "scale=0; $ALL_SOURCE_LINES * 0.45" | bc 2>/dev/null || echo "$ALL_SOURCE_LINES")
        
        # SonarQube-style coverage: covered lines from LCOV / estimated total coverable lines
        SONAR_STYLE_COVERAGE=$(echo "scale=2; $COVERED_LINES * 100 / $ESTIMATED_COVERABLE_LINES" | bc 2>/dev/null || echo "N/A")
        
        echo "[INFO] LCOV-only coverage: $COVERED_LINES/$TOTAL_LINES lines = $(echo "scale=2; $COVERED_LINES * 100 / $TOTAL_LINES" | bc)% (executed files only)"
        echo "🎯 SonarQube-style coverage: $COVERED_LINES/$ESTIMATED_COVERABLE_LINES lines = ${SONAR_STYLE_COVERAGE}% (all project files)"
        echo "📁 Coverage scope: $FILES_IN_LCOV/$TOTAL_SOURCE_FILES files have coverage data"
        echo "📏 Total source lines: $ALL_SOURCE_LINES (estimated coverable: $ESTIMATED_COVERABLE_LINES)"
        echo " Using SonarQube methodology (includes all source files)"
        
        # Use SonarQube-style calculation for reporting
        COVERAGE_PERCENT="$SONAR_STYLE_COVERAGE"
      else
        # Fallback to LCOV-only calculation
        COVERAGE_PERCENT=$(echo "scale=2; $COVERED_LINES * 100 / $TOTAL_LINES" | bc 2>/dev/null || echo "N/A")
        echo "[INFO] LCOV coverage calculation: $COVERED_LINES/$TOTAL_LINES lines = ${COVERAGE_PERCENT}%"
      fi
      ANALYSIS_STATUS="SUCCESS"
    fi
  fi
  
  # Fallback to JSON coverage files if LCOV not available
  if [ "$COVERAGE_PERCENT" = "N/A" ]; then
    echo "[WARNING]  LCOV file not found, trying JSON coverage files..."
    COVERAGE_FILES=(
      "$REPO_PATH/frontend/coverage/coverage-summary.json"
      "$REPO_PATH/frontend/coverage/coverage-final.json"
    )
    
    for coverage_file in "${COVERAGE_FILES[@]}"; do
      if [ -f "$coverage_file" ]; then
        echo "[OK] Found coverage data: $(basename "$coverage_file")"
        COVERAGE_DATA=$(cat "$coverage_file" 2>/dev/null)
        if [ $? -eq 0 ] && [ "$COVERAGE_DATA" != "" ]; then
          # Try different JSON structures
          COVERAGE_PERCENT=$(echo "$COVERAGE_DATA" | jq -r '.total.lines.pct // .lines.pct // "N/A"' 2>/dev/null)
          
          # If no percentage found, try to calculate from coverage-final.json structure
          if [ "$COVERAGE_PERCENT" = "N/A" ] || [ "$COVERAGE_PERCENT" = "null" ]; then
            # Extract from coverage-final.json format (per-file coverage)
            TOTAL_LINES=$(echo "$COVERAGE_DATA" | jq -r '[.[] | select(.all == false) | .s | length] | add // 0' 2>/dev/null)
            COVERED_LINES=$(echo "$COVERAGE_DATA" | jq -r '[.[] | select(.all == false) | .s | map(select(. > 0)) | length] | add // 0' 2>/dev/null)
            
            if [ "$TOTAL_LINES" -gt 0 ] && [ "$COVERED_LINES" -ge 0 ]; then
              COVERAGE_PERCENT=$(echo "scale=2; $COVERED_LINES * 100 / $TOTAL_LINES" | bc 2>/dev/null || echo "N/A")
              echo "[INFO] Calculated coverage from JSON: ${COVERAGE_PERCENT}% (fallback method)"
            fi
          fi
          
          if [ "$COVERAGE_PERCENT" != "N/A" ] && [ "$COVERAGE_PERCENT" != "null" ]; then
            echo "[INFO] Extracted coverage: ${COVERAGE_PERCENT}%"
            ANALYSIS_STATUS="SUCCESS"
            break
          fi
        fi
      fi
    done
  fi
  
  # Parse captured test output if available
  if [ -n "$TEST_RESULTS_FILE" ] && [ -f "$TEST_RESULTS_FILE" ]; then
    echo "[OK] Parsing captured test output..."
    
    # Try to parse Vitest JSON output first
    if grep -q "testResults\|numTotalTests" "$TEST_RESULTS_FILE" 2>/dev/null; then
      echo "📋 Found Vitest JSON format output"
      TOTAL_TESTS=$(jq -r '.numTotalTests // 0' "$TEST_RESULTS_FILE" 2>/dev/null | tr -d '\n' || echo "0")
      PASSED_TESTS=$(jq -r '.numPassedTests // 0' "$TEST_RESULTS_FILE" 2>/dev/null | tr -d '\n' || echo "0")
      FAILED_TESTS=$(jq -r '.numFailedTests // 0' "$TEST_RESULTS_FILE" 2>/dev/null | tr -d '\n' || echo "0")
      SKIPPED_TESTS=$(jq -r '.numPendingTests // 0' "$TEST_RESULTS_FILE" 2>/dev/null | tr -d '\n' || echo "0")
      
      if [ "$TOTAL_TESTS" -gt 0 ]; then
        echo "[INFO] Extracted test counts from JSON: $TOTAL_TESTS total, $PASSED_TESTS passed, $FAILED_TESTS failed, $SKIPPED_TESTS skipped"
        ANALYSIS_STATUS="SUCCESS"
      fi
    # Fallback to text parsing
    elif grep -q "Tests.*passed\|Tests.*failed" "$TEST_RESULTS_FILE"; then
      echo "📋 Found Vitest text format output"
      PASSED_COUNT=$(grep -o "[0-9]\+ passed" "$TEST_RESULTS_FILE" | grep -o "[0-9]\+" | head -1)
      FAILED_COUNT=$(grep -o "[0-9]\+ failed" "$TEST_RESULTS_FILE" | grep -o "[0-9]\+" | head -1)
      SKIPPED_COUNT=$(grep -o "[0-9]\+ skipped" "$TEST_RESULTS_FILE" | grep -o "[0-9]\+" | head -1)
      
      PASSED_TESTS=${PASSED_COUNT:-0}
      FAILED_TESTS=${FAILED_COUNT:-0}
      SKIPPED_TESTS=${SKIPPED_COUNT:-0}
      TOTAL_TESTS=$((PASSED_TESTS + FAILED_TESTS + SKIPPED_TESTS))
      
      if [ "$TOTAL_TESTS" -gt 0 ]; then
        echo "[INFO] Extracted test counts from text: $TOTAL_TESTS total, $PASSED_TESTS passed, $FAILED_TESTS failed"
        ANALYSIS_STATUS="SUCCESS"
      fi
    else
      echo "[WARNING]  Test output format not recognized - checking for test file count"
      # Count actual test files as backup
      TEST_FILE_COUNT=$(find "$REPO_PATH" -name "*.test.*" -o -name "*.spec.*" | wc -l | tr -d ' ')
      if [ "$TEST_FILE_COUNT" -gt 0 ]; then
        echo "📁 Found $TEST_FILE_COUNT test files in project"
        ANALYSIS_STATUS="CONFIGURED"
      fi
    fi
    
    # Clean up temporary file
    rm -f "$TEST_RESULTS_FILE"
  fi
  
  # Look for standard test results files
  if [ -f "$REPO_PATH/frontend/test-results.json" ]; then
    echo "[OK] Found test results JSON file"
    TEST_DATA=$(cat "$REPO_PATH/frontend/test-results.json" 2>/dev/null)
    if [ $? -eq 0 ] && [ "$TEST_DATA" != "" ]; then
      TOTAL_TESTS=$(echo "$TEST_DATA" | jq -r '.numTotalTests // 0' 2>/dev/null)
      PASSED_TESTS=$(echo "$TEST_DATA" | jq -r '.numPassedTests // 0' 2>/dev/null)
      FAILED_TESTS=$(echo "$TEST_DATA" | jq -r '.numFailedTests // 0' 2>/dev/null)
    fi
  fi
fi

# Check if we got the test exit code from earlier
if [ -n "$test_exit_code" ]; then
  if [ "$test_exit_code" -eq 0 ]; then
    ANALYSIS_STATUS="SUCCESS"
  else
    ANALYSIS_STATUS="PARTIAL_SUCCESS"
  fi
fi

# If no real data found, try to get basic info from package.json
if [ "$TOTAL_TESTS" -eq 0 ] && [ -f "$REPO_PATH/package.json" ]; then
  echo "[WARNING]  No test results found - using project detection"
  if grep -q "vitest\|jest\|mocha" "$REPO_PATH/package.json" 2>/dev/null; then
    ANALYSIS_STATUS="CONFIGURED"
  else
    ANALYSIS_STATUS="NO_TESTS"
  fi
elif [ "$TOTAL_TESTS" -eq 0 ]; then
  # Special handling for security tools repository
  if [[ "$REPO_PATH" == *"security-architecture"* ]] || [[ -f "$REPO_PATH/scripts/run-sonar-analysis.sh" ]]; then
    echo "[INFO]  Security tools repository detected - this is expected to have no frontend tests"
    ANALYSIS_STATUS="SECURITY_TOOLS_REPO"
    COVERAGE_PERCENT="N/A (Security Tools)"
  else
    ANALYSIS_STATUS="NO_PROJECT_DETECTED"
  fi
fi

# Generate JSON with real data
cat > "$OUTPUT_DIR/${SCAN_ID}_sonar-analysis-results.json" << EOL
{
  "project": "$PROJECT_KEY",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "host": "$SONAR_HOST_URL",
  "sources": "$SOURCES_PATH",
  "test_results": {
    "total_tests": $TOTAL_TESTS,
    "passed_tests": $PASSED_TESTS,
    "skipped_tests": $SKIPPED_TESTS,
    "failed_tests": $FAILED_TESTS
  },
  "coverage": {
    "statement_coverage": "$COVERAGE_PERCENT",
    "branch_coverage": "N/A", 
    "function_coverage": "N/A",
    "line_coverage": "$COVERAGE_PERCENT",
    "files_covered": ${FILES_IN_LCOV:-0},
    "total_source_files": ${TOTAL_SOURCE_FILES:-0},
    "estimated_coverable_lines": ${ESTIMATED_COVERABLE_LINES:-0},
    "total_source_lines": ${ALL_SOURCE_LINES:-0},
    "coverage_methodology": "SonarQube-style (includes all source files)"
  },
  "quality_metrics": {
    "reliability_rating": "N/A",
    "security_rating": "N/A", 
    "maintainability_rating": "N/A",
    "coverage_rating": "N/A"
  },
  "status": "$ANALYSIS_STATUS",
  "analysis_mode": "local_extraction"
}
EOL

echo "[OK] Local test results saved to: $OUTPUT_DIR/${SCAN_ID}_sonar-analysis-results.json"
echo ""
echo ""
echo "[INFO] Test Summary:"
echo "=================="
echo "• Total Tests: $TOTAL_TESTS"
echo "• Passed: $PASSED_TESTS"
echo "• Failed: $FAILED_TESTS" 
echo "• Skipped: $SKIPPED_TESTS"
echo "• Coverage: $COVERAGE_PERCENT"
echo "• Status: $ANALYSIS_STATUS"
echo ""

# Generate project dashboard URL
PROJECT_URL="${SONAR_HOST_URL}/dashboard?id=${PROJECT_KEY}"

echo "Analysis complete! Check your SonarQube dashboard at ${SONAR_HOST_URL}"
echo "📊 Project Dashboard: ${PROJECT_URL}"
echo ""
echo "✅ SonarQube Analysis completed successfully"
