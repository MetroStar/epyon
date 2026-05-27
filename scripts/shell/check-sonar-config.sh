#!/bin/bash

# SonarQube Configuration Checker
# Displays your current SonarQube configuration with masked credentials

show_help() {
  cat <<'EOF'
Usage: check-sonar-config.sh [--help]

Displays SonarQube/SonarCloud configuration from .env.sonar files and
shows which scanner binary will be used.

Options:
  -h, --help    Show this help text and exit.
EOF
}

if [[ "${1:-}" == "--help" ]] || [[ "${1:-}" == "-h" ]]; then
  show_help
  exit 0
fi

echo "============================================"
echo "🔍 SonarQube Configuration Checker"
echo "============================================"
echo ""

# Check for .env.sonar files
SONAR_ENV_FILES=(
  "/Users/rnelson/Desktop/Side_Projects/comet/.env.sonar"
  "$(pwd)/.env.sonar"
  "$HOME/.env.sonar"
)

echo "📂 Searching for .env.sonar files:"
FOUND_CONFIG=false
for env_file in "${SONAR_ENV_FILES[@]}"; do
  if [ -f "$env_file" ]; then
    echo "  ✅ Found: $env_file"
    FOUND_CONFIG=true
    CONFIG_FILE="$env_file"
  else
    echo "  ❌ Not found: $env_file"
  fi
done
echo ""

if [ "$FOUND_CONFIG" = true ]; then
  echo "============================================"
  echo "📋 Configuration from: $CONFIG_FILE"
  echo "============================================"
  
  # Source the config
  source "$CONFIG_FILE"
  
  # Display settings
  if [ -n "$SONAR_HOST_URL" ]; then
    echo "Host URL: $SONAR_HOST_URL"
  else
    echo "Host URL: [NOT SET]"
  fi
  
  if [ -n "$SONAR_TOKEN" ]; then
    TOKEN_PREFIX="${SONAR_TOKEN:0:8}"
    TOKEN_SUFFIX="${SONAR_TOKEN: -4}"
    TOKEN_LENGTH=${#SONAR_TOKEN}
    echo "Token: ${TOKEN_PREFIX}...${TOKEN_SUFFIX} (${TOKEN_LENGTH} chars)"
    echo ""
    echo "✅ Token is properly configured!"
  else
    echo "Token: [NOT SET]"
    echo ""
    echo "❌ Token is missing!"
  fi
  
  if [ -n "$SONAR_PROJECT_KEY" ]; then
    echo "Project Key: $SONAR_PROJECT_KEY"
  else
    echo "Project Key: [NOT SET - will use default]"
  fi
  
else
  echo "============================================"
  echo "⚠️  No configuration files found"
  echo "============================================"
  echo ""
  echo "To set up SonarQube configuration, create a .env.sonar file:"
  echo ""
  echo "Example content:"
  echo "  export SONAR_TOKEN='your-token-here'"
  echo "  export SONAR_HOST_URL='https://sonarqube.example.com'  # Use your SonarQube instance URL"
  echo "  export SONAR_PROJECT_KEY='your-project-key'"
  echo ""
  echo "Recommended location:"
  echo "  $HOME/.env.sonar (applies to all projects)"
  echo "  or"
  echo "  <project-dir>/.env.sonar (project-specific)"
fi

echo ""
echo "============================================"
echo "🔧 Environment Variables (if set):"
echo "============================================"
if [ -n "$SONAR_HOST_URL" ]; then
  echo "SONAR_HOST_URL: $SONAR_HOST_URL"
else
  echo "SONAR_HOST_URL: [not set]"
fi

if [ -n "$SONAR_TOKEN" ]; then
  echo "SONAR_TOKEN: [SET]"
else
  echo "SONAR_TOKEN: [not set]"
fi

if [ -n "$SONAR_PROJECT_KEY" ]; then
  echo "SONAR_PROJECT_KEY: $SONAR_PROJECT_KEY"
else
  echo "SONAR_PROJECT_KEY: [not set]"
fi

echo ""
echo "============================================"
echo "📍 Which Scanner Will Be Used?"
echo "============================================"

# Check for sonarqube-scanner in various locations
if command -v sonarqube-scanner &> /dev/null; then
  SCANNER_PATH=$(command -v sonarqube-scanner)
  echo "Global scanner found: $SCANNER_PATH"
  echo ""
  sonarqube-scanner --version 2>&1 | head -5
elif command -v npx &> /dev/null; then
  echo "Will use: npx sonarqube-scanner (downloads on-demand)"
  echo ""
  echo "To check npx version:"
  npx --version
else
  echo "❌ No scanner available (neither global nor npx)"
fi

echo ""
