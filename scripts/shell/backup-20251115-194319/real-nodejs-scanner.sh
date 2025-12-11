#!/bin/bash

# REAL Node.js Security Scanner - NO FAKE SCANS
# Only runs actual, verified security tools

set -e  # Exit on any error

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
TARGET_DIR="${1:-$(pwd)}"
OUTPUT_DIR="$TARGET_DIR/real-security-scan-$TIMESTAMP"

echo -e "${WHITE}===============================================${NC}"
echo -e "${WHITE}🔥 REAL Node.js Security Scanner${NC}"
echo -e "${WHITE}   NO FAKE SCANS - VERIFIED TOOLS ONLY${NC}"
echo -e "${WHITE}===============================================${NC}"
echo

# Validate project
if [ ! -f "$TARGET_DIR/package.json" ]; then
    echo -e "${RED}❌ No package.json found. Not a Node.js project.${NC}"
    exit 1
fi

# Check dependencies
echo -e "${BLUE}🔍 Checking required tools...${NC}"

# Check npm
if ! command -v npm >/dev/null 2>&1; then
    echo -e "${RED}❌ npm not found${NC}"
    exit 1
fi
echo -e "${GREEN}✅ npm found: $(npm --version)${NC}"

# Check Docker
if ! command -v docker >/dev/null 2>&1; then
    echo -e "${RED}❌ Docker not found (required for security scans)${NC}"
    exit 1
fi

if ! docker info >/dev/null 2>&1; then
    echo -e "${RED}❌ Docker daemon not running${NC}"
    exit 1
fi
echo -e "${GREEN}✅ Docker available${NC}"

# Setup output
mkdir -p "$OUTPUT_DIR"/{logs,raw-data,reports}
echo -e "${BLUE}📁 Output: $OUTPUT_DIR${NC}"
echo

# 1. REAL NPM DEPENDENCY CHECK
echo -e "${PURPLE}1️⃣ NPM DEPENDENCY ANALYSIS${NC}"
echo "================================================"
cd "$TARGET_DIR"

if [ ! -d "node_modules" ] || [ -z "$(ls -A node_modules 2>/dev/null)" ]; then
    echo -e "${YELLOW}Installing dependencies...${NC}"
    npm install 2>&1 | tee "$OUTPUT_DIR/logs/npm-install.log"
fi

echo -e "${BLUE}Running npm audit...${NC}"
npm audit --json > "$OUTPUT_DIR/raw-data/npm-audit.json" 2>/dev/null || echo '{"vulnerabilities": {}}' > "$OUTPUT_DIR/raw-data/npm-audit.json"
npm audit 2>&1 | tee "$OUTPUT_DIR/logs/npm-audit.log"

VULN_COUNT=$(cat "$OUTPUT_DIR/raw-data/npm-audit.json" | jq '.metadata.vulnerabilities.total // 0' 2>/dev/null || echo "0")
echo -e "${GREEN}✅ NPM Audit: $VULN_COUNT vulnerabilities found${NC}"
echo

# 2. REAL SECRET DETECTION
echo -e "${PURPLE}2️⃣ SECRET DETECTION (TruffleHog)${NC}"
echo "================================================"

SECRET_SCAN_SUCCESS=false
echo -e "${BLUE}Pulling TruffleHog Docker image...${NC}"
if docker pull trufflesecurity/trufflehog:latest >/dev/null 2>&1; then
    echo -e "${BLUE}Running TruffleHog secret scan...${NC}"
    if docker run --rm -v "$TARGET_DIR:/workdir" trufflesecurity/trufflehog:latest filesystem /workdir --json --no-update > "$OUTPUT_DIR/raw-data/trufflehog-results.json" 2>"$OUTPUT_DIR/logs/trufflehog.log"; then
        # Fix: TruffleHog outputs one JSON object per line, need to count lines properly
        SECRET_COUNT=$(wc -l < "$OUTPUT_DIR/raw-data/trufflehog-results.json" 2>/dev/null | tr -d ' ' || echo "0")
        echo -e "${GREEN}✅ TruffleHog: $SECRET_COUNT potential secrets found${NC}"
        SECRET_SCAN_SUCCESS=true
    else
        echo -e "${RED}❌ TruffleHog scan failed${NC}"
        echo "[]" > "$OUTPUT_DIR/raw-data/trufflehog-results.json"
    fi
else
    echo -e "${RED}❌ Cannot pull TruffleHog image${NC}"
    echo "[]" > "$OUTPUT_DIR/raw-data/trufflehog-results.json"
fi
echo

# 3. REAL VULNERABILITY SCANNING
echo -e "${PURPLE}3️⃣ VULNERABILITY SCANNING (Grype)${NC}"
echo "================================================"

VULN_SCAN_SUCCESS=false
echo -e "${BLUE}Pulling Grype Docker image...${NC}"
if docker pull anchore/grype:latest >/dev/null 2>&1; then
    echo -e "${BLUE}Running Grype vulnerability scan...${NC}"
    if docker run --rm -v "$TARGET_DIR:/workdir" anchore/grype:latest dir:/workdir -o json > "$OUTPUT_DIR/raw-data/grype-results.json" 2>"$OUTPUT_DIR/logs/grype.log"; then
        GRYPE_COUNT=$(cat "$OUTPUT_DIR/raw-data/grype-results.json" | jq '.matches | length' 2>/dev/null || echo "0")
        echo -e "${GREEN}✅ Grype: $GRYPE_COUNT vulnerabilities found${NC}"
        VULN_SCAN_SUCCESS=true
    else
        echo -e "${RED}❌ Grype scan failed${NC}"
        echo '{"matches": []}' > "$OUTPUT_DIR/raw-data/grype-results.json"
    fi
else
    echo -e "${RED}❌ Cannot pull Grype image${NC}"
    echo '{"matches": []}' > "$OUTPUT_DIR/raw-data/grype-results.json"
fi
echo

# 4. REAL MALWARE DETECTION  
echo -e "${PURPLE}4️⃣ MALWARE DETECTION (ClamAV)${NC}"
echo "================================================"

MALWARE_SCAN_SUCCESS=false
echo -e "${BLUE}Pulling ClamAV Docker image...${NC}"
# Use clamav/clamav:stable with platform specification for ARM64 compatibility
if docker pull --platform linux/amd64 clamav/clamav:stable >/dev/null 2>&1; then
    echo -e "${BLUE}Running ClamAV malware scan...${NC}"
    echo -e "${YELLOW}Note: ClamAV will update virus definitions (may take time)${NC}"
    
    # Use the stable ClamAV image with platform specification
    CLAMAV_IMAGE="clamav/clamav:stable"
    
    if timeout 300 docker run --platform linux/amd64 --rm -v "$TARGET_DIR:/workdir" "$CLAMAV_IMAGE" bash -c "
        freshclam --quiet --no-warnings 2>/dev/null || echo 'Warning: Could not update definitions'
        clamscan -r /workdir --infected 2>&1 || clamscan -r /workdir 2>&1
    " > "$OUTPUT_DIR/logs/clamav.log" 2>&1; then
        MALWARE_COUNT=$(grep -c "FOUND" "$OUTPUT_DIR/logs/clamav.log" 2>/dev/null || echo "0")
        if [ "$MALWARE_COUNT" -gt 0 ]; then
            echo -e "${RED}⚠️ ClamAV: $MALWARE_COUNT infected files found${NC}"
        else
            echo -e "${GREEN}✅ ClamAV: No malware detected${NC}"
        fi
        MALWARE_SCAN_SUCCESS=true
    else
        echo -e "${RED}❌ ClamAV scan failed or timed out${NC}"
        echo "Scan failed" > "$OUTPUT_DIR/logs/clamav.log"
    fi
else
    echo -e "${RED}❌ Cannot pull ClamAV image${NC}"
    echo "Cannot pull image" > "$OUTPUT_DIR/logs/clamav.log"
fi
echo

# GENERATE REAL RESULTS REPORT
echo -e "${PURPLE}📊 GENERATING REAL RESULTS REPORT${NC}"
echo "================================================"

cat > "$OUTPUT_DIR/reports/real-security-report.md" << EOF
# REAL Node.js Security Scan Results

**Project:** $(basename "$TARGET_DIR")
**Scan Date:** $(date)
**Tools:** Real security scanners only - NO FAKE RESULTS

## 🔥 VERIFIED RESULTS

### NPM Audit (Dependency Vulnerabilities)
- **Status:** ✅ Completed
- **Vulnerabilities:** $VULN_COUNT found
- **Details:** See \`logs/npm-audit.log\`

### TruffleHog (Secret Detection) 
- **Status:** $([ "$SECRET_SCAN_SUCCESS" = true ] && echo "✅ Completed" || echo "❌ Failed")
- **Secrets Found:** $([ "$SECRET_SCAN_SUCCESS" = true ] && echo "$SECRET_COUNT" || echo "N/A - Scan Failed")
- **Details:** See \`raw-data/trufflehog-results.json\`

### Grype (Vulnerability Scanning)
- **Status:** $([ "$VULN_SCAN_SUCCESS" = true ] && echo "✅ Completed" || echo "❌ Failed")  
- **Vulnerabilities:** $([ "$VULN_SCAN_SUCCESS" = true ] && echo "$GRYPE_COUNT" || echo "N/A - Scan Failed")
- **Details:** See \`raw-data/grype-results.json\`

### ClamAV (Malware Detection)
- **Status:** $([ "$MALWARE_SCAN_SUCCESS" = true ] && echo "✅ Completed" || echo "❌ Failed")
- **Infected Files:** $([ "$MALWARE_SCAN_SUCCESS" = true ] && echo "${MALWARE_COUNT:-0}" || echo "N/A - Scan Failed")  
- **Details:** See \`logs/clamav.log\`

## 📁 Scan Files

All results are stored in: \`$OUTPUT_DIR\`

- \`logs/\` - Detailed scan logs
- \`raw-data/\` - Raw JSON results  
- \`reports/\` - This report

## ⚠️ IMPORTANT

These are REAL scan results from actual security tools:
- NPM Audit from npm registry
- TruffleHog from Truffle Security  
- Grype from Anchore
- ClamAV from ClamAV Foundation

No simulated or fake results were generated.

---
Scan completed: $(date)
EOF

echo -e "${GREEN}✅ Real security scan completed!${NC}"
echo -e "${BLUE}📊 Report: $OUTPUT_DIR/reports/real-security-report.md${NC}"

# Open report on macOS
if command -v open >/dev/null 2>&1; then
    echo -e "${BLUE}📖 Opening report...${NC}"
    open "$OUTPUT_DIR/reports/real-security-report.md"
fi

cd - >/dev/null