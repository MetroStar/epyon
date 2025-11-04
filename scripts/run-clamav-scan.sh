#!/bin/bash

# ClamAV Antivirus Scan Script
# Scans for malware and viruses in the codebase using Docker

# Configuration - Support target directory override
REPO_PATH="${TARGET_DIR:-$(pwd)}"
OUTPUT_DIR="./clamav-reports"
SCAN_LOG="$OUTPUT_DIR/clamav-scan.log"
INFECTED_LOG="$OUTPUT_DIR/clamav-infected.log"

# Create output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

echo "============================================"
echo "Starting ClamAV antivirus scan..."
echo "============================================"
echo "Repository: $REPO_PATH"
echo "Output Directory: $OUTPUT_DIR"
echo "Scan Log: $SCAN_LOG"
echo ""

echo "Updating ClamAV virus definitions..."
echo ""

# First, update virus definitions
docker run --rm \
  -v clamav-db:/var/lib/clamav \
  clamav/clamav-debian:latest \
  freshclam

if [ $? -ne 0 ]; then
  echo "⚠️  Warning: Failed to update virus definitions. Proceeding with existing definitions..."
fi

echo ""
echo "Running ClamAV scan..."
echo ""

# Run ClamAV scan using Docker
# --infected: Only show infected files
# --recursive: Scan directories recursively
# --log: Log scan results
# --exclude-dir: Exclude specific directories
docker run --rm \
  -v "$REPO_PATH:/scan" \
  -v clamav-db:/var/lib/clamav \
  -v "$PWD/$OUTPUT_DIR:/reports" \
  clamav/clamav-debian:latest \
  clamscan \
  --recursive \
  --infected \
  --log=/reports/clamav-scan.log \
  --exclude-dir=node_modules \
  --exclude-dir=.git \
  --exclude-dir=dist \
  --exclude-dir=build \
  --exclude-dir=coverage \
  --exclude-dir=clamav-reports \
  --exclude-dir=trufflehog-reports \
  /scan 2>&1

SCAN_EXIT_CODE=$?

echo ""
echo "============================================"

# Parse results based on exit code
if [ $SCAN_EXIT_CODE -eq 0 ]; then
  echo "✅ ClamAV scan completed successfully!"
  echo "============================================"
  echo "🎉 No malware or viruses detected!"
elif [ $SCAN_EXIT_CODE -eq 1 ]; then
  echo "⚠️  ClamAV scan completed with threats detected!"
  echo "============================================"
  echo "🚨 MALWARE/VIRUSES FOUND! Check the detailed logs."
  
  # Extract infected files from log
  if [ -f "$SCAN_LOG" ]; then
    echo ""
    echo "Infected files:"
    echo "==============="
    grep "FOUND" "$SCAN_LOG" | tee "$INFECTED_LOG"
  fi
else
  echo "❌ ClamAV scan failed with error code: $SCAN_EXIT_CODE"
  echo "============================================"
fi

# Display summary if scan log exists
if [ -f "$SCAN_LOG" ]; then
  echo ""
  echo "Scan Summary:"
  echo "============="
  
  # Extract summary information from log
  if grep -q "SCAN SUMMARY" "$SCAN_LOG"; then
    sed -n '/----------- SCAN SUMMARY -----------/,/End Date:/p' "$SCAN_LOG"
  else
    # Fallback: count files and infected
    SCANNED_FILES=$(grep -c "OK$" "$SCAN_LOG" 2>/dev/null || echo "Unknown")
    INFECTED_FILES=$(grep -c "FOUND$" "$SCAN_LOG" 2>/dev/null || echo "0")
    
    echo "Scanned files: $SCANNED_FILES"
    echo "Infected files: $INFECTED_FILES"
  fi
  
  echo ""
  echo "Detailed results saved to: $SCAN_LOG"
  
  if [ -f "$INFECTED_LOG" ] && [ -s "$INFECTED_LOG" ]; then
    echo "Infected files list: $INFECTED_LOG"
  fi
else
  echo ""
  echo "⚠️  No scan log generated. Check Docker configuration."
fi

echo ""
echo "============================================"
echo "ClamAV scan complete."
echo "============================================"