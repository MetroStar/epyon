#!/bin/bash

# ClamAV Results Analysis Script
# Analyzes ClamAV scan results and provides detailed reporting

SCAN_LOG="./clamav-reports/clamav-scan.log"
INFECTED_LOG="./clamav-reports/clamav-infected.log"

echo "============================================"
echo "ClamAV Scan Results Analysis"
echo "============================================"
echo

# Check if scan log exists
if [ ! -f "$SCAN_LOG" ]; then
    echo "❌ No scan log found at $SCAN_LOG"
    echo "Run 'npm run virus:scan' first to generate results."
    exit 1
fi

echo "📊 Scan Overview:"
echo "=================="

# Extract key metrics from the scan summary
if grep -q "SCAN SUMMARY" "$SCAN_LOG"; then
    KNOWN_VIRUSES=$(grep "Known viruses:" "$SCAN_LOG" | tail -1 | awk '{print $3}')
    ENGINE_VERSION=$(grep "Engine version:" "$SCAN_LOG" | tail -1 | awk '{print $3}')
    SCANNED_DIRS=$(grep "Scanned directories:" "$SCAN_LOG" | tail -1 | awk '{print $3}')
    SCANNED_FILES=$(grep "Scanned files:" "$SCAN_LOG" | tail -1 | awk '{print $3}')
    INFECTED_FILES=$(grep "Infected files:" "$SCAN_LOG" | tail -1 | awk '{print $3}')
    DATA_SCANNED=$(grep "Data scanned:" "$SCAN_LOG" | tail -1 | awk '{print $3" "$4}')
    SCAN_TIME=$(grep "Time:" "$SCAN_LOG" | tail -1 | awk '{print $2" "$3" "$4" "$5" "$6}')
    
    echo "ClamAV Engine Version: $ENGINE_VERSION"
    echo "Known Virus Signatures: $KNOWN_VIRUSES"
    echo "Directories Scanned: $SCANNED_DIRS"
    echo "Files Scanned: $SCANNED_FILES"
    echo "Data Scanned: $DATA_SCANNED"
    echo "Scan Duration: $SCAN_TIME"
    echo
    
    # Security status
    if [ "$INFECTED_FILES" -eq 0 ]; then
        echo "🎉 Security Status: CLEAN"
        echo "✅ No malware or viruses detected"
    else
        echo "🚨 Security Status: THREATS DETECTED"
        echo "⚠️  Infected Files Found: $INFECTED_FILES"
    fi
else
    echo "⚠️  Unable to parse scan summary from log file"
fi

echo
echo "📁 Scan Coverage Analysis:"
echo "=========================="

# Analyze what types of files were scanned
echo "File types scanned:"
if [ -f "$SCAN_LOG" ]; then
    # Extract file extensions from scanned files (if available in verbose logs)
    grep ": OK$" "$SCAN_LOG" 2>/dev/null | \
        sed 's/.*\.\([^.]*\): OK$/\1/' | \
        sort | uniq -c | sort -nr | head -10
    
    if [ $? -ne 0 ] || [ "$(grep -c ": OK$" "$SCAN_LOG")" -eq 0 ]; then
        echo "  (File type breakdown not available - use verbose scanning for details)"
    fi
fi

echo
echo "🔍 Threat Analysis:"
echo "==================="

if [ -f "$INFECTED_LOG" ] && [ -s "$INFECTED_LOG" ]; then
    echo "⚠️  INFECTED FILES DETECTED:"
    echo "----------------------------"
    cat "$INFECTED_LOG"
    
    echo
    echo "🛡️  Recommended Actions:"
    echo "- Quarantine or delete infected files immediately"
    echo "- Run a full system scan"
    echo "- Update antivirus definitions"
    echo "- Check file sources and download history"
    echo "- Consider scanning backup systems"
else
    echo "✅ No threats detected in this scan"
    echo
    echo "🛡️  Security Recommendations:"
    echo "- Continue regular scanning schedule"
    echo "- Keep ClamAV definitions updated"
    echo "- Monitor file uploads and downloads"
    echo "- Maintain security best practices"
fi

echo
echo "📈 Scan Performance:"
echo "===================="

if grep -q "SCAN SUMMARY" "$SCAN_LOG"; then
    # Calculate performance metrics
    if [ ! -z "$SCANNED_FILES" ] && [ ! -z "$SCAN_TIME" ]; then
        # Extract just the seconds for calculation
        SECONDS_ONLY=$(echo "$SCAN_TIME" | grep -o '[0-9.]*' | head -1)
        if [ ! -z "$SECONDS_ONLY" ] && [ "$SECONDS_ONLY" != "0" ]; then
            FILES_PER_SEC=$(echo "scale=2; $SCANNED_FILES / $SECONDS_ONLY" | bc 2>/dev/null || echo "N/A")
            echo "Scan Speed: $FILES_PER_SEC files/second"
        fi
    fi
    
    echo "Efficiency: High (excluded unnecessary directories)"
    echo "Coverage: Focused on source code and application files"
else
    echo "Performance metrics not available"
fi

echo
echo "📋 Scan History:"
echo "================="

# Show recent scan timestamps if multiple scans exist
if [ -f "$SCAN_LOG" ]; then
    echo "Latest scan completion times:"
    grep "End Date:" "$SCAN_LOG" | tail -5
fi

echo
echo "💾 Output Files:"
echo "================"
echo "Main scan log: $SCAN_LOG"
if [ -f "$INFECTED_LOG" ]; then
    echo "Infected files log: $INFECTED_LOG"
else
    echo "Infected files log: None (no threats found)"
fi

echo
echo "🔧 Command Usage:"
echo "================="
echo "Run new scan:     npm run virus:scan"
echo "Analyze results:  npm run virus:analyze  (or ./analyze-clamav-results.sh)"
echo "View raw log:     cat $SCAN_LOG"

echo
echo "============================================"
echo "Analysis complete."
echo "============================================"